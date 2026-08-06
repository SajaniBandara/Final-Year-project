"""
plot_fade_results.py
=====================
Automated plotting script for FADE (B3 baseline) vs MOBIGUARD comparison
on a Hidden Forwarding attack variant (Attacks 5-8).

Modeled on plot_tap_results.py's style (95% CI error bars, supervisor's
MATLAB look), but scoped to the metrics that are actually meaningful for
the FADE/B3 comparison per main.tex:

  - M1 (MCC)  — reported "all frameworks" (main.tex Experiment 5 table).
    FADE's side is read from fade_metrics_Attack<N>_<pct>_seed<S>.csv
    (fade_save_metrics()'s node-per-epoch pp_tp/fp/tn/fn summary), NOT
    from FADE__Attack<N>_<pct>_seed<S>.csv's own per-cycle cur_MCC column — that
    column is computed at flow level with only 1-2 tracked flows, which
    degenerates to ~0 by the MCC formula's epsilon term whenever a cycle
    has only TP samples and no TN counterexample (or vice versa). See
    load_fade_summary_mcc()'s docstring below.

    MOBIGUARD's side is read from each run's LAST cycle's cumulative
    TP/FP/TN/FN (see load_mobiguard_final_mcc()), NOT a mean of every
    cycle's cur_MCC. write_security_metrics_csv()'s cur_MCC is a per-cycle
    snapshot over a STICKY confusion matrix (is_detected_node[] is set
    true once and never reset, routing.cc) — it necessarily starts at 0
    during the run's cold-start cycles (before any node is malicious yet)
    and ramps toward a converged value as detection accumulates. FADE's
    fade_save_metrics() is called exactly ONCE, at the end of the whole
    run, using the fully-accumulated pp_tp/fp/tn/fn counters — i.e. FADE
    reports a single converged snapshot. Averaging MOBIGUARD's cur_MCC
    over every cycle (including the cold-start ones) against FADE's single
    converged number is not apples-to-apples and structurally understates
    MOBIGUARD (found + fixed 2026-07-16, see PENDING_FIXES.md Fix 14).
    Using MOBIGUARD's own last cycle mirrors FADE's methodology exactly.
  - M3 (UCR)  — "reported for S5-S8 only" (main.tex Experiment 5 table);
    THIS replaces TVR (M2), which main.tex marks N/A for S5-S8 — TVR is a
    Selective-Time-Delay metric (Variants 1-4) and is not meaningful here.
  - M4 (Mitigation Latency) — main.tex states explicitly: "B3 (FADE)
    reports no explicit node isolation mechanism, blocking attack flows
    via flow-rule removal only" (main.tex:3650-3653). FADE's own CSV
    hard-codes this column to 0 for exactly this reason (see
    fade_write_per_cycle_csv() in routing.cc) — the flat-zero FADE line
    in this panel is not a plotting bug, it is the documented behavior
    the thesis text describes.
  - M6 (Overall Latency) — "all frameworks."
  - PDR — supplementary QoS sanity check, same shared global metric both
    methods report (average_packet_delivery_ratio_dsrc).

CSV column layouts DIFFER between the two file types (FADE's per-cycle
writer inserts two extra PIR columns MOBIGUARD's writer doesn't have —
see fade_write_per_cycle_csv()'s header comment in routing.cc), so each
file type has its own column-index map below. Do not reuse
plot_tap_results.py's COL_* constants against FADE files.

Usage:
    python3 plot_fade_results.py --attack 7
    python3 plot_fade_results.py --attack 5 --attack 6 --attack 7 --attack 8
"""

import argparse
import glob
import numpy as np
import matplotlib.pyplot as plt
import os
import scipy.stats as stats

RESULTS_DIR = "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR  = os.path.join(PROJECT_DIR, "output", "fade")

ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

ATTACK_LABELS = {
    5: "Attack 5 (Hidden Forwarding, Active, Control Plane)",
    6: "Attack 6 (Hidden Forwarding, Active, Data Plane)",
    7: "Attack 7 (Hidden Forwarding, Passive, Control Plane)",
    8: "Attack 8 (Hidden Forwarding, Passive, Data Plane)",
}

# Short single-line form for the combined figure's rotated row labels —
# full ATTACK_LABELS strings are too long to rotate 90° in a packed 4-row
# grid without overlapping the neighboring row's label.
ATTACK_LABELS_SHORT = {
    5: "Attack 5 (Active, CP)",
    6: "Attack 6 (Active, DP)",
    7: "Attack 7 (Passive, CP)",
    8: "Attack 8 (Passive, DP)",
}

# Percentages excluded per attack due to known data contamination.
# RESOLVED 2026-07-14: MOBIGUARD_Attack<N>_<pct>.csv is now collected by
# run_rule_based_sweep.py, which runs each (attack, pct) pair's seeds
# SEQUENTIALLY and renames the result to embed the seed
# (MOBIGUARD_Attack<N>_<pct>[_d<D>ms]_seed<S>.csv) immediately after each
# run — the interleaving bug this dict used to work around (two concurrent
# processes appending to the same seed-less filename) can no longer happen.
# Kept as an empty dict (rather than deleted) so a future contamination
# find has an obvious place to re-populate it.
EXCLUDED_PERCENTAGES = {}

# MOBIGUARD_Attack<N>_<pct>.csv column layout (write_security_metrics_csv, routing.cc)
MOB_COL_PDR_AVG = 2
MOB_COL_LAT_AVG = 4
MOB_COL_MCC_CUR = 5   # kept for reference; MCC panel now uses last-cycle TP/FP/TN/FN instead
MOB_COL_MIT_CUR = 11
MOB_COL_TP      = 13
MOB_COL_FP      = 14
MOB_COL_TN      = 15
MOB_COL_FN      = 16
MOB_COL_UCR_AVG = 20

# FADE__Attack<N>_<pct>_seed<S>.csv column layout (fade_write_per_cycle_csv, routing.cc)
# NOTE: two extra PIR columns (17,18) shift TVR/UCR two places right vs MOBIGUARD's file.
FADE_COL_PDR_AVG = 2
FADE_COL_LAT_AVG = 4
FADE_COL_MCC_CUR = 5
FADE_COL_MIT_CUR = 11   # always 0.0 — FADE has no mitigation stage (see module docstring)
FADE_COL_UCR_AVG = 22

ALPHA = 0.05


def read_csv(filepath):
    rows = []
    if not os.path.exists(filepath):
        return rows
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                rows.append([float(v.strip()) for v in line.split(',')])
            except ValueError:
                continue
    return rows


def extract_column(rows, col):
    return np.array([r[col] for r in rows if len(r) > col])


def mean_and_ci(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = np.mean(values)
    if n == 1:
        return m, 0.0
    s  = np.std(values, ddof=1)
    t  = stats.t.ppf(1 - ALPHA / 2, df=n - 1)
    return m, t * (s / np.sqrt(n))


def load_method_data(prefix, attack_number, seeds=(1,)):
    """
    prefix is the literal filename prefix as written by the C++ side —
    "MOBIGUARD" (single underscore before "_Attack") or "FADE_" (double
    underscore: the "FADE_" prefix plus the canonical "_Attack..." suffix
    gives "FADE__Attack...").

    seeds=(1,): FADE__Attack<N>_<pct>[_d<D>ms]_seed<S>.csv — the isolated
    FADE sweep (run_hf_attacks.py) only ever collects seed=1.

    seeds=(1,2,3): MOBIGUARD_Attack<N>_<pct>[_d<D>ms]_seed<S>.csv — each
    seed's rows are concatenated, so mean_and_ci naturally averages over
    all 3 seeds' cycles combined (run_rule_based_sweep.py, 2026-07-14; see
    EXCLUDED_PERCENTAGES comment above for why the old single shared
    filename could not do this safely). MOBIGUARD therefore gets a deeper
    sample than FADE's single seed — an honest reflection of what was
    actually collected for each method, not an attempt to force parity.
    """
    data = {}
    for pct in ATTACK_PERCENTAGES:
        rows = []
        for seed in seeds:
            for filepath in glob.glob(os.path.join(
                    RESULTS_DIR, f"{prefix}_Attack{attack_number}_{pct}*_seed{seed}.csv")):
                rows.extend(read_csv(filepath))
        data[pct] = rows
    return data


def load_fade_summary_mcc(attack_number, seeds=(1,)):
    """
    FADE__Attack<N>_<pct>_seed<S>.csv's own cur_MCC/avg_MCC columns are
    computed at FLOW level (fade_write_per_cycle_csv section 1): with only
    1-2 flows tracked by fade_flow_config, most cycles have either a TP-only
    or a TN-only sample and no counterexample in the SAME cycle, so the MCC
    formula's epsilon-regularized denominator forces cur_MCC to ~0 even
    when detection is working correctly (see PENDING_FIXES.md Fix 7/Fix 8
    discussion — this is a small-sample artifact of the per-cycle file,
    not a detection failure).
    fade_metrics_Attack<N>_<pct>_seed<S>.csv (written once per run by
    fade_save_metrics(), using the node-per-epoch pp_tp/fp/tn/fn counters
    Fix 7 introduced) does not have this problem — far more samples. Use it
    for FADE's MCC instead. (routing_fade_per_cycle.csv, the per-cycle
    file this reads, used to be a single untagged shared file that
    concurrent runs could cross-contaminate — since fixed by tagging it
    with g_sim_tag — but the small-sample MCC artifact above is the
    reason this function avoids it regardless of tagging.)
    """
    data = {}
    for pct in ATTACK_PERCENTAGES:
        vals = []
        for seed in seeds:
            filepath = os.path.join(RESULTS_DIR, f"fade_metrics_Attack{attack_number}_{pct}_seed{seed}.csv")
            if not os.path.exists(filepath):
                continue
            with open(filepath) as f:
                next(f)  # header
                for line in f:
                    parts = [p.strip() for p in line.strip().split(',')]
                    if len(parts) >= 10:
                        vals.append(float(parts[9]))  # mcc column
        data[pct] = vals
    return data


def compute_mcc(tp, fp, tn, fn):
    eps = 1e-6
    num = (tp * tn) - (fp * fn)
    den = np.sqrt((tp + fp + eps) * (tp + fn + eps) * (tn + fp + eps) * (tn + fn + eps))
    return num / den


def load_mobiguard_final_mcc(attack_number, seeds=(1, 2, 3)):
    """
    MOBIGUARD's converged, end-of-run MCC per (pct, seed) — the LAST row's
    cumulative TP/FP/TN/FN in each seed's own CSV, matching FADE's
    single-converged-snapshot methodology (see module docstring's M1
    section). Each seed's file is read separately (unlike load_method_data,
    which concatenates all seeds' rows together and would lose the
    per-seed "last row" boundary needed here).
    """
    data = {}
    for pct in ATTACK_PERCENTAGES:
        vals = []
        for seed in seeds:
            for filepath in glob.glob(os.path.join(
                    RESULTS_DIR, f"MOBIGUARD_Attack{attack_number}_{pct}*_seed{seed}.csv")):
                rows = read_csv(filepath)
                if not rows:
                    continue
                last = rows[-1]
                if len(last) <= MOB_COL_FN:
                    continue
                tp, fp, tn, fn = (last[MOB_COL_TP], last[MOB_COL_FP],
                                   last[MOB_COL_TN], last[MOB_COL_FN])
                vals.append(compute_mcc(tp, fp, tn, fn))
        data[pct] = vals
    return data


def plot_metric(ax, fade_data, mob_data, fade_col, mob_col, ylabel, title,
                 pcts, excluded_pcts, ylim=None, yticks=None):
    x = np.array(pcts)

    fade_means, fade_cis = [], []
    mob_means, mob_cis = [], []

    for pct in pcts:
        fm, fc = mean_and_ci(extract_column(fade_data[pct], fade_col))
        fade_means.append(fm); fade_cis.append(fc)

        mm, mc = mean_and_ci(extract_column(mob_data[pct], mob_col))
        mob_means.append(mm); mob_cis.append(mc)

    return _draw_comparison(ax, x, fade_means, fade_cis, mob_means, mob_cis, ylabel, title,
                             excluded_pcts, ylim, yticks)


def plot_mcc_metric(ax, attack_number, ylabel, title,
                     pcts, excluded_pcts, ylim=None, yticks=None):
    x = np.array(pcts)
    fade_mcc = load_fade_summary_mcc(attack_number)
    mob_mcc  = load_mobiguard_final_mcc(attack_number, seeds=(1, 2, 3))

    fade_means, fade_cis = [], []
    mob_means, mob_cis = [], []

    for pct in pcts:
        fm, fc = mean_and_ci(np.array(fade_mcc[pct]))
        fade_means.append(fm); fade_cis.append(fc)

        mm, mc = mean_and_ci(np.array(mob_mcc[pct]))
        mob_means.append(mm); mob_cis.append(mc)

    return _draw_comparison(ax, x, fade_means, fade_cis, mob_means, mob_cis, ylabel, title,
                             excluded_pcts, ylim, yticks)


def _draw_comparison(ax, x, fade_means, fade_cis, mob_means, mob_cis, ylabel, title,
                      excluded_pcts=None, ylim=None, yticks=None):
    fade_means = np.array(fade_means); fade_cis = np.array(fade_cis)
    mob_means  = np.array(mob_means);  mob_cis  = np.array(mob_cis)

    p1 = ax.errorbar(x, fade_means, yerr=fade_cis,
                      fmt='o', color='red', markerfacecolor='red',
                      markersize=9, linewidth=2, capsize=18, linestyle='-',
                      label='FADE (Zhang et al. 2021)')

    p2 = ax.errorbar(x, mob_means, yerr=mob_cis,
                      fmt='s', color='blue', markerfacecolor='blue',
                      markersize=9, linewidth=2, capsize=18, linestyle='--',
                      label='MOBIGUARD (Proposed)')

    if excluded_pcts:
        for pct in excluded_pcts:
            ax.axvspan(pct - 8, pct + 8, color='grey', alpha=0.15, zorder=0)
        ax.text(0.02, 0.02,
                f"grey = {', '.join(str(p) + '%' for p in excluded_pcts)} excluded\n(contaminated CSV, see report)",
                transform=ax.transAxes, fontsize=10, color='dimgrey',
                verticalalignment='bottom', style='italic')

    ax.grid(True, linestyle='-', alpha=0.2, linewidth=1.0)
    ax.set_axisbelow(True)
    ax.set_xlabel("Attack Percentage (%)", fontsize=22)
    ax.set_ylabel(ylabel, fontsize=22)
    ax.tick_params(axis='both', labelsize=22)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_xlim([-5, 105])
    if ylim is not None:
        ax.set_ylim(ylim)
    if yticks is not None:
        ax.set_yticks(yticks)
    ax.set_title(title, fontsize=20, pad=10)
    return p1, p2


METRICS = [
    (FADE_COL_PDR_AVG, MOB_COL_PDR_AVG, "Packet Delivery Ratio (%)",  "(a) PDR [supplementary]", [-5, 115], [0, 20, 40, 60, 80, 100]),
    (FADE_COL_UCR_AVG, MOB_COL_UCR_AVG, "Unauthorized Copy Rate (%)", "(c) UCR [M3]",            [-5, 115], [0, 20, 40, 60, 80, 100]),
    (FADE_COL_MIT_CUR, MOB_COL_MIT_CUR, "Mitigation Latency (ms)",    "(d) Mitigation [M4]",     None, None),
    (FADE_COL_LAT_AVG, MOB_COL_LAT_AVG, "End-to-End Latency (ms)",    "(e) Latency [M6]",        None, None),
]


def _blank_row(axes_row, message):
    """Render empty panels with a centered explanatory message (all pcts excluded)."""
    titles = ["(b) MCC [M1]", "(a) PDR [supplementary]", "(c) UCR [M3]", "(d) Mitigation [M4]", "(e) Latency [M6]"]
    for ax, title in zip(axes_row, titles):
        ax.set_xticks([0, 20, 40, 60, 80, 100])
        ax.set_xlim([-5, 105])
        ax.set_xlabel("Attack Percentage (%)", fontsize=22)
        ax.set_title(title, fontsize=20, pad=10)
        ax.grid(True, linestyle='-', alpha=0.2, linewidth=1.0)
    axes_row[2].text(0.5, 0.5, message, transform=axes_row[2].transAxes,
                      ha='center', va='center', fontsize=16, color='firebrick',
                      style='italic', wrap=True)


def plot_attack_row(axes_row, attack_number, row_label=None):
    """Draw one attack's 5-panel comparison across the given row of axes."""
    fade_data = load_method_data("FADE_", attack_number)
    mob_data  = load_method_data("MOBIGUARD", attack_number, seeds=(1, 2, 3))

    excluded = EXCLUDED_PERCENTAGES.get(attack_number, [])
    pcts = [p for p in ATTACK_PERCENTAGES if p not in excluded]

    for pct in ATTACK_PERCENTAGES:
        tag = "  [EXCLUDED — contaminated]" if pct in excluded else ""
        print(f"  {pct}%: FADE={len(fade_data[pct])} rows, MOBIGUARD={len(mob_data[pct])} rows{tag}")

    if not pcts:
        _blank_row(axes_row, "All percentages excluded —\nCSV contaminated by concurrent\ntraining job. Needs clean re-run.")
        return None, None

    p1, p2 = plot_mcc_metric(
        axes_row[0], attack_number,
        "Matthews Correlation Coefficient", "(b) MCC [M1]",
        pcts, excluded,
        ylim=[-1.1, 1.1], yticks=[-1.0, -0.5, 0.0, 0.5, 1.0]
    )
    for ax, (fcol, mcol, ylabel, title, ylim, yticks) in zip(axes_row[1:], METRICS):
        plot_metric(ax, fade_data, mob_data, fcol, mcol, ylabel, title, pcts, excluded, ylim, yticks)

    if row_label:
        axes_row[0].annotate(
            row_label, xy=(0, 0.5), xytext=(-axes_row[0].yaxis.labelpad - 55, 0),
            xycoords=axes_row[0].yaxis.label, textcoords='offset points',
            fontsize=18, fontweight='bold', ha='right', va='center', rotation=90
        )
    return p1, p2


def plot_attack(attack_number):
    print(f"\n=== Attack {attack_number} ===")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    excluded = EXCLUDED_PERCENTAGES.get(attack_number, [])
    label = ATTACK_LABELS.get(attack_number, f"Attack {attack_number}")
    title_suffix = ""
    if excluded:
        title_suffix = f"  [{', '.join(str(p)+'%' for p in excluded)} excluded — contaminated CSV]"

    fig, axes = plt.subplots(1, len(METRICS) + 1, figsize=(7 * (len(METRICS) + 1), 7))
    fig.suptitle(f"Complete Performance Evaluation — {label}{title_suffix}\n"
                 "FADE (Zhang et al. IEEE TPDS 2021) vs MOBIGUARD (Proposed)",
                 fontsize=22, fontweight='bold', y=1.02)

    first_p1, first_p2 = plot_attack_row(axes, attack_number)

    fig.legend(
        [first_p1, first_p2],
        ['FADE (Zhang et al. 2021)', 'MOBIGUARD (Proposed)'],
        loc='upper right', ncol=2, fontsize=20,
        bbox_to_anchor=(0.98, 1.08), markerscale=1.5
    )

    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, f"Figure_Attack{attack_number}_AllMetrics.png")
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    print(f"  Saved: {out_path}")
    plt.close(fig)


def plot_combined(attack_numbers):
    print(f"\n=== Combined figure: attacks {attack_numbers} ===")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    n_rows = len(attack_numbers)
    n_cols = len(METRICS) + 1
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(7 * n_cols, 6.5 * n_rows))
    if n_rows == 1:
        axes = axes[np.newaxis, :]

    fig.suptitle("Complete Performance Evaluation — Hidden Forwarding Attacks 5-8\n"
                 "FADE (Zhang et al. IEEE TPDS 2021) vs MOBIGUARD (Proposed)",
                 fontsize=24, fontweight='bold', y=1.01)

    first_p1, first_p2 = None, None
    row_labels = []
    for row, attack_number in enumerate(attack_numbers):
        print(f"\n--- row {row}: Attack {attack_number} ---")
        label = ATTACK_LABELS_SHORT.get(attack_number, f"Attack {attack_number}")
        excluded = EXCLUDED_PERCENTAGES.get(attack_number, [])
        row_labels.append(label + (" *" if excluded else ""))
        p1, p2 = plot_attack_row(axes[row], attack_number)
        if first_p1 is None:
            first_p1, first_p2 = p1, p2
        # Only the bottom row keeps x-axis label; only first column of each row keeps y-axis label (already set)
        if row != n_rows - 1:
            for ax in axes[row]:
                ax.set_xlabel("")

    plt.tight_layout(rect=[0.045, 0, 1, 1])
    fig.subplots_adjust(hspace=0.45)

    # Row labels placed via fig.text at each row's actual vertical center
    # (post-layout ax positions), avoiding the overlap that per-axis
    # annotate() produced when rows are packed tightly by tight_layout.
    # Kept short + single-line (see ATTACK_LABELS_SHORT) since a rotated
    # multi-line label is tall enough to bleed into the neighboring row
    # in a packed 4-row grid.
    for row, text in enumerate(row_labels):
        pos = axes[row][0].get_position()
        y_center = (pos.y0 + pos.y1) / 2
        fig.text(0.012, y_center, text, rotation=90, fontsize=15, fontweight='bold',
                  ha='center', va='center')
    if any(EXCLUDED_PERCENTAGES.get(a) for a in attack_numbers):
        fig.text(0.012, 0.005, "* some % excluded (contaminated CSV)",
                  fontsize=10, style='italic', color='dimgrey', ha='left', va='bottom')

    fig.legend(
        [first_p1, first_p2],
        ['FADE (Zhang et al. 2021)', 'MOBIGUARD (Proposed)'],
        loc='upper right', ncol=2, fontsize=20,
        bbox_to_anchor=(0.98, 1.01), markerscale=1.5
    )

    out_path = os.path.join(OUTPUT_DIR, "Figure_Combined_Attacks5-8_AllMetrics.png")
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    print(f"\n  Saved: {out_path}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Plot FADE vs MOBIGUARD comparison for HF attack variants.")
    parser.add_argument("--attack", type=int, action="append", choices=[5, 6, 7, 8],
                         help="Attack number(s) to plot (repeatable). Default: all of 5,6,7,8.")
    parser.add_argument("--combined", action="store_true",
                         help="Produce one figure with all attacks stacked as rows, instead of one PNG per attack.")
    args = parser.parse_args()
    attacks = args.attack if args.attack else [5, 6, 7, 8]

    if args.combined:
        plot_combined(attacks)
    else:
        for a in attacks:
            plot_attack(a)

    print("\nDone.")


if __name__ == "__main__":
    main()
