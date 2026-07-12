"""
plot_fade_results.py
=====================
Automated plotting script for FADE (B3 baseline) vs MOBIGUARD comparison
on a Hidden Forwarding attack variant (Attacks 5-8).

Modeled on plot_tap_results.py's style (95% CI error bars, supervisor's
MATLAB look), but scoped to the metrics that are actually meaningful for
the FADE/B3 comparison per main.tex:

  - M1 (MCC)  — reported "all frameworks" (main.tex Experiment 5 table).
    FADE's side is read from fade_metrics_V<variant>_pct<pct>_s<seed>.csv
    (fade_save_metrics()'s node-per-epoch pp_tp/fp/tn/fn summary), NOT
    from FADE_Attack<N>_<pct>.csv's own per-cycle cur_MCC column — that
    column is computed at flow level with only 1-2 tracked flows, which
    degenerates to ~0 by the MCC formula's epsilon term whenever a cycle
    has only TP samples and no TN counterexample (or vice versa). See
    load_fade_summary_mcc()'s docstring below.
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
import numpy as np
import matplotlib.pyplot as plt
import os
import scipy.stats as stats

RESULTS_DIR = "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
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

# Percentages excluded per attack due to known data contamination: the
# 2026-07-11/12 dedicated sweep (run_hf_attacks.py) collided with the
# concurrently-running 180-sim LSTM training collection job
# (run_training_attacks.py) on these exact (attack, pct) combos — both
# processes append to the SAME MOBIGUARD_Attack<N>_<pct>.csv (no seed/run-ID
# in the filename or row schema), so rows from the two runs (different
# simTime, different seeds) are interleaved beyond reconstruction. See
# the chat discussion / PENDING_FIXES.md for detail. Do not just delete
# this dict when re-running — update it to reflect whatever is actually
# still contaminated at the time.
EXCLUDED_PERCENTAGES = {
    5: [0, 20, 40],
}

# MOBIGUARD_Attack<N>_<pct>.csv column layout (write_security_metrics_csv, routing.cc)
MOB_COL_PDR_AVG = 2
MOB_COL_LAT_AVG = 4
MOB_COL_MCC_CUR = 5
MOB_COL_MIT_CUR = 11
MOB_COL_UCR_AVG = 20

# FADE_Attack<N>_<pct>.csv column layout (fade_write_per_cycle_csv, routing.cc)
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


def load_method_data(prefix, attack_number):
    data = {}
    for pct in ATTACK_PERCENTAGES:
        filepath = os.path.join(RESULTS_DIR, f"{prefix}_Attack{attack_number}_{pct}.csv")
        data[pct] = read_csv(filepath)
    return data


def load_fade_summary_mcc(attack_number, seeds=(1,)):
    """
    FADE_Attack<N>_<pct>.csv's own cur_MCC/avg_MCC columns are computed at
    FLOW level (fade_write_per_cycle_csv section 1): with only 1-2 flows
    tracked by fade_flow_config, most cycles have either a TP-only or a
    TN-only sample and no counterexample in the SAME cycle, so the MCC
    formula's epsilon-regularized denominator forces cur_MCC to ~0 even
    when detection is working correctly (see PENDING_FIXES.md Fix 7/Fix 8
    discussion — this is a small-sample artifact of the per-cycle file,
    not a detection failure).
    fade_metrics_V<variant>_pct<pct>_s<seed>.csv (written once per run by
    fade_save_metrics(), using the node-per-epoch pp_tp/fp/tn/fn counters
    Fix 7 introduced) does not have this problem — far more samples, and
    its filename embeds variant/pct/seed so it can't be cross-contaminated
    by concurrent runs the way the shared routing_fade_per_cycle.csv can.
    Use it for FADE's MCC instead.
    """
    variant = attack_number - 1
    data = {}
    for pct in ATTACK_PERCENTAGES:
        vals = []
        for seed in seeds:
            filepath = os.path.join(RESULTS_DIR, f"fade_metrics_V{variant}_pct{pct}_s{seed}.csv")
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


def plot_metric(ax, fade_data, mob_data, fade_col, mob_col, ylabel, title,
                 ylim=None, yticks=None):
    x = np.array(ATTACK_PERCENTAGES)

    fade_means, fade_cis = [], []
    mob_means, mob_cis = [], []

    for pct in ATTACK_PERCENTAGES:
        fm, fc = mean_and_ci(extract_column(fade_data[pct], fade_col))
        fade_means.append(fm); fade_cis.append(fc)

        mm, mc = mean_and_ci(extract_column(mob_data[pct], mob_col))
        mob_means.append(mm); mob_cis.append(mc)

    return _draw_comparison(ax, x, fade_means, fade_cis, mob_means, mob_cis, ylabel, title, ylim, yticks)


def plot_mcc_metric(ax, attack_number, mob_data, mob_col, ylabel, title,
                     ylim=None, yticks=None):
    x = np.array(ATTACK_PERCENTAGES)
    fade_mcc = load_fade_summary_mcc(attack_number)

    fade_means, fade_cis = [], []
    mob_means, mob_cis = [], []

    for pct in ATTACK_PERCENTAGES:
        fm, fc = mean_and_ci(np.array(fade_mcc[pct]))
        fade_means.append(fm); fade_cis.append(fc)

        mm, mc = mean_and_ci(extract_column(mob_data[pct], mob_col))
        mob_means.append(mm); mob_cis.append(mc)

    return _draw_comparison(ax, x, fade_means, fade_cis, mob_means, mob_cis, ylabel, title, ylim, yticks)


def _draw_comparison(ax, x, fade_means, fade_cis, mob_means, mob_cis, ylabel, title,
                      ylim=None, yticks=None):
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


def plot_attack(attack_number):
    print(f"\n=== Attack {attack_number} ===")
    fade_data = load_method_data("FADE", attack_number)
    mob_data  = load_method_data("MOBIGUARD", attack_number)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for pct in ATTACK_PERCENTAGES:
        print(f"  {pct}%: FADE={len(fade_data[pct])} rows, MOBIGUARD={len(mob_data[pct])} rows")

    label = ATTACK_LABELS.get(attack_number, f"Attack {attack_number}")

    metrics = [
        (FADE_COL_PDR_AVG, MOB_COL_PDR_AVG, "Packet Delivery Ratio (%)",        "(a) PDR [supplementary]", [-5, 115], [0, 20, 40, 60, 80, 100]),
        (FADE_COL_UCR_AVG, MOB_COL_UCR_AVG, "Unauthorized Copy Rate (%)",       "(c) UCR [M3]",            [-5, 115], [0, 20, 40, 60, 80, 100]),
        (FADE_COL_MIT_CUR, MOB_COL_MIT_CUR, "Mitigation Latency (ms)",          "(d) Mitigation [M4]",     None, None),
        (FADE_COL_LAT_AVG, MOB_COL_LAT_AVG, "End-to-End Latency (ms)",          "(e) Latency [M6]",        None, None),
    ]

    fig, axes = plt.subplots(1, len(metrics) + 1, figsize=(7 * (len(metrics) + 1), 7))
    fig.suptitle(f"Complete Performance Evaluation — {label}\n"
                 "FADE (Zhang et al. IEEE TPDS 2021) vs MOBIGUARD (Proposed)",
                 fontsize=22, fontweight='bold', y=1.02)

    first_p1, first_p2 = plot_mcc_metric(
        axes[0], attack_number, mob_data, MOB_COL_MCC_CUR,
        "Matthews Correlation Coefficient", "(b) MCC [M1]",
        ylim=[-1.1, 1.1], yticks=[-1.0, -0.5, 0.0, 0.5, 1.0]
    )
    for ax, (fcol, mcol, ylabel, title, ylim, yticks) in zip(axes[1:], metrics):
        plot_metric(ax, fade_data, mob_data, fcol, mcol, ylabel, title, ylim, yticks)

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


def main():
    parser = argparse.ArgumentParser(description="Plot FADE vs MOBIGUARD comparison for HF attack variants.")
    parser.add_argument("--attack", type=int, action="append", choices=[5, 6, 7, 8],
                         help="Attack number(s) to plot (repeatable). Default: all of 5,6,7,8.")
    args = parser.parse_args()
    attacks = args.attack if args.attack else [5, 6, 7, 8]

    for a in attacks:
        plot_attack(a)

    print("\nDone.")


if __name__ == "__main__":
    main()
