"""
plot_tap_results.py
===================
Automated plotting script for TAP vs MOBIGUARD comparison.
Follows supervisor's MATLAB style:
  - Average values with 95% confidence interval error bars
  - Different linestyles and marker styles per method
  - Grid lines enabled
  - Properly labelled axes with units
  - FontSize 22 (matching supervisor's MATLAB)

Metric scope: plots only the current, active main.tex performance metrics
applicable to a TAP-vs-MOBIGUARD comparison on Attack 2 (Selective Time
Delay, Data Plane) — M1 (MCC), M2 (TVR), M4 (Mitigation Latency), M6
(Overall Latency) — plus PDR as a supplementary QoS sanity-check panel
(PDR is not one of the 12 numbered metrics in the current main.tex
revision; it only existed as "M5" in an old, now-commented-out numbering).
Detection Rate and FPR were dropped: FPR is explicitly a hyperparameter
hard-constraint in main.tex (not a top-level metric), and DR doesn't
appear under any current M1-M12 title — both are sub-components MCC
already summarizes. M3/M5/M7-M12 are excluded: M3 (UCR) only applies to
hidden-forwarding attacks (Attack 2 never produces unauthorized copies);
M5/M8/M9/M12 are ablation-only, excluded from all benchmarking per
main.tex:4623; M7/M11 have no TAP-side equivalent (TAP has no
crypto/blockchain layer); M10 is a static architectural claim, not a
runtime metric.

Usage:
    python3 plot_tap_results.py

CSV files must be in:
    /home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/

CSV column order (columns are 0-indexed):
    0:  cycle
    1:  current PDR%
    2:  average PDR%
    3:  current latency ms
    4:  average latency ms
    5:  current MCC
    6:  average MCC
    7:  current DR%
    8:  average DR%
    9:  current FPR%
    10: average FPR%
    11: current mitigation ms
    12: average mitigation ms
    13: TP
    14: FP
    15: TN
    16: FN
    17: current TVR% (M2, eq:tvr — ground truth, same definition for both methods)
    18: average TVR%
"""

import argparse
import numpy as np
import matplotlib.pyplot as plt
import os
import scipy.stats as stats

# ─── Configuration ────────────────────────────────────────────────────────────

RESULTS_DIR = "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR  = os.path.join(PROJECT_DIR, "output", "tap")

ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

# The simulation appends a "_d<delay>ms" suffix to every Attack 1/2 result file
# whenever --attack_number is set (routing.cc, g_delay_suffix). run_std_attacks.py
# always passes --attack_number and defaults the delay to 80 ms, so the CSVs it
# produces are named e.g. TAP_Attack2_40_d80ms.csv. This must match, or no data
# is found. Override with --delay to plot a different point of a delay sweep.
DEFAULT_DELAY_MS = 80


def delay_suffix(delay_ms):
    """Return the filename suffix for a fixed delay, e.g. '_d80ms', or '' if None."""
    return f"_d{int(delay_ms)}ms" if delay_ms is not None else ""

# Column indices in CSV — only the columns feeding an official metric (or the
# PDR supplementary panel) are kept here; COL_DR_CUR/COL_FPR_CUR intentionally
# removed along with the panels that used them.
COL_PDR_AVG    = 2
COL_LAT_AVG    = 4
COL_MCC_CUR    = 5
COL_MIT_CUR    = 11
COL_TVR_AVG    = 18

ALPHA     = 0.05   # significance level for 95% CI

# ─── Helper: read all rows from a CSV file ───────────────────────────────────

def read_csv(filepath):
    """Return list of rows as float lists. Skips empty lines."""
    rows = []
    if not os.path.exists(filepath):
        return rows
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append([float(v.strip()) for v in line.split(',')])
            except ValueError:
                continue
    return rows


def extract_column(rows, col):
    """Extract a single column from rows as numpy array."""
    return np.array([r[col] for r in rows if len(r) > col])


# ─── Helper: compute mean and 95% CI ────────────────────────────────────────

def mean_and_ci(values):
    """
    Returns (mean, ci_half_width) for a 95% confidence interval.
    Uses t-distribution with n-1 degrees of freedom, matching
    supervisor's MATLAB: t_value = tinv(1-alpha/2, n-1)
                         ci = t_value * (std / sqrt(n))
    """
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = np.mean(values)
    if n == 1:
        return m, 0.0
    s   = np.std(values, ddof=1)       # sample std (ddof=1 matches MATLAB std)
    t   = stats.t.ppf(1 - ALPHA / 2, df=n - 1)
    ci  = t * (s / np.sqrt(n))
    return m, ci


# ─── Load data for all attack percentages ────────────────────────────────────

def load_method_data(prefix, suffix=""):
    """
    Load data for one method (TAP or MOBIGUARD) across all attack percentages.
    `suffix` is the delay tag (e.g. '_d80ms') the simulation appends to the
    filename. Returns dict: {attack_pct: rows_list}
    """
    data = {}
    for pct in ATTACK_PERCENTAGES:
        filepath = os.path.join(RESULTS_DIR, f"{prefix}_Attack2_{pct}{suffix}.csv")
        data[pct] = read_csv(filepath)
    return data


# ─── Plot a single metric subplot ────────────────────────────────────────────

def plot_metric(ax, tap_data, mob_data, col, ylabel, title,
                ylim=None, yticks=None):
    """
        Plot one metric panel comparing both methods:
            - TAP (red solid -o)
            - MOBIGUARD (blue dashed -s)
      - 95% CI error bars (CapSize=18, matching supervisor's MATLAB)
      - Grid, font size 22, proper axis labels

        Returns (p1, p2): the TAP and MOBIGUARD errorbar handles, for callers
        that build a shared figure-level legend.
    """
    x = np.array(ATTACK_PERCENTAGES)

    tap_means, tap_cis = [], []
    mob_means, mob_cis = [], []

    for pct in ATTACK_PERCENTAGES:
        tap_vals = extract_column(tap_data[pct], col)
        tm, tc = mean_and_ci(tap_vals)
        tap_means.append(tm)
        tap_cis.append(tc)

        mob_vals = extract_column(mob_data[pct], col)
        mm, mc = mean_and_ci(mob_vals)
        mob_means.append(mm)
        mob_cis.append(mc)

    tap_means = np.array(tap_means)
    tap_cis   = np.array(tap_cis)
    mob_means = np.array(mob_means)
    mob_cis   = np.array(mob_cis)

    # ── TAP line — red solid with circle markers (matches supervisor's p1 style)
    p1 = ax.errorbar(x, tap_means, yerr=tap_cis,
                     fmt='o',
                     color='red',
                     markerfacecolor='red',
                     markersize=9,
                     linewidth=2,
                     capsize=18,
                     linestyle='-',
                     label='TAP (Arsalan & Rehman 2018)')

    # ── MOBIGUARD line — blue dashed with square markers
    p2 = ax.errorbar(x, mob_means, yerr=mob_cis,
                     fmt='s',
                     color='blue',
                     markerfacecolor='blue',
                     markersize=9,
                     linewidth=2,
                     capsize=18,
                     linestyle='--',
                     label='MOBIGUARD (Proposed)')

    # ── Grid (matches supervisor: grid on, GridAlpha=0.2)
    ax.grid(True, linestyle='-', alpha=0.2, linewidth=1.0)
    ax.set_axisbelow(True)

    # ── Axes labels and ticks (FontSize 22, matching supervisor)
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


# ─── Main plotting function ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Plot TAP vs MOBIGUARD comparison for Attack 2.",
    )
    parser.add_argument(
        "--delay", type=int, default=DEFAULT_DELAY_MS, metavar="MS",
        help=(
            "Attack delay (ms) of the run to plot; selects the '_d<MS>ms' CSV "
            f"filename suffix (default {DEFAULT_DELAY_MS}, matching run_std_attacks.py). "
            "Use --no-suffix for legacy files written without a delay tag."
        ),
    )
    parser.add_argument(
        "--no-suffix", action="store_true",
        help="Read files with no '_d<delay>ms' suffix (legacy naming).",
    )
    args = parser.parse_args()

    suffix = "" if args.no_suffix else delay_suffix(args.delay)

    print("Loading CSV data...")
    if suffix:
        print(f"  Using filename suffix '{suffix}'")
    tap_data = load_method_data("TAP", suffix)
    mob_data = load_method_data("MOBIGUARD", suffix)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Verify files loaded
    for pct in ATTACK_PERCENTAGES:
        n_tap = len(tap_data[pct])
        n_mob = len(mob_data[pct])
        print(f"  Attack {pct}%: TAP={n_tap} rows, MOBIGUARD={n_mob} rows")

    if all(len(tap_data[p]) == 0 for p in ATTACK_PERCENTAGES) and \
       all(len(mob_data[p]) == 0 for p in ATTACK_PERCENTAGES):
        print(f"\n⚠  No data found in {RESULTS_DIR}")
        print(f"   Expected files like  TAP_Attack2_40{suffix}.csv")
        print( "   Check the --delay value matches the runs, or pass --no-suffix.")

    print("\nGenerating Figure 1: Detection Quality (M1 MCC, M2 TVR)")

    # ── Figure 1: Detection-quality metrics — M1 (MCC), M2 (TVR) ─────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 7))
    fig.suptitle("Detection Quality — Attack 2\n"
                 "(Selective Time Delay Attack — Data Plane)",
                 fontsize=22, fontweight='bold', y=1.02)

    # Subplot (a): Matthews Correlation Coefficient (M1)
    p1, p2 = plot_metric(
        axes[0], tap_data, mob_data,
        col    = COL_MCC_CUR,
        ylabel = "Matthews Correlation Coefficient",
        title  = "(a) MCC [M1]",
        ylim   = [-1.1, 1.1],
        yticks = [-1.0, -0.5, 0.0, 0.5, 1.0]
    )

    # Subplot (b): Safety-Critical Threshold Violation Rate (M2)
    plot_metric(
        axes[1], tap_data, mob_data,
        col    = COL_TVR_AVG,
        ylabel = "Threshold Violation Rate (%)",
        title  = "(b) TVR [M2]",
        ylim   = [-5, 115],
        yticks = [0, 20, 40, 60, 80, 100]
    )

    # Shared legend at top (matching supervisor's NumColumns=2 style)
    legend_handle = fig.legend(
        [p1, p2],
        ['TAP (Arsalan & Rehman 2018)', 'MOBIGUARD (Proposed)'],
        loc='upper right',
        ncol=2,
        fontsize=20,
        bbox_to_anchor=(0.98, 1.08),
        markerscale=1.5
    )

    plt.tight_layout()
    fig1_path = os.path.join(OUTPUT_DIR, "Figure1_Attack2_MCC_TVR.png")
    fig.savefig(fig1_path, dpi=150, bbox_inches='tight')
    print(f"  Saved: {fig1_path}")
    plt.close(fig)

    # ── Figure 2: Timing metrics — M4 (Mitigation Latency), M6 (Latency) ─────
    print("\nGenerating Figure 2: Mitigation & Overall Latency (M4, M6)")

    fig2, axes2 = plt.subplots(1, 2, figsize=(14, 7))
    fig2.suptitle("Mitigation and Latency Performance — Attack 2\n"
                  "(Selective Time Delay Attack — Data Plane)",
                  fontsize=22, fontweight='bold', y=1.02)

    # Subplot (a): Mitigation Latency (M4)
    p1b, p2b = plot_metric(
        axes2[0], tap_data, mob_data,
        col    = COL_MIT_CUR,
        ylabel = "Mitigation Latency (ms)",
        title  = "(a) Mitigation Latency [M4]",
        ylim   = None,
        yticks = None
    )

    # Subplot (b): Overall System Latency (M6)
    plot_metric(
        axes2[1], tap_data, mob_data,
        col    = COL_LAT_AVG,
        ylabel = "End-to-End Latency (ms)",
        title  = "(b) Overall Latency [M6]",
        ylim   = None,
        yticks = None
    )

    legend_handle2 = fig2.legend(
        [p1b, p2b],
        ['TAP (Arsalan & Rehman 2018)', 'MOBIGUARD (Proposed)'],
        loc='upper right',
        ncol=2,
        fontsize=20,
        bbox_to_anchor=(0.98, 1.08),
        markerscale=1.5
    )

    plt.tight_layout()
    fig2_path = os.path.join(OUTPUT_DIR, "Figure2_Attack2_Mitigation_Latency.png")
    fig2.savefig(fig2_path, dpi=150, bbox_inches='tight')
    print(f"  Saved: {fig2_path}")
    plt.close(fig2)

    # ── Figure 3: Complete evaluation — M1, M2, M4, M6 + PDR (supplementary) ─
    print("\nGenerating Figure 3: All metrics combined")

    metrics = [
        (COL_PDR_AVG, "Packet Delivery Ratio (%)",         "(a) PDR [supplementary]", [-5, 115],  [0,20,40,60,80,100]),
        (COL_MCC_CUR, "Matthews Correlation Coefficient",  "(b) MCC [M1]",            [-1.1, 1.1], [-1.0, -0.5, 0.0, 0.5, 1.0]),
        (COL_TVR_AVG, "Threshold Violation Rate (%)",      "(c) TVR [M2]",            [-5, 115],  [0,20,40,60,80,100]),
        (COL_MIT_CUR, "Mitigation Latency (ms)",           "(d) Mitigation [M4]",     None,       None),
        (COL_LAT_AVG, "End-to-End Latency (ms)",           "(e) Latency [M6]",        None,       None),
    ]

    fig3, axes3 = plt.subplots(1, len(metrics), figsize=(7 * len(metrics), 7))
    fig3.suptitle("Complete Performance Evaluation — Attack 2 (Selective Time Delay, Data Plane)\n"
                  "TAP (Arsalan & Rehman FIT 2018) vs MOBIGUARD (Proposed)",
                  fontsize=22, fontweight='bold', y=1.02)

    first_p1, first_p2 = None, None
    for ax, (col, ylabel, title, ylim, yticks) in zip(axes3, metrics):
        p1c, p2c = plot_metric(ax, tap_data, mob_data,
                               col=col, ylabel=ylabel, title=title,
                               ylim=ylim, yticks=yticks)
        if first_p1 is None:
            first_p1, first_p2 = p1c, p2c

    fig3.legend(
        [first_p1, first_p2],
        ['TAP (Arsalan & Rehman 2018)', 'MOBIGUARD (Proposed)'],
        loc='upper right', ncol=2, fontsize=20,
        bbox_to_anchor=(0.98, 1.08), markerscale=1.5
    )

    plt.tight_layout()
    fig3_path = os.path.join(OUTPUT_DIR, "Figure3_Attack2_AllMetrics.png")
    fig3.savefig(fig3_path, dpi=150, bbox_inches='tight')
    print(f"  Saved: {fig3_path}")
    plt.close(fig3)

    print("\n✅ All figures generated successfully.")
    print(f"   Output directory: {OUTPUT_DIR}")
    print("   Files created:")
    print(f"   - Figure1_Attack2_MCC_TVR.png")
    print(f"   - Figure2_Attack2_Mitigation_Latency.png")
    print(f"   - Figure3_Attack2_AllMetrics.png")


if __name__ == "__main__":
    main()
