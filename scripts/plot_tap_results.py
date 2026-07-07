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
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import csv
import os
import scipy.stats as stats

# ─── Configuration ────────────────────────────────────────────────────────────

RESULTS_DIR = "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR  = os.path.join(PROJECT_DIR, "output", "tap")

ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

# Column indices in CSV
COL_PDR_AVG    = 2
COL_LAT_AVG    = 4
COL_MCC_CUR    = 5
COL_DR_CUR     = 7
COL_FPR_CUR    = 9
COL_MIT_CUR    = 11
COL_TP         = 13
COL_FP         = 14
COL_TN         = 15
COL_FN         = 16

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
    m   = np.mean(values)
    s   = np.std(values, ddof=1)       # sample std (ddof=1 matches MATLAB std)
    if n == 1:
        return m, 0.0
    t   = stats.t.ppf(1 - ALPHA / 2, df=n - 1)
    ci  = t * (s / np.sqrt(n))
    return m, ci


# ─── Load data for all attack percentages ────────────────────────────────────

def load_method_data(prefix):
    """
    Load data for one method (TAP or MOBIGUARD) across all attack percentages.
    Returns dict: {attack_pct: rows_list}
    """
    data = {}
    for pct in ATTACK_PERCENTAGES:
        filepath = os.path.join(RESULTS_DIR, f"{prefix}_Attack2_{pct}.csv")
        data[pct] = read_csv(filepath)
    return data


# ─── Plot a single metric subplot ────────────────────────────────────────────

def plot_metric(ax, tap_data, mob_data, col, ylabel, title,
                ylim=None, yticks=None):
    """
        Plot one metric panel with:
            - TAP (red solid -o)
      - 95% CI error bars (CapSize=18, matching supervisor's MATLAB)
      - Grid, font size 22, proper axis labels
    """
    x = np.array(ATTACK_PERCENTAGES)

    tap_means = []
    tap_cis   = []

    for pct in ATTACK_PERCENTAGES:
        tap_vals = extract_column(tap_data[pct], col)

        tm, tc = mean_and_ci(tap_vals)

        tap_means.append(tm)
        tap_cis.append(tc)

    tap_means = np.array(tap_means)
    tap_cis   = np.array(tap_cis)

    # ── TAP line — red solid with circle markers (matches supervisor's p1 style)
    p1 = ax.errorbar(x, tap_means, yerr=tap_cis,
                     fmt='-o',
                     color='red',
                     markerfacecolor='red',
                     markersize=9,
                     linewidth=2,
                     capsize=18,
                     linestyle='-',
                     label='TAP (Arsalan & Rehman 2018)')

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

    return p1


# ─── Main plotting function ───────────────────────────────────────────────────

def main():
    print("Loading CSV data...")
    tap_data = load_method_data("TAP")
    mob_data = load_method_data("MOBIGUARD")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Verify files loaded
    for pct in ATTACK_PERCENTAGES:
        n_tap = len(tap_data[pct])
        n_mob = len(mob_data[pct])
        print(f"  Attack {pct}%: TAP={n_tap} rows, MOBIGUARD={n_mob} rows")

    print("\nGenerating Figure 1: Performance Evaluation of Attack 2 (Selective Time Delay — Data Plane)")

    # ── Figure 1: Three-subplot figure matching supervisor's example ──────────
    fig, axes = plt.subplots(1, 3, figsize=(21, 7))
    fig.suptitle("Performance Evaluation of Attack 2\n"
                 "(Selective Time Delay Attack — Data Plane)",
                 fontsize=22, fontweight='bold', y=1.02)

    # Subplot (a): Packet Delivery Ratio
    p1 = plot_metric(
        axes[0], tap_data, mob_data,
        col    = COL_PDR_AVG,
        ylabel = "Packet Delivery Ratio (%)",
        title  = "(a) Packet Delivery Ratio",
        ylim   = [-5, 115],
        yticks = [0, 20, 40, 60, 80, 100]
    )

    # Subplot (b): Matthews Correlation Coefficient
    plot_metric(
        axes[1], tap_data, mob_data,
        col    = COL_MCC_CUR,
        ylabel = "Matthews Correlation Coefficient",
        title  = "(b) Matthews Correlation Coefficient",
        ylim   = [-1.1, 1.1],
        yticks = [-1.0, -0.5, 0.0, 0.5, 1.0]
    )

    # Subplot (c): False Positive Rate
    plot_metric(
        axes[2], tap_data, mob_data,
        col    = COL_FPR_CUR,
        ylabel = "False Positive Rate (%)",
        title  = "(c) False Positive Rate",
        ylim   = [-5, 115],
        yticks = [0, 20, 40, 60, 80, 100]
    )

    # Shared legend at top (matching supervisor's NumColumns=2 style)
    legend_handle = fig.legend(
        [p1],
        ['TAP (Arsalan & Rehman 2018)'],
        loc='upper right',
        ncol=1,
        fontsize=20,
        bbox_to_anchor=(0.98, 1.08),
        markerscale=1.5
    )

    plt.tight_layout()
    fig1_path = os.path.join(OUTPUT_DIR, "Figure1_Attack2_PDR_MCC_FPR.png")
    fig.savefig(fig1_path, dpi=150, bbox_inches='tight')
    print(f"  Saved: {fig1_path}")
    plt.close(fig)

    # ── Figure 2: Detection Rate and Mitigation Latency ──────────────────────
    print("\nGenerating Figure 2: Detection Rate and Mitigation Latency")

    fig2, axes2 = plt.subplots(1, 2, figsize=(14, 7))
    fig2.suptitle("Detection Performance of Attack 2\n"
                  "(Selective Time Delay Attack — Data Plane)",
                  fontsize=22, fontweight='bold', y=1.02)

    # Subplot (a): Detection Rate
    p1b = plot_metric(
        axes2[0], tap_data, mob_data,
        col    = COL_DR_CUR,
        ylabel = "Detection Rate (%)",
        title  = "(a) Detection Rate",
        ylim   = [-5, 115],
        yticks = [0, 20, 40, 60, 80, 100]
    )

    # Subplot (b): Mitigation Latency
    plot_metric(
        axes2[1], tap_data, mob_data,
        col    = COL_MIT_CUR,
        ylabel = "Mitigation Latency (ms)",
        title  = "(b) Mitigation Latency",
        ylim   = None,
        yticks = None
    )

    legend_handle2 = fig2.legend(
        [p1b],
        ['TAP (Arsalan & Rehman 2018)'],
        loc='upper right',
        ncol=1,
        fontsize=20,
        bbox_to_anchor=(0.98, 1.08),
        markerscale=1.5
    )

    plt.tight_layout()
    fig2_path = os.path.join(OUTPUT_DIR, "Figure2_Attack2_DR_Mitigation.png")
    fig2.savefig(fig2_path, dpi=150, bbox_inches='tight')
    print(f"  Saved: {fig2_path}")
    plt.close(fig2)

    # ── Figure 3: All six metrics in one 6-panel figure ─────────────────────
    print("\nGenerating Figure 3: All metrics combined")

    fig3, axes3 = plt.subplots(1, 6, figsize=(42, 7))
    fig3.suptitle("Complete Performance Evaluation — Attack 2 (Selective Time Delay, Data Plane)\n"
                  "TAP (Arsalan & Rehman FIT 2018)",
                  fontsize=22, fontweight='bold', y=1.02)

    metrics = [
        (COL_PDR_AVG, "Packet Delivery Ratio (%)",         "(a) PDR",         [-5, 115],  [0,20,40,60,80,100]),
        (COL_LAT_AVG, "End-to-End Latency (ms)",           "(b) Latency",     None,       None),
        (COL_MCC_CUR, "Matthews Correlation Coefficient",  "(c) MCC",         [-1.1, 1.1], [-1.0, -0.5, 0.0, 0.5, 1.0]),
        (COL_DR_CUR,  "Detection Rate (%)",                "(d) DR",          [-5, 115],  [0,20,40,60,80,100]),
        (COL_FPR_CUR, "False Positive Rate (%)",           "(e) FPR",         [-5, 115],  [0,20,40,60,80,100]),
        (COL_MIT_CUR, "Mitigation Latency (ms)",           "(f) Mitigation",  None,       None),
    ]

    first_p1 = None
    for ax, (col, ylabel, title, ylim, yticks) in zip(axes3, metrics):
        p1c = plot_metric(ax, tap_data, mob_data,
                          col=col, ylabel=ylabel, title=title,
                          ylim=ylim, yticks=yticks)
        if first_p1 is None:
            first_p1 = p1c

    fig3.legend(
        ['TAP (Arsalan & Rehman 2018)'],
        loc='upper right', ncol=1, fontsize=20,
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
    print(f"   - Figure1_Attack2_PDR_MCC_FPR.png")
    print(f"   - Figure2_Attack2_DR_Mitigation.png")
    print(f"   - Figure3_Attack2_AllMetrics.png")


if __name__ == "__main__":
    main()
