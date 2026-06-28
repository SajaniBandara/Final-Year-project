"""
plot_hf_results.py — eFADE vs MOBIGUARD for HF Attacks 5–8

Produces one AllMetrics figure per attack (4 panels: PDR | MCC | DR | FPR)
matching the style of Figure3_Attack2_AllMetrics.png from plot_tap_results.py.

CSV files — copy from Linux results_routing/ to simulations/results/hf/

  eFADE summary (one row per run):
    fade_metrics_V4_pct{0,20,40,60,80,100}.csv   ← Attack 5
    fade_metrics_V5_pct{...}.csv                  ← Attack 6
    fade_metrics_V6_pct{...}.csv                  ← Attack 7
    fade_metrics_V7_pct{...}.csv                  ← Attack 8

    Columns (header row): attack_variant, attack_percentage, total_flows,
                          pdr(%), pir(%), tp, fp, tn, fn, mcc

  MOBIGUARD per-cycle (no header):
    MOBIGUARD_Attack{5,6,7,8}_{0,20,40,60,80,100}.csv

    Columns: cycle, cur_PDR, avg_PDR, cur_lat, avg_lat,
             cur_MCC, avg_MCC, cur_DR, avg_DR, cur_FPR, avg_FPR,
             cur_mit, avg_mit, TP, FP, TN, FN

95% CI error bars use t-distribution (same as plot_tap_results.py):
    ci = t(1-alpha/2, df=n-1) * std / sqrt(n)

FPR note: eFADE FPR is structurally 0 (dest_set never reaches size>=2 for
legitimate nodes). It is plotted as a flat line to demonstrate perfect
specificity alongside MOBIGUARD's non-zero FPR.

Usage:
    python3 scripts/plot_hf_results.py
"""

import os
import numpy as np
import matplotlib.pyplot as plt
import scipy.stats as stats

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results", "hf")
OUTPUT_DIR  = os.path.join(PROJECT_DIR, "output", "hf")

ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]
ALPHA = 0.05   # 95% CI

ATTACKS = [
    {"variant": 4, "number": 5, "label": "Attack 5 (Active CP)",  "color": "#e41a1c", "marker": "o"},
    {"variant": 5, "number": 6, "label": "Attack 6 (Active DP)",  "color": "#377eb8", "marker": "s"},
    {"variant": 6, "number": 7, "label": "Attack 7 (Passive CP)", "color": "#4daf4a", "marker": "^"},
    {"variant": 7, "number": 8, "label": "Attack 8 (Passive DP)", "color": "#984ea3", "marker": "D"},
]

# ─── Column indices ───────────────────────────────────────────────────────────
F_PDR = 3
F_TP, F_FP, F_TN, F_FN, F_MCC = 5, 6, 7, 8, 9

M_PDR_AVG = 2
M_MCC_CUR = 5
M_DR_CUR  = 7
M_FPR_CUR = 9
M_TP, M_FP, M_TN, M_FN = 13, 14, 15, 16


# ─── IO helpers ───────────────────────────────────────────────────────────────

def read_rows(path, skip_header=False):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if skip_header and not (line[0].isdigit() or line[0] == '-'):
                continue
            try:
                rows.append([float(v.strip()) for v in line.split(",")])
            except ValueError:
                continue
    return rows


def mean_ci(values):
    """
    Mean + 95% CI half-width via t-distribution.
    Matches supervisor's MATLAB: t_value = tinv(1-alpha/2, n-1)
                                 ci = t_value * std / sqrt(n)
    Returns (mean, ci) or (None, None) if no data.
    """
    n = len(values)
    if n == 0:
        return None, None
    m = float(np.mean(values))
    if n == 1:
        return m, 0.0
    t  = stats.t.ppf(1 - ALPHA / 2, df=n - 1)
    ci = t * float(np.std(values, ddof=1)) / np.sqrt(n)
    return m, ci


# ─── Data loading ─────────────────────────────────────────────────────────────

def load_fade(variant, pct):
    path = os.path.join(RESULTS_DIR, f"fade_metrics_V{variant}_pct{pct}.csv")
    rows = read_rows(path, skip_header=True)
    if not rows:
        return None
    arr = np.array(rows)
    tp, fp, tn, fn = arr[:, F_TP], arr[:, F_FP], arr[:, F_TN], arr[:, F_FN]
    dr  = np.where(tp + fn > 0, tp / (tp + fn), 0.0) * 100.0
    fpr = np.where(fp + tn > 0, fp / (fp + tn), 0.0) * 100.0
    return {
        "pdr": arr[:, F_PDR],
        "mcc": arr[:, F_MCC],
        "dr":  dr,
        "fpr": fpr,
    }


def load_mobiguard(number, pct):
    path = os.path.join(RESULTS_DIR, f"MOBIGUARD_Attack{number}_{pct}.csv")
    rows = read_rows(path, skip_header=False)
    if not rows:
        return None
    arr  = np.array(rows)
    last = arr[[-1]]   # final cycle = converged averages
    tp, fp, tn, fn = last[:, M_TP], last[:, M_FP], last[:, M_TN], last[:, M_FN]
    dr  = np.where(tp + fn > 0, tp / (tp + fn), 0.0) * 100.0
    fpr = np.where(fp + tn > 0, fp / (fp + tn), 0.0) * 100.0
    return {
        "pdr": last[:, M_PDR_AVG],
        "mcc": last[:, M_MCC_CUR],
        "dr":  dr,
        "fpr": fpr,
    }


def load_all():
    fade, mob = {}, {}
    for atk in ATTACKS:
        v, n = atk["variant"], atk["number"]
        fade[v], mob[n] = {}, {}
        mf, mm = [], []
        for pct in ATTACK_PERCENTAGES:
            fade[v][pct] = load_fade(v, pct)
            mob[n][pct]  = load_mobiguard(n, pct)
            if fade[v][pct] is None: mf.append(pct)
            if mob[n][pct]  is None: mm.append(pct)
        sf = "OK" if not mf else f"MISSING {mf}"
        sm = "OK" if not mm else f"MISSING {mm}"
        print(f"  Attack {n} (V{v}):  FADE={sf}  MOBIGUARD={sm}")
    return fade, mob


# ─── Plot primitives ──────────────────────────────────────────────────────────
#
# Visual distinction:
#   eFADE     — solid line, filled marker, linewidth=2.5
#   MOBIGUARD — dashed line, hollow marker, linewidth=1.5

def _series(ax, data_by_pct, key, color, marker, label, filled, lw, ls):
    x, means, cis = [], [], []
    for pct in ATTACK_PERCENTAGES:
        d    = data_by_pct.get(pct)
        vals = d[key] if (d and key in d) else np.array([])
        m, c = mean_ci(vals)
        x.append(pct)
        means.append(m if m is not None else 0.0)
        cis.append(c  if c is not None else 0.0)
    mfc = color if filled else "none"
    return ax.errorbar(
        x, means, yerr=cis,
        fmt=marker, color=color,
        markerfacecolor=mfc, markeredgecolor=color,
        markersize=10, linewidth=lw, capsize=18,
        linestyle=ls, label=label,
    )


def plot_fade(ax, data_by_pct, key, color, marker, label="eFADE"):
    return _series(ax, data_by_pct, key, color, marker, label,
                   filled=True, lw=2.5, ls="-")


def plot_mob(ax, data_by_pct, key, color, marker, label="MOBIGUARD"):
    return _series(ax, data_by_pct, key, color, marker, label,
                   filled=False, lw=1.5, ls="--")


def style_ax(ax, ylabel, title, ylim=None, yticks=None):
    ax.grid(True, linestyle="-", alpha=0.2, linewidth=1.0)
    ax.set_axisbelow(True)
    ax.set_xlabel("Attack Percentage (%)", fontsize=22)
    ax.set_ylabel(ylabel, fontsize=22)
    ax.tick_params(axis="both", labelsize=22)
    ax.set_xticks(ATTACK_PERCENTAGES)
    ax.set_xlim([-5, 105])
    ax.set_title(title, fontsize=20, pad=10)
    if ylim   is not None: ax.set_ylim(ylim)
    if yticks is not None: ax.set_yticks(yticks)


# ─── Figures ──────────────────────────────────────────────────────────────────

def figures_per_attack(fade, mob):
    """
    One AllMetrics figure per attack — 4 panels: PDR | MCC | DR | FPR
    Matches Figure3_Attack2_AllMetrics.png style from plot_tap_results.py.
    eFADE FPR is plotted as a flat 0 line to show perfect specificity.
    """
    for atk in ATTACKS:
        v, n = atk["variant"], atk["number"]
        c, mk = atk["color"], atk["marker"]

        fig, axes = plt.subplots(1, 4, figsize=(28, 7))
        fig.suptitle(
            f"Performance Evaluation — {atk['label']}\n"
            f"eFADE vs MOBIGUARD",
            fontsize=22, fontweight="bold", y=1.02
        )

        hf0 = plot_fade(axes[0], fade[v], "pdr", c, mk, "eFADE")
        hm0 = plot_mob (axes[0], mob[n],  "pdr", c, mk, "MOBIGUARD")

        plot_fade(axes[1], fade[v], "mcc", c, mk, "eFADE")
        plot_mob (axes[1], mob[n],  "mcc", c, mk, "MOBIGUARD")

        plot_fade(axes[2], fade[v], "dr",  c, mk, "eFADE")
        plot_mob (axes[2], mob[n],  "dr",  c, mk, "MOBIGUARD")

        plot_fade(axes[3], fade[v], "fpr", c, mk, "eFADE (0 by design)")
        plot_mob (axes[3], mob[n],  "fpr", c, mk, "MOBIGUARD")

        style_ax(axes[0], "Packet Delivery Ratio (%)",        "(a) PDR",
                 ylim=[-5, 115], yticks=[0, 20, 40, 60, 80, 100])
        style_ax(axes[1], "Matthews Correlation Coefficient", "(b) MCC",
                 ylim=[-1.1, 1.1], yticks=[-1.0, -0.5, 0.0, 0.5, 1.0])
        style_ax(axes[2], "Detection Rate (%)",               "(c) DR",
                 ylim=[-5, 115], yticks=[0, 20, 40, 60, 80, 100])
        style_ax(axes[3], "False Positive Rate (%)",          "(d) FPR",
                 ylim=[-5, 115], yticks=[0, 20, 40, 60, 80, 100])

        fig.legend(
            [hf0, hm0],
            ["eFADE (solid, filled)", "MOBIGUARD (dashed, hollow)"],
            loc="upper right", ncol=1, fontsize=20,
            bbox_to_anchor=(0.98, 1.08), markerscale=1.5,
        )

        plt.tight_layout()
        path = os.path.join(OUTPUT_DIR, f"Figure_Attack{n}_AllMetrics.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        print(f"  Saved: {path}")
        plt.close(fig)


def figure_mcc_summary(fade, mob):
    """MCC for all 4 attacks — Active | Passive split."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 7))
    fig.suptitle("eFADE vs MOBIGUARD — MCC\nActive HF  |  Passive HF",
                 fontsize=22, fontweight="bold", y=1.05)

    groups = [(axes[0], "(a) Active HF — Attacks 5 & 6",  [5, 6]),
              (axes[1], "(b) Passive HF — Attacks 7 & 8", [7, 8])]

    for ax, title, numbers in groups:
        handles, labels = [], []
        for atk in ATTACKS:
            if atk["number"] not in numbers:
                continue
            v, n = atk["variant"], atk["number"]
            c, mk = atk["color"], atk["marker"]
            hf = plot_fade(ax, fade[v], "mcc", c, mk, f"{atk['label']} eFADE")
            hm = plot_mob (ax, mob[n],  "mcc", c, mk, f"{atk['label']} MOBIGUARD")
            handles += [hf, hm]
            labels  += [f"{atk['label']} — eFADE (solid)",
                        f"{atk['label']} — MOBIGUARD (dashed)"]
        style_ax(ax, "Matthews Correlation Coefficient", title,
                 ylim=[-1.1, 1.1], yticks=[-1.0, -0.5, 0.0, 0.5, 1.0])
        ax.legend(handles, labels, fontsize=14, loc="lower right")

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "Figure_Summary_MCC.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    print(f"  Saved: {path}")
    plt.close(fig)


def figure_pdr_stability(fade, mob):
    """
    PDR across all 4 attacks — demonstrates HF is stealthy
    (PDR stays stable because original packet is still delivered).
    Active | Passive split.
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 7))
    fig.suptitle("PDR Stability Under HF Attack — original packet still delivered",
                 fontsize=20, fontweight="bold", y=1.05)

    groups = [(axes[0], "(a) Active HF — Attacks 5 & 6",  [5, 6]),
              (axes[1], "(b) Passive HF — Attacks 7 & 8", [7, 8])]

    for ax, title, numbers in groups:
        handles, labels = [], []
        for atk in ATTACKS:
            if atk["number"] not in numbers:
                continue
            v, n = atk["variant"], atk["number"]
            c, mk = atk["color"], atk["marker"]
            hf = plot_fade(ax, fade[v], "pdr", c, mk, "")
            hm = plot_mob (ax, mob[n],  "pdr", c, mk, "")
            handles += [hf, hm]
            labels  += [f"{atk['label']} eFADE",
                        f"{atk['label']} MOBIGUARD"]
        style_ax(ax, "Packet Delivery Ratio (%)", title,
                 ylim=[-5, 115], yticks=[0, 20, 40, 60, 80, 100])
        ax.legend(handles, labels, fontsize=14, loc="lower right")

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "Figure_PDR_Stability.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    print(f"  Saved: {path}")
    plt.close(fig)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Loading CSVs from: {RESULTS_DIR}\n")
    fade, mob = load_all()
    print()

    print("Generating figures...")
    figures_per_attack(fade, mob)   # Figure_Attack{5-8}_AllMetrics.png
    figure_mcc_summary(fade, mob)   # Figure_Summary_MCC.png
    figure_pdr_stability(fade, mob) # Figure_PDR_Stability.png

    print(f"\nDone. Output: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
