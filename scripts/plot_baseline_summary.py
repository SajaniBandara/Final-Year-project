#!/usr/bin/env python3
"""
plot_baseline_summary.py — SOTA-baseline vs MOBIGUARD comparison figures from
results_routing/baseline_summary_60s.csv (built by build_baseline_summary.py).

Figures -> results/baseline_figs/ :
  baseline_STD_A1A2.png    MOBIGUARD vs TAP   (Selective Time Delay)
  baseline_HF_A5-A8.png    MOBIGUARD vs FADE  (Hidden Forwarding)
  baseline_TCAM_A3A4.png   SFTO-Guard         (TCAM exhaustion)

Each: one column per attack variant, rows = MCC / DR% / FPR% vs attack %.
Line chart (change over attack intensity), one y-axis per panel, no dual axis.
Palette: Okabe-Ito subset, validated CVD-safe (blue=MOBIGUARD, orange=baseline).
"""
import csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NS3 = os.path.expanduser("~/ns3_g13/ns-allinone-3.35/ns-3.35")
CSV = os.path.join(NS3, "results_routing", "baseline_summary_60s.csv")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "results", "baseline_figs")
os.makedirs(OUT, exist_ok=True)

COLOR = {"MOBIGUARD": "#0072B2", "TAP": "#E69F00", "FADE": "#E69F00", "SFTO": "#E69F00"}
MARK = {"MOBIGUARD": "o", "TAP": "s", "FADE": "s", "SFTO": "s"}
METRICS = [("mcc_matrix", "MCC (matrix)", (-1.05, 1.05)),
           ("avg_DR", "DR  (%)", (-3, 105)),
           ("avg_FPR", "FPR  (%)", (-3, 105))]

rows = list(csv.DictReader(open(CSV)))


def series(method, attack, key):
    pts = [(int(r["pct"]), float(r[key])) for r in rows
           if r["method"] == method and int(r["attack"]) == attack and r[key] != ""]
    pts.sort()
    return [p for p, _ in pts], [v for _, v in pts]


def figure(fname, title, attacks, methods, labels):
    n = len(attacks)
    fig, axes = plt.subplots(3, n, figsize=(3.2 * n, 7.6), sharex=True, squeeze=False)
    for ci, a in enumerate(attacks):
        for ri, (key, ylab, ylim) in enumerate(METRICS):
            ax = axes[ri][ci]
            for m in methods:
                x, y = series(m, a, key)
                if not x:
                    continue
                ax.plot(x, y, MARK[m] + "-", color=COLOR[m], lw=1.6, ms=6,
                        mec="white", mew=0.8, label=labels[m], zorder=3)
            ax.set_ylim(*ylim)
            ax.grid(True, color="#e6e6e6", lw=0.8, zorder=0)
            ax.set_axisbelow(True)
            for s in ("top", "right"):
                ax.spines[s].set_visible(False)
            if ri == 0:
                ax.set_title(f"Attack {a}", fontsize=11)
            if ci == 0:
                ax.set_ylabel(ylab, fontsize=10)
            if ri == 2:
                ax.set_xlabel("attack %", fontsize=10)
            ax.set_xticks([20, 40, 60, 80, 100])
    h, l = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=len(methods), frameon=False,
               bbox_to_anchor=(0.5, 1.0), fontsize=10)
    fig.suptitle(title, y=1.04, fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    p = os.path.join(OUT, fname)
    fig.savefig(p, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {p}")


figure("baseline_STD_A1A2.png",
       "Selective Time Delay — MOBIGUARD vs TAP baseline (60 s, seed 1)",
       [1, 2], ["MOBIGUARD", "TAP"],
       {"MOBIGUARD": "MOBIGUARD", "TAP": "TAP (Arsalan & Rehman 2018)"})

figure("baseline_HF_A5-A8.png",
       "Hidden Forwarding — MOBIGUARD vs FADE baseline (60 s, seed 1)",
       [5, 6, 7, 8], ["MOBIGUARD", "FADE"],
       {"MOBIGUARD": "MOBIGUARD", "FADE": "FADE (eFADE)"})

figure("baseline_TCAM_A3A4.png",
       "TCAM Exhaustion — SFTO-Guard baseline (offline, seed 1)",
       [3, 4], ["SFTO"],
       {"SFTO": "SFTO-Guard (Tang et al. 2023)"})

print(f"\nfigures in {OUT}")
