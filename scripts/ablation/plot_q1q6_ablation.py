#!/usr/bin/env python3
"""
plot_q1q6_ablation.py — report figures for the Q1-Q6 component-isolation ablation.

Reads whatever per-config CSVs exist in results_routing/ and plots them, so it
works after a single config has run (e.g. --configs Q1) and again unchanged once
the rest land. Nothing here re-runs the simulator.

Inputs (both produced by run_q1q6_ablation.py):
  MOBIGUARD_Attack<N>_<pct>[_d80ms]_seed<S>_Q<n>.csv
      The INLINE per-node confusion matrix, final row, cols 13-16 (TP,FP,TN,FN
      -- TN before FN). These counters LATCH: a node flagged once stays flagged,
      so FP is monotone non-decreasing over a run and FPR grows with run length.
  detector_windows_Attack<N>_<pct>[_d80ms]_seed<S>.csv
      The PER-WINDOW detector grid -- the paper's M1 statistic (eq:mcc). Not
      config-tagged by the simulator, so it is only attributable to a config when
      one config has been run since the file was written. See --no-m1.

The two disagree substantially (see fig 4). Until that is resolved, fig 4 is a
diagnostic, not a result: do not publish figs 1-3 and fig 4 as if they measured
the same thing.

Usage:
  python3 scripts/ablation/plot_q1q6_ablation.py                 # all configs found
  python3 scripts/ablation/plot_q1q6_ablation.py --pct 60 --seed 1
  python3 scripts/ablation/plot_q1q6_ablation.py --no-m1         # skip the M1 comparison
  python3 scripts/ablation/plot_q1q6_ablation.py --outdir /tmp/figs

Figures are written to output/ablation/<config>/ -- one directory per config
(output/ablation/q1/, .../q2/, ...), so configs never overwrite one another.
This sits alongside the existing output/{fade,hf,lstm,tap}/ figure sets and
follows their Figure_*.png naming.
"""

import argparse
import csv
import glob
import math
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ── Palette ──────────────────────────────────────────────────────────────────
# Validated categorical slots (light surface #fcfcfb): worst adjacent CVD
# dE 9.1, worst adjacent normal-vision dE 22.9, all inside the L band. Aqua and
# yellow fall below 3:1 contrast on this surface, so every bar carries a direct
# value label -- that is the relief rule, not decoration. Do not drop the labels.
C_BLUE, C_ORANGE, C_AQUA, C_YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
SURFACE = "#fcfcfb"
INK, INK_2, INK_MUTED = "#0b0b0b", "#52514e", "#8a8880"
GRID = "#e3e2dd"

ATTACKS = [1, 2, 3, 4, 5, 6, 7, 8]
# Family bands drive the x-axis grouping annotation. The Q1 story is precisely
# that the rule layer covers the first two families and is blind to the third.
FAMILIES = [("Selective Time Delay", [1, 2]),
            ("TCAM Exhaustion", [3, 4]),
            ("Hidden Forwarding", [5, 6, 7, 8])]
# A5-A8 naming per hf_attack_helper.h:10-11 (and docs/DETECTION_IMPLEMENTATION.md
# :335-338): A = Active, P = Passive; CP = control plane, DP = data plane.
# The order is NOT AHF-CP/AHF-DP/PHF-CP/PHF-DP by coincidence -- it mirrors the
# S5/S6/S7/S8 signature numbering, so do not reorder these independently.
VLABEL = {1: "A1\nSTD-CP", 2: "A2\nSTD-DP", 3: "A3\nTCAM-CP", 4: "A4\nTCAM-DP",
          5: "A5\nAHF-CP", 6: "A6\nAHF-DP", 7: "A7\nPHF-CP", 8: "A8\nPHF-DP"}

COL_CUR_DR, COL_CUR_FPR = 7, 9
COL_TP, COL_FP, COL_TN, COL_FN = 13, 14, 15, 16


def mcc(tp, fp, fn, tn):
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return 0.0 if d == 0 else (tp * tn - fp * fn) / d


def suffix(a):
    return "_d80ms" if a in (1, 2) else ""


def read_inline(results, a, pct, seed, tag):
    """Final-row confusion matrix + rates from one per-config MOBIGUARD CSV."""
    p = results / f"MOBIGUARD_Attack{a}_{pct}{suffix(a)}_seed{seed}_{tag}.csv"
    if not p.exists():
        return None
    rows = [l for l in open(p) if l.strip() and not l.lstrip().startswith("#")]
    if not rows:
        return None
    c = [x.strip() for x in rows[-1].split(",")]
    if len(c) <= COL_FN:
        return None
    tp, fp, tn, fn = (int(float(c[i])) for i in (COL_TP, COL_FP, COL_TN, COL_FN))
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, mcc=mcc(tp, fp, fn, tn),
                dr=float(c[COL_CUR_DR]), fpr=float(c[COL_CUR_FPR]))


def read_m1(results, a, pct, seed, warmup=30.0):
    """Per-window M1 (eq:mcc) from detector_windows.csv, warm-up windows dropped."""
    g = glob.glob(str(results / f"detector_windows_Attack{a}_{pct}*seed{seed}.csv"))
    if not g:
        return None
    tp = fp = fn = tn = 0
    for x in csv.DictReader(open(g[0])):
        if float(x["w_start"]) < warmup:
            continue
        s, t = float(x["score"]) >= 0.5, int(x["truth"]) == 1
        if s and t: tp += 1
        elif s: fp += 1
        elif t: fn += 1
        else: tn += 1
    if tp + fp + fn + tn == 0:
        return None
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, mcc=mcc(tp, fp, fn, tn),
                dr=100 * tp / (tp + fn) if tp + fn else 0.0,
                fpr=100 * fp / (fp + tn) if fp + tn else 0.0)


# ── Chart furniture ──────────────────────────────────────────────────────────
def base_axes(figsize):
    fig, ax = plt.subplots(figsize=figsize, dpi=200)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    # Recessive grid, behind the marks; no vertical rules against categories.
    ax.yaxis.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.xaxis.grid(False)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK_2, length=0, labelsize=8)
    return fig, ax


def family_bands(ax, y=-0.185):
    """Label the three attack families under the variant ticks."""
    for name, members in FAMILIES:
        xs = [ATTACKS.index(m) for m in members]
        mid = (min(xs) + max(xs)) / 2
        ax.annotate(name, xy=(mid, y), xycoords=("data", "axes fraction"),
                    ha="center", va="top", fontsize=7.5, color=INK_MUTED)
        ax.annotate("", xy=(min(xs) - 0.34, y + 0.035), xytext=(max(xs) + 0.34, y + 0.035),
                    xycoords=("data", "axes fraction"), textcoords=("data", "axes fraction"),
                    arrowprops=dict(arrowstyle="-", color=GRID, linewidth=1.1))


def finish(fig, ax, title, ylabel, outpath, has_legend=False):
    # Header stack: title / legend / plot. Deliberately NO explanatory sentence
    # inside the image -- run conditions, caveats and the latching note belong in
    # the LaTeX \caption, not baked into the PNG where they cannot be edited.
    ax.set_title(title, fontsize=11.5, color=INK, loc="left",
                 pad=30 if has_legend else 12, fontweight="600")
    ax.set_ylabel(ylabel, fontsize=8.5, color=INK_2)
    ax.set_xticks(range(len(ATTACKS)))
    ax.set_xticklabels([VLABEL[a] for a in ATTACKS], fontsize=8, color=INK_2)
    family_bands(ax)
    fig.tight_layout()
    fig.savefig(outpath, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {outpath}")


def label_bars(ax, bars, fmt="{:.0f}"):
    """Direct value labels — required (relief rule), not optional.

    Zeros are labelled too: in this ablation a 0 is a real finding (the rule
    layer is blind to Hidden Forwarding), not missing data.
    """
    for b in bars:
        h = b.get_height()
        ax.annotate(fmt.format(h), xy=(b.get_x() + b.get_width() / 2, h),
                    xytext=(0, 2), textcoords="offset points",
                    ha="center", va="bottom", fontsize=6.4, color=INK_2)


def zero_marks(ax, bars, color):
    """Draw a baseline stub wherever a bar is zero.

    A zero-height bar renders nothing, so in a grouped chart the surviving bars
    stop being symmetric about their tick and the whole group reads as
    misaligned with its x-axis label (it did). The stub restores the group's
    visual centre and, as a bonus, makes 'measured zero' visually distinct from
    'no data'. It sits exactly at y=0, so it never overstates the value.
    """
    for b in bars:
        if b.get_height() != 0:
            continue
        ax.plot([b.get_x(), b.get_x() + b.get_width()], [0, 0],
                color=color, linewidth=2.0, solid_capstyle="butt", zorder=4)


# ── Figures ──────────────────────────────────────────────────────────────────
def fig_confusion(data, tag, out):
    """Fig 1 — the supervisor's literal deliverable: TP/FP/FN/TN per variant."""
    fig, ax = base_axes((7.6, 3.9))
    x = np.arange(len(ATTACKS))
    w = 0.20
    gap = 0.012  # 2px-equivalent surface gap between adjacent fills
    series = [("TP", "tp", C_BLUE), ("FP", "fp", C_ORANGE),
              ("FN", "fn", C_AQUA), ("TN", "tn", C_YELLOW)]
    for i, (name, key, colr) in enumerate(series):
        vals = [data[a][key] if data.get(a) else 0 for a in ATTACKS]
        b = ax.bar(x + (i - 1.5) * (w + gap), vals, w, label=name,
                   color=colr, zorder=3, linewidth=0)
        zero_marks(ax, b, colr)
        label_bars(ax, b)
    leg = ax.legend(frameon=False, fontsize=8, ncol=4, loc="lower left",
                    bbox_to_anchor=(0, 1.005), labelcolor=INK_2, handlelength=1.1)
    for t in leg.get_texts():
        t.set_color(INK_2)
    finish(fig, ax, f"{tag} — confusion matrix by attack variant",
           "nodes", out, has_legend=True)


def fig_mcc(data, tag, out):
    """Fig 2 — MCC per variant, single series (no legend: the title names it)."""
    fig, ax = base_axes((7.2, 3.6))
    x = np.arange(len(ATTACKS))
    vals = [data[a]["mcc"] if data.get(a) else 0.0 for a in ATTACKS]
    b = ax.bar(x, vals, 0.56, color=C_BLUE, zorder=3, linewidth=0)
    zero_marks(ax, b, C_BLUE)
    label_bars(ax, b, fmt="{:.3f}")
    ax.set_ylim(0, 1.08)
    finish(fig, ax, f"{tag} — detection quality (MCC) by attack variant",
           "MCC", out)


def fig_dr_fpr(data, tag, out):
    """Fig 3 — DR and FPR share one percentage axis (never a dual axis)."""
    fig, ax = base_axes((7.4, 3.7))
    x = np.arange(len(ATTACKS))
    w = 0.34
    gap = 0.014
    dr = [data[a]["dr"] if data.get(a) else 0.0 for a in ATTACKS]
    fpr = [data[a]["fpr"] if data.get(a) else 0.0 for a in ATTACKS]
    b1 = ax.bar(x - (w + gap) / 2, dr, w, label="Detection rate", color=C_BLUE, zorder=3, linewidth=0)
    b2 = ax.bar(x + (w + gap) / 2, fpr, w, label="False-positive rate", color=C_ORANGE, zorder=3, linewidth=0)
    zero_marks(ax, b1, C_BLUE)
    zero_marks(ax, b2, C_ORANGE)
    label_bars(ax, b1, fmt="{:.1f}")
    label_bars(ax, b2, fmt="{:.1f}")
    ax.set_ylim(0, 118)
    leg = ax.legend(frameon=False, fontsize=8, ncol=2, loc="lower left",
                    bbox_to_anchor=(0, 1.005), handlelength=1.1)
    for t in leg.get_texts():
        t.set_color(INK_2)
    finish(fig, ax, f"{tag} — detection rate vs false-positive rate",
           "%", out, has_legend=True)


def fig_metric_gap(inline, m1, tag, out):
    """Fig 4 — DIAGNOSTIC: inline latched MCC vs paper's per-window M1 MCC."""
    fig, ax = base_axes((7.4, 3.7))
    x = np.arange(len(ATTACKS))
    w = 0.34
    gap = 0.014
    a1 = [inline[a]["mcc"] if inline.get(a) else 0.0 for a in ATTACKS]
    a2 = [m1[a]["mcc"] if m1.get(a) else 0.0 for a in ATTACKS]
    b1 = ax.bar(x - (w + gap) / 2, a1, w, label="Inline per-node (latched)", color=C_BLUE, zorder=3, linewidth=0)
    b2 = ax.bar(x + (w + gap) / 2, a2, w, label="Per-window M1 (eq:mcc)", color=C_ORANGE, zorder=3, linewidth=0)
    zero_marks(ax, b1, C_BLUE)
    zero_marks(ax, b2, C_ORANGE)
    label_bars(ax, b1, fmt="{:.2f}")
    label_bars(ax, b2, fmt="{:.2f}")
    ax.set_ylim(0, 1.16)
    leg = ax.legend(frameon=False, fontsize=8, ncol=2, loc="lower left",
                    bbox_to_anchor=(0, 1.005), handlelength=1.1)
    for t in leg.get_texts():
        t.set_color(INK_2)
    finish(fig, ax, f"{tag} — MCC statistic comparison (diagnostic)",
           "MCC", out, has_legend=True)


def main():
    ap = argparse.ArgumentParser(description="Q1-Q6 ablation report figures")
    ap.add_argument("--results", default=None, help="results_routing dir")
    ap.add_argument("--outdir", default=None,
                    help="root for figures (default <repo>/output/ablation, matching the "
                         "existing output/<family> layout); each "
                         "config writes into <root>/<q1|q2|...>/")
    ap.add_argument("--pct", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-m1", action="store_true", help="skip the per-window comparison figure")
    args = ap.parse_args()

    # This file lives at scripts/ablation/, so the repo root is three levels up.
    repo = Path(__file__).resolve().parents[2]
    ns3 = Path(os.environ.get("NS3_DIR", Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"))
    results = Path(args.results) if args.results else ns3 / "results_routing"
    outroot = Path(args.outdir) if args.outdir else repo / "output" / "ablation"

    if not results.is_dir():
        raise SystemExit(f"results dir not found: {results} (set --results or NS3_DIR)")

    tags = sorted({p.name.rsplit("_", 1)[1].split(".")[0]
                   for p in results.glob("MOBIGUARD_Attack*_Q*.csv")})
    if not tags:
        raise SystemExit(f"no per-config MOBIGUARD_*_Q<n>.csv in {results}")
    print(f"configs found: {', '.join(tags)}")

    for tag in tags:
        inline = {a: read_inline(results, a, args.pct, args.seed, tag) for a in ATTACKS}
        inline = {a: v for a, v in inline.items() if v}
        if not inline:
            print(f"  {tag}: no readable CSVs, skipped")
            continue
        print(f"{tag}: {len(inline)}/8 variants")
        # One directory per config, so Q2..Q6 land beside Q1 without collisions.
        outdir = outroot / tag.lower()
        outdir.mkdir(parents=True, exist_ok=True)
        fig_confusion(inline, tag, outdir / f"Figure_{tag}_ConfusionByVariant.png")
        fig_mcc(inline, tag, outdir / f"Figure_{tag}_MCC.png")
        fig_dr_fpr(inline, tag, outdir / f"Figure_{tag}_DR_vs_FPR.png")

        if not args.no_m1 and len(tags) == 1:
            # Only attributable to this config when it is the only one that has
            # run -- detector_windows.csv carries no config tag.
            m1 = {a: read_m1(results, a, args.pct, args.seed) for a in ATTACKS}
            m1 = {a: v for a, v in m1.items() if v}
            if m1:
                fig_metric_gap(inline, m1, tag, outdir / f"Figure_{tag}_MetricDiscrepancy.png")

    print(f"\nFigures in {outroot}/<config>/")


if __name__ == "__main__":
    main()
