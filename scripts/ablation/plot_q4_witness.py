#!/usr/bin/env python3
"""
plot_q4_witness.py — the Q4 figures that plot_q1q6_ablation.py cannot.

WHY THIS IS SEPARATE
--------------------
plot_q1q6_ablation.py draws every config from the INLINE per-node confusion
matrix. For Q4 that matrix is the wrong instrument: every signature is disabled
and the witness never calls record_detection_event() directly, reaching the
generic matrix only via
    witness -> trust_update_negative() -> quarantine -> record_detection_event()
so its TP/FP measure quarantine, not witness detection (run_q1q6_ablation.py
:250-266). Q4's actual result lives in the witness-native counters, which had no
figure at all. These are those figures.

Style, palette and furniture are imported from plot_q1q6_ablation rather than
restated, so the Q4 set is pixel-consistent with the Q1 set and a palette change
lands in both.

Usage:
  NS3_DIR=/path/to/ns-3.35 python3 scripts/ablation/plot_q4_witness.py
  python3 scripts/ablation/plot_q4_witness.py --results <dir> --pct 60 --seed 1
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from plot_q1q6_ablation import (ATTACKS, VLABEL, SURFACE, GRID, INK, INK_2,
                                INK_MUTED, C_BLUE, C_ORANGE, C_AQUA,
                                base_axes, family_bands, finish, label_bars,
                                zero_marks, suffix)

# Witness-native columns in the security-metrics CSV. POSITIONAL by necessity:
# write_security_metrics_csv() emits a multi-line '#' header, so DictReader sees
# only the first line's names while rows carry ~52 fields. Mirrors
# run_q1q6_ablation.py:_W_BASE -- keep the two in sync.
_W_BASE = {"witness_da": 28, "TP_W": 41, "FP_W": 42, "FN_W": 43,
           "precision": 44, "recall": 45}
# The 9-column TCAM block is emitted ONLY for attack 3 and 4, shifting everything
# after it. Without this offset A3/A4 silently read neighbouring columns.
_TCAM_BLOCK_LEN, _TCAM_ATTACKS = 9, (3, 4)


def read_witness(results, a, pct, seed):
    p = results / f"MOBIGUARD_Attack{a}_{pct}{suffix(a)}_seed{seed}_Q4.csv"
    if not p.exists():
        return None
    rows = [l for l in open(p) if l.strip() and not l.lstrip().startswith("#")]
    if not rows:
        return None
    c = [x.strip() for x in rows[-1].split(",")]
    off = _TCAM_BLOCK_LEN if a in _TCAM_ATTACKS else 0
    idx = {k: v + off for k, v in _W_BASE.items()}
    if len(c) <= idx["recall"]:
        return None
    try:
        return {k: float(c[i]) for k, i in idx.items()}
    except (TypeError, ValueError):
        return None


def fig_counts(d, out):
    """Fig 1 — TP_W/FP_W/FN_W per variant: the isolation result AND the FP cost."""
    fig, ax = base_axes((7.6, 3.9))
    x = np.arange(len(ATTACKS))
    w, gap = 0.26, 0.012
    for i, (name, key, colr) in enumerate([("TP_W", "TP_W", C_BLUE),
                                           ("FP_W", "FP_W", C_ORANGE),
                                           ("FN_W", "FN_W", C_AQUA)]):
        vals = [d[a][key] if d.get(a) else 0 for a in ATTACKS]
        b = ax.bar(x + (i - 1) * (w + gap), vals, w, label=name,
                   color=colr, zorder=3, linewidth=0)
        zero_marks(ax, b, colr)
        label_bars(ax, b)
    leg = ax.legend(frameon=False, fontsize=8, ncol=3, loc="lower left",
                    bbox_to_anchor=(0, 1.005), labelcolor=INK_2, handlelength=1.1)
    for t in leg.get_texts():
        t.set_color(INK_2)
    finish(fig, ax, "Q4 — witness-native detections by attack variant",
           "node alerts", out, has_legend=True)


def fig_dup(d, out):
    """Fig 3 — duplicate alerts. Surfaces the A5/A6 anomaly: ~1500 alerts each
    while TP_W/FP_W/FN_W are all zero, i.e. the witness is generating traffic
    that never lands in the confusion matrix."""
    fig, ax = base_axes((7.6, 3.4))
    vals = [d[a]["witness_da"] if d.get(a) else 0 for a in ATTACKS]
    b = ax.bar(np.arange(len(ATTACKS)), vals, 0.52, color=C_BLUE,
               zorder=3, linewidth=0)
    zero_marks(ax, b, C_BLUE)
    label_bars(ax, b)
    finish(fig, ax, "Q4 — duplicate witness alerts by attack variant",
           "duplicate alerts", out)


def fig_pr(d, out):
    """Fig 2 — precision vs recall, ONLY for the variants where the witness fired.

    A1-A6 are deliberately excluded: with TP_W=FP_W=FN_W=0 both rates are
    UNDEFINED, not zero, and plotting them as 0 % would read as "the witness
    failed" when it correctly stayed silent.
    """
    live = [a for a in ATTACKS if d.get(a) and (d[a]["TP_W"] + d[a]["FP_W"] + d[a]["FN_W"]) > 0]
    if not live:
        return False
    fig, ax = plt.subplots(figsize=(4.6, 3.6), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.xaxis.grid(False)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK_2, length=0, labelsize=8)

    x = np.arange(len(live))
    w, gap = 0.34, 0.012
    for i, (name, key, colr) in enumerate([("Precision", "precision", C_BLUE),
                                           ("Recall", "recall", C_ORANGE)]):
        b = ax.bar(x + (i - 0.5) * (w + gap), [d[a][key] for a in live], w,
                   label=name, color=colr, zorder=3, linewidth=0)
        label_bars(ax, b, fmt="{:.1f}")
    ax.set_ylim(0, 105)
    ax.set_xticks(x)
    ax.set_xticklabels([VLABEL[a] for a in live], fontsize=8, color=INK_2)
    ax.set_ylabel("percent", fontsize=8.5, color=INK_2)
    leg = ax.legend(frameon=False, fontsize=8, ncol=2, loc="lower left",
                    bbox_to_anchor=(0, 1.005), labelcolor=INK_2, handlelength=1.1)
    for t in leg.get_texts():
        t.set_color(INK_2)
    ax.set_title("Q4 — witness precision vs recall", fontsize=11.5, color=INK,
                 loc="left", pad=30, fontweight="600")
    ax.annotate("variants with no witness activity omitted (rates undefined)",
                xy=(0, -0.17), xycoords="axes fraction", fontsize=7,
                color=INK_MUTED, ha="left", va="top")
    fig.tight_layout()
    fig.savefig(out, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    return True


def main():
    ap = argparse.ArgumentParser(description="Q4 witness-native figures")
    ap.add_argument("--results", default=None)
    ap.add_argument("--pct", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--outdir", default=None)
    args = ap.parse_args()

    ns3 = Path(os.environ.get("NS3_DIR", Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"))
    results = Path(args.results) if args.results else ns3 / "results_routing"
    if not results.is_dir():
        raise SystemExit(f"results dir not found: {results} (set --results or NS3_DIR)")

    outdir = Path(args.outdir) if args.outdir else \
        Path(__file__).resolve().parent.parent.parent / "output" / "ablation" / "q4"
    outdir.mkdir(parents=True, exist_ok=True)

    d = {a: read_witness(results, a, args.pct, args.seed) for a in ATTACKS}
    found = [a for a in ATTACKS if d.get(a)]
    if not found:
        raise SystemExit(f"no Q4 CSVs in {results}")
    print(f"Q4: {len(found)}/8 variants")

    fig_counts(d, outdir / "Figure_Q4_WitnessNative.png")
    print(f"  wrote {outdir / 'Figure_Q4_WitnessNative.png'}")
    if fig_pr(d, outdir / "Figure_Q4_WitnessPrecisionRecall.png"):
        print(f"  wrote {outdir / 'Figure_Q4_WitnessPrecisionRecall.png'}")
    fig_dup(d, outdir / "Figure_Q4_WitnessDuplicateAlerts.png")
    print(f"  wrote {outdir / 'Figure_Q4_WitnessDuplicateAlerts.png'}")


if __name__ == "__main__":
    main()
