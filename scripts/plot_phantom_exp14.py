#!/usr/bin/env python3
"""PHANTOM Exp 1 (penetration x intensity) and Exp 4 (AOEI) figures."""
import csv
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

D = Path(__file__).resolve().parent.parent / "docs/phantom_exp23"


def sfto_line(exp):
    """SFTO-Guard S3/S4 mean MCC per swept point, from sfto_sweep.csv."""
    p = D / "sfto_sweep.csv"
    if not p.is_file():
        return [], []
    rows = [r for r in csv.DictReader(open(p)) if int(r["exp"]) == exp]
    pts = sorted({float(r["point"]) for r in rows})
    xs, ys = [], []
    for pt in pts:
        vals = [float(r["SFTO_MCC"]) for r in rows
                if float(r["point"]) == pt and r["SFTO_MCC"] not in ("", "None")]
        if vals:
            xs.append(pt); ys.append(sum(vals) / len(vals))
    return xs, ys


def load(path):
    rows = list(csv.DictReader(open(path)))
    def num(v):
        try: return float(v)
        except (TypeError, ValueError): return None
    for r in rows:
        for c in ("MCC", "FPR"): r[c] = num(r[c])
    return rows


def plot_exp1():
    rows = load(D / "exp1_scores.csv")
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    colors = {55: "#27ae60", 100: "#1f5fa8", 200: "#c0392b"}
    labels = {55: r"1.1$\Delta_{max}$ (55ms)", 100: r"2$\Delta_{max}$ (100ms)", 200: r"4$\Delta_{max}$ (200ms)"}
    for I in (55, 100, 200):
        pts = sorted([r for r in rows if r["arm"] == "PHANTOM" and r["attack"] == "macro"
                      and float(r["intensity"]) == I and r["MCC"] is not None],
                     key=lambda r: float(r["pen"]))
        ax[0].plot([float(r["pen"]) for r in pts], [r["MCC"] for r in pts], "o-",
                   color=colors[I], lw=1.8, label="PHANTOM "+labels[I])
    # TAP reference (S1 avg at delay 100)
    tap = sorted([r for r in rows if r["arm"] == "TAP" and r["attack"] == "1"
                  and float(r["intensity"]) == 100 and r["MCC"] is not None], key=lambda r: float(r["pen"]))
    if tap:
        ax[0].plot([float(r["pen"]) for r in tap], [r["MCC"] for r in tap], "s--",
                   color="grey", lw=1.2, label="TAP (S1, 100ms)")
    sx, sy = sfto_line(1)
    if sx:
        ax[0].plot(sx, sy, "^--", color="#d35400", lw=1.3, label="SFTO-Guard (S3/S4)")
    ax[0].set_xlabel("attack penetration (%)"); ax[0].set_ylabel("MCC (M1)")
    ax[0].set_title("(a) Detection vs penetration & intensity"); ax[0].grid(alpha=.3); ax[0].legend(fontsize=8)
    # (b) macro FPR vs penetration per intensity
    for I in (55, 100, 200):
        pts = sorted([r for r in rows if r["arm"] == "PHANTOM" and r["attack"] == "macro"
                      and float(r["intensity"]) == I and r["FPR"] is not None], key=lambda r: float(r["pen"]))
        ax[1].plot([float(r["pen"]) for r in pts], [r["FPR"] for r in pts], "o-",
                   color=colors[I], lw=1.8, label=labels[I])
    ax[1].set_xlabel("attack penetration (%)"); ax[1].set_ylabel("macro FPR (%)")
    ax[1].set_title("(b) FPR vs penetration"); ax[1].grid(alpha=.3); ax[1].legend(fontsize=8)
    fig.suptitle("PHANTOM Exp 1 — Penetration x Intensity  [N=200, seed 1, 60s]", y=1.02)
    fig.tight_layout()
    for e in ("png", "pdf"): fig.savefig(D / f"exp1_mcc.{e}", dpi=150, bbox_inches="tight")
    plt.close(fig); print("wrote exp1_mcc.png/pdf")


def plot_exp4():
    rows = load(D / "exp4_scores.csv")
    # AOEI mapping: target ratio {0.10,0.25,0.75,1.0} <-> AOEI {0.25,0.5,0.75,1.0}
    aoei = {0.10: 0.25, 0.25: 0.5, 0.75: 0.75, 1.00: 1.0}
    fig, ax = plt.subplots(1, 1, figsize=(6.2, 4.4))
    for att, c, lab in (("macro", "#1f5fa8", "PHANTOM (macro S1-S4)"),
                        ("1", "#c0392b", "PHANTOM S1"), ("2", "#e67e22", "PHANTOM S2")):
        pts = sorted([r for r in rows if r["arm"] == "PHANTOM" and r["attack"] == att and r["MCC"] is not None],
                     key=lambda r: float(r["ratio"]))
        if pts:
            ax.plot([aoei[float(r["ratio"])] for r in pts], [r["MCC"] for r in pts],
                    "o-", color=c, lw=1.7, label=lab)
    tap = sorted([r for r in rows if r["arm"] == "TAP" and r["attack"] == "2" and r["MCC"] is not None],
                 key=lambda r: float(r["ratio"]))
    if tap:
        ax.plot([aoei[float(r["ratio"])] for r in tap], [r["MCC"] for r in tap],
                "s--", color="grey", lw=1.2, label="TAP S2")
    # SFTO-Guard operates on S3/S4 (TCAM), invariant to timing selectivity -> flat reference
    sx, sy = sfto_line(3)
    if sy:
        lvl = sy[-1]  # default N=200 S3/S4 mean
        ax.axhline(lvl, color="#d35400", ls="--", lw=1.2, label="SFTO-Guard (S3/S4, invariant)")
    ax.set_xlabel("attack observable evidence index (AOEI)"); ax.set_ylabel("MCC (M1)")
    ax.set_title("PHANTOM Exp 4 — Detection vs observable evidence\n[N=200, 40%, seed 1, 60s]")
    ax.grid(alpha=.3); ax.legend(fontsize=8)
    fig.tight_layout()
    for e in ("png", "pdf"): fig.savefig(D / f"exp4_aoei.{e}", dpi=150, bbox_inches="tight")
    plt.close(fig); print("wrote exp4_aoei.png/pdf")


if __name__ == "__main__":
    plot_exp1(); plot_exp4()
