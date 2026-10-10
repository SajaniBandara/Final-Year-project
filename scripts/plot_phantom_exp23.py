#!/usr/bin/env python3
"""
plot_phantom_exp23.py — PHANTOM Exp 2 (speed) & Exp 3 (scale) figures from the
tidy score CSVs written by score_phantom_exp23.py.

Exp 2 (fig:exp2_speed): macro MCC and FPR vs mean speed, PHANTOM vs TAP.
Exp 3 (fig:exp3_scale): macro MCC and end-to-end latency vs vehicle count,
                        with the 100 ms safety bound.
"""
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


def load(path, key):
    rows = list(csv.DictReader(open(path)))
    def num(v):
        try: return float(v)
        except (TypeError, ValueError): return None
    for r in rows:
        r[key] = float(r[key]); r["attack"] = r["attack"]
        for c in ("MCC", "DR", "FPR", "lat_ms"):
            r[c] = num(r[c])
    return rows


def series(rows, key, arm, attack, col):
    pts = sorted([r for r in rows if r["arm"] == arm and r["attack"] == str(attack)
                  and r[col] is not None], key=lambda r: r[key])
    return [r[key] for r in pts], [r[col] for r in pts]


def plot_exp2():
    rows = load(D / "exp2_scores.csv", "speed")
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    # (a) macro MCC vs speed
    x, y = series(rows, "speed", "PHANTOM", "macro", "MCC")
    ax[0].plot(x, y, "o-", color="#1f5fa8", lw=2, label="PHANTOM (macro S1–S4)")
    for a, c in ((1, "#c0392b"), (2, "#e67e22")):
        xt, yt = series(rows, "speed", "TAP", a, "MCC")
        if xt: ax[0].plot(xt, yt, "s--", color=c, lw=1.4, label=f"TAP (S{a})")
    sx, sy = sfto_line(3)  # SFTO S3/S4 is speed-invariant -> flat reference at default level
    if sy:
        ax[0].axhline(sy[-1], color="#d35400", ls="--", lw=1.2, label="SFTO-Guard (S3/S4, invariant)")
    ax[0].set_xlabel("mean vehicle speed cap (km/h)"); ax[0].set_ylabel("MCC (M1)")
    ax[0].set_title("(a) Detection quality vs speed"); ax[0].grid(alpha=.3); ax[0].legend(fontsize=8)
    # (b) FPR vs speed — the alpha_v-sign question
    x, y = series(rows, "speed", "PHANTOM", "macro", "FPR")
    ax[1].plot(x, y, "o-", color="#1f5fa8", lw=2, label="PHANTOM (macro)")
    for a in (1, 2):
        xa, ya = series(rows, "speed", "PHANTOM", a, "FPR")
        if xa: ax[1].plot(xa, ya, ".--", lw=1, alpha=.7, label=f"PHANTOM S{a}")
    ax[1].axhline(1.0, color="grey", ls=":", lw=1, label="1% target")
    ax[1].set_xlabel("mean vehicle speed cap (km/h)"); ax[1].set_ylabel("FPR (%)")
    ax[1].set_title("(b) False-positive rate vs speed  (α_v test)"); ax[1].grid(alpha=.3); ax[1].legend(fontsize=8)
    fig.suptitle("PHANTOM Exp 2 — Detection across vehicular speed  [N=200, seed 1, 180 s, 40%]", y=1.02)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(D / f"exp2_speed.{ext}", dpi=150, bbox_inches="tight")
    plt.close(fig); print("wrote exp2_speed.png/pdf")


def plot_exp3():
    rows = load(D / "exp3_scores.csv", "nveh")
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    x, y = series(rows, "nveh", "PHANTOM", "macro", "MCC")
    ax[0].plot(x, y, "o-", color="#1f5fa8", lw=2, label="PHANTOM (macro S1–S4)")
    for a, c in ((1, "#c0392b"), (2, "#e67e22")):
        xt, yt = series(rows, "nveh", "TAP", a, "MCC")
        if xt: ax[0].plot(xt, yt, "s--", color=c, lw=1.4, label=f"TAP (S{a})")
    sx, sy = sfto_line(3)
    if sx: ax[0].plot(sx, sy, "^--", color="#d35400", lw=1.3, label="SFTO-Guard (S3/S4)")
    ax[0].set_xlabel("vehicles (N)"); ax[0].set_ylabel("MCC (M1)")
    ax[0].set_title("(a) Detection quality vs scale"); ax[0].grid(alpha=.3); ax[0].legend(fontsize=8)
    # (b) e2e latency vs N (PHANTOM, per-attack avg_lat_ms; use S1 as representative + macro mean)
    for a, c in ((1, "#1f5fa8"), (2, "#27ae60"), (3, "#8e44ad"), (4, "#e67e22")):
        xa, ya = series(rows, "nveh", "PHANTOM", a, "lat_ms")
        if xa: ax[1].plot(xa, ya, "o-", color=c, lw=1.4, label=f"S{a}")
    ax[1].axhline(100.0, color="red", ls=":", lw=1.2, label="100 ms bound")
    ax[1].set_xlabel("vehicles (N)"); ax[1].set_ylabel("end-to-end latency (ms)")
    ax[1].set_title("(b) Latency vs scale"); ax[1].grid(alpha=.3); ax[1].legend(fontsize=8)
    fig.suptitle("PHANTOM Exp 3 — Scalability  [maxspeed 150, seed 1, 180 s, 40%]", y=1.02)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(D / f"exp3_scale.{ext}", dpi=150, bbox_inches="tight")
    plt.close(fig); print("wrote exp3_scale.png/pdf")


if __name__ == "__main__":
    plot_exp2(); plot_exp3()
