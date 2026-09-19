#!/usr/bin/env python3
"""VANGUARD-HF Exp 2 (speed, split active/passive) and Exp 3 (scale) figures."""
import csv
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

D = Path(__file__).resolve().parent.parent / "docs/vanguard_exp23"


def load(path, key):
    rows = list(csv.DictReader(open(path)))
    def num(v):
        try: return float(v)
        except (TypeError, ValueError): return None
    for r in rows:
        r[key] = float(r[key])
        for c in ("MCC", "FPR", "UCR", "lat_ms"): r[c] = num(r[c])
    return rows


def ser(rows, key, arm, attack, col):
    pts = sorted([r for r in rows if r["arm"] == arm and r["attack"] == attack and r[col] is not None],
                 key=lambda r: r[key])
    return [r[key] for r in pts], [r[col] for r in pts]


def fade_macro(rows, key, col="MCC"):
    xs = sorted({r[key] for r in rows if r["arm"] == "FADE"})
    out = []
    for x in xs:
        vals = [r[col] for r in rows if r["arm"] == "FADE" and r[key] == x and r[col] is not None]
        out.append(sum(vals)/len(vals) if vals else None)
    return xs, out


def plot_exp2():
    rows = load(D / "exp2_scores.csv", "speed")
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    for att, c, lab in (("macro", "#1f5fa8", "VANGUARD (macro S5–S8)"),
                        ("active(S5,S6)", "#27ae60", "VANGUARD active (S5,S6)"),
                        ("passive(S7,S8)", "#8e44ad", "VANGUARD passive (S7,S8)")):
        x, y = ser(rows, "speed", "VANGUARD", att, "MCC")
        if x: ax[0].plot(x, y, "o-", color=c, lw=1.7, label=lab)
    fx, fy = fade_macro(rows, "speed")
    ax[0].plot(fx, fy, "s--", color="grey", lw=1.2, label="FADE (macro)")
    ax[0].set_xlabel("mean vehicle speed cap (km/h)"); ax[0].set_ylabel("MCC (M1)")
    ax[0].set_title("(a) Detection vs speed"); ax[0].grid(alpha=.3); ax[0].legend(fontsize=8)
    x, y = ser(rows, "speed", "VANGUARD", "macro", "FPR")
    ax[1].plot(x, y, "o-", color="#1f5fa8", lw=1.8)
    ax[1].set_xlabel("mean vehicle speed cap (km/h)"); ax[1].set_ylabel("macro FPR (%)")
    ax[1].set_title("(b) False-positive rate vs speed"); ax[1].grid(alpha=.3)
    fig.suptitle("VANGUARD-HF Exp 2 — Detection across vehicular speed  [N=200, seed 1, 60s, 40%]", y=1.02)
    fig.tight_layout()
    for e in ("png", "pdf"): fig.savefig(D / f"exp2_speed.{e}", dpi=150, bbox_inches="tight")
    plt.close(fig); print("wrote exp2_speed.png/pdf")


def plot_exp3():
    rows = load(D / "exp3_scores.csv", "nveh")
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    for att, c, lab in (("macro", "#1f5fa8", "VANGUARD (macro)"),
                        ("active(S5,S6)", "#27ae60", "active (S5,S6)"),
                        ("passive(S7,S8)", "#8e44ad", "passive (S7,S8)")):
        x, y = ser(rows, "nveh", "VANGUARD", att, "MCC")
        if x: ax[0].plot(x, y, "o-", color=c, lw=1.7, label=lab)
    fx, fy = fade_macro(rows, "nveh")
    ax[0].plot(fx, fy, "s--", color="grey", lw=1.2, label="FADE (macro)")
    ax[0].set_xlabel("vehicles (N)"); ax[0].set_ylabel("MCC (M1)")
    ax[0].set_title("(a) Detection vs scale"); ax[0].grid(alpha=.3); ax[0].legend(fontsize=8)
    for a, c in (("S5", "#1f5fa8"), ("S6", "#27ae60"), ("S7", "#8e44ad"), ("S8", "#e67e22")):
        x, y = ser(rows, "nveh", "VANGUARD", a, "lat_ms")
        if x: ax[1].plot(x, y, "o-", color=c, lw=1.4, label=a)
    ax[1].axhline(100, color="red", ls=":", lw=1.2, label="100 ms bound")
    ax[1].set_xlabel("vehicles (N)"); ax[1].set_ylabel("end-to-end latency (ms)")
    ax[1].set_title("(b) Latency vs scale"); ax[1].grid(alpha=.3); ax[1].legend(fontsize=8)
    fig.suptitle("VANGUARD-HF Exp 3 — Scalability  [maxspeed 150, seed 1, 60s, 40%]", y=1.02)
    fig.tight_layout()
    for e in ("png", "pdf"): fig.savefig(D / f"exp3_scale.{e}", dpi=150, bbox_inches="tight")
    plt.close(fig); print("wrote exp3_scale.png/pdf")


if __name__ == "__main__":
    plot_exp2(); plot_exp3()
