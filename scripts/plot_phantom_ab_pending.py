#!/usr/bin/env python3
"""
plot_phantom_ab_pending.py — AB7 / AB9 / AB10 / AB12 figures from ab_pending_scores.csv.
Each figure plots the property the component serves; MCC (M1) is a reference panel only.
An infinite metric (e.g. M4 with quarantine off, M5 with failover ablated) is drawn as an
arrow at the top of the panel labelled "inf".
"""
import csv, math, os
from pathlib import Path
os.environ.setdefault("MPLCONFIGDIR", "/tmp/mplcfg")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs/phantom_exp23"
FULL, ABL = "#1f77b4", "#d62728"       # full PHANTOM / ablated substitute
ATTK = {1: "#1f77b4", 2: "#2ca02c", 3: "#9467bd", 4: "#8c564b"}
plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.3})

def num(x):
    if x in ("", None): return None
    return float(x)

rows = list(csv.DictReader(open(OUT / "ab_pending_scores.csv")))
def get(arm, a, p, k):
    for r in rows:
        if r["arm"] == arm and int(r["attack"]) == a and int(r["pct"]) == p:
            return num(r[k])
    return None
def mean(xs):
    xs = [x for x in xs if x is not None and not math.isinf(x)]
    return sum(xs) / len(xs) if xs else None

# Exp 1 (enforcement off) M1 reference for AB10
exp1 = {}
for r in csv.DictReader(open(OUT / "exp1_scores.csv")):
    if r["arm"] == "PHANTOM" and r["exp"] == "1" and r["attack"] in ("1", "2", "3") and r["MCC"] \
            and (r["attack"] == "3" or r["intensity"] == "100"):
        exp1[(int(r["attack"]), int(r["pen"]))] = float(r["MCC"])

def inf_arrow(ax, xs, ytop, color):
    for x in xs:
        ax.annotate("inf", xy=(x, ytop), xytext=(x, ytop * 0.80), ha="center", color=color, fontsize=8,
                    arrowprops=dict(arrowstyle="->", color=color, lw=1))

def fig_ab7():
    P = [20, 40, 60, 80, 100]
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for arm, c, lab in (("ab7full", FULL, "full PHANTOM"), ("ab7off", ABL, "AB7: detection only")):
        ax[0].plot(P, [mean([get(arm, a, p, "M6_ms") for a in (1, 2, 3, 4)]) for p in P], "o-", color=c, label=lab)
        ax[2].plot(P, [mean([get(arm, a, p, "M1") for a in (1, 2, 3, 4)]) for p in P], "o-", color=c, label=lab)
    m4 = [mean([get("ab7full", a, p, "M4_ms") for a in (1, 2, 3, 4)]) / 1000 for p in P]
    ax[1].plot(P, m4, "o-", color=FULL, label="full PHANTOM")
    top = max(m4) * 1.7; ax[1].set_ylim(0, top); inf_arrow(ax[1], P, top * 0.95, ABL)
    ax[1].plot([], [], color=ABL, label="AB7: unbounded (never quarantined)")
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M6 end to end latency (ms)", title="(a) End to end latency")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC (reference)", title="(c) Detection (reference)")
    for a in ax: a.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(OUT / "ab7_quarantine.png", dpi=170); plt.close(fig)

def fig_ab9():
    P = [20, 40, 60, 80, 100]; PC = [40, 60, 80, 100]
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    ax[0].plot(P, [mean([get("ab7full", a, p, "M5_max_ms") for a in (1, 3)]) for p in P], "o-", color=FULL, label="full PHANTOM")
    top = 24; ax[0].set_ylim(0, top); inf_arrow(ax[0], PC, top * 0.95, ABL)
    ax[0].plot([], [], color=ABL, label="AB9: no failover (undefined, inf)")
    for arm, c, lab, ps in (("ab7full", FULL, "full PHANTOM", P), ("ab9sub", ABL, "AB9: no isolation", PC)):
        ax[1].plot(ps, [mean([get(arm, a, p, "M4_ms") for a in (1, 3)]) / 1000 for p in ps], "o-", color=c, label=lab)
        ax[2].plot(ps, [mean([get(arm, a, p, "M1") for a in (1, 3)]) for p in ps], "o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M5 failover latency (ms)", title="(a) Controller failover")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC (reference)", title="(c) Detection (reference)")
    for a in ax: a.axvline(33, color="gray", ls=":", lw=1); a.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(OUT / "ab9_failover.png", dpi=170); plt.close(fig)

def fig_ab10():
    PC = [40, 60, 80, 100]
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for a, lab in ((1, "S1 (A1)"), (2, "S2 (A2)"), (3, "S3 (A3)")):
        ax[0].plot(PC, [get("ab10sub", a, p, "forged_share_pct") for p in PC], "o-", color=ATTK[a], label=lab)
    ax[0].plot(PC, [0] * 4, "k--", lw=1, label="full PHANTOM (0)")
    for a, lab in ((1, "S1"), (2, "S2")):
        ax[1].plot(PC, [exp1.get((a, p)) for p in PC], "o--", color=ATTK[a], label=f"{lab} full")
        ax[1].plot(PC, [get("ab10sub", a, p, "M1") for p in PC], "s-", color=ATTK[a], label=f"{lab} AB10")
    ax[2].plot(PC, [get("ab10sub", a, 40, "M11_pct") if False else get("ab10sub", 1, p, "M11_pct") for p in PC], "o-", color=ABL, label="AB10 (A1)")
    ax[2].plot(PC, [get("ab10sub", 3, p, "M11_pct") for p in PC], "s--", color=ABL, label="AB10 (A3)")
    ax[2].plot(PC, [0] * 4, "k--", lw=1, label="full PHANTOM"); ax[2].set_ylim(-5, 105)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="forged proofs accepted (%)", title="(a) Proof integrity")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M1 MCC, S1 and S2 (reference)", title="(b) Detection (reference)")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M11 unauthorized commit rate (%)", title="(c) Unauthorized FlowMods")
    for a in ax: a.axvline(33, color="gray", ls=":", lw=1); a.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(OUT / "ab10_keys.png", dpi=170); plt.close(fig)

def fig_ab12():
    P = [20, 40, 60, 80, 100]; PC = [40, 60, 80, 100]
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    ax[0].plot(P, [mean([get("ab7full", a, p, "M11_pct") for a in (1, 3)]) for p in P], "o-", color=FULL, label="full PHANTOM")
    ax[0].plot(PC, [mean([get("ab12sub", a, p, "M11_pct") for a in (1, 3)]) for p in PC], "o-", color=ABL, label="AB12: legitimise")
    ax[0].set_ylim(-5, 105)
    for arm, c, lab, ps in (("ab7full", FULL, "full PHANTOM", P), ("ab12sub", ABL, "AB12: legitimise", PC)):
        ax[1].plot(ps, [mean([get(arm, a, p, "M4_ms") for a in (1, 3)]) / 1000 for p in ps], "o-", color=c, label=lab)
        ax[2].plot(ps, [mean([get(arm, a, p, "M1") for a in (1, 3)]) for p in ps], "o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M11 unauthorized commit rate (%)", title="(a) Unauthorized FlowMods")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC (reference)", title="(c) Detection (reference)")
    for a in ax: a.axvline(33, color="gray", ls=":", lw=1); a.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(OUT / "ab12_legit.png", dpi=170); plt.close(fig)

if __name__ == "__main__":
    for f in (fig_ab7, fig_ab9, fig_ab10, fig_ab12): f()
    print("wrote ab7_quarantine.png ab9_failover.png ab10_keys.png ab12_legit.png")
