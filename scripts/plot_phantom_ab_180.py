#!/usr/bin/env python3
"""
plot_phantom_ab_180.py — DRAFT figures for the PHANTOM ablations from the 180 s, seed-1 scores
(docs/phantom_exp23/ab_pending_scores.csv, written by score_phantom_ab_pending.py).
Each figure plots the property the component serves; MCC (M1) is a reference panel unless detection
is the property. Error bars: M6/M4 = std over per-routing-cycle values of the single run (cycle >= 30 s),
M1 = std over 10 s blocks. An infinite metric is drawn as an arrow labelled "inf".
Output: docs/phantom_exp23/draft_180s/  (drafts: the supervisor sees findings before final plots).
AB2/AB3/AB5 are offline LSTM experiments and are not produced here.
Run:  ~/oqs-env/bin/python scripts/plot_phantom_ab_180.py   (retry on the flaky matplotlib import)
"""
import csv, math, os
from pathlib import Path
os.environ.setdefault("MPLCONFIGDIR", "/tmp/mplcfg")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "docs/phantom_exp23/ab_pending_scores.csv"
OUT = REPO / "docs/phantom_exp23/draft_180s"
OUT.mkdir(parents=True, exist_ok=True)
FULL, ABL = "#1f77b4", "#d62728"
AT = {1: "#1f77b4", 2: "#2ca02c", 3: "#9467bd", 4: "#8c564b"}
plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.3})
P = [20, 40, 60, 80, 100]
PC = [40, 60, 80, 100]

R = list(csv.DictReader(open(SRC)))
def num(x):
    try: return float(x)
    except (TypeError, ValueError): return None
def get(arm, a, p, k, sp=150, dl=100):
    for r in R:
        if r["arm"] == arm and int(r["attack"]) == a and int(r["pct"]) == p \
                and int(r["speed"]) == sp and int(r["delay"]) == dl:
            return num(r[k])
    return None
def fin(xs): return [x for x in xs if x is not None and not math.isinf(x)]
def mean(xs):
    xs = fin(xs); return sum(xs) / len(xs) if xs else None
def agg(arm, atts, p, k): return mean([get(arm, a, p, k) for a in atts])
def series(arm, atts, ps, k, scale=1.0):
    out = []
    for p in ps:
        v = agg(arm, atts, p, k)
        out.append(None if v is None else v * scale)
    return out
def plot(ax, xs, ys, **kw):
    pts = [(x, y) for x, y in zip(xs, ys) if y is not None]
    if pts: ax.plot([a for a, _ in pts], [b for _, b in pts], **kw)
def errplot(ax, xs, ys, es, **kw):
    pts = [(x, y, e or 0.0) for x, y, e in zip(xs, ys, es) if y is not None]
    if pts: ax.errorbar([a for a, _, _ in pts], [b for _, b, _ in pts], yerr=[c for _, _, c in pts],
                        capsize=2, **kw)
def inf_arrow(ax, xs, ytop, color):
    for x in xs:
        ax.annotate("inf", xy=(x, ytop), xytext=(x, ytop * 0.80), ha="center", color=color, fontsize=8,
                    arrowprops=dict(arrowstyle="->", color=color, lw=1))
def finish(fig, ax, name, thr33=False):
    for a in ax:
        if thr33: a.axvline(33, color="gray", ls=":", lw=1)
        a.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(OUT / name, dpi=170); plt.close(fig)

ALL = (1, 2, 3, 4)

def ab1():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for arm, c, lab in (("ab7full", FULL, "full PHANTOM (OBU pre-filter)"), ("ab1sub", ABL, "AB1: no pre-filter")):
        errplot(ax[0], P, series(arm, ALL, P, "M6_ms"), series(arm, ALL, P, "M6_cyc_std"), fmt="o-", color=c, label=lab)
        plot(ax[1], P, series(arm, ALL, P, "M4_ms", 1e-3), marker="o", color=c, label=lab)
        errplot(ax[2], P, series(arm, ALL, P, "M1"), series(arm, ALL, P, "M1_blk_std"), fmt="o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M6 end to end latency (ms)", title="(a) End to end latency")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC", title="(c) Detection")
    finish(fig, ax, "ab1_obu.png")

def ab4():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for arm, c, lab in (("ab7full", FULL, "full PHANTOM (ZK proof)"), ("ab4sub", ABL, "AB4: direct comparison")):
        plot(ax[0], P, series(arm, (2,), P, "M10_raw_ts", 1e-3), marker="o", color=c, label=lab)
        plot(ax[1], P, series(arm, (2,), P, "M7_stark_ms", 1e3), marker="o", color=c, label=lab)
        errplot(ax[2], P, series(arm, (2,), P, "M1"), series(arm, (2,), P, "M1_blk_std"), fmt="o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M10 raw timestamps exposed (thousands)", title="(a) Privacy cost")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M7 verification overhead (us per proof)", title="(b) Verification overhead")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 MCC, S2 (reference)", title="(c) Detection (reference)")
    finish(fig, ax, "ab4_stark.png")

def ab7():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for arm, c, lab in (("ab7full", FULL, "full PHANTOM"), ("ab7off", ABL, "AB7: detection only")):
        errplot(ax[0], P, series(arm, ALL, P, "M6_ms"), series(arm, ALL, P, "M6_cyc_std"), fmt="o-", color=c, label=lab)
        errplot(ax[2], P, series(arm, ALL, P, "M1"), series(arm, ALL, P, "M1_blk_std"), fmt="o-", color=c, label=lab)
    m4 = series("ab7full", ALL, P, "M4_ms", 1e-3)
    plot(ax[1], P, m4, marker="o", color=FULL, label="full PHANTOM")
    top = max(fin(m4)) * 1.7; ax[1].set_ylim(0, top); inf_arrow(ax[1], P, top * 0.95, ABL)
    ax[1].plot([], [], color=ABL, label="AB7: unbounded (never quarantined)")
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M6 end to end latency (ms)", title="(a) End to end latency")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC (reference)", title="(c) Detection (reference)")
    finish(fig, ax, "ab7_quarantine.png")

def ab8():
    fig, ax = plt.subplots(1, 2, figsize=(7.6, 3.3))
    for arm, c, lab in (("ab8full", FULL, "full PHANTOM: f+1 quorum"), ("ab8sub", ABL, "AB8: single RSU")):
        plot(ax[0], P, series(arm, (1, 3), P, "M11_pct"), marker="o", color=c, label=lab)
        errplot(ax[1], P, series(arm, (1, 3), P, "M1"), series(arm, (1, 3), P, "M1_blk_std"), fmt="o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M11 unauthorized commit rate (%)", title="(a) Unauthorized FlowMods", ylim=(-5, 105))
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC (reference)", title="(b) Detection (reference)")
    finish(fig, ax, "ab8_endorse.png")

def ab9():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    plot(ax[0], P, series("ab7full", (1, 3), P, "M5_max_ms"), marker="o", color=FULL, label="full PHANTOM")
    ax[0].set_ylim(0, 24); inf_arrow(ax[0], PC, 22.5, ABL); ax[0].plot([], [], color=ABL, label="AB9: no failover (undefined, inf)")
    for arm, c, lab, ps in (("ab7full", FULL, "full PHANTOM", P), ("ab9sub", ABL, "AB9: no isolation", PC)):
        plot(ax[1], ps, series(arm, (1, 3), ps, "M4_ms", 1e-3), marker="o", color=c, label=lab)
        errplot(ax[2], ps, series(arm, (1, 3), ps, "M1"), series(arm, (1, 3), ps, "M1_blk_std"), fmt="o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M5 failover latency (ms)", title="(a) Controller failover")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC", title="(c) Detection")
    finish(fig, ax, "ab9_failover.png", thr33=True)

def ab10():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for a, lab in ((1, "A1 (S1)"), (2, "A2 (S2)"), (3, "A3 (S3)")):
        plot(ax[0], PC, [get("ab10sub", a, p, "forged_share_pct") for p in PC], marker="o", color=AT[a], label=lab)
    ax[0].plot(PC, [0] * 4, "k--", lw=1, label="full PHANTOM (0)")
    for a, lab in ((1, "S1"), (2, "S2")):
        plot(ax[1], PC, [get("ab7full", a, p, "M1") for p in PC], marker="o", ls="--", color=AT[a], label=f"{lab} full")
        errplot(ax[1], PC, [get("ab10sub", a, p, "M1") for p in PC], [get("ab10sub", a, p, "M1_blk_std") for p in PC],
                fmt="s-", color=AT[a], label=f"{lab} AB10")
    plot(ax[2], PC, [get("ab10sub", 1, p, "M11_pct") for p in PC], marker="o", color=ABL, label="AB10 (A1)")
    plot(ax[2], PC, [get("ab10sub", 3, p, "M11_pct") for p in PC], marker="s", ls="--", color=ABL, label="AB10 (A3)")
    ax[2].plot(PC, [0] * 4, "k--", lw=1, label="full PHANTOM"); ax[2].set_ylim(-5, 105)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="forged proofs accepted (%)", title="(a) Proof integrity")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M1 MCC, S1 and S2", title="(b) Detection")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M11 unauthorized commit rate (%)", title="(c) Unauthorized FlowMods")
    finish(fig, ax, "ab10_keys.png", thr33=True)

def ab11():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    steps = list(range(6)); lab = ["0", "1", "2", "3", "4", "5+"]
    for arm, c, name in (("ab11rot", FULL, "with key rotation"), ("ab11norot", ABL, "AB11: no rotation")):
        sh = []
        for k in steps:
            att = sum(get(arm, a, p, f"ab11_att{k}") or 0 for a in ALL for p in (40, 100))
            acc = sum(get(arm, a, p, f"ab11_acc{k}") or 0 for a in ALL for p in (40, 100))
            sh.append(100.0 * acc / att if att else None)
        plot(ax[0], steps, sh, marker="o", color=c, label=name)
    ax[0].set_xticks(steps); ax[0].set_xticklabels(lab); ax[0].set_ylim(-5, 105)
    for arm, c, name in (("ab11rot", FULL, "with rotation"), ("ab11norot", ABL, "AB11: no rotation")):
        plot(ax[1], [40, 100], [mean([get(arm, a, p, "M11_pct") for a in (1, 3)]) for p in (40, 100)], marker="o", color=c, label=name)
        for a, ls in ((1, "o-"), (2, "s--")):
            errplot(ax[2], [40, 100], [get(arm, a, p, "M1") for p in (40, 100)], [get(arm, a, p, "M1_blk_std") for p in (40, 100)],
                    fmt=ls, color=c, label=f"{name}, S{a}")
    ax[1].set_ylim(-5, 105)
    ax[0].set(xlabel="whole cycles since revocation", ylabel="forged proofs accepted (%)", title="(a) Revoked-key replay")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M11 unauthorized commit rate (%)", title="(b) Unauthorized FlowMods")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 MCC, S1 and S2 (reference)", title="(c) Detection (reference)")
    finish(fig, ax, "ab11_rotation.png")

def ab13():
    S, D = (10, 60, 100, 140), (55, 100, 200)
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    for arm, c, lab in (("ab13full", FULL, "mobility adjusted"), ("ab13sub", ABL, "AB13: static 22.9 ms")):
        errplot(ax[0], S, [get(arm, 1, 40, "M1", sp, 55) for sp in S], [get(arm, 1, 40, "M1_blk_std", sp, 55) for sp in S],
                fmt="o-", color=c, label=lab)
        for sp, ls in ((10, "o-"), (140, "s--")):
            plot(ax[1], D, [get(arm, 1, 40, "M1", sp, dl) for dl in D], marker=ls[0], ls=ls[1:], color=c, label=f"{lab}, {sp} km/h")
    for arm, c, lab in (("ab13fullE", FULL, "mobility adjusted"), ("ab13subE", ABL, "AB13: static 22.9 ms")):
        plot(ax[2], S, [get(arm, 1, 40, "M2_TVR_mean", sp, 55) for sp in S], marker="o", color=c, label=lab)
    ax[0].set(xlabel="mean speed (km/h)", ylabel="M1 MCC, S1 (55 ms delay)", title="(a) Mobility stratified detection")
    ax[1].set(xlabel="injected delay (ms)", ylabel="M1 MCC, S1", title="(b) Attack intensity")
    ax[2].set(xlabel="mean speed (km/h)", ylabel="M2 TVR (%), enforcement on", title="(c) Threshold violation rate")
    ax[0].set_ylim(0.5, 0.8); ax[1].set_ylim(0.5, 0.8)    # common M1 scale: do not magnify ~0.005 differences
    finish(fig, ax, "ab13_threshold.png")

def ab12():
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
    plot(ax[0], P, series("ab7full", (1, 3), P, "M11_pct"), marker="o", color=FULL, label="full PHANTOM")
    plot(ax[0], PC, series("ab12sub", (1, 3), PC, "M11_pct"), marker="o", color=ABL, label="AB12: legitimise")
    ax[0].set_ylim(-5, 105)
    for arm, c, lab, ps in (("ab7full", FULL, "full PHANTOM", P), ("ab12sub", ABL, "AB12: legitimise", PC)):
        plot(ax[1], ps, series(arm, (1, 3), ps, "M4_ms", 1e-3), marker="o", color=c, label=lab)
        errplot(ax[2], ps, series(arm, (1, 3), ps, "M1"), series(arm, (1, 3), ps, "M1_blk_std"), fmt="o-", color=c, label=lab)
    ax[0].set(xlabel="attack penetration p (%)", ylabel="M11 unauthorized commit rate (%)", title="(a) Unauthorized FlowMods")
    ax[1].set(xlabel="attack penetration p (%)", ylabel="M4 mitigation latency (s)", title="(b) Mitigation latency")
    ax[2].set(xlabel="attack penetration p (%)", ylabel="M1 macro MCC (reference)", title="(c) Detection (reference)")
    finish(fig, ax, "ab12_legit.png", thr33=True)

if __name__ == "__main__":
    for f in (ab1, ab4, ab7, ab8, ab9, ab10, ab11, ab12, ab13): f()
    print("wrote", ", ".join(sorted(p.name for p in OUT.glob("*.png"))))
