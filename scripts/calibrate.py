#!/usr/bin/env python3
"""calibrate.py -- one-off calibration analysis on VALIDATION seeds 2 and 3 (supervisor 2026-10-09).
Stage 1 (--stage 1): U_thresh by the paper's rule (best MCC at FPR <= 1 %), and S1 setting table (jitter suppression off / on).
Stage 2 (--stage 2 --s1 {0,1}): TAP margin, SFTO theta, eFADE matched/compared to LRAD's false-alarm rate per node-cycle.
All numbers are post warm-up (45 s), per RSU node-cycle, pooled over the two seeds."""
import argparse, glob, json, math, sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_scorer as es

RES = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
OUT = Path(__file__).resolve().parent.parent / "docs" / "calibration"
SEEDS, NV, NR, T, W = (2, 3), 200, 64, 180, int(es.WARMUP_S)

def load(tag):
    p = glob.glob(str(RES / f"events_Attack*_{tag}.csv"))
    return es.parse(p[0]) if p else None

def mcc(tp, fp, fn, tn): return es.mcc(tp, fp, fn, tn)

def state_positive(ev, n):
    sc = [c for (c, nn) in ev["state"] if nn == n]
    return set(range(min(sc), max(sc) + 1)) if sc else set()

def s1_row(sup):
    """S1 / S4 false-alarm rates on benign, A1 detection, false quarantines, S1 alarms per 15 s bin."""
    r = dict(setting=("jitter suppression ON" if sup else "jitter suppression OFF"))
    ben = [load(f"cal_s1{sup}_A0_s{s}") for s in SEEDS]; a1 = [load(f"cal_s1{sup}_A1_s{s}") for s in SEEDS]
    if any(e is None for e in ben + a1): return None
    for name, bit in (("S1", 0), ("S4", 3)):
        fire = dec = nc = 0
        for ev in ben:
            fire += sum(ev["fire"][c].get(bit, 0) for c in ev["fire"] if c >= W)
            dec += sum(ev["dec"][c].get(bit, 0) for c in ev["dec"] if c >= W)
            nc += len({(n, c) for n, l in ev["alm"].items() for (c, w, m) in l if m >> bit & 1 and c >= W})
        r[f"{name}_per_decision"] = fire / dec if dec else float("nan")
        r[f"{name}_per_nodecycle"] = nc / (NR * (T - W) * len(SEEDS))
        r[f"{name}_alarm_nodecycles"] = nc; r[f"{name}_decisions"] = dec
    comp = [es.score(ev, NV, NR, T, es.WARMUP_S)[1] for ev in ben]
    r["LRAD_benign_FPR_per_nodecycle"] = sum(s["FP"] for s in comp) / sum(s["FP"] + s["TN"] for s in comp)
    r["benign_false_quarantines"] = [s["quarantined_false"] for s in comp]
    an = [es.score(ev, NV, NR, T, es.WARMUP_S)[1] for ev in a1]
    r["A1_DR"] = sum(s["TP"] for s in an) / max(1, sum(s["TP"] + s["FN"] for s in an))
    r["A1_FPR"] = sum(s["FP"] for s in an) / sum(s["FP"] + s["TN"] for s in an)
    r["A1_M1"] = [round(s["M1"], 4) for s in an]
    r["A1_false_quarantines"] = [s["quarantined_false"] for s in an]; r["A1_true_quarantines"] = [s["quarantined_true"] for s in an]
    bins = defaultdict(int)
    for ev in ben:
        for n, l in ev["alm"].items():
            for c in {c for (c, w, m) in l if m & 1 and c >= W}: bins[(c - W) // 15] += 1
    r["S1_alarm_nodecycles_per_15s_bin_benign_mean_over_seeds"] = [round(bins[b] / len(SEEDS), 2) for b in range(math.ceil((T - W) / 15))]
    return r

def utresh():
    runs = []
    for s in SEEDS:
        for tag, att in ((f"cal_s10_A0_s{s}", 0), (f"cal_A3_s{s}", 3), (f"cal_A4_s{s}", 4)):
            ev = load(tag)
            if ev is None: return None
            runs.append((ev, att))
    thr = [round(0.01 * i, 3) for i in range(1, 100)]
    table = []
    for th in thr:
        tp = fp = fn = tn = 0
        for ev, att in runs:
            for n in range(NV, NV + NR):
                pos = state_positive(ev, n) if att else set()
                for c in range(W, T):
                    u = ev["uv"].get((c, n))
                    if u is None: continue
                    a = u[0] > th; p = c in pos
                    if p and a: tp += 1
                    elif p: fn += 1
                    elif a: fp += 1
                    else: tn += 1
        table.append(dict(thr=th, TP=tp, FP=fp, FN=fn, TN=tn, MCC=mcc(tp, fp, fn, tn), FPR=(fp / (fp + tn) if fp + tn else float("nan")), DR=(tp / (tp + fn) if tp + fn else float("nan"))))
    feas = [t for t in table if t["FPR"] <= 0.01 and not math.isnan(t["MCC"])]
    best = max(feas, key=lambda t: t["MCC"]) if feas else min(table, key=lambda t: t["FPR"])
    return dict(table=table, best=best, feasible=bool(feas), current=next(t for t in table if abs(t["thr"] - 0.20) < 1e-9))

def lrad_benign_fpr(ben, uthr):
    """LRAD's benign false-alarm rate per RSU node-cycle with S4 re-evaluated at `uthr` (S4 = occupancy > uthr; every other alarm source
    as logged). Benign: every alarm is a false alarm."""
    nc = 0
    for ev in ben:
        a = set()
        for n, lst in ev["alm"].items():
            for (c, w, m) in lst:
                if c >= W and (m & ~(1 << 3) & ~es.WITNESS_BITS & 0xFFFFFFFF): a.add((n, c))
        for (c, n), u in ev["uv"].items():
            if c >= W and NV <= n < NV + NR and u[0] > uthr: a.add((n, c))
        nc += len(a)
    return nc / (NR * (T - W) * len(ben))

def stage2(sup, uthr=0.37):
    ben = [load(f"cal_s1{sup}_A0_s{s}") for s in SEEDS]
    target = lrad_benign_fpr(ben, uthr)
    res = dict(target_LRAD_FPR_per_nodecycle=target, s1_setting=sup, U_thresh=uthr, LRAD_FPR_at_old_U_thresh_0_20=lrad_benign_fpr(ben, 0.20))
    s4 = sum(1 for ev in ben for (c, n), u in ev["uv"].items() if c >= W and NV <= n < NV + NR and u[0] > uthr)
    res["S4_at_uthr_per_nodecycle"] = s4 / (NR * (T - W) * len(ben))
    # TAP margin
    tap = [load(f"cal_tap_A0_s{s}") for s in SEEDS]
    if all(tap):
        grid = [10 ** (e / 40.0) for e in range(-320, 41)]   # 1e-8 .. 10 s, 40 steps per decade
        rows = []
        for m in grid:
            nc = sum(1 for ev in tap for (c, n), u in ev["uv"].items() if c >= W and NV <= n < NV + NR and u[2] > m)
            rows.append((m, nc / (NR * (T - W) * len(SEEDS))))
        m_best = min(rows, key=lambda r: abs(r[1] - target))
        res["TAP"] = dict(margin_s=m_best[0], FPR=m_best[1], default_margin_s=1e-6, FPR_at_default=min(rows, key=lambda r: abs(r[0] - 1e-6))[1],
                          max_dev_s=max((u[2] for ev in tap for u in ev["uv"].values()), default=None))
    # SFTO theta
    sf = [load(f"cal_s10_A0_s{s}") for s in SEEDS]
    if all(sf):
        rows = []
        for th in [round(0.01 * i, 3) for i in range(1, 100)]:
            nc = sum(1 for ev in sf for (c, n), u in ev["uv"].items() if c >= W and NV <= n < NV + NR and u[1] >= th)
            rows.append((th, nc / (NR * (T - W) * len(SEEDS))))
        th_best = min(rows, key=lambda r: abs(r[1] - target))
        res["SFTO"] = dict(theta=th_best[0], FPR=th_best[1], default_theta=0.90, FPR_at_default=next(r for r in rows if abs(r[0] - 0.90) < 1e-9)[1],
                           max_achievable_FPR=max(r[1] for r in rows))
    # eFADE (no threshold knob)
    fb = [load(f"cal_fade_A0_s{s}") for s in SEEDS]
    if all(fb):
        sc = [es.score(ev, NV, NR, T, es.WARMUP_S, False, 1 << 16)[1] for ev in fb]
        res["eFADE"] = dict(FPR_benign=sum(s["FP"] for s in sc) / sum(s["FP"] + s["TN"] for s in sc), tunable=False)
    return res

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--stage", type=int, default=1); ap.add_argument("--s1", type=int, default=0); ap.add_argument("--uthresh", type=float, default=0.37)
    a = ap.parse_args(); OUT.mkdir(parents=True, exist_ok=True)
    if a.stage == 1:
        out = dict(S1={f"suppress_{k}": s1_row(k) for k in (0, 1)}, U_thresh=utresh())
        json.dump(out, open(OUT / "stage1.json", "w"), indent=1, default=str)
        for k, v in out["S1"].items(): print(k, json.dumps(v, default=str)[:1500])
        u = out["U_thresh"]
        if u: print("U_thresh best:", u["best"], "feasible(FPR<=1%):", u["feasible"], "| current 0.20:", u["current"])
    else:
        out = stage2(a.s1, a.uthresh); json.dump(out, open(OUT / f"stage2_s1_{a.s1}.json", "w"), indent=1, default=str); print(json.dumps(out, indent=1, default=str))
