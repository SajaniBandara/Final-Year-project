#!/usr/bin/env python3
"""tmin_analysis.py -- (1) benign-run quarantine breakdown by trust-decrement cause, (2) T_min selection (supervisor 2026-10-09, night 2).
Selection rule: best MCC of 'node quarantined' vs 'node is an attacker', pooled over benign + A1 + A3 on seeds 2 and 3, subject to at most 5 %
of honest nodes quarantined (pooled). If no T_min reaches 5 %: STOP and send the table (this script prints STOP)."""
import glob, json, math, sys
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_scorer as es

RES = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
OUT = Path(__file__).resolve().parent.parent / "docs" / "quarantine"
NV, NR = 200, 64
CAUSES = ["batch_or_sig", "hop_proof", "delay_proof", "witness_DA", "witness_NFA", "S4_attrib", "S5_attrib", "other"]

def load(tag):
    p = glob.glob(str(RES / f"events_Attack*_{tag}.csv"))
    return es.parse(p[0]) if p else None

def attackers(ev):
    a = {n for n in ev["atk"] if n < NV + NR}
    a |= {n for (c, n) in ev["act"] if NV <= n < NV + NR}
    a |= {n for (c, n) in ev["state"] if NV <= n < NV + NR}
    return a

def breakdown(tag):
    ev = load(tag)
    if ev is None: return None
    q = {n: v for n, v in ev["quax"].items() if n < NV + NR}
    typ = Counter("vehicle" if v["type"] == 0 else "RSU" for v in q.values())
    tot = [0] * 8; primary = Counter(); present = Counter()
    for v in q.values():
        for b in range(8): tot[b] += v["dec"][b]
        nz = [b for b in range(8) if v["dec"][b]]
        for b in nz: present[CAUSES[b]] += 1
        if nz: primary[CAUSES[max(nz, key=lambda b: v["dec"][b])]] += 1
    allt = [0] * 8
    for n, v in ev["td"].items():
        for b in range(8): allt[b] += v["dec"][b]
    times = sorted(round(v["t"], 1) for v in q.values())
    return dict(tag=tag, cfg=ev["cfg"], quarantined=len(q), by_type=dict(typ), decrements_behind_quarantines={CAUSES[b]: tot[b] for b in range(8)},
                quarantines_with_cause_present=dict(present), quarantines_by_dominant_cause=dict(primary),
                whole_run_decrements_all_nodes={CAUSES[b]: allt[b] for b in range(8)}, nodes_with_any_decrement=len(ev["td"]),
                quarantine_times_s=times, first_quarantine_s=(times[0] if times else None), last_quarantine_s=(times[-1] if times else None),
                rows=[dict(node=n, type=("vehicle" if v["type"] == 0 else "RSU"), t=round(v["t"], 2), trust=round(v["trust"], 3), dec={CAUSES[b]: v["dec"][b] for b in range(8) if v["dec"][b]}) for n, v in sorted(q.items(), key=lambda kv: kv[1]["t"])])

def select():
    res = {}
    for tm in (0.3, 0.5, 0.7):
        tp = fp = fn = tn = 0; per = {}
        for a in (0, 1, 3):
            ptp = pfp = pfn = ptn = 0
            for s in (2, 3):
                ev = load(f"tm{int(tm*10):02d}_A{a}_s{s}")
                if ev is None: return None
                att = attackers(ev); qs = {n for n in ev["qua"] if n < NV + NR}
                for n in range(NV + NR):
                    isa = n in att; isq = n in qs
                    if isa and isq: ptp += 1
                    elif isa: pfn += 1
                    elif isq: pfp += 1
                    else: ptn += 1
            per[f"A{a}"] = dict(TP=ptp, FP=pfp, FN=pfn, TN=ptn, honest_quarantined_pct=100.0 * pfp / max(1, pfp + ptn))
            tp += ptp; fp += pfp; fn += pfn; tn += ptn
        res[tm] = dict(TP=tp, FP=fp, FN=fn, TN=tn, MCC=es.mcc(tp, fp, fn, tn), honest_quarantined_pct=100.0 * fp / max(1, fp + tn), per_scenario=per)
    feas = {k: v for k, v in res.items() if v["honest_quarantined_pct"] <= 5.0 and not math.isnan(v["MCC"])}
    best = max(feas, key=lambda k: feas[k]["MCC"]) if feas else None
    return dict(table=res, best_T_min=best, STOP=(best is None))

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    out = dict(breakdown={t: breakdown(t) for t in ("tm07_A0_s2", "repro_old_A0_s2")}, selection=select())
    json.dump(out, open(OUT / "quarantine_analysis.json", "w"), indent=1, default=str)
    for t, b in out["breakdown"].items():
        if b: print(t, {k: v for k, v in b.items() if k not in ("rows", "quarantine_times_s")})
    s = out["selection"]
    if s:
        for tm, v in s["table"].items(): print("T_min", tm, {k: (round(x, 4) if isinstance(x, float) else x) for k, x in v.items() if k != "per_scenario"}, {k: round(x["honest_quarantined_pct"], 2) for k, x in v["per_scenario"].items()})
        print("best T_min:", s["best_T_min"], "STOP" if s["STOP"] else "")
