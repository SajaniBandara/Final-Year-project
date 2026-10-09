#!/usr/bin/env python3
"""Synthetic tests for event_scorer.py (supervisor 2026-10-08, test (a) and the invariants of test (b))."""
import math, sys
from collections import defaultdict
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import event_scorer as es

def mk(acts=(), alarms=None, qua=None):
    ev = dict(act=defaultdict(int), alm=defaultdict(list), qua={}, fire=defaultdict(lambda: defaultdict(int)),
              wit=defaultdict(int), atk=set(), commit="test", last_cycle=0, qua_events=defaultdict(list),
              state=defaultdict(int), dec=defaultdict(lambda: defaultdict(int)), variant=-1)
    for (c, n) in acts: ev["act"][(c, n)] += 1
    for n, lst in (alarms or {}).items(): ev["alm"][n] = list(lst)
    for n, c in (qua or {}).items(): ev["qua"][n] = c; ev["qua_events"][c].append(n)
    return ev

NV, NR, T = 10, 2, 10
A, B = 10, 11
fails = 0
def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1

# (a) A attacks 3-5, quarantined end of cycle 5; one alarm raised in cycle 6 covers 3..6 (window 4); B flagged only in 4.
ev = mk(acts=[(3, A), (4, A), (5, A)], alarms={A: [(6, 4, 1)], B: [(4, 1, 1)]}, qua={A: 5})
per, s = es.score(ev, NV, NR, T, warmup=0, stop_after_quarantine=True)   # test (a) is the superseded rule-4 scenario
for c in range(T):
    p = per[c]
    # per-node expectations by cycle
    expA = "TP" if c in (3, 4, 5) else ("TN" if c < 3 else None)
    expB = "FP" if c == 4 else "TN"
    exp = defaultdict(int)
    if expA: exp[expA] += 1
    exp[expB] += 1
    got = {k: p[k] for k in ("TP", "FP", "FN", "TN")}
    check(f"a: cycle {c} counts {dict((k,v) for k,v in got.items() if v)}", all(got[k] == exp.get(k, 0) for k in got))
check("a: A has no FP in cycle 6 (late alarm after quarantine)", per[6]["FP"] == 0 and per[6]["scored"] == 1)
check("a: totals TP=3 FP=1 FN=0", (s["TP"], s["FP"], s["FN"]) == (3, 1, 0))

# (b) invariants on a random-ish log
import random
random.seed(1)
acts = [(c, n) for n in range(NV, NV+NR) for c in range(T) if random.random() < 0.4]
ev = mk(acts=acts)
per, s = es.score(ev, NV, NR, T, warmup=0)
check("b: scored = TP+FP+FN+TN every cycle", all(p["TP"]+p["FP"]+p["FN"]+p["TN"] == p["scored"] == NR for p in per))
check("b: per-cycle sums equal pooled counts", all(sum(p[k] for p in per) == s[k] for k in ("TP","FP","FN","TN")))
check("b: flag nothing -> MCC 0 on pooled counts", s["TP"] == 0 and s["FP"] == 0 and es.mcc(s["TP"], s["FP"], s["FN"], s["TN"]) == 0.0)
al = {n: [(c, 1, 1) for c in range(T)] for n in range(NV, NV+NR)}
per, s = es.score(mk(acts=acts, alarms=al), NV, NR, T, warmup=0)
check("b: flag everything every cycle -> MCC 0", abs(es.mcc(s["TP"], s["FP"], s["FN"], s["TN"])) < 1e-9)
al = {n: [(c, 1, 1) for (c, nn) in acts if nn == n] for n in range(NV, NV+NR)}
per, s = es.score(mk(acts=acts, alarms=al), NV, NR, T, warmup=0)
check("b: flag exactly the positives -> MCC 1", abs(s["M1"] - 1.0) < 1e-9 and s["FP"] == 0 and s["FN"] == 0)
check("b: p=0 (no positives) -> MCC undefined", math.isnan(es.score(mk(), NV, NR, T, 0)[1]["M1"]))
# amended rules (2026-10-09): rule 4 dropped -> same log, every node scored every cycle
ev = mk(acts=[(3, A), (4, A), (5, A)], alarms={A: [(6, 4, 1)], B: [(4, 1, 1)]}, qua={A: 5})
per, s = es.score(ev, NV, NR, T, warmup=0)
check("rule 4 dropped: scored = NR in all cycles", all(p["scored"] == NR for p in per))
check("rule 4 dropped: A gives TP 3,4,5 and (alarm window covers 6 but A did not attack) cycle 6 is TN", [per[c]["TP"] for c in (3,4,5)] == [1,1,1] and per[6]["TN"] == 2 and per[6]["FP"] == 0)
check("rule 4 dropped: false quarantine count 0 (A attacked before its quarantine)", s["quarantined_false"] == 0)
# A3/A4 STATE label: entries present cycles 3..6 (gap at 5 inside interval): positive = 3..6 continuously; alarm at 8 (after) is FP; alarm at 5 is TP
ev = mk(); ev["variant"] = 2
ev["state"][(3, A)] = 2; ev["state"][(4, A)] = 2; ev["state"][(6, A)] = 1
ev["alm"][A] = [(4, 1, 4), (5, 1, 4), (8, 1, 4)]
per, s = es.score(ev, NV, NR, T, warmup=0)
posA = [c for c in range(T) if per[c]["TP"] + per[c]["FN"] - (0) > 0]
check("state label: positive cycles are 3..6 for A", posA == [3, 4, 5, 6])
check("state label: alarms at 4,5 are TP, cycle 6 (no alarm) is FN, alarm at 8 is FP", per[4]["TP"] == 1 and per[5]["TP"] == 1 and per[6]["FN"] == 1 and per[8]["FP"] == 1 and per[3]["FN"] == 1)
# witness alarms excluded by default
ev = mk(acts=[(3, A)], alarms={A: [(3, 1, 1 << 9)]})
per, s = es.score(ev, NV, NR, T, warmup=0)
check("witness-only alarm is not an alarm by default (FN)", per[3]["FN"] == 1)
per, s = es.score(ev, NV, NR, T, warmup=0, alarm_mask=0xFFFFFFFF)
check("witness alarm counts when asked (TP)", per[3]["TP"] == 1)
ok, info = es.check_same_positives({"full": es.score(mk(acts=[(3, A)]), NV, NR, T, 0)[1], "abl": es.score(mk(acts=[(3, A), (4, A)]), NV, NR, T, 0)[1]})
check("TP+FN identity check flags arms with different positives", (not ok) and info["differing"][0][0] == "abl")
print("ALL PASS" if fails == 0 else f"{fails} FAILED"); sys.exit(1 if fails else 0)
