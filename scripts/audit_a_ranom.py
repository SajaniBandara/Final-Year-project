"""audit (a): where do the R_anom false alarms of A5-A8 sit relative to the attacker's own node-cycles?"""
import sys, glob, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent)); import event_scorer as es
R = Path.home()/"ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"; BIT = 1 << 13
for a in (5,6,7,8):
  for s in (2,3):
    ev = es.parse(glob.glob(str(R/f"events_Attack{a}_40_*bio0_A{a}_s{s}.csv"))[0])
    actn = {n for (c,n) in ev["act"]}                       # nodes that ever acted
    acycles = collections.defaultdict(set)
    for (c,n) in ev["act"]: acycles[n].add(c)
    tp = fp = fp_actor = fp_near = fp_other = 0
    for n, l in ev["alm"].items():
        for (c, w, m) in l:
            if c < 45 or not (m & BIT): continue
            if c in acycles[n]: tp += 1; continue
            fp += 1
            if n in actn:
                if any(abs(c - k) <= 10 for k in acycles[n]): fp_near += 1
                else: fp_actor += 1
            else: fp_other += 1
    print(f"A{a} s{s}: R_anom alarms on action cycles={tp}  FP total={fp}: on an acting node within 10 cycles of an action={fp_near}, same node later={fp_actor}, never-acting node={fp_other}")
