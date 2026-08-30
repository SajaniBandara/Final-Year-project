#!/usr/bin/env python3
"""
corrected_mitigation_latency.py — M4 / L_mit recomputed to match eq:l_mit
(2026-08-31, after the quarantine-enforcement work).

THREE DEFECTS in the in-simulation M4, all measured on the completed A5-A8
runs, all fixable offline from data already on disk:

  (1) The reported figure is not a mean of L_mit. routing.cc:117578 accumulates
      a PER-CYCLE mean and divides by the cycle count, over a node set that
      grows as more nodes quarantine. For A5's control arm that turns a true
      mean of 2,697 ms into a reported 6,937 ms -- a 2.6x accumulation
      artefact, nothing to do with mitigation.

  (2) t_onset is attack_start_time for every DECLARED node
      (attack_declaration.h:204, hf_attack_helper.h:653), not the instant that
      node actually began misbehaving. Nodes that start late -- or never attack
      at all -- are charged latency for an attack they had not yet launched.
      Correcting this alone cuts L_mit by 1.5-2.5x.

  (3) Nodes quarantined WITHOUT EVER ATTACKING are folded into the average as
      though they were slow mitigations. Under enforcement they are the
      opposite: mitigated before doing harm. They are reported separately here
      rather than averaged in.

Scope: RSU nodes only. Per-node first-attack time comes from the per-RSU
lstm_training CSVs (hf_send_gt), which have no vehicle rows.
"""
import re, csv, os, sys, statistics as st, argparse
from pathlib import Path

RES = Path.home()/"G_13/ns-allinone-3.35/ns-3.35/results_routing"
TR  = RES/"lstm_training"
# Run logs holding the [TRUST-QUARANTINE] lines. Session-specific, so it is a
# required argument rather than a hardcoded path.
ap = argparse.ArgumentParser(description=__doc__,
                             formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--log-dir", required=True,
                help="directory containing the per-run launcher logs (QF*.log / QC*.log)")
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--pct", type=int, default=60)
_args = ap.parse_args()
LOG = Path(_args.log_dir)
if not LOG.is_dir():
    sys.exit(f"ERROR: --log-dir not found: {LOG}")
ATTACK_START = 10.0

def quarantine_times(tag):
    q = {}
    p = LOG/f"{tag}.log"
    if not p.exists(): return q
    with open(p, errors="ignore") as fh:
        for line in fh:
            m = re.search(r'\[TRUST-QUARANTINE\] node=(\d+) .*t=([0-9.]+)', line)
            if m: q.setdefault(int(m.group(1)), float(m.group(2)))
    return q

def first_attack(av, tag, rsu):
    f = TR/f"RSU_{rsu}"/f"Attack{av}_{_args.pct}_seed{_args.seed}_{tag}.csv"
    if not f.exists(): return None
    with open(f) as fh:
        for x in csv.DictReader(fh):
            if float(x["hf_send_gt"]) > 0:
                return int(float(x["cycle"]))
    return None

def reported(av, tag):
    f = RES/f"MOBIGUARD_Attack{av}_{_args.pct}_seed{_args.seed}_{tag}.csv"
    if not f.exists(): return float("nan")
    rows = list(csv.reader(open(f)))
    hdr = [h.strip() for h in rows[0]]
    try: return float(rows[-1][hdr.index("avg_mit_ms")])
    except Exception: return float("nan")

print("="*92)
print("M4 / L_mit — reported vs corrected  (RSU nodes; ms)")
print("="*92)
print(f"\n{'variant':<8}{'arm':<6}{'reported':>10}{'true mean':>11}{'CORRECTED':>11}"
      f"{'n scored':>10}{'pre-attack q':>14}{'never attacked':>16}")
for av in (5,6,7,8):
    for tag, arm in ((f"QF{av}","ON"), (f"QC{av}","OFF")):
        q = quarantine_times(tag)
        coded, corr, pre = [], [], 0
        for n, t in q.items():
            r = n - 200
            if not (0 <= r <= 63): continue
            if t > ATTACK_START: coded.append(t - ATTACK_START)
            fa = first_attack(av, tag, r)
            if fa is None: pre += 1          # quarantined, never attacked
            elif t > fa:   corr.append(t - fa)
        print(f"A{av:<7}{arm:<6}{reported(av,tag):>10.0f}"
              f"{(st.mean(coded)*1000 if coded else 0):>11.0f}"
              f"{(st.mean(corr)*1000 if corr else 0):>11.0f}"
              f"{len(corr):>10}{pre:>14}{pre:>16}")
    print()
print("reported   = avg_mit_ms straight from the MOBIGUARD CSV (defects 1+2+3)")
print("true mean  = mean(t_quarantine - attack_start_time)  -> removes defect 1 only")
print("CORRECTED  = mean(t_quarantine - node's OWN first attack), pre-attack")
print("             quarantines excluded and counted separately -> defects 1+2+3 removed")
