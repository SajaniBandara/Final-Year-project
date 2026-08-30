#!/usr/bin/env python3
"""
quarantine_enforcement_report.py — validation report for eq:quarantine enforcement
(supervisor priority-one item, 2026-08-30/31).

Pairs each enforcement-ON run (QF*) with its matched control (QC*) -- same build,
same seed, same config, differing only in --enable_quarantine_enforcement -- and
reports the three things asked for:

  1. Post-quarantine firing cycles (validation ask #3). Must be ~0 with
     enforcement on; the control shows what it was before.
  2. M4 / mitigation latency (ask #4). Must NOT be reported from a control run:
     with enforcement off, Lmit measures the latency of a flag that has no
     effect on the data path.
  3. The cost of enforcement -- PDR / latency / UCR -- since a quarantined
     origin's flows are now actually dropped.
"""
import re, csv, os, sys, math, argparse
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

def quarantine_times(tag):
    q = {}
    p = LOG/f"{tag}.log"
    if not p.exists(): return q
    with open(p, errors="ignore") as fh:
        for line in fh:
            m = re.search(r'\[TRUST-QUARANTINE\] node=(\d+) .*t=([0-9.]+)', line)
            if m: q.setdefault(int(m.group(1)), float(m.group(2)))
    return q

def post_q(av, tag):
    q = quarantine_times(tag); n = still = tot = 0
    lags = []
    for node, t in q.items():
        r = node - 200
        if not (0 <= r <= 63): continue
        f = TR/f"RSU_{r}"/f"Attack{av}_{_args.pct}_seed{_args.seed}_{tag}.csv"
        if not f.exists(): continue
        n += 1; c = 0
        with open(f) as fh:
            for x in csv.DictReader(fh):
                cy = int(float(x["cycle"]))
                if cy > t and float(x["hf_send_gt"]) > 0:
                    c += 1; lags.append(cy - t)
        tot += c
        if c: still += 1
    return n, still, tot, lags

def sim_metrics(av, tag):
    f = RES/f"MOBIGUARD_Attack{av}_{_args.pct}_seed{_args.seed}_{tag}.csv"
    if not f.exists(): return None
    rows = list(csv.reader(open(f)))
    if len(rows) < 2: return None
    hdr = [h.strip() for h in rows[0]]; last = rows[-1]
    def g(name):
        try: return float(last[hdr.index(name)])
        except Exception: return float("nan")
    return {k: g(k) for k in ("avg_PDR","avg_lat_ms","avg_mit_ms","avg_TVR","avg_UCR")}

print("="*78)
print("eq:quarantine ENFORCEMENT — validation report")
print("="*78)
print("\n1. POST-QUARANTINE FIRING CYCLES  (ask #3: must be ~0 with enforcement)\n")
print(f"{'variant':<9}{'arm':<18}{'quarantined':>12}{'kept firing':>12}{'cycles':>9}{'max lag':>9}")
for av in (5,6,7,8):
    for tag, arm in ((f"QF{av}","enforcement ON"), (f"QC{av}","control OFF")):
        n, still, tot, lags = post_q(av, tag)
        ml = f"{max(lags):.1f}s" if lags else "-"
        print(f"A{av:<8}{arm:<18}{n:>12}{still:>12}{tot:>9}{ml:>9}")
    print()

print("\n2. M4 / MITIGATION LATENCY  (ask #4)\n")
print("   Control-arm M4 is the latency of an INERT flag and must not be reported.\n")
print(f"{'variant':<9}{'M4 ON (ms)':>14}{'M4 OFF (ms)':>14}")
for av in (5,6,7,8):
    a = sim_metrics(av, f"QF{av}"); b = sim_metrics(av, f"QC{av}")
    if a and b:
        print(f"A{av:<8}{a['avg_mit_ms']:>14.1f}{b['avg_mit_ms']:>14.1f}   <- report ON only")

print("\n\n3. COST OF ENFORCEMENT\n")
print(f"{'variant':<9}{'PDR ON':>9}{'PDR OFF':>9}{'lat ON':>9}{'lat OFF':>9}{'UCR ON':>9}{'UCR OFF':>9}")
for av in (5,6,7,8):
    a = sim_metrics(av, f"QF{av}"); b = sim_metrics(av, f"QC{av}")
    if a and b:
        print(f"A{av:<8}{a['avg_PDR']:>9.2f}{b['avg_PDR']:>9.2f}"
              f"{a['avg_lat_ms']:>9.2f}{b['avg_lat_ms']:>9.2f}"
              f"{a['avg_UCR']:>9.2f}{b['avg_UCR']:>9.2f}")
print()
