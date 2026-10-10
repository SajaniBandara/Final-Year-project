#!/usr/bin/env python3
"""
score_phantom_exp5.py -- Exp 5 per-variant table at the default setting
(N=200, p=40 %, 150 km/h, 100 ms delay; 180 s, seed 1; = the Exp 3 N=200 runs).
PHANTOM/TAP MCC from docs/phantom_exp23/exp3_scores.csv, SFTO from sfto_sweep.csv (exp 3, N=200),
M2 = mean/std over routing cycles >= 30 of cur_TVR (S1/S2 only), M4 = (prevention rate, mean latency of
attackers that acted before containment) from the last row of the run's MOBIGUARD CSV.
Writes docs/phantom_exp23/exp5_table.csv
"""
import csv, sys, statistics
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_phantom_ab_pending as ab

D = ab.REPO / "docs/phantom_exp23"
rows3 = [r for r in csv.DictReader(open(D / "exp3_scores.csv")) if r["nveh"] == "200"]
sfto = {r["variant"]: r["SFTO_MCC"] for r in csv.DictReader(open(D / "sfto_sweep.csv"))
        if r["exp"] == "3" and r["point"] == "200"}
out = []
for a in (1, 2, 3, 4):
    ph = next(r for r in rows3 if r["arm"] == "PHANTOM" and r["attack"] == str(a))
    tp = next((r for r in rows3 if r["arm"] == "TAP" and r["attack"] == str(a)), None)
    h, data = ab.read(ab.csv_path(a, 40, "e180_exp3_nv200"))
    key = [c for c in h if c.endswith("cycle")][0]
    d = [r for r in data if (ab.fnum(r[key]) or 0) >= 30]
    tv = [ab.fnum(r["cur_TVR"]) for r in d]
    last = data[-1]
    out.append(dict(variant=f"S{a}", PHANTOM_MCC=ph["MCC"], TAP_MCC=(tp or {}).get("MCC", "n/a"),
                    SFTO_MCC=sfto.get(f"S{a}", "n/a"),
                    M2_TVR_pct_mean=(statistics.mean(tv) if a <= 2 else ""),
                    M2_TVR_pct_std=(statistics.pstdev(tv) if a <= 2 else ""),
                    M4_prevention_rate=last.get("lmit_prevention_rate"), M4_mean_mit_ms=last.get("avg_mit_ms")))
with open(D / "exp5_table.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
for r in out: print(r)
