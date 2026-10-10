#!/usr/bin/env python3
"""
score_phantom_ci.py -- across-cycle intervals for PHANTOM Exp 1-4 at 180 s, seed 1
(supervisor directive 2026-10-08: CI = mean +/- std over per-routing-cycle values within the run).

One row per (run). Columns:
  M1, M1_blk_mean/std/n   per-RSU deduped 10 s blocks (finest unit M1 has) after 30 s warm-up
  <col>_mean/_std/_n       mean/std over routing cycles >= 30 of cur_TVR, cur_lat_ms, cur_PDR
CAVEAT (see STATUS_REPORT section 2): cur_DR/cur_FPR/cur_MCC are derived from cumulative TP/FP
counters, so they are NOT included; cur_TVR, cur_lat_ms, cur_PDR are per-cycle quantities.
95 % half-width = 1.96 * std / sqrt(n) assumes independent cycles; cycles are autocorrelated, so
report std and treat the half-width as optimistic.
Writes docs/phantom_exp23/exp_ci_180.csv
"""
import csv, re, sys, statistics
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_phantom_ab_pending as ab

RES, OUT, WARM = ab.RES, ab.REPO / "docs/phantom_exp23/exp_ci_180.csv", 30
COLS = ["cur_TVR", "cur_lat_ms", "cur_PDR"]
rx = re.compile(r"MOBIGUARD_Attack(\d)_(\d+)(?:_d(\d+)ms)?_seed1_(e180_exp\d_.+)\.csv$")


def main():
    cache, rows = {}, []
    for f in sorted(RES.glob("MOBIGUARD_Attack*_seed1_e180_exp*.csv")):
        m = rx.search(f.name)
        if not m: continue
        a, pct, dly, tag = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
        h, data = ab.read(f)
        if not data: continue
        key = [c for c in h if c.endswith("cycle")][0]
        d = [r for r in data if (ab.fnum(r[key]) or 0) >= WARM]
        row = dict(exp=tag.split("_")[1], tag=tag, attack=a, pct=pct, delay=dly, cycles=len(data))
        if a:
            if tag not in cache: cache[tag] = ab.m1_pooled(tag)
            row["M1"] = (cache[tag].get(f"A{a}") or (None,))[0]
            bm, bs = ab.m1_blocks(tag, a)
            row["M1_blk_mean"], row["M1_blk_std"] = bm, bs
        for c in COLS:
            xs = [x for x in (ab.fnum(r.get(c)) for r in d) if x is not None]
            row[c + "_mean"] = statistics.mean(xs) if xs else None
            row[c + "_std"] = statistics.pstdev(xs) if len(xs) > 1 else None
            row[c + "_n"] = len(xs)
        rows.append(row)
    fields = ["exp", "tag", "attack", "pct", "delay", "cycles", "M1", "M1_blk_mean", "M1_blk_std"] + \
             [c + s for c in COLS for s in ("_mean", "_std", "_n")]
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
