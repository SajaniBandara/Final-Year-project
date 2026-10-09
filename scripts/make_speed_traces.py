#!/usr/bin/env python3
"""make_speed_traces.py -- speed-scaled mobility traces for the speed axis (supervisor 2026-10-09).

Method: time-scale the SUMO urban trace with a 60 km/h road limit (mobility_urban_60.tcl, max speed exactly 60.0 km/h)
by k = target/60 per vehicle: every vehicle keeps its departure time t_dep (first setdest), its path and its waypoint
positions; each waypoint time becomes t' = t_dep + (t - t_dep)/k and each speed v' = k*v. So the same traffic follows
the same routes k times faster, and the trace's speed limit equals the target. Departures are preserved (not scaled) so
the vehicle insertion pattern, and therefore the 45 s warm-up, is the same for every trace.
Caveat: a faster trace finishes trips earlier; after its last waypoint a vehicle stays parked at its end point.

Usage: make_speed_traces.py [--targets 10 40 70 100 130 150]   -> mobility/mobility_urban_v<target>.tcl, docs/speed_traces.csv
"""
import argparse, csv, re, statistics as st
from pathlib import Path

MOB = Path("/home/sdvn_hidden_attacks/ns3_g13/mobility")
BASE = MOB / "mobility_urban_60.tcl"
BASE_LIMIT = 60.0
SET_RE = re.compile(r'^\$node_\((\d+)\) set ([XYZ])_ ')
AT_RE = re.compile(r'^\$ns_ at ([\d.]+) "\$node_\((\d+)\) setdest ([-\d.e]+) ([-\d.e]+) ([-\d.e]+)"')

def load():
    sets, ats, tdep = [], [], {}
    for line in open(BASE):
        line = line.rstrip("\n")
        if SET_RE.match(line): sets.append(line); continue
        m = AT_RE.match(line)
        if m:
            t, n = float(m.group(1)), int(m.group(2)); tdep.setdefault(n, t)
            ats.append((t, n, m.group(3), m.group(4), float(m.group(5))))
    return sets, ats, tdep

def stats(speeds_ms):
    kmh = [v * 3.6 for v in speeds_ms]
    mv = sorted(x for x in kmh if x > 0.36)           # moving: > 0.1 m/s
    return dict(mean_all=st.mean(kmh), mean_moving=st.mean(mv), median_moving=st.median(mv),
                p95_moving=mv[int(0.95 * len(mv)) - 1], max=max(kmh))

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--targets", type=int, nargs="+", default=[10, 40, 70, 100, 130, 150])
    a = ap.parse_args()
    sets, ats, tdep = load()
    out_rows = [dict(trace="mobility_urban_60 (base, limit 60)", target_kmh=60, k=1.0, **stats([v for *_, v in ats]))]
    for tgt in a.targets:
        k = tgt / BASE_LIMIT
        new = []
        for (t, n, x, y, v) in ats:
            t2 = tdep[n] + (t - tdep[n]) / k
            new.append((t2, n, x, y, v * k))
        new.sort(key=lambda r: (r[0], r[1]))
        path = MOB / f"mobility_urban_v{tgt}.tcl"
        with open(path, "w") as f:
            for s in sets: f.write(s + "\n")
            for (t2, n, x, y, v2) in new:
                f.write(f'$ns_ at {t2:.4f} "$node_({n}) setdest {x} {y} {v2:.4f}"\n')
        out_rows.append(dict(trace=path.name, target_kmh=tgt, k=round(k, 4), **stats([r[4] for r in new])))
    docs = Path(__file__).resolve().parent.parent / "docs" / "speed_traces.csv"
    with open(docs, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys())); w.writeheader()
        for r in out_rows: w.writerow({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()})
    for r in out_rows: print({k: (round(v, 1) if isinstance(v, float) else v) for k, v in r.items()})

if __name__ == "__main__":
    main()
