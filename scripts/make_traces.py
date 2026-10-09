#!/usr/bin/env python3
"""make_traces.py -- speed-axis traces and the N-sweep base trace, with routes that REPEAT (supervisor 2026-10-09, night 2).

Looping: a vehicle that reaches the end of its route drives it back, then forward again, repeating until the horizon (default 400 s of
trace time), so no vehicle parks after its trip. Reversal keeps every segment's duration, so the stop-and-go pattern is preserved.

Speed traces (10, 40, 70, 100, 130, 150 km/h): time-scale the 60 km/h-limit SUMO trace (mobility_urban_60.tcl) by k = target / 60 per vehicle:
same routes and waypoints, each vehicle keeps its departure time, segment durations / k, speeds * k; then loop.
N sweep (N = 100, 160, 220, 280, 340, 400): ONE 400-vehicle trace (mobility_urban_scale400.tcl, all departures within 0..32 s <= 44 s) with its
vehicle ids permuted in a FIXED random order (seed 20261009) and renumbered 0..399; the trace for N is the first N vehicles of that file,
so the subsets are nested. Written to mobility_urban_N400_perm.tcl (use with --N_Vehicles=N --mobility_trace_file=...).
ASSERTION: the share of vehicles moving at t = 50, 100, 150 s is within 5 points across the six speed traces."""
import argparse, bisect, csv, json, random, re
from pathlib import Path
MOB = Path("/home/sdvn_hidden_attacks/ns3_g13/mobility")
DOCS = Path(__file__).resolve().parent.parent / "docs"
SET_RE = re.compile(r'^\$node_\((\d+)\) set ([XYZ])_ ([-\d.e]+)')
AT_RE = re.compile(r'^\$ns_ at ([\d.]+) "\$node_\((\d+)\) setdest ([-\d.e]+) ([-\d.e]+) ([-\d.e]+)"')

def load(path):
    start, way = {}, {}
    for line in open(path):
        m = SET_RE.match(line)
        if m:
            start.setdefault(int(m.group(1)), {})[m.group(2)] = float(m.group(3)); continue
        m = AT_RE.match(line)
        if m: way.setdefault(int(m.group(2)), []).append((float(m.group(1)), float(m.group(3)), float(m.group(4)), float(m.group(5))))
    return start, way

def loop_route(start, wp, k, horizon):
    """-> list of (t, x, y, v): the route with durations / k, driven forward then back, repeating, until `horizon`."""
    t0 = wp[0][0]
    pts = [(start["X"], start["Y"])] + [(x, y) for (_, x, y, _) in wp]        # pts[0] = start, pts[j+1] = destination of line j
    dur = [(wp[i + 1][0] - wp[i][0]) / k for i in range(len(wp) - 1)]
    dur.append(dur[-1] if dur else 1.0 / k)
    out, t, j, direction, nseg = [], t0, 0, 1, len(wp)
    while t < horizon:
        if direction == 1:
            a, b, d = pts[j], pts[j + 1], dur[j]
            j += 1
            if j >= nseg: direction, j = -1, nseg - 1
        else:
            a, b, d = pts[j + 1], pts[j], dur[j]
            j -= 1
            if j < 0: direction, j = 1, 0
        dist = ((b[0] - a[0]) ** 2 + (b[1] - a[1]) ** 2) ** 0.5
        out.append((t, b[0], b[1], dist / d if d > 0 else 0.0))
        t += d
    return out

def write(path, starts, routes, order=None):
    ids = order if order is not None else sorted(routes)
    rows = []
    with open(path, "w") as f:
        for new, old in enumerate(ids):
            f.write(f"$node_({new}) set X_ {starts[old]['X']}\n$node_({new}) set Y_ {starts[old]['Y']}\n$node_({new}) set Z_ 0\n")
            rows += [(t, new, x, y, v) for (t, x, y, v) in routes[old]]
        for (t, n, x, y, v) in sorted(rows, key=lambda r: (r[0], r[1])):
            f.write(f'$ns_ at {t:.4f} "$node_({n}) setdest {x:.2f} {y:.2f} {v:.4f}"\n')

def moving_share(routes, t):
    mv = 0
    for r in routes.values():
        times = [x[0] for x in r]
        if times[0] <= t and r[bisect.bisect_right(times, t) - 1][3] > 0.1: mv += 1
    return 100.0 * mv / len(routes)

def raw_share(path, t):
    """share moving in an ORIGINAL (non-looped) trace: parked after the last waypoint."""
    s, w = load(path); mv = 0
    for n, lst in w.items():
        times = [x[0] for x in lst]
        end = times[-1] + (times[-1] - times[-2] if len(times) > 1 else 1.0)
        if times[0] <= t < end and lst[bisect.bisect_right(times, t) - 1][3] > 0.1: mv += 1
    return 100.0 * mv / len(w)

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--targets", type=int, nargs="+", default=[10, 40, 70, 100, 130, 150])
    ap.add_argument("--horizon", type=float, default=400.0); a = ap.parse_args()
    start, way = load(MOB / "mobility_urban_60.tcl")
    rows, shares = [], {}
    for tgt in a.targets:
        k = tgt / 60.0
        routes = {n: loop_route(start[n], way[n], k, a.horizon) for n in way}
        write(MOB / f"mobility_urban_v{tgt}.tcl", start, routes)
        shares[f"v{tgt}"] = [moving_share(routes, t) for t in (50, 100, 150)]
        sp = [x[3] * 3.6 for r in routes.values() for x in r if x[0] <= 180]
        mv = sorted(x for x in sp if x > 0.36)
        rows.append(dict(trace=f"mobility_urban_v{tgt}.tcl", limit_kmh=tgt, k=round(k, 4), mean_all=sum(sp) / len(sp), mean_moving=sum(mv) / len(mv),
                         median_moving=mv[len(mv) // 2], p95_moving=mv[int(0.95 * len(mv)) - 1], max=max(sp)))
    for name, p in (("default (mobility_urban_150, not looped)", MOB / "mobility_urban_150.tcl"), ("base 60 (not looped)", MOB / "mobility_urban_60.tcl")):
        shares[name] = [raw_share(p, t) for t in (50, 100, 150)]
    with open(DOCS / "speed_traces.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader()
        for r in rows: w.writerow({k: (round(v, 1) if isinstance(v, float) else v) for k, v in r.items()})
    with open(DOCS / "speed_trace_moving_share.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["trace", "moving_pct_at_50s", "moving_pct_at_100s", "moving_pct_at_150s"])
        for k, v in shares.items(): w.writerow([k] + [round(x, 1) for x in v])
    print("limit | mean_moving | p95 | max     moving % at 50 / 100 / 150 s")
    for r in rows: print(f"{r['limit_kmh']:4d} {r['mean_moving']:6.1f} {r['p95_moving']:6.1f} {r['max']:6.1f}     " + " / ".join(f"{x:.1f}" for x in shares[f"v{r['limit_kmh']}"]))
    for k, v in shares.items():
        if not k.startswith("v"): print(k, " / ".join(f"{x:.1f}" for x in v))
    sp = [v for k, v in shares.items() if k.startswith("v")]
    spread = [max(c) - min(c) for c in zip(*sp)]
    ok = all(x <= 5.0 for x in spread)
    print("spread across the six speed traces at 50/100/150 s (points):", [round(x, 1) for x in spread], "ASSERT within 5:", "PASS" if ok else "FAIL")
    s4, w4 = load(MOB / "mobility_urban_scale400.tcl")
    order = sorted(w4); random.Random(20261009).shuffle(order)
    routes4 = {n: loop_route(s4[n], w4[n], 1.0, a.horizon) for n in w4}
    write(MOB / "mobility_urban_N400_perm.tcl", s4, routes4, order)
    dep = [routes4[n][0][0] for n in w4]
    print("N400_perm: vehicles", len(order), "last departure %.1f s" % max(dep), "(<= 44 s: %s)" % (max(dep) <= 44.0), "first 6 original ids:", order[:6])
    json.dump(dict(order=order, seed=20261009), open(DOCS / "N400_perm_order.json", "w"))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
