#!/usr/bin/env python3
"""Share of the 200 vehicles still on their trip / actually moving at t = 50, 100, 150 s, per mobility trace.
in-trip : departure (first setdest) <= t < end of the last waypoint segment (vehicle has not yet parked after its trip)
moving  : in-trip AND the speed of the current segment > 0.1 m/s (a vehicle can also pause at a light)"""
import re, csv, sys, bisect
from pathlib import Path
MOB = Path("/home/sdvn_hidden_attacks/ns3_g13/mobility")
AT = re.compile(r'^\$ns_ at ([\d.]+) "\$node_\((\d+)\) setdest ([-\d.e]+) ([-\d.e]+) ([-\d.e]+)"')
def load(path):
    w = {}
    for line in open(path):
        m = AT.match(line)
        if m: w.setdefault(int(m.group(2)), []).append((float(m.group(1)), float(m.group(5))))
    for n in w: w[n].sort()
    return w
def share(w, t):
    intrip = moving = 0
    for n, lst in w.items():
        times = [x[0] for x in lst]
        end = times[-1] + (times[-1] - times[-2] if len(times) > 1 else 1.0)
        if times[0] <= t < end:
            intrip += 1
            i = bisect.bisect_right(times, t) - 1
            if lst[i][1] > 0.1: moving += 1
    return intrip / len(w), moving / len(w)
rows = []
traces = [("default (--maxspeed=150)", MOB / "mobility_urban_150.tcl"), ("base 60 km/h limit", MOB / "mobility_urban_60.tcl")] + \
         [(f"v{v}", MOB / f"mobility_urban_v{v}.tcl") for v in (10, 40, 70, 100, 130, 150)]
out = Path(__file__).resolve().parent.parent / "docs" / "speed_trace_moving_share.csv"
with open(out, "w", newline="") as f:
    wr = csv.writer(f); wr.writerow(["trace", "t_s", "in_trip_pct", "moving_pct"])
    for name, p in traces:
        w = load(p)
        line = [name]
        for t in (50, 100, 150):
            a, b = share(w, t); wr.writerow([name, t, round(100 * a, 1), round(100 * b, 1)]); line.append(f"{t}s: trip {100*a:.0f}% / moving {100*b:.0f}%")
        print(" | ".join(line))
