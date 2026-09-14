#!/usr/bin/env python3
"""
Plot the full-system sensitivity sweep (Task 8.5) as a knob x metric grid,
matching the reference template: one row per swept knob, columns = the metric
family (detection MCC, FPR, consensus latency, security bytes, end-to-end
latency). The selected optimum is marked on the MCC panel.

Reads docs/sensitivity_2026-09-14/raw_points.csv (+ optima.json for the marks),
writes docs/sensitivity_2026-09-14/sensitivity_grid.png and .pdf.
"""
import csv
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

D = "/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project/docs/sensitivity_2026-09-14"
rows = list(csv.DictReader(open(os.path.join(D, "raw_points.csv"))))
optima = json.load(open(os.path.join(D, "optima.json")))

# preserve first-seen knob order
knobs = list(dict.fromkeys(r["param"] for r in rows))
# column metric -> (label, unit)
COLS = [("avg_MCC", "MCC (M1)"),
        ("avg_FPR", "FPR % (M1)"),
        ("t_consensus_ms_avg", "consensus (ms, M7)"),
        ("o_crypto_bytes_pkt", "security (B/pkt, M7)"),
        ("avg_lat_ms", "L_e2e (ms, M6)")]

def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

nrow, ncol = len(knobs), len(COLS)
fig, ax = plt.subplots(nrow, ncol, figsize=(3.0 * ncol, 1.9 * nrow), squeeze=False)
fig.suptitle("MOBIGUARD full-system sensitivity (Task 8.5): 17 knobs x metrics "
             "(OFAT, 60 s, seed 1, Q6, per-knob attack)", fontsize=12, y=0.998)

for i, knob in enumerate(knobs):
    pts = sorted((r for r in rows if r["param"] == knob), key=lambda r: fnum(r["value"]))
    xs = [fnum(r["value"]) for r in pts]
    attack = pts[0]["attack"]
    opt = optima.get(knob, {})
    best_val = fnum(opt.get("best_value")) if opt.get("sensitive") else None
    for j, (col, label) in enumerate(COLS):
        a = ax[i][j]
        ys = [fnum(r[col]) for r in pts]
        if any(y is not None for y in ys):
            a.plot(xs, ys, marker="o", ms=3, lw=1.2, color="#1f5fa8")
        if col == "avg_MCC" and best_val is not None:
            a.axvline(best_val, color="#c0392b", ls="--", lw=1.0)
        a.tick_params(labelsize=6)
        a.grid(True, alpha=0.25, lw=0.4)
        if j == 0:
            tag = "flat/keep default" if opt and not opt.get("sensitive") else f"opt={opt.get('best_value')}"
            a.set_ylabel(f"{knob}\n(A{attack})", fontsize=7)
            a.annotate(tag, xy=(0.02, 0.9), xycoords="axes fraction", fontsize=6,
                       color="#c0392b" if opt.get("sensitive") else "#555")
        if i == 0:
            a.set_title(label, fontsize=8)
        if i == nrow - 1:
            a.set_xlabel("knob value", fontsize=7)

fig.tight_layout(rect=(0, 0, 1, 0.995))
for ext in ("png", "pdf"):
    fig.savefig(os.path.join(D, f"sensitivity_grid.{ext}"), dpi=140, bbox_inches="tight")
print("wrote", os.path.join(D, "sensitivity_grid.png"), "and .pdf")
print(f"grid: {nrow} knobs x {ncol} metrics")
