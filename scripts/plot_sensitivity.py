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

# column metric -> label
COLS = [("avg_MCC", "MCC (M1)"),
        ("avg_FPR", "FPR % (M1)"),
        ("t_consensus_ms_avg", "consensus (ms, M7)"),
        ("o_crypto_bytes_pkt", "security (B/pkt, M7)"),
        ("avg_lat_ms", "L_e2e (ms, M6)")]

# knobs grouped by subsystem -> one readable figure per group
GROUPS = [
    ("s1_timing",   "S1 timing / mobility baseline (A1)",
     ["s1_k", "s1_beta", "s1_delta0", "s1_alpha_rho", "s1_alpha_v"]),
    ("trust",       "Trust & enforcement (A2)",
     ["trust_t_min", "trust_delta_p", "trust_delta_r", "T_hold"]),
    ("controller",  "Controller trust (A1)",
     ["trust_t_min_ctrl", "trust_delta_p_ctrl", "trust_delta_r_ctrl"]),
    ("witness",     "Witness verification (A7)",
     ["witness_window", "witness_f"]),
    ("tcam",        "TCAM S4 (A4)",
     ["tcam_util_thresh"]),
    ("crypto",      "Crypto / consensus overhead (A1)",
     ["t_sync", "batch_size"]),
]

def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

def plot_group(gid, title, gknobs):
    gknobs = [k for k in gknobs if any(r["param"] == k for r in rows)]
    nrow, ncol = len(gknobs), len(COLS)
    fig, ax = plt.subplots(nrow, ncol, figsize=(3.3 * ncol, 2.6 * nrow), squeeze=False)
    fig.suptitle(f"MOBIGUARD sensitivity (Task 8.5) — {title}   [OFAT, 60 s, seed 1, Q6]",
                 fontsize=13, y=1.0)
    for i, knob in enumerate(gknobs):
        pts = sorted((r for r in rows if r["param"] == knob), key=lambda r: fnum(r["value"]))
        xs = [fnum(r["value"]) for r in pts]
        attack = pts[0]["attack"]
        opt = optima.get(knob, {})
        best_val = fnum(opt.get("best_value")) if opt.get("sensitive") else None
        for j, (col, label) in enumerate(COLS):
            a = ax[i][j]
            ys = [fnum(r[col]) for r in pts]
            if any(y is not None for y in ys):
                a.plot(xs, ys, marker="o", ms=5, lw=1.6, color="#1f5fa8")
            if col == "avg_MCC" and best_val is not None:
                a.axvline(best_val, color="#c0392b", ls="--", lw=1.4)
            a.tick_params(labelsize=8)
            a.grid(True, alpha=0.3, lw=0.5)
            if j == 0:
                tag = "flat / keep default" if opt and not opt.get("sensitive") else f"optimum = {opt.get('best_value')}"
                a.set_ylabel(f"{knob}\n(A{attack})", fontsize=10)
                a.annotate(tag, xy=(0.03, 0.88), xycoords="axes fraction", fontsize=8,
                           color="#c0392b" if opt.get("sensitive") else "#555")
            if i == 0:
                a.set_title(label, fontsize=10)
            if i == nrow - 1:
                a.set_xlabel("knob value", fontsize=9)
    fig.tight_layout(rect=(0, 0, 1, 0.99))
    out = os.path.join(D, f"sensitivity_{gid}.png")
    fig.savefig(out, dpi=140, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote sensitivity_{gid}.png  ({nrow} knobs x {ncol} metrics)")

print("per-group sensitivity figures:")
for gid, title, gknobs in GROUPS:
    plot_group(gid, title, gknobs)
