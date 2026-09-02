#!/usr/bin/env python3
"""
build_baseline_summary.py — collapse the P1 SOTA-baseline + comparison runs into
one tidy, plot-ready CSV.

Output: results_routing/baseline_summary_60s.csv  (long format, one row per
(method, attack, pct)). Columns:

  method     TAP | FADE | SFTO | MOBIGUARD
  attack     1..8
  family     STD (A1/2) | HF (A5-8) | TCAM (A3/4)
  pct        20 40 60 80 100
  avg_PDR avg_lat_ms avg_MCC avg_DR avg_FPR TP FP TN FN avg_TVR avg_UCR
  src        source file / dir

- TAP/FADE/MOBIGUARD: final-cycle cumulative row of the per-cycle CSV.
- SFTO: from sfto_pipeline/results/hpc_p1_a{3,4}[_p<pct>]/metrics.json.
- MOBIGUARD prefers the *_cmp60 tagged 60s runs; falls back to canonical.
"""
import csv, glob, json, os, sys

NS3 = os.path.expanduser("~/ns3_g13/ns-allinone-3.35/ns-3.35")
R = os.path.join(NS3, "results_routing")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SFTO = os.path.join(REPO, "sfto_pipeline", "results")
OUT = os.path.join(R, "baseline_summary_60s.csv")

FAMILY = {1: "STD", 2: "STD", 3: "TCAM", 4: "TCAM",
          5: "HF", 6: "HF", 7: "HF", 8: "HF"}
PCTS = [20, 40, 60, 80, 100]
# per-cycle CSV column indices (0-based), shared TAP / MOBIGUARD / FADE layout
C = dict(avg_PDR=2, avg_lat_ms=4, avg_MCC=6, avg_DR=8, avg_FPR=10,
         TP=13, FP=14, TN=15, FN=16, avg_TVR=18)
FADE_UCR_COL = 22  # column 23; TODO confirm vs write_security_metrics_csv()

rows = []


def last_data_row(path):
    vals = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            vals = [x.strip() for x in line.split(",")]
    return vals


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return ""


def mcc_from_matrix(tp, fp, tn, fn):
    """Cumulative-matrix MCC. '' if any cell missing or denominator 0."""
    try:
        tp, fp, tn, fn = float(tp), float(fp), float(tn), float(fn)
    except (TypeError, ValueError):
        return ""
    den = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    if den == 0:
        return ""
    return round((tp * tn - fp * fn) / den, 4)


def add_percycle(method, attack, path):
    v = last_data_row(path)
    if not v:
        return
    row = dict(method=method, attack=attack, family=FAMILY[attack],
               pct=None, src=os.path.basename(path))
    for k, i in C.items():
        row[k] = num(v[i]) if i < len(v) else ""
    row["avg_UCR"] = num(v[FADE_UCR_COL]) if (method == "FADE" and len(v) > FADE_UCR_COL) else ""
    rows.append(row)
    return row


def collect_percycle(method, prefix, attacks):
    for a in attacks:
        for p in PCTS:
            hits = sorted(glob.glob(os.path.join(R, f"{prefix}_Attack{a}_{p}_*seed1{'_cmp60' if method=='MOBIGUARD' else ''}.csv"))
                          or glob.glob(os.path.join(R, f"{prefix}_Attack{a}_{p}_seed1.csv"))
                          or glob.glob(os.path.join(R, f"{prefix}_Attack{a}_{p}_d*ms_seed1.csv")))
            if not hits:
                continue
            row = add_percycle(method, a, hits[0])
            if row:
                row["pct"] = p


# --- TAP (A1,A2), MOBIGUARD cmp60 (A1,2,5-8) from per-cycle CSVs ---
collect_percycle("TAP", "TAP", [1, 2])
collect_percycle("MOBIGUARD", "MOBIGUARD", [1, 2, 5, 6, 7, 8])

# --- FADE (A5-8): use fade_metrics_*.csv (flow-level confusion + real MCC).
# The per-cycle FADE_Attack*.csv avg_MCC collapses to ~0 (1-2 positives/cycle);
# efade_detection.h already computes the cumulative-matrix MCC here. ---
for a in [5, 6, 7, 8]:
    for p in PCTS:
        hits = sorted(glob.glob(os.path.join(R, f"fade_metrics_Attack{a}_{p}_seed1*.csv")))
        if not hits:
            continue
        r = list(csv.DictReader(open(hits[0])))
        if not r:
            continue
        m = r[-1]
        rows.append(dict(
            method="FADE", attack=a, family=FAMILY[a], pct=p,
            avg_PDR=num(m.get("pdr", "")), avg_lat_ms="",
            avg_MCC=num(m.get("mcc", "")),
            avg_DR=(round(float(m["tp"]) / (float(m["tp"]) + float(m["fn"])) * 100, 2)
                    if float(m["tp"]) + float(m["fn"]) > 0 else 0.0),
            avg_FPR=(round(float(m["fp"]) / (float(m["fp"]) + float(m["tn"])) * 100, 2)
                     if float(m["fp"]) + float(m["tn"]) > 0 else 0.0),
            TP=int(float(m["tp"])), FP=int(float(m["fp"])),
            TN=int(float(m["tn"])), FN=int(float(m["fn"])),
            avg_TVR="", avg_UCR="", src=os.path.basename(hits[0])))

# --- SFTO (A3,A4) from metrics.json ---
for a, base in ((3, "a3"), (4, "a4")):
    for p in PCTS:
        d = os.path.join(SFTO, f"hpc_p1_{base}" + ("" if p == 20 else f"_p{p}"))
        mj = os.path.join(d, "metrics.json")
        if not os.path.isfile(mj):
            continue
        m = json.load(open(mj))
        rows.append(dict(
            method="SFTO", attack=a, family="TCAM", pct=p,
            avg_PDR="", avg_lat_ms="",
            avg_MCC=round(m["mcc"], 4), avg_DR=round(m["recall"] * 100, 2),
            avg_FPR=round(m["fpr"] * 100, 2),
            TP=m["TP"], FP=m["FP"], TN=m["TN"], FN=m["FN"],
            avg_TVR="", avg_UCR="", src=os.path.relpath(d, REPO)))

# Uniform cumulative-matrix MCC for every row (matches FADE's fade_metrics mcc
# and SFTO's metrics.json mcc; replaces the per-cycle-average avg_MCC for
# TAP/MOBIGUARD). Plot + tables should use mcc_matrix for a like-for-like
# cross-method comparison.
for r in rows:
    r["mcc_matrix"] = mcc_from_matrix(r.get("TP"), r.get("FP"), r.get("TN"), r.get("FN"))

cols = ["method", "attack", "family", "pct", "avg_PDR", "avg_lat_ms",
        "mcc_matrix", "avg_MCC", "avg_DR", "avg_FPR", "TP", "FP", "TN", "FN",
        "avg_TVR", "avg_UCR", "src"]
rows.sort(key=lambda r: (r["method"], r["attack"], r["pct"] or 0))
with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

print(f"wrote {OUT}  ({len(rows)} rows)")
by_m = {}
for r in rows:
    by_m.setdefault(r["method"], set()).add((r["attack"], r["pct"]))
for m, s in sorted(by_m.items()):
    print(f"  {m:10s} {len(s):2d} (attack,pct) points")
