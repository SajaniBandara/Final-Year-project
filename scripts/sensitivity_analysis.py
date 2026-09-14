#!/usr/bin/env python3
"""
Full-system sensitivity analysis (Task 8.5), 2026-09-14.

One-factor-at-a-time (OFAT) sweep of every tunable design parameter that is
settable at run time. For each parameter the full range is swept in equal steps
with EVERY OTHER parameter left at its compiled default; the value giving the
best performance is selected. One 30 s run per data point, single seed (per the
supervisor's instruction -- no multi-seed).

Full-system config = Q6 (all detectors + crypto + witness + LSTM + BTMM on).

PERFORMANCE METRIC. Each point is scored from the final row of its MOBIGUARD CSV
(the simulator's own per-cycle cumulative metrics, available at 30 s -- unlike
the M1 detector-window pipeline, which excludes the first 30 s and would leave a
30 s run with nothing to score). Detection parameters are selected on avg_MCC
(tie-break: lower avg_FPR); the two crypto-overhead parameters (t_sync,
batch_size), which do not change detection, are selected on lowest avg_lat_ms.

ATTACK PER PARAMETER. A parameter can only show sensitivity under an attack its
detector governs, so each is swept under the variant it controls (see PARAMS).
This mapping is the one judgement call here; change the "attack" field to
re-target. gamma (Krum) is NOT included: it is an offline federated-aggregation
parameter, not a run-time sim flag, so its sensitivity needs retraining per
point, not a 30 s in-sim run.

Usage:
  python3 scripts/sensitivity_analysis.py [--workers N] [--only p1,p2] [--dry-run]
Outputs (under docs/sensitivity_2026-09-14/):
  raw_points.csv     one row per (parameter, value) with all metrics
  optima.json        best value per parameter + the proposed default changes
  summary.txt        human-readable table
"""
import argparse
import csv
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

NS3_DIR = "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35"
RESULTS = os.path.join(NS3_DIR, "results_routing")
REPO    = "/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project"
OUTDIR  = os.path.join(REPO, "docs", "sensitivity_2026-09-14")
SEED, SIMT = 1, 30

# Full-system (Q6) flags, fixed for every run.
Q6 = ("--g_disable_s1_s2=0 --g_disable_s3_s4=0 --g_disable_s5_s6=0 --g_disable_s7_s8=0 "
      "--g_disable_ranom=0 --enable_lstm_inference=1 --enable_witness_mechanism=1 "
      "--disable_crypto=0 --g_disable_btmm_trust=0 --enable_quarantine_enforcement=1")
BASE = (f"--N_RSUs=64 --N_Vehicles=200 --N_Controllers=4 --architecture=3 --maxspeed=150 "
        f"--mobility_scenario=0 --use_sumo_mobility=1 --routing_test=false --sim_run=1 "
        f"--simTime={SIMT} --sim_seed={SEED} --enable_detector_windows=1 --enable_lstm_cls=1 "
        f"--training=0")

# MOBIGUARD final-row 0-indexed columns (write_security_metrics_csv layout).
COL = {"cycle": 0, "avg_PDR": 2, "avg_lat_ms": 4, "avg_MCC": 6, "avg_DR": 8,
       "avg_FPR": 10, "avg_mit_ms": 12, "TP": 13, "FP": 14, "FN": 16, "avg_UCR": 20}


def frange(lo, hi, step):
    """Inclusive equal-step range, FP-drift-safe."""
    n = round((hi - lo) / step)
    return [round(lo + i * step, 6) for i in range(n + 1)]


def irange(lo, hi, step):
    return list(range(lo, hi + 1, step))


# name -> flag, values (full range, equal step), attack variant it governs, %,
# objective ('max_mcc' | 'min_lat'), compiled default (for the report).
PARAMS = [
    {"name": "s1_k",             "flag": "s1_k",             "vals": irange(1, 3, 1),            "attack": 1, "pct": 60, "obj": "max_mcc", "default": 3.0},
    {"name": "s1_beta",          "flag": "s1_beta",          "vals": frange(0.70, 0.95, 0.05),  "attack": 1, "pct": 60, "obj": "max_mcc", "default": 0.95},
    {"name": "trust_t_min",      "flag": "trust_t_min",      "vals": frange(0.30, 0.70, 0.10),  "attack": 2, "pct": 60, "obj": "max_mcc", "default": 0.50},
    {"name": "trust_t_min_ctrl", "flag": "trust_t_min_ctrl", "vals": frange(0.30, 0.70, 0.10),  "attack": 1, "pct": 60, "obj": "max_mcc", "default": 0.50},
    {"name": "trust_delta_p",    "flag": "trust_delta_p",    "vals": frange(0.05, 0.30, 0.05),  "attack": 2, "pct": 60, "obj": "max_mcc", "default": 0.10},
    {"name": "trust_delta_r",    "flag": "trust_delta_r",    "vals": frange(0.02, 0.10, 0.02),  "attack": 2, "pct": 60, "obj": "max_mcc", "default": 0.05},
    {"name": "witness_window",   "flag": "witness_window",   "vals": frange(5, 15, 2),          "attack": 7, "pct": 60, "obj": "max_mcc", "default": 10.0},
    {"name": "tcam_util_thresh", "flag": "tcam_util_thresh", "vals": frange(0.20, 0.80, 0.10),  "attack": 4, "pct": 60, "obj": "max_mcc", "default": 0.216667},  # A4: S4/occupancy-detected (A3 is S3/endorsement, ignores U_thresh)
    {"name": "T_hold",           "flag": "T_hold",           "vals": frange(0.01, 0.05, 0.01),  "attack": 2, "pct": 60, "obj": "max_mcc", "default": 0.01},
    {"name": "t_sync",           "flag": "t_sync",           "vals": frange(0.5, 2.0, 0.5),     "attack": 1, "pct": 60, "obj": "min_lat", "default": 1.0},
    {"name": "batch_size",       "flag": "batch_size",       "vals": irange(10, 20, 2),         "attack": 1, "pct": 60, "obj": "min_lat", "default": 15},
]


def mobiguard_path(attack, pct, tag):
    suffix = "_d80ms" if attack in (1, 2) else ""
    return os.path.join(RESULTS, f"MOBIGUARD_Attack{attack}_{pct}{suffix}_seed{SEED}_{tag}.csv")


def build_cmd(p, val, tag):
    parts = [BASE, Q6, f"--attack_number={p['attack']}", f"--attack_percentage={p['pct']}"]
    if p["attack"] in (1, 2):
        parts.append("--attack_delay_ms=80 --attack_delay_pseudo_random=0")
    # integer-valued flags must not be passed as 1.0
    v = int(val) if float(val).is_integer() and p["name"] in ("s1_k", "batch_size") else val
    parts.append(f"--{p['flag']}={v}")
    parts.append(f"--run_tag={tag}")
    return ["./waf", "--run-no-build", "scratch/routing/routing " + " ".join(parts)]


def parse_metrics(path):
    if not os.path.exists(path):
        return None
    data = [l.split(",") for l in open(path).read().splitlines()
            if l.strip() and not l.lstrip().startswith("#")]
    if not data:
        return None
    last = [c.strip() for c in data[-1]]
    out = {}
    for k, i in COL.items():
        try:
            out[k] = float(last[i])
        except (IndexError, ValueError):
            out[k] = None
    out["_rows"] = len(data)
    return out


def run_point(p, idx, val, dry):
    tag = f"SENS_{p['name']}_{idx:02d}"
    cmd = build_cmd(p, val, tag)
    rec = {"param": p["name"], "flag": p["flag"], "value": val, "attack": p["attack"],
           "pct": p["pct"], "obj": p["obj"], "tag": tag}
    if dry:
        rec["cmd"] = " ".join(cmd)
        return rec
    t0 = datetime.now()
    proc = subprocess.run(cmd, cwd=NS3_DIR, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, text=True, timeout=600)
    rec["rc"] = proc.returncode
    rec["wall_s"] = round((datetime.now() - t0).total_seconds(), 1)
    m = parse_metrics(mobiguard_path(p["attack"], p["pct"], tag))
    rec["metrics"] = m
    return rec


def score(rec):
    m = rec.get("metrics")
    if not m:
        return None
    return m["avg_MCC"] if rec["obj"] == "max_mcc" else m["avg_lat_ms"]


# A parameter is only "sensitive" if its metric actually moves across the sweep.
# Below these floors the sweep is flat (single-seed 30s noise), so we do NOT
# change the default off an arbitrary tie -- we keep it and mark it insensitive.
FLAT_EPS_MCC = 0.005    # avg_MCC spread
FLAT_EPS_LAT = 0.5      # avg_lat_ms spread (ms)

def spread(recs, key):
    vals = [r["metrics"][key] for r in recs if r.get("metrics") and r["metrics"].get(key) is not None]
    return (max(vals) - min(vals)) if vals else 0.0

def pick_best(recs):
    scored = [r for r in recs if score(r) is not None]
    if not scored:
        return None, False
    obj = scored[0]["obj"]
    if obj == "max_mcc":
        sensitive = spread(scored, "avg_MCC") >= FLAT_EPS_MCC
        best = max(scored, key=lambda r: (r["metrics"]["avg_MCC"], -(r["metrics"]["avg_FPR"] or 0)))
    else:
        sensitive = spread(scored, "avg_lat_ms") >= FLAT_EPS_LAT
        best = min(scored, key=lambda r: r["metrics"]["avg_lat_ms"])
    return best, sensitive


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only", default="", help="comma-separated parameter names to run")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    os.makedirs(OUTDIR, exist_ok=True)
    params = PARAMS if not a.only else [p for p in PARAMS if p["name"] in a.only.split(",")]
    jobs = [(p, i, v) for p in params for i, v in enumerate(p["vals"])]
    print(f"{len(params)} parameters, {len(jobs)} points, {SIMT}s each, seed {SEED}, "
          f"{a.workers} workers, full-system(Q6). start {datetime.now():%H:%M:%S}")
    for p in params:
        print(f"  {p['name']:<18} flag=--{p['flag']:<16} attack A{p['attack']} obj={p['obj']} "
              f"vals={p['vals']}")
    if a.dry_run:
        for p, i, v in jobs:
            print(run_point(p, i, v, True)["cmd"])
        return 0

    recs = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(run_point, p, i, v, False): (p["name"], v) for p, i, v in jobs}
        for f in as_completed(futs):
            r = f.result(); recs.append(r)
            m = r.get("metrics") or {}
            print(f"  done {r['param']:<18}={r['value']:<9} rc={r.get('rc')} "
                  f"MCC={m.get('avg_MCC')} FPR={m.get('avg_FPR')} lat={m.get('avg_lat_ms')} "
                  f"({r.get('wall_s')}s)")

    # raw points
    with open(os.path.join(OUTDIR, "raw_points.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["param", "flag", "value", "attack", "pct", "obj", "rc",
                    "avg_MCC", "avg_DR", "avg_FPR", "avg_lat_ms", "avg_UCR", "rows", "tag"])
        for r in sorted(recs, key=lambda x: (x["param"], x["value"])):
            m = r.get("metrics") or {}
            w.writerow([r["param"], r["flag"], r["value"], r["attack"], r["pct"], r["obj"],
                        r.get("rc"), m.get("avg_MCC"), m.get("avg_DR"), m.get("avg_FPR"),
                        m.get("avg_lat_ms"), m.get("avg_UCR"), m.get("_rows"), r["tag"]])

    # optima + summary
    optima, lines = {}, []
    lines.append(f"Full-system sensitivity analysis (Task 8.5) -- {datetime.now():%Y-%m-%d %H:%M}")
    lines.append(f"OFAT, {SIMT}s/point, seed {SEED}, Q6. Metric: MOBIGUARD final-row avg_MCC "
                 "(detection) or avg_lat_ms (overhead).\n")
    for p in params:
        rs = [r for r in recs if r["param"] == p["name"]]
        best, sensitive = pick_best(rs)
        lines.append(f"== {p['name']}  (--{p['flag']}, A{p['attack']} {p['pct']}%, {p['obj']}, "
                     f"default {p['default']})")
        for r in sorted(rs, key=lambda x: x["value"]):
            m = r.get("metrics") or {}
            star = "  <== best" if (best and sensitive and r["tag"] == best["tag"]) else ""
            lines.append(f"   {r['value']:<9}  MCC={m.get('avg_MCC')}  DR={m.get('avg_DR')}  "
                         f"FPR={m.get('avg_FPR')}  lat={m.get('avg_lat_ms')}{star}")
        if not best:
            lines.append("   -> no scoreable point\n"); continue
        bm = best["metrics"]
        if not sensitive:
            optima[p["name"]] = {"flag": p["flag"], "default": p["default"], "best_value": p["default"],
                                 "sensitive": False, "changed": False,
                                 "note": "flat sweep (metric spread below noise floor) -- keep default"}
            lines.append(f"   -> INSENSITIVE at 30s (metric does not move); keep default {p['default']}\n")
        else:
            optima[p["name"]] = {"flag": p["flag"], "default": p["default"], "best_value": best["value"],
                                 "sensitive": True, "avg_MCC": bm["avg_MCC"], "avg_FPR": bm["avg_FPR"],
                                 "avg_lat_ms": bm["avg_lat_ms"], "changed": best["value"] != p["default"]}
            lines.append(f"   -> optimum {best['value']} (was {p['default']}"
                         f"{', CHANGED' if best['value'] != p['default'] else ', unchanged'})\n")
    json.dump(optima, open(os.path.join(OUTDIR, "optima.json"), "w"), indent=2)
    open(os.path.join(OUTDIR, "summary.txt"), "w").write("\n".join(lines))
    print("\n".join(lines))
    print(f"\nwrote {OUTDIR}/ (raw_points.csv, optima.json, summary.txt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
