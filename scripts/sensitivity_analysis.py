#!/usr/bin/env python3
"""
Full-system sensitivity analysis (Task 8.5), 2026-09-14 (v2: 60 s, multi-metric,
full knob set).

Fills the paper's promised-but-unwritten parameter sensitivity analysis. The
settings table (main.tex Simulation settings) specifies every tunable "swept
independently, selected for best X on the validation split"; the Ablation Study
defers to it ("parameter sensitivity is addressed separately"). This produces the
data for that section.

Method: one-factor-at-a-time (OFAT). Each knob is swept over its full range in
equal steps with EVERY OTHER knob at its compiled default. 60 s per run, single
seed (30 s EWMA/warm-up + 30 s scored), full-system (Q6).

Metrics per point (from the MOBIGUARD final row -- available at 60 s):
  detection : avg_MCC, avg_DR, avg_FPR            (M1)
  mitigation: avg_mit_ms, lmit_prevention_rate    (M4)
  attack    : avg_TVR (M2), avg_UCR (M3)
  latency   : avg_lat_ms (M6, L_e2e)
  overhead  : o_crypto_bytes_pkt (M7 security bytes/pkt),
              t_consensus_ms_avg, t_batch_ms_avg, t_stark_ms_avg (M7 timing)
  control   : ctrl_failover_max_ms (M5)
  crypto    : sig_valid_rate ; witness: WAP_recall

Selection criterion is per knob (paper's stated objective), applied to the
collected metrics -- NOT a uniform MCC ranking. Flat sweeps keep their default.

Knobs NOT swept in-sim (flagged, not run): gamma (offline Krum -- needs
retraining), block throughput (modelled cap, no tunable), T_fwd (fixed = Delta_max).
"block interval" == T_SYNC_INTERVAL in the code (same anchor cadence), swept as t_sync.

Usage: python3 scripts/sensitivity_analysis.py [--workers N] [--only a,b] [--dry-run]
Outputs: docs/sensitivity_2026-09-14/{raw_points.csv, optima.json, summary.txt}
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
SEED, SIMT = 1, 60

Q6 = ("--g_disable_s1_s2=0 --g_disable_s3_s4=0 --g_disable_s5_s6=0 --g_disable_s7_s8=0 "
      "--g_disable_ranom=0 --enable_lstm_inference=1 --enable_witness_mechanism=1 "
      "--disable_crypto=0 --g_disable_btmm_trust=0 --enable_quarantine_enforcement=1")
BASE = (f"--N_RSUs=64 --N_Vehicles=200 --N_Controllers=4 --architecture=3 --maxspeed=150 "
        f"--mobility_scenario=0 --use_sumo_mobility=1 --routing_test=false --sim_run=1 "
        f"--simTime={SIMT} --sim_seed={SEED} --enable_detector_windows=1 --enable_lstm_cls=1 "
        f"--training=0")

# MOBIGUARD final-row 0-indexed columns (verified against the current header).
COL = {"avg_MCC": 6, "avg_DR": 8, "avg_FPR": 10, "avg_lat_ms": 4, "avg_mit_ms": 12,
       "avg_TVR": 18, "avg_UCR": 20, "sig_valid_rate": 21, "ctrl_failover_max_ms": 33,
       "o_crypto_bytes_pkt": 36, "t_batch_ms_avg": 37, "t_consensus_ms_avg": 39,
       "t_stark_ms_avg": 40, "WAP_recall": 45, "lmit_prevention_rate": 54}
# metrics printed in the per-knob table (the paper/Shageeth column family)
SHOW = ["avg_MCC", "avg_DR", "avg_FPR", "avg_lat_ms", "t_consensus_ms_avg",
        "o_crypto_bytes_pkt", "ctrl_failover_max_ms"]


def frange(lo, hi, step):
    n = round((hi - lo) / step)
    return [round(lo + i * step, 8) for i in range(n + 1)]


def irange(lo, hi, step):
    return list(range(lo, hi + 1, step))


def pct_range(default, pcts=(-30, -20, -10, 0, 10, 20, 30)):
    """Robustness sweep: default scaled by +/-{10,20,30}% (paper's coefficient sweep)."""
    return [round(default * (1 + p / 100.0), 10) for p in pcts]


# Selection objective per knob (paper's stated criterion), applied to metrics:
#   max_mcc            : highest avg_MCC (tie: lower avg_FPR)
#   mcc_fpr1           : highest avg_MCC among points with avg_FPR <= 1% (k, U_thresh)
#   min_fpr_hi_dr      : Delta_r/Delta_p -- min false-quarantine (avg_FPR) at full DR
#   min_consensus      : overhead knobs -- lowest t_consensus_ms_avg
#   min_overhead_bytes : lowest o_crypto_bytes_pkt
PARAMS = [
    # S1 timing (A1)
    {"name": "s1_k",             "flag": "s1_k",             "vals": irange(1, 3, 1),          "attack": 1, "pct": 60, "obj": "mcc_fpr1",    "default": 1.0,      "int": True},
    {"name": "s1_beta",          "flag": "s1_beta",          "vals": frange(0.70, 0.95, 0.05), "attack": 1, "pct": 60, "obj": "max_mcc",     "default": 0.95},
    {"name": "s1_delta0",        "flag": "s1_delta0",        "vals": pct_range(0.00447305),    "attack": 1, "pct": 60, "obj": "max_mcc",     "default": 0.00447305, "robust": True},
    {"name": "s1_alpha_rho",     "flag": "s1_alpha_rho",     "vals": pct_range(0.00011315),    "attack": 1, "pct": 60, "obj": "max_mcc",     "default": 0.00011315, "robust": True},
    {"name": "s1_alpha_v",       "flag": "s1_alpha_v",       "vals": pct_range(-0.00150238),   "attack": 1, "pct": 60, "obj": "max_mcc",     "default": -0.00150238, "robust": True},
    # trust / enforcement (A2)
    {"name": "trust_t_min",      "flag": "trust_t_min",      "vals": frange(0.30, 0.70, 0.10), "attack": 2, "pct": 60, "obj": "max_mcc",     "default": 0.70},
    {"name": "trust_delta_p",    "flag": "trust_delta_p",    "vals": frange(0.05, 0.30, 0.05), "attack": 2, "pct": 60, "obj": "min_fpr_hi_dr", "default": 0.30},
    {"name": "trust_delta_r",    "flag": "trust_delta_r",    "vals": frange(0.02, 0.10, 0.02), "attack": 2, "pct": 60, "obj": "min_fpr_hi_dr", "default": 0.04},
    {"name": "T_hold",           "flag": "T_hold",           "vals": frange(0.01, 0.05, 0.01), "attack": 2, "pct": 60, "obj": "max_mcc",     "default": 0.01},
    # controller trust (A1)
    {"name": "trust_t_min_ctrl", "flag": "trust_t_min_ctrl", "vals": frange(0.30, 0.70, 0.10), "attack": 1, "pct": 60, "obj": "max_mcc",     "default": 0.50},
    {"name": "trust_delta_p_ctrl","flag": "trust_delta_p_ctrl","vals": frange(0.05, 0.30, 0.05),"attack": 1, "pct": 60, "obj": "max_mcc",    "default": 0.10},
    {"name": "trust_delta_r_ctrl","flag": "trust_delta_r_ctrl","vals": frange(0.02, 0.10, 0.02),"attack": 1, "pct": 60, "obj": "max_mcc",    "default": 0.05},
    # TCAM (A4, S4-detected)
    {"name": "tcam_util_thresh", "flag": "tcam_util_thresh", "vals": frange(0.20, 0.80, 0.10), "attack": 4, "pct": 60, "obj": "mcc_fpr1",    "default": 0.20},
    # witness (A7)
    {"name": "witness_window",   "flag": "witness_window",   "vals": frange(5, 15, 2),         "attack": 7, "pct": 60, "obj": "max_mcc",     "default": 9.0},
    {"name": "witness_f",        "flag": "witness_f",        "vals": irange(1, 3, 1),          "attack": 7, "pct": 60, "obj": "max_mcc",     "default": 1, "int": True},
    # crypto / consensus overhead (A1)
    {"name": "t_sync",           "flag": "t_sync",           "vals": frange(0.5, 2.0, 0.5),    "attack": 1, "pct": 60, "obj": "min_consensus", "default": 1.0},
    {"name": "batch_size",       "flag": "batch_size",       "vals": irange(10, 20, 2),        "attack": 1, "pct": 60, "obj": "min_consensus", "default": 15, "int": True},
]


def mobiguard_path(attack, pct, tag):
    suffix = "_d80ms" if attack in (1, 2) else ""
    return os.path.join(RESULTS, f"MOBIGUARD_Attack{attack}_{pct}{suffix}_seed{SEED}_{tag}.csv")


def build_cmd(p, val, tag):
    parts = [BASE, Q6, f"--attack_number={p['attack']}", f"--attack_percentage={p['pct']}"]
    if p["attack"] in (1, 2):
        parts.append("--attack_delay_ms=80 --attack_delay_pseudo_random=0")
    v = int(val) if p.get("int") else val
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
                          stderr=subprocess.DEVNULL, text=True, timeout=900)
    rec["rc"] = proc.returncode
    rec["wall_s"] = round((datetime.now() - t0).total_seconds(), 1)
    rec["metrics"] = parse_metrics(mobiguard_path(p["attack"], p["pct"], tag))
    return rec


def m(r, k):
    return (r.get("metrics") or {}).get(k)


def pick_best(recs):
    """Return (best_rec, sensitive) using the knob's paper criterion."""
    ok = [r for r in recs if m(r, "avg_MCC") is not None]
    if not ok:
        return None, False
    obj = ok[0]["obj"]
    prim = {"min_consensus": "t_consensus_ms_avg", "min_overhead_bytes": "o_crypto_bytes_pkt"}.get(obj, "avg_MCC")
    vals = [m(r, prim) for r in ok if m(r, prim) is not None]
    sensitive = (max(vals) - min(vals)) >= (0.5 if prim != "avg_MCC" else 0.005) if vals else False
    if obj == "mcc_fpr1":
        elig = [r for r in ok if (m(r, "avg_FPR") or 1e9) <= 1.0] or ok
        best = max(elig, key=lambda r: m(r, "avg_MCC"))
    elif obj == "min_fpr_hi_dr":
        dr = max(m(r, "avg_DR") or 0 for r in ok)
        elig = [r for r in ok if (m(r, "avg_DR") or 0) >= dr - 1e-6] or ok
        best = min(elig, key=lambda r: (m(r, "avg_FPR") if m(r, "avg_FPR") is not None else 1e9))
    elif obj == "min_consensus":
        best = min(ok, key=lambda r: (m(r, "t_consensus_ms_avg") if m(r, "t_consensus_ms_avg") is not None else 1e9))
    elif obj == "min_overhead_bytes":
        best = min(ok, key=lambda r: (m(r, "o_crypto_bytes_pkt") if m(r, "o_crypto_bytes_pkt") is not None else 1e9))
    else:  # max_mcc
        best = max(ok, key=lambda r: (m(r, "avg_MCC"), -(m(r, "avg_FPR") or 0)))
    return best, sensitive


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only", default="")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    os.makedirs(OUTDIR, exist_ok=True)
    params = PARAMS if not a.only else [p for p in PARAMS if p["name"] in a.only.split(",")]
    jobs = [(p, i, v) for p in params for i, v in enumerate(p["vals"])]
    print(f"{len(params)} knobs, {len(jobs)} points, {SIMT}s, seed {SEED}, {a.workers} workers, "
          f"Q6. start {datetime.now():%H:%M:%S}")
    if a.dry_run:
        for p, i, v in jobs[:3] + jobs[-3:]:
            print(run_point(p, i, v, True)["cmd"])
        return 0

    recs = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(run_point, p, i, v, False) for p, i, v in jobs]
        for f in as_completed(futs):
            r = f.result(); recs.append(r)
            print(f"  {r['param']:<20}={r['value']:<12} rc={r.get('rc')} MCC={m(r,'avg_MCC')} "
                  f"FPR={m(r,'avg_FPR')} cons_ms={m(r,'t_consensus_ms_avg')} bytes={m(r,'o_crypto_bytes_pkt')} "
                  f"({r.get('wall_s')}s)")

    with open(os.path.join(OUTDIR, "raw_points.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        cols = ["param", "flag", "value", "attack", "obj", "rc", "wall_s"] + list(COL.keys())
        w.writerow(cols)
        for r in sorted(recs, key=lambda x: (x["param"], x["value"])):
            w.writerow([r["param"], r["flag"], r["value"], r["attack"], r["obj"], r.get("rc"),
                        r.get("wall_s")] + [m(r, k) for k in COL])

    optima, lines = {}, []
    lines.append(f"Full-system sensitivity analysis (Task 8.5) -- {datetime.now():%Y-%m-%d %H:%M}")
    lines.append(f"OFAT, {SIMT}s/point (30s warm-up + 30s scored), seed {SEED}, Q6. Multi-metric.\n")
    lines.append("cols: MCC | DR | FPR | L_e2e(ms) | consensus(ms) | crypto(B/pkt) | failover(ms)\n")
    for p in params:
        rs = [r for r in recs if r["param"] == p["name"]]
        best, sensitive = pick_best(rs)
        lines.append(f"== {p['name']}  (--{p['flag']}, A{p['attack']} {p['pct']}%, obj={p['obj']}, default {p['default']})")
        for r in sorted(rs, key=lambda x: x["value"]):
            star = "  <==" if (best and sensitive and r["tag"] == best["tag"]) else ""
            lines.append("   {:<12} {} {} {} {} {} {} {}{}".format(
                r["value"], *[m(r, k) for k in SHOW], star))
        if not best:
            lines.append("   -> no scoreable point\n"); continue
        if not sensitive:
            optima[p["name"]] = {"flag": p["flag"], "default": p["default"], "best_value": p["default"],
                                 "sensitive": False, "changed": False, "note": "flat -- keep default"}
            lines.append(f"   -> INSENSITIVE (metric flat); keep default {p['default']}\n")
        else:
            optima[p["name"]] = {"flag": p["flag"], "default": p["default"], "best_value": best["value"],
                                 "sensitive": True, "changed": best["value"] != p["default"],
                                 "metrics": {k: m(best, k) for k in SHOW}}
            lines.append(f"   -> optimum {best['value']} (was {p['default']}"
                         f"{', CHANGED' if best['value'] != p['default'] else ', unchanged'})\n")
    json.dump(optima, open(os.path.join(OUTDIR, "optima.json"), "w"), indent=2)
    open(os.path.join(OUTDIR, "summary.txt"), "w").write("\n".join(lines))
    print("\n".join(lines[:4]))
    print(f"wrote {OUTDIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
