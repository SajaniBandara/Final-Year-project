"""
run_tcam_sweep.py
Automated sweep runner for MOBIGUARD TCAM detection evaluation.
Run from your ns-3 root directory:
    python3 run_tcam_sweep.py

Produces per-percentage CSVs in results_routing/:
    MOBIGUARD_baseline.csv
    MOBIGUARD_Attack3_20.csv  ...  MOBIGUARD_Attack3_80.csv
    MOBIGUARD_Attack4_20.csv  ...  MOBIGUARD_Attack4_80.csv
"""

import subprocess
import os
import sys
import time
import math

# ── configuration ─────────────────────────────────────────────────────────────
NS3_ROOT    = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(NS3_ROOT, "results_routing")
LOG_DIR     = os.path.join(RESULTS_DIR, "sweep_logs")

# Shared network parameters — must match your simulation setup
BASE_ARGS = (
    "--routing_test=false "
    "--N_Vehicles=200 "
    "--N_RSUs=64 "
    "--N_Controllers=4 "
    "--mobility_scenario=0 "
    "--maxspeed=150 "
    "--use_sumo_mobility=1 "
    "--architecture=3 "
    "--attack_rate_pps=20 "
    "--attack_start_time=10 "
    "--tcam_slowpath_ms=50"
)

# Attack percentages to sweep
PERCENTAGES = [20, 40, 60, 80]

# ── simulation time calculation ───────────────────────────────────────────────
#
# TCAM fills at:  fill_time = TCAM_HW_SIZE / attack_rate_pps
#                           = 256 / 20 = 12.8 s
# Saturation at:  attack_start + fill_time = 10 + 12.8 = 22.8 s
#
# For S3 (Attack 3): need ~15 cycles after saturation to show sustained effect
#   simTime = ceil(22.8) + 15 = 38 → use 60s (round number, clean plots)
#
# For S4 (Attack 4): need slow-path hits to accumulate above lambda_pi_thresh=15
#   Packets route through RSUs at ~1 Hz per flow, 200 vehicles
#   At 40% dp_attack_pct → 80 attacker vehicles each filling their nearest RSU
#   Need at least 15 slow-path events per RSU per second → needs real traffic
#   Use 90s to give enough forwarding time after saturation
#
# Baseline: 30s is enough for stable benign metrics

SIM_TIMES = {
    "baseline": 30,
    "attack3":  60,   # S3 detection + post-saturation latency effect
    "attack4":  90,   # S4 needs slow-path hits to accumulate
}

# ── helpers ───────────────────────────────────────────────────────────────────
def run(label, args, sim_time, log_path):
    cmd = (
        f'./waf --run "scratch/routing {BASE_ARGS} '
        f'--simTime={sim_time} {args}"'
    )
    print(f"\n{'='*60}")
    print(f"  Running: {label}")
    print(f"  simTime: {sim_time}s")
    print(f"  Args:    {args}")
    print(f"  Log:     {log_path}")
    print(f"{'='*60}")

    t0 = time.time()
    with open(log_path, "w") as log:
        result = subprocess.run(
            cmd, shell=True, cwd=NS3_ROOT,
            stdout=log, stderr=subprocess.STDOUT
        )
    elapsed = time.time() - t0

    status = "OK" if result.returncode == 0 else f"FAILED (rc={result.returncode})"
    print(f"  {status}  —  {elapsed:.1f}s wall time")

    if result.returncode != 0:
        print(f"  Last 20 lines of log:")
        with open(log_path) as f:
            lines = f.readlines()
        for l in lines[-20:]:
            print("    " + l.rstrip())
        return False
    return True

def clean(paths):
    for p in paths:
        if os.path.exists(p):
            os.remove(p)
            print(f"  Removed: {p}")

def csv_rows(path):
    """Count data rows (non-comment, non-empty) in a CSV."""
    if not os.path.exists(path):
        return 0
    count = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                count += 1
    return count

# ── setup ─────────────────────────────────────────────────────────────────────
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(LOG_DIR,     exist_ok=True)

timestamp = time.strftime("%Y%m%d_%H%M%S")

print("\nMOBIGUARD TCAM sweep runner")
print(f"NS3 root:    {NS3_ROOT}")
print(f"Results dir: {RESULTS_DIR}")
print(f"Log dir:     {LOG_DIR}")
print(f"Percentages: {PERCENTAGES}")
print(f"Sim times:   baseline={SIM_TIMES['baseline']}s  "
      f"attack3={SIM_TIMES['attack3']}s  "
      f"attack4={SIM_TIMES['attack4']}s")

# ── build first ───────────────────────────────────────────────────────────────
print("\n── waf build ──")
build_result = subprocess.run(
    "./waf build", shell=True, cwd=NS3_ROOT,
    capture_output=True, text=True
)
if build_result.returncode != 0:
    print("BUILD FAILED — aborting sweep")
    print(build_result.stderr[-2000:])
    sys.exit(1)
print("  Build OK")

# ── run definitions ───────────────────────────────────────────────────────────
runs = []

# 1. baseline
runs.append(dict(
    label      = "baseline",
    args       = "--active_attack_variant=-1 --attack_percentage=0",
    sim_time   = SIM_TIMES["baseline"],
    out_csv    = os.path.join(RESULTS_DIR, "MOBIGUARD_baseline.csv"),
    log        = os.path.join(LOG_DIR, f"{timestamp}_baseline.log"),
))

# 2. Attack 3 (CP TCAM) at each percentage
for pct in PERCENTAGES:
    runs.append(dict(
        label    = f"Attack3_{pct}pct",
        args     = (
            f"--active_attack_variant=2 "
            f"--attack_percentage={pct}"
        ),
        sim_time = SIM_TIMES["attack3"],
        out_csv  = os.path.join(RESULTS_DIR, f"MOBIGUARD_Attack3_{pct}.csv"),
        log      = os.path.join(LOG_DIR, f"{timestamp}_attack3_{pct}.log"),
    ))

# 3. Attack 4 (DP TCAM) at each percentage
for pct in PERCENTAGES:
    runs.append(dict(
        label    = f"Attack4_{pct}pct",
        args     = (
            f"--active_attack_variant=3 "
            f"--attack_percentage={pct}"
        ),
        sim_time = SIM_TIMES["attack4"],
        out_csv  = os.path.join(RESULTS_DIR, f"MOBIGUARD_Attack4_{pct}.csv"),
        log      = os.path.join(LOG_DIR, f"{timestamp}_attack4_{pct}.log"),
    ))

total = len(runs)
print(f"\nTotal runs: {total}  "
      f"({1} baseline + {len(PERCENTAGES)} Attack3 + {len(PERCENTAGES)} Attack4)")

# ── clean stale output CSVs ───────────────────────────────────────────────────
print("\n── cleaning stale output files ──")
clean([r["out_csv"] for r in runs])

# ── execute runs ──────────────────────────────────────────────────────────────
results = []
sweep_start = time.time()

for i, r in enumerate(runs, 1):
    print(f"\n[{i}/{total}]", end="")
    ok = run(r["label"], r["args"], r["sim_time"], r["log"])
    rows = csv_rows(r["out_csv"])
    results.append((r["label"], ok, rows, r["out_csv"]))

# ── summary ───────────────────────────────────────────────────────────────────
total_time = time.time() - sweep_start
print(f"\n{'='*60}")
print(f"SWEEP COMPLETE  —  {total_time/60:.1f} min total")
print(f"{'='*60}")
print(f"{'Label':<22} {'Status':<8} {'Rows':<6} CSV")
print(f"{'-'*22} {'-'*8} {'-'*6} {'-'*35}")
for label, ok, rows, csv_path in results:
    status = "OK" if ok else "FAIL"
    fname  = os.path.basename(csv_path)
    flag   = "" if rows > 0 else "  ← NO DATA"
    print(f"{label:<22} {status:<8} {rows:<6} {fname}{flag}")

# warn if any file has no data rows
no_data = [(l, p) for l, ok, rows, p in results if rows == 0]
if no_data:
    print(f"\nWARNING: {len(no_data)} file(s) have no data rows:")
    for l, p in no_data:
        print(f"  {l}: {p}")
    print("  Check the log files in:", LOG_DIR)
else:
    print(f"\nAll {total} output files have data. Ready to plot:")
    print("  python3 plot_tcam_detection.py")
