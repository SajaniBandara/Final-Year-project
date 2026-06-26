#!/usr/bin/env python3
"""
run_std_attacks.py — Parallel launcher for Selective Time Delay attack sweeps.

Runs both attack variants across all 6 attack percentages {0,20,40,60,80,100}
as concurrent subprocesses so every combination finishes in the time of the
longest single run instead of serially.

Result CSVs written by the simulation:
  results_routing/MOBIGUARD_Attack1_<pct>.csv  — Attack 1 (CP), MOBIGUARD S1 detector
  results_routing/MOBIGUARD_Attack2_<pct>.csv  — Attack 2 (DP), MOBIGUARD S2 detector
  results_routing/TAP_Attack2_<pct>.csv        — Attack 2 (DP), TAP baseline detector

Per-run logs (stdout + stderr):
  logs/A<N>_pct<P>_seed<S>.log

Usage examples:
  # Run all 12 combinations (both attacks × 6 percentages) in parallel:
  python3 scripts/run_std_attacks.py

  # Sync headers + rebuild first, then run:
  python3 scripts/run_std_attacks.py --build

  # Run only Attack 1 at 40%:
  python3 scripts/run_std_attacks.py --attack 1 --percentage 40

  # Use a different RNG seed / run index:
  python3 scripts/run_std_attacks.py --seed 2 --sim-run 3

  # Limit to 4 parallel jobs (useful on low-core machines):
  python3 scripts/run_std_attacks.py --workers 4

  # Clear old result CSVs before starting:
  python3 scripts/run_std_attacks.py --clean
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent.parent          # …/Final-Year-project/
NS3_DIR     = Path.home() / "ns-allinone-3.35" / "ns-3.35"
SCRATCH_DIR = NS3_DIR / "scratch"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = PROJECT_DIR / "logs"

# ---------------------------------------------------------------------------
# Simulation parameters — mirrors run_attack2_sweep.sh conventions
# ---------------------------------------------------------------------------
ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

ATTACKS = [
    {"attack_number": 1, "label": "Attack1_CP"},
    {"attack_number": 2, "label": "Attack2_DP"},
]

# Fixed topology / mobility parameters shared across all runs.
# Matches run_attack2_sweep.sh and the thesis simulation table.
FIXED_PARAMS = {
    "routing_test":     "false",
    "N_Vehicles":       200,
    "N_RSUs":           64,
    "N_Controllers":    4,
    "mobility_scenario": 0,
    "maxspeed":         150,
    "use_sumo_mobility": 1,
    "architecture":     3,
}

# Headers to copy from PROJECT_DIR to SCRATCH_DIR before a build.
SYNC_FILES = [
    "routing.cc",
    "attack_declaration.h",
    "attack_variables.h",
    "selective_time_delay.h",
    "tap_detection.h",
    "s1_detection.h",
    "s2_detection.h",
    "hf_attack_helper.h",
    "efade_detection.h",
    "optimization_lifetime.py",
    "tcam_detection.h",
]

# Result CSV patterns expected after all runs complete.
EXPECTED_RESULTS = (
    [f"MOBIGUARD_Attack1_{p}.csv" for p in ATTACK_PERCENTAGES] +
    [f"MOBIGUARD_Attack2_{p}.csv" for p in ATTACK_PERCENTAGES] +
    [f"TAP_Attack2_{p}.csv"       for p in ATTACK_PERCENTAGES]
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sync_files() -> None:
    """Copy the latest project headers and routing.cc into NS-3 scratch."""
    print("── Syncing project files to NS-3 scratch ──")
    for name in SYNC_FILES:
        src = PROJECT_DIR / name
        dst = SCRATCH_DIR / name
        if not src.exists():
            print(f"  WARNING: {src} not found — skipping")
            continue
        shutil.copy2(src, dst)
        print(f"  copied  {name}")


def build_simulation() -> bool:
    """Run ./waf build. Returns True on success."""
    print("\n── Building NS-3 simulation ──")
    result = subprocess.run(
        ["./waf", "build"],
        cwd=NS3_DIR,
        text=True,
    )
    if result.returncode != 0:
        print("ERROR: Build failed. Fix compilation errors before running.")
        return False
    print("Build successful.\n")
    return True


def clean_results(attack: int | None, percentage: int | None) -> None:
    """Remove old result CSVs that match the requested scope."""
    patterns = []
    attacks  = [attack] if attack else [1, 2]
    percs    = [percentage] if percentage is not None else ATTACK_PERCENTAGES

    for a in attacks:
        for p in percs:
            if a == 1:
                patterns.append(RESULTS_DIR / f"MOBIGUARD_Attack1_{p}.csv")
            else:
                patterns.append(RESULTS_DIR / f"MOBIGUARD_Attack2_{p}.csv")
                patterns.append(RESULTS_DIR / f"TAP_Attack2_{p}.csv")

    removed = 0
    for f in patterns:
        if f.exists():
            f.unlink()
            removed += 1
    if removed:
        print(f"── Removed {removed} old result file(s) ──\n")


def build_waf_command(attack_number: int, attack_percentage: int,
                      sim_time: int, seed: int, sim_run: int) -> list[str]:
    """Construct the full ./waf --run command for one simulation run."""
    params = dict(FIXED_PARAMS)
    params["simTime"]          = sim_time
    params["attack_number"]    = attack_number
    params["attack_percentage"] = attack_percentage
    params["sim_seed"]         = seed
    params["sim_run"]          = sim_run

    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    return ["./waf", "--run", f"scratch/routing {param_str}"]


def run_one(attack_number: int, attack_percentage: int,
            sim_time: int, seed: int, sim_run: int,
            log_path: Path) -> dict:
    """
    Execute a single simulation run.
    Returns a result dict with label, returncode, elapsed time, and log path.
    """
    label = f"A{attack_number}_pct{attack_percentage}"
    cmd   = build_waf_command(attack_number, attack_percentage, sim_time, seed, sim_run)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now()
    print(f"  [{label}] started  {start.strftime('%H:%M:%S')}  →  {log_path.name}")

    with open(log_path, "w") as logf:
        logf.write(f"# Command: {' '.join(cmd)}\n")
        logf.write(f"# Started: {start.isoformat()}\n\n")
        proc = subprocess.run(
            cmd,
            cwd=NS3_DIR,
            stdout=logf,
            stderr=subprocess.STDOUT,
            text=True,
        )

    elapsed = (datetime.now() - start).total_seconds()
    ok      = proc.returncode == 0
    status  = "OK" if ok else "FAILED"
    print(f"  [{label}] {status:<6}  {elapsed:5.0f}s  →  {log_path.name}")

    return {
        "label":            label,
        "attack_number":    attack_number,
        "attack_percentage": attack_percentage,
        "returncode":       proc.returncode,
        "elapsed_s":        elapsed,
        "log":              log_path,
        "ok":               ok,
    }


def check_results(scope_attacks: list[int], scope_percs: list[int]) -> None:
    """Print a table showing which expected result CSVs were produced."""
    print("\n── Result files ──")
    all_ok = True
    for a in scope_attacks:
        for p in scope_percs:
            files = []
            if a == 1:
                files = [RESULTS_DIR / f"MOBIGUARD_Attack1_{p}.csv"]
            else:
                files = [
                    RESULTS_DIR / f"MOBIGUARD_Attack2_{p}.csv",
                    RESULTS_DIR / f"TAP_Attack2_{p}.csv",
                ]
            for f in files:
                exists = f.exists() and f.stat().st_size > 0
                mark   = "✓" if exists else "✗ MISSING"
                print(f"  {mark:<10}  {f.name}")
                if not exists:
                    all_ok = False
    if all_ok:
        print("\n  All expected result files present.")
    else:
        print("\n  Some files missing — check the corresponding log in logs/")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch Selective Time Delay attack simulations in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--build", action="store_true",
        help="Sync project headers to scratch and run ./waf build before simulating.",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Delete old result CSVs for the selected scope before running.",
    )
    parser.add_argument(
        "--attack", type=int, choices=[1, 2], default=None,
        help="Run only this attack number (default: both 1 and 2).",
    )
    parser.add_argument(
        "--percentage", type=int, choices=ATTACK_PERCENTAGES, default=None,
        metavar="{0,20,40,60,80,100}",
        help="Run only this attack percentage (default: all six).",
    )
    parser.add_argument(
        "--sim-time", type=int, default=40,
        help="Simulation duration in seconds (default: 40 for quick testing; use 300 for thesis runs).",
    )
    parser.add_argument(
        "--seed", type=int, default=1,
        help="NS-3 RNG seed (default: 1).",
    )
    parser.add_argument(
        "--sim-run", type=int, default=1,
        help="NS-3 RNG run index (default: 1).",
    )
    parser.add_argument(
        "--workers", type=int, default=12,
        help="Maximum number of parallel simulation processes (default: 12 = all at once).",
    )
    args = parser.parse_args()

    # ── Optional sync + build ────────────────────────────────────────────────
    if args.build:
        sync_files()
        if not build_simulation():
            sys.exit(1)

    # ── Resolve scope ────────────────────────────────────────────────────────
    scope_attacks = [args.attack] if args.attack else [a["attack_number"] for a in ATTACKS]
    scope_percs   = [args.percentage] if args.percentage is not None else ATTACK_PERCENTAGES

    if args.clean:
        clean_results(args.attack, args.percentage)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Build run list ───────────────────────────────────────────────────────
    runs = [
        {
            "attack_number":    a,
            "attack_percentage": p,
            "log": LOGS_DIR / f"A{a}_pct{p}_seed{args.seed}.log",
        }
        for a in scope_attacks
        for p in scope_percs
    ]

    total = len(runs)
    print(
        f"\n── Launching {total} run(s)  "
        f"[attacks={scope_attacks}  percentages={scope_percs}  "
        f"simTime={args.sim_time}s  seed={args.seed}  "
        f"workers={min(args.workers, total)}] ──\n"
    )

    # ── Run in parallel ──────────────────────────────────────────────────────
    passed, failed = [], []
    wall_start = datetime.now()

    with ThreadPoolExecutor(max_workers=min(args.workers, total)) as pool:
        futures = {
            pool.submit(
                run_one,
                r["attack_number"],
                r["attack_percentage"],
                args.sim_time,
                args.seed,
                args.sim_run,
                r["log"],
            ): r
            for r in runs
        }
        for fut in as_completed(futures):
            result = fut.result()
            (passed if result["ok"] else failed).append(result)

    wall_elapsed = (datetime.now() - wall_start).total_seconds()

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n── Summary  (wall time: {wall_elapsed:.0f}s) ──")
    print(f"  Passed : {len(passed)}/{total}")
    if failed:
        print(f"  Failed : {len(failed)}")
        for r in failed:
            print(f"    {r['label']}  (returncode={r['returncode']})")
            print(f"      log → {r['log']}")

    check_results(scope_attacks, scope_percs)

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
