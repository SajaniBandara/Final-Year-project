#!/usr/bin/env python3
"""
run_hf_attacks.py — Parallel launcher for Hidden Forwarding (HF) attack sweeps.

Runs all four HF attack variants across all 6 attack percentages {0,20,40,60,80,100}
as concurrent subprocesses.

Attack mapping:
  attack_number=5  →  active_attack_variant=4  →  Attack 5 (HF CP)
  attack_number=6  →  active_attack_variant=5  →  Attack 6 (HF DP)
  attack_number=7  →  active_attack_variant=6  →  Attack 7 (HF CP variant)
  attack_number=8  →  active_attack_variant=7  →  Attack 8 (HF DP variant)

Result CSVs written by the simulation:
  results_routing/MOBIGUARD_Attack<N>_<pct>.csv  — MOBIGUARD detector
  results_routing/FADE_Attack<N>_<pct>.csv        — eFADE detector (primary for HF)

Per-run files in the NS-3 working directory (tagged, no collision):
  fade_results_V<v>_pct<p>.csv   — per-flow FADE detection detail
  fade_metrics_V<v>_pct<p>.csv   — per-run FADE summary row

Per-run logs (stdout + stderr):
  logs/A<N>_pct<P>_seed<S>.log

Usage examples:
  # Run all 24 combinations (4 attacks × 6 percentages) in parallel:
  python3 scripts/run_hf_attacks.py

  # Sync headers + rebuild first, then run:
  python3 scripts/run_hf_attacks.py --build

  # Run only Attack 5 at 40%:
  python3 scripts/run_hf_attacks.py --attack 5 --percentage 40

  # Limit to 6 parallel jobs:
  python3 scripts/run_hf_attacks.py --workers 6

  # Clear old result CSVs before starting:
  python3 scripts/run_hf_attacks.py --clean
"""

import argparse
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
PROJECT_DIR = Path(__file__).resolve().parent.parent
NS3_DIR     = Path.home() / "ns-allinone-3.35/ns-3.35"
SCRATCH_DIR = NS3_DIR / "scratch"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = PROJECT_DIR / "logs"

# ---------------------------------------------------------------------------
# Simulation parameters
# ---------------------------------------------------------------------------
ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

ATTACKS = [
    {"attack_number": 5, "label": "Attack5_HF_CP"},
    {"attack_number": 6, "label": "Attack6_HF_DP"},
    {"attack_number": 7, "label": "Attack7_HF_CP_v2"},
    {"attack_number": 8, "label": "Attack8_HF_DP_v2"},
]

FIXED_PARAMS = {
    "routing_test":      "false",
    "N_Vehicles":        200,
    "N_RSUs":            64,
    "N_Controllers":     4,
    "mobility_scenario": 0,
    "maxspeed":          150,
    "use_sumo_mobility": 1,
    "architecture":      3,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sync_files() -> None:
    print("── Syncing project files to NS-3 scratch ──")
    routing_dir = SCRATCH_DIR / "routing"
    routing_dir.mkdir(parents=True, exist_ok=True)

    # A stale scratch/routing.cc (from before routing.cc was moved into
    # scratch/routing/) creates a second program also named 'routing', which
    # collides with the subdir target and breaks the build. Remove it.
    stale = SCRATCH_DIR / "routing.cc"
    if stale.exists():
        stale.unlink()
        print(f"  removed stale  {stale.relative_to(SCRATCH_DIR.parent)}")

    for src in sorted((PROJECT_DIR / "scratch").iterdir()):
        if not src.is_file():
            continue
        if src.name == "routing.cc" or src.suffix == ".h":
            # routing.cc builds as the 'routing' program from scratch/routing/.
            # Its #include "..." project headers must sit in the same directory,
            # because waf only adds the program's own dir to the include path.
            dest = routing_dir / src.name
        else:
            # .py helpers are loaded by routing.cc via hardcoded scratch/ paths.
            dest = SCRATCH_DIR / src.name
        
        # Avoid SameFileError for symlinked setups
        if dest.exists() and os.path.samefile(src, dest):
            print(f"  already synced  {src.name}")
            continue
            
        shutil.copy2(src, dest)
        print(f"  copied  {src.name}  →  {dest.relative_to(SCRATCH_DIR.parent)}")


def build_simulation() -> bool:
    print("\n── Building NS-3 simulation ──")
    result = subprocess.run(["./waf", "build"], cwd=NS3_DIR, text=True)
    if result.returncode != 0:
        print("ERROR: Build failed. Fix compilation errors before running.")
        return False
    print("Build successful.\n")
    return True


def clean_results(attack: int | None, percentage: int | None) -> None:
    attacks = [attack] if attack else [a["attack_number"] for a in ATTACKS]
    percs   = [percentage] if percentage is not None else ATTACK_PERCENTAGES

    patterns = []
    for a in attacks:
        for p in percs:
            patterns.append(RESULTS_DIR / f"MOBIGUARD_Attack{a}_{p}.csv")
            patterns.append(RESULTS_DIR / f"FADE_Attack{a}_{p}.csv")

    removed = sum(1 for f in patterns if f.exists() and (f.unlink() or True))
    if removed:
        print(f"── Removed {removed} old result file(s) ──\n")


def build_waf_command(attack_number: int, attack_percentage: int,
                      sim_time: int, seed: int, sim_run: int) -> list[str]:
    params = dict(FIXED_PARAMS)
    params["simTime"]           = sim_time
    params["attack_number"]     = attack_number
    params["attack_percentage"] = attack_percentage
    params["sim_seed"]          = seed
    params["sim_run"]           = sim_run

    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    # routing.cc lives in scratch/routing/, so waf registers the program as
    # 'scratch/routing/routing' (not 'scratch/routing').
    return ["./waf", "--run", f"scratch/routing/routing {param_str}"]


def run_one(attack_number: int, attack_percentage: int,
            sim_time: int, seed: int, sim_run: int,
            log_path: Path) -> dict:
    label = f"A{attack_number}_pct{attack_percentage}"
    cmd   = build_waf_command(attack_number, attack_percentage, sim_time, seed, sim_run)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now()
    print(f"  [{label}] started  {start.strftime('%H:%M:%S')}  →  {log_path.name}")

    with open(log_path, "w") as logf:
        logf.write(f"# Command: {' '.join(cmd)}\n")
        logf.write(f"# Started: {start.isoformat()}\n\n")
        logf.flush()
        proc = subprocess.run(
            cmd,
            cwd=NS3_DIR,
            stdout=logf,
            stderr=subprocess.STDOUT,
            text=True,
        )

    elapsed = (datetime.now() - start).total_seconds()
    ok      = proc.returncode == 0
    print(f"  [{label}] {'OK' if ok else 'FAILED':<6}  {elapsed:5.0f}s  →  {log_path.name}")

    return {
        "label":             label,
        "attack_number":     attack_number,
        "attack_percentage": attack_percentage,
        "returncode":        proc.returncode,
        "elapsed_s":         elapsed,
        "log":               log_path,
        "ok":                ok,
    }


def check_results(scope_attacks: list[int], scope_percs: list[int]) -> None:
    print("\n── Result files ──")
    all_ok = True
    for a in scope_attacks:
        for p in scope_percs:
            for f in [
                RESULTS_DIR / f"MOBIGUARD_Attack{a}_{p}.csv",
                RESULTS_DIR / f"FADE_Attack{a}_{p}.csv",
            ]:
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
        description="Launch Hidden Forwarding attack simulations in parallel.",
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
        "--attack", type=int, choices=[5, 6, 7, 8], default=None,
        help="Run only this attack number (default: all four 5–8).",
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
        help="Maximum number of parallel simulation processes (default: 12).",
    )
    args = parser.parse_args()

    if args.build:
        sync_files()
        if not build_simulation():
            sys.exit(1)

    scope_attacks = [args.attack] if args.attack else [a["attack_number"] for a in ATTACKS]
    scope_percs   = [args.percentage] if args.percentage is not None else ATTACK_PERCENTAGES

    if args.clean:
        clean_results(args.attack, args.percentage)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    runs = [
        {
            "attack_number":     a,
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
