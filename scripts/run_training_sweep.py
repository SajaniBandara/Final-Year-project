#!/usr/bin/env python3
"""
run_training_sweep.py — Launch all MOBIGUARD LSTM training data collection runs.

Covers all 8 attack variants × 6 attack percentages × N seeds, plus benign
(attack_number=0) × N seeds, with --training=1 so lstm_logger.h writes CSVs.

Output CSVs:
  results_routing/lstm_training/RSU_{r}/Attack{v}_{pct}[_d{X}ms]_seed{s}.csv

Usage:
  # Full sweep (all 8 attacks, 3 seeds, workers=10):
  python3 scripts/run_training_sweep.py

  # Resume after partial completion (skips runs whose CSVs are already full):
  python3 scripts/run_training_sweep.py --resume

  # Limit parallel jobs (safe for RAM-constrained machines):
  python3 scripts/run_training_sweep.py --workers 5

  # Run only specific attacks:
  python3 scripts/run_training_sweep.py --attacks 1 3 4

  # Run only priority attacks (1, 3, 4 — not yet collected):
  python3 scripts/run_training_sweep.py --priority

  # Run with fewer seeds:
  python3 scripts/run_training_sweep.py --seeds 1 2 3

  # Shorter sim for testing (use 300 for thesis):
  python3 scripts/run_training_sweep.py --sim-time 300

  # Sync files to NS-3 scratch and rebuild first:
  python3 scripts/run_training_sweep.py --build --priority
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
# Paths — mirror run_std_attacks.py conventions
# ---------------------------------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent.parent
NS3_DIR     = Path.home() / "ns3_g13_apsari/ns-allinone-3.35/ns-3.35"
SCRATCH_DIR = NS3_DIR / "scratch"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = PROJECT_DIR / "logs"

# ---------------------------------------------------------------------------
# Sweep parameters
# ---------------------------------------------------------------------------
ALL_ATTACKS      = [1, 2, 3, 4, 5, 6, 7, 8]
PRIORITY_ATTACKS = [1, 3, 4]   # zero data collected so far
PERCENTAGES      = [0, 20, 40, 60, 80, 100]
DEFAULT_SEEDS    = [1, 2, 3]   # 3 seeds sufficient for FYP (mean ± std)

FIXED_PARAMS = {
    "routing_test":      "false",
    "N_Vehicles":        200,
    "N_RSUs":            64,
    "N_Controllers":     4,
    "mobility_scenario": 0,
    "maxspeed":          150,
    "use_sumo_mobility": 1,
    "architecture":      3,
    "training":          1,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sync_files() -> None:
    print("── Syncing project files to NS-3 scratch ──")
    routing_dir = SCRATCH_DIR / "routing"
    routing_dir.mkdir(parents=True, exist_ok=True)
    stale = SCRATCH_DIR / "routing.cc"
    if stale.exists():
        stale.unlink()
        print(f"  removed stale scratch/routing.cc")
    for src in sorted((PROJECT_DIR / "scratch").iterdir()):
        if not src.is_file():
            continue
        if src.name == "routing.cc" or src.suffix == ".h":
            dest = routing_dir / src.name
        else:
            dest = SCRATCH_DIR / src.name

        # Avoid SameFileError for symlinked/hardlinked setups where the ns-3
        # scratch file already IS the project scratch file (same inode).
        # Mirrors the guard in run_std_attacks.py's sync_files().
        if dest.exists() and os.path.samefile(src, dest):
            print(f"  already synced  {src.name}")
            continue

        shutil.copy2(src, dest)
        print(f"  copied  {src.name}  →  {dest.relative_to(SCRATCH_DIR.parent)}")


def build_simulation() -> bool:
    print("\n── Building NS-3 simulation ──")
    result = subprocess.run(["./waf", "build"], cwd=NS3_DIR, text=True)
    if result.returncode != 0:
        print("ERROR: Build failed.")
        return False
    print("Build successful.\n")
    return True


def lstm_csv_path(attack: int, pct: int, seed: int) -> Path | None:
    """Find the RSU_0 CSV for this run, if it exists. Globs rather than an
    exact match since attacks 1/2 carry an extra _d<X>ms segment before
    _seed<S> that other attacks/benign don't."""
    matches = sorted((RESULTS_DIR / "lstm_training" / "RSU_0").glob(
        f"Attack{attack}_{pct}*_seed{seed}.csv"))
    return matches[0] if matches else None


def csv_is_complete(attack: int, pct: int, seed: int, sim_time: int) -> bool:
    """Return True if the RSU_0 CSV for this run already has enough rows."""
    path = lstm_csv_path(attack, pct, seed)
    if path is None:
        return False
    try:
        lines = path.read_text().splitlines()
        # header + sim_time rows (1 Hz); allow 95% to handle short runs
        return len(lines) >= int(sim_time * 0.95)
    except OSError:
        return False


def build_waf_command(attack: int, pct: int, seed: int, sim_time: int) -> list[str]:
    params = dict(FIXED_PARAMS)
    params["simTime"]           = sim_time
    params["attack_percentage"] = pct
    params["sim_seed"]          = seed
    if attack > 0:
        params["attack_number"] = attack
    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    return ["./waf", "--run", f"scratch/routing/routing {param_str}"]


def run_one(attack: int, pct: int, seed: int,
            sim_time: int, log_path: Path) -> dict:
    label = f"A{attack}_pct{pct}_seed{seed}"
    cmd   = build_waf_command(attack, pct, seed, sim_time)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now()
    print(f"  [{label}] started  {start.strftime('%H:%M:%S')}  →  {log_path.name}")

    with open(log_path, "w") as logf:
        logf.write(f"# Command: {' '.join(cmd)}\n")
        logf.write(f"# Started: {start.isoformat()}\n\n")
        logf.flush()
        proc = subprocess.run(
            cmd, cwd=NS3_DIR,
            stdout=logf, stderr=subprocess.STDOUT, text=True,
        )

    elapsed = (datetime.now() - start).total_seconds()
    ok = proc.returncode == 0
    print(f"  [{label}] {'OK' if ok else 'FAILED':<6}  {elapsed/3600:.2f}h  →  {log_path.name}")
    return {"label": label, "attack": attack, "pct": pct, "seed": seed,
            "returncode": proc.returncode, "elapsed_s": elapsed, "ok": ok}


def check_outputs(runs: list[dict], sim_time: int) -> None:
    print("\n── Output verification ──")
    missing = []
    for r in runs:
        path = lstm_csv_path(r["attack"], r["pct"], r["seed"])
        ok = path is not None and len(path.read_text().splitlines()) >= int(sim_time * 0.95)
        mark = "✓" if ok else "✗ MISSING"
        name = path.name if path else f"Attack{r['attack']}_{r['pct']}_seed{r['seed']}.csv"
        print(f"  {mark:<12} RSU_0/{name}")
        if not ok:
            missing.append(r["label"])
    if missing:
        print(f"\n  {len(missing)} run(s) missing output — re-run or check logs/")
    else:
        print(f"\n  All {len(runs)} runs produced output in RSU_0/ ✓")
        print(f"  Full check: ls {RESULTS_DIR}/lstm_training/RSU_0/ | wc -l")
        print(f"  Expected: {len(runs)} files")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch all MOBIGUARD LSTM training data collection runs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--build",    action="store_true",
                        help="Sync files to NS-3 scratch and ./waf build first.")
    parser.add_argument("--resume",   action="store_true",
                        help="Skip runs whose RSU_0 CSV already has enough rows.")
    parser.add_argument("--priority", action="store_true",
                        help=f"Run only priority attacks {PRIORITY_ATTACKS} (no data yet).")
    parser.add_argument("--attacks",  type=int, nargs="+",
                        metavar="N", default=None,
                        help="Specific attack numbers to run (1–8). Overrides --priority.")
    parser.add_argument("--seeds",    type=int, nargs="+",
                        default=DEFAULT_SEEDS, metavar="S",
                        help=f"Seeds to use (default: {DEFAULT_SEEDS}).")
    parser.add_argument("--percentage", type=int, choices=PERCENTAGES,
                        default=None, metavar="{0,20,40,60,80,100}",
                        help="Run only this percentage (default: all six).")
    parser.add_argument("--sim-time", type=int, default=300,
                        help="Simulation duration in seconds (default: 300).")
    parser.add_argument("--workers",  type=int, default=10,
                        help="Max parallel simulation processes (default: 10).")
    args = parser.parse_args()

    if args.build:
        sync_files()
        if not build_simulation():
            sys.exit(1)

    # Resolve scope
    if args.attacks:
        scope_attacks = args.attacks
    elif args.priority:
        scope_attacks = PRIORITY_ATTACKS
    else:
        scope_attacks = ALL_ATTACKS

    scope_pcts   = [args.percentage] if args.percentage is not None else PERCENTAGES
    scope_seeds  = args.seeds

    # Build run list
    runs = [
        {"attack": a, "pct": p, "seed": s,
         "log": LOGS_DIR / f"A{a}_pct{p}_seed{s}_training.log"}
        for a in scope_attacks
        for p in scope_pcts
        for s in scope_seeds
    ]

    # Resume: skip completed runs
    if args.resume:
        skipped = [r for r in runs if csv_is_complete(r["attack"], r["pct"],
                                                       r["seed"], args.sim_time)]
        runs    = [r for r in runs if not csv_is_complete(r["attack"], r["pct"],
                                                           r["seed"], args.sim_time)]
        if skipped:
            print(f"── Resuming: skipping {len(skipped)} already-complete runs ──")

    total   = len(runs)
    workers = min(args.workers, total)

    print(f"\n── Launching {total} run(s)  "
          f"[attacks={scope_attacks}  pcts={scope_pcts}  seeds={scope_seeds}  "
          f"simTime={args.sim_time}s  workers={workers}] ──")
    print(f"   Estimated wall time: ~{total / workers:.0f} × per-run time\n")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    passed, failed = [], []
    wall_start = datetime.now()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_one, r["attack"], r["pct"], r["seed"],
                        args.sim_time, r["log"]): r
            for r in runs
        }
        for fut in as_completed(futures):
            result = fut.result()
            (passed if result["ok"] else failed).append(result)

    wall_elapsed = (datetime.now() - wall_start).total_seconds()
    print(f"\n── Summary  (wall time: {wall_elapsed/3600:.2f}h) ──")
    print(f"  Passed : {len(passed)}/{total}")
    if failed:
        print(f"  Failed : {len(failed)}")
        for r in failed:
            print(f"    {r['label']}  (exit {r['returncode']})  log → logs/{r['label']}_training.log")

    check_outputs(runs, args.sim_time)
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
