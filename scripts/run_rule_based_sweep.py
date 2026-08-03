#!/usr/bin/env python3
"""
run_rule_based_sweep.py — Full rule-based (MOBIGUARD S1-S8) re-collection
after the S1 sigma-cold-start/granularity fix (s1_detection.h, 2026-07-14).

Why this script exists: s1_detection.h's sigma^2 EWMA used to be updated
from the CYCLE-AVERAGED observed delay (once per cycle) while
s1_detect_packet() compared RAW PER-PACKET delays against the resulting
threshold — averaging N packets shrinks variance by ~1/N, so the k*sigma
margin was calibrated ~sqrt(N) too tight for what it was actually tested
against (confirmed: 11,193 S1 triggers / 38 cycles in one smoke test,
FPR 28-50% vs a 1% calibration target). Fixed by updating sigma^2 from
each packet's own raw deviation. This does NOT affect the LSTM pipeline
(delta_t logged to the LSTM training CSVs is unchanged; the LSTM never
reads S1's detection verdict) — only the rule-based MOBIGUARD_Attack*.csv
confusion-matrix files, which is what this script regenerates.

Covers all 8 attacks x 6 percentages x N seeds, NORMAL mode only (full
S1-S8 stack active, no TAP/FADE isolation) -- this is the mode that
writes MOBIGUARD_Attack<N>_<pct>*.csv.

Seed-collision handling: write_security_metrics_csv() has no seed in its
output filename and opens with ios::app, so two seeds of the SAME
(attack, percentage) writing concurrently would interleave into one file
-- the exact contamination bug found and fixed earlier this session.
Each (attack, percentage) pair therefore runs its seeds SEQUENTIALLY in
one worker "lane"; the resulting CSV is renamed to embed the seed
immediately after each run completes, before the next seed in that lane
starts. Different (attack, percentage) lanes run fully in parallel.

Usage:
  # Sync headers + rebuild only, then exit (run again without --build to sweep):
  python3 scripts/run_rule_based_sweep.py --build
  python3 scripts/run_rule_based_sweep.py --seeds 1 2 3 --workers 28 --clean
"""

import argparse
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
NS3_DIR     = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
SCRATCH_DIR = NS3_DIR / "scratch"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = PROJECT_DIR / "logs" / "rule_based_sweep"
BINARY_PATH = NS3_DIR / "build" / "scratch" / "routing" / "routing"

ATTACKS             = list(range(1, 9))
ATTACK_PERCENTAGES  = [0, 20, 40, 60, 80, 100]

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


def sync_files() -> None:
    """Copy project scratch files into ns-3.35/scratch/routing/ (subdirectory form)."""
    print("-- Syncing project files to NS-3 scratch --")
    routing_dir = SCRATCH_DIR / "routing"
    routing_dir.mkdir(parents=True, exist_ok=True)

    # A stale scratch/routing.cc from before the move to the subdirectory
    # creates a second 'routing' program that collides with the subdir target.
    stale = SCRATCH_DIR / "routing.cc"
    if stale.exists():
        stale.unlink()
        print(f"  removed stale  scratch/routing.cc")

    for src in sorted((PROJECT_DIR / "scratch").iterdir()):
        if not src.is_file():
            continue
        if src.name == "routing.cc" or src.suffix == ".h":
            dest = routing_dir / src.name
        else:
            dest = SCRATCH_DIR / src.name

        # Avoid SameFileError for symlinked setups
        if dest.exists() and os.path.samefile(src, dest):
            print(f"  already synced  {src.name}")
            continue

        shutil.copy2(src, dest)
        print(f"  copied  {src.name}  ->  {dest.relative_to(SCRATCH_DIR.parent)}")


def build_simulation() -> bool:
    print("\n-- Building NS-3 simulation --")
    result = subprocess.run(["./waf", "build"], cwd=NS3_DIR, text=True)
    if result.returncode != 0:
        print("ERROR: Build failed.")
        return False
    print("Build successful.\n")
    return True


def result_filename(attack_number: int, pct: int) -> str:
    suffix = "_d80ms" if attack_number in (1, 2) else ""
    return f"MOBIGUARD_Attack{attack_number}_{pct}{suffix}.csv"


def clean_results(attacks: list, percs: list) -> None:
    removed = 0
    for a in attacks:
        for p in percs:
            f = RESULTS_DIR / result_filename(a, p)
            if f.exists():
                f.unlink()
                removed += 1
            # also sweep away any stale per-seed files from a prior partial run
            for stale in RESULTS_DIR.glob(f"MOBIGUARD_Attack{a}_{p}*_seed*.csv"):
                stale.unlink()
                removed += 1
    if removed:
        print(f"-- Removed {removed} old result file(s) --\n")


def build_waf_command(attack_number: int, pct: int, sim_time: int,
                       seed: int, sim_run: int) -> list:
    params = dict(FIXED_PARAMS)
    params["simTime"]           = sim_time
    params["attack_number"]     = attack_number
    params["attack_percentage"] = pct
    params["sim_seed"]          = seed
    params["sim_run"]           = sim_run
    if attack_number in (1, 2):
        # Exact 80ms (filename tags "_d80ms") -- must disable the banded
        # pseudo-random draw (attack_delay_pseudo_random default=true as of
        # the mobility amplification fix, scratch/attack_variables.h) or
        # this sweep silently gets a random 72-88ms delay per packet instead.
        params["attack_delay_ms"] = 80
        params["attack_delay_pseudo_random"] = 0
    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    return ["./waf", "--run-no-build", f"scratch/routing/routing {param_str}"]


def run_lane(attack_number: int, pct: int, seeds: list,
             sim_time: int, sim_run: int) -> dict:
    """Runs all seeds for one (attack, pct) pair SEQUENTIALLY (avoids the
    shared-filename contamination bug), renaming each result immediately."""
    lane_results = []
    for seed in seeds:
        label    = f"A{attack_number}_pct{pct}_seed{seed}"
        log_path = LOGS_DIR / f"{label}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        cmd   = build_waf_command(attack_number, pct, sim_time, seed, sim_run)
        start = datetime.now()
        print(f"  [{label}] started  {start.strftime('%H:%M:%S')}")

        with open(log_path, "w") as logf:
            logf.write(f"# Command: {' '.join(cmd)}\n# Started: {start.isoformat()}\n\n")
            logf.flush()
            proc = subprocess.run(cmd, cwd=NS3_DIR, stdout=logf,
                                   stderr=subprocess.STDOUT, text=True)

        elapsed = (datetime.now() - start).total_seconds()
        ok      = proc.returncode == 0

        # Rename the freshly-written shared-name CSV to embed the seed BEFORE
        # the next seed in this lane starts and reopens the shared filename.
        src  = RESULTS_DIR / result_filename(attack_number, pct)
        dst  = RESULTS_DIR / src.name.replace(".csv", f"_seed{seed}.csv")
        renamed = False
        if src.exists():
            src.rename(dst)
            renamed = True

        print(f"  [{label}] {'OK' if ok else 'FAILED':<6}  {elapsed:5.0f}s"
              f"  {'-> ' + dst.name if renamed else '(NO OUTPUT FILE)'}")
        lane_results.append({"label": label, "ok": ok, "elapsed_s": elapsed,
                             "renamed": renamed})
    return {"attack_number": attack_number, "pct": pct, "runs": lane_results}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Re-collect rule-based MOBIGUARD confusion-matrix data "
                     "(all 8 attacks) after the S1 sigma fix.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--attack", type=int, choices=ATTACKS, default=None)
    parser.add_argument("--percentage", type=int, choices=ATTACK_PERCENTAGES, default=None)
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--sim-time", type=int, default=40)
    parser.add_argument("--sim-run", type=int, default=1)
    parser.add_argument("--workers", type=int, default=28,
                        help="Max concurrent (attack,pct) lanes (default 28).")
    args = parser.parse_args()

    if args.build:
        sync_files()
        if not build_simulation():
            sys.exit(1)
        print("Build complete. Re-run without --build to launch the sweep.")
        sys.exit(0)

    if not BINARY_PATH.exists():
        print(f"ERROR: {BINARY_PATH} not found. Run with --build first.")
        sys.exit(1)

    scope_attacks = [args.attack] if args.attack else ATTACKS
    scope_percs   = [args.percentage] if args.percentage is not None else ATTACK_PERCENTAGES

    if args.clean:
        clean_results(scope_attacks, scope_percs)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    lanes = [(a, p) for a in scope_attacks for p in scope_percs]
    total_runs = len(lanes) * len(args.seeds)
    print(f"\n-- Launching {len(lanes)} lane(s) x {len(args.seeds)} seed(s) "
          f"= {total_runs} run(s)  [attacks={scope_attacks}  percentages={scope_percs}  "
          f"seeds={args.seeds}  simTime={args.sim_time}s  "
          f"workers={min(args.workers, len(lanes))}] --\n")

    wall_start = datetime.now()
    lane_summaries = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(lanes))) as pool:
        futures = {
            pool.submit(run_lane, a, p, args.seeds, args.sim_time, args.sim_run): (a, p)
            for a, p in lanes
        }
        for fut in as_completed(futures):
            lane_summaries.append(fut.result())

    wall = (datetime.now() - wall_start).total_seconds()
    passed = sum(1 for ls in lane_summaries for r in ls["runs"] if r["ok"] and r["renamed"])
    failed = total_runs - passed
    print(f"\n-- Summary (wall time: {wall:.0f}s) --")
    print(f"  Passed : {passed}/{total_runs}")
    if failed:
        print(f"  FAILED : {failed}/{total_runs} -- check logs/rule_based_sweep/")

    print("\n-- Result files (sample check) --")
    missing = 0
    for a in scope_attacks:
        for p in scope_percs:
            for s in args.seeds:
                base = result_filename(a, p).replace(".csv", f"_seed{s}.csv")
                f = RESULTS_DIR / base
                if not f.exists() or f.stat().st_size == 0:
                    print(f"  MISSING  {base}")
                    missing += 1
    if missing == 0:
        print("  All expected per-seed result files present.")


if __name__ == "__main__":
    main()
