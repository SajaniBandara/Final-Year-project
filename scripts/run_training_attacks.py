#!/usr/bin/env python3
"""
run_training_attacks.py — Collect LSTM training CSVs for all 8 attack variants.

Runs: 8 attacks × 5 percentages {20,40,60,80,100} × 5 seeds = 200 simulations
Output: lstm_training/RSU_*/A{v}_pct{p}_seed{s}.csv  (labels 0=benign, 1=malicious RSU)

Benign data (A0_pct0) is collected separately by running the simulation with
--active_attack_variant=-1 (already done / running). This script covers attacks 1-8.

Usage:
    python3 scripts/run_training_attacks.py                 # all 200 runs
    python3 scripts/run_training_attacks.py --attack 1      # attack 1 only (25 runs)
    python3 scripts/run_training_attacks.py --pct 20 40     # specific percentages
    python3 scripts/run_training_attacks.py --workers 15    # cap parallel jobs
    python3 scripts/run_training_attacks.py --dry-run       # print commands only
"""

import argparse, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

NS3_DIR     = Path.home() / "ns3_g13_apsari/ns-allinone-3.35/ns-3.35"
BINARY      = NS3_DIR / "build/scratch/routing/routing"
LIB_PATH    = str(NS3_DIR / "build/lib")
LOGS_DIR    = Path(__file__).resolve().parent.parent / "logs" / "training"
RESULTS_DIR = NS3_DIR / "results_routing"

ATTACKS      = list(range(1, 9))          # 1–8
PERCENTAGES  = [0, 20, 40, 60, 80, 100]  # 6 percentages → 8×6×5 = 240 total
SEEDS        = [1, 2, 3, 4, 5]
SIM_TIME     = 60
MAX_WORKERS  = 25    # 25 attack + 5 benign = 30 on 32 threads; safe headroom


def build_env():
    env = os.environ.copy()
    existing = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{LIB_PATH}:{existing}" if existing else LIB_PATH
    return env


def build_cmd(attack_number: int, pct: int, seed: int) -> list:
    # active_attack_variant is synced automatically from attack_number inside routing.cc
    return [
        str(BINARY),
        "--training=1",
        f"--attack_number={attack_number}",
        f"--attack_percentage={pct}",
        f"--sim_seed={seed}",
        f"--simTime={SIM_TIME}",
    ]


def run_one(attack_number: int, pct: int, seed: int,
            dry_run: bool, env: dict) -> dict:
    label = f"A{attack_number}_pct{pct}_seed{seed}"
    cmd   = build_cmd(attack_number, pct, seed)

    if dry_run:
        print(f"[DRY] {' '.join(cmd)}")
        return {"label": label, "rc": 0, "elapsed": 0}

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOGS_DIR / f"{label}.log"

    t0 = time.time()
    with open(log_path, "w") as log_fh:
        proc = subprocess.run(cmd, cwd=str(NS3_DIR),
                              stdout=subprocess.DEVNULL,
                              stderr=log_fh,
                              env=env)
    elapsed = time.time() - t0
    rc = proc.returncode
    status = "OK" if rc == 0 else f"FAIL(rc={rc})"
    print(f"  [{status}] {label}  {elapsed/60:.1f} min  log={log_path.name}")
    return {"label": label, "rc": rc, "elapsed": elapsed}


def main(args):
    attacks = args.attack if args.attack else ATTACKS
    pcts    = args.pct    if args.pct    else PERCENTAGES
    seeds   = args.seed   if args.seed   else SEEDS

    jobs = [(a, p, s) for a in attacks for p in pcts for s in seeds]
    print(f"MOBIGUARD LSTM Attack Training Launcher")
    print(f"  Binary : {BINARY}")
    print(f"  Jobs   : {len(jobs)} total  ({len(attacks)} attacks × "
          f"{len(pcts)} pcts × {len(seeds)} seeds)")
    print(f"  Workers: {args.workers}")
    print(f"  simTime: {SIM_TIME}s")
    if args.dry_run:
        print("  Mode   : DRY RUN (no simulations launched)\n")
    else:
        print(f"  Logs   : {LOGS_DIR}/\n")

    if not args.dry_run and not BINARY.exists():
        sys.exit(f"Binary not found: {BINARY}\nRun: cd {NS3_DIR} && ./waf build")

    env      = build_env()
    t_start  = time.time()
    failed   = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_one, a, p, s, args.dry_run, env): (a, p, s)
                   for (a, p, s) in jobs}
        for fut in as_completed(futures):
            result = fut.result()
            if result["rc"] != 0:
                failed.append(result["label"])

    elapsed_total = time.time() - t_start
    print(f"\n{'='*50}")
    print(f"Done: {len(jobs)-len(failed)}/{len(jobs)} succeeded  "
          f"({elapsed_total/60:.1f} min total)")
    if failed:
        print(f"FAILED ({len(failed)}):")
        for f in failed:
            print(f"  {f}")
    else:
        print("All runs succeeded.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack",  type=int, nargs="+", choices=ATTACKS,
                    help="Attack numbers to run (default: all 1-8)")
    ap.add_argument("--pct",     type=int, nargs="+",
                    help="Attack percentages (default: 20 40 60 80 100)")
    ap.add_argument("--seed",    type=int, nargs="+",
                    help="RNG seeds (default: 1 2 3 4 5)")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS,
                    help=f"Parallel jobs (default {MAX_WORKERS})")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print commands without running")
    main(ap.parse_args())
