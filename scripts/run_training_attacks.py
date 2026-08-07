#!/usr/bin/env python3
"""
run_training_attacks.py — Collect LSTM training CSVs for all 8 attack variants.

Runs: 8 attacks × 5 percentages {20,40,60,80,100} × 5 seeds = 200 simulations
      (+ 1 benign config × 5 seeds if attack 0 is included = 240 total)
Output: lstm_training/RSU_*/Attack{v}_{pct}[_d{X}ms]_seed{s}.csv  (labels 0=benign, 1=malicious RSU)

Usage:
    python3 scripts/run_training_attacks.py                 # all 240 runs
    python3 scripts/run_training_attacks.py --attack 1      # attack 1 only
    python3 scripts/run_training_attacks.py --pct 20 40     # specific percentages
    python3 scripts/run_training_attacks.py --workers 15    # cap parallel jobs
    python3 scripts/run_training_attacks.py --dry-run       # print commands only
    python3 scripts/run_training_attacks.py --force         # re-run even if output exists

Safety (2026-08-06): this machine has frozen mid-sweep twice before, losing all
in-flight progress. Measured per-instance RSS for this binary is ~350-450MB, but
this box is shared (other users + occasionally another concurrent sweep) and can
run with only a few GB truly free. Two independent safeguards are applied on top
of --workers:
  1. Resumability — a job whose output already looks complete (all N_RSUS files
     present with enough rows) is skipped. A freeze no longer means starting over;
     just re-run the same command and finished work is kept.
  2. Live throttling — before launching each new job, MemAvailable and load
     average are checked; launching pauses (does not abort) if the machine is
     under pressure, and resumes once it recovers. This protects against
     headroom shrinking mid-sweep from other users' activity, independent of
     whatever --workers ceiling was requested.
Each job also runs under `nice` so it doesn't starve other users on this shared host.
"""

import argparse, os, signal, subprocess, sys, time
from pathlib import Path

NS3_DIR     = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BINARY      = NS3_DIR / "build/scratch/routing/routing"
LIB_PATH    = str(NS3_DIR / "build/lib")
LOGS_DIR    = Path(__file__).resolve().parent.parent / "logs" / "training"
RESULTS_DIR = NS3_DIR / "results_routing"
LSTM_DIR    = RESULTS_DIR / "lstm_training"

ATTACKS      = list(range(0, 9))          # 0 (benign) + 1–8
PERCENTAGES  = [0, 20, 40, 60, 80, 100]   # 6 percentages → 8×6×5 = 240 total
SEEDS        = [1, 2, 3, 4, 5]
SIM_TIME     = 300   # Issue 3 fix (2026-08-02): paper spec (main.tex) is 300s/run —
                      # was 90s, which understated block counts (~9/run vs ~30 the
                      # paper's arithmetic assumes) and inflated the warm-up-exclusion
                      # proportion to ~33% of the run instead of the intended ~10%.
N_RSUS       = 64

MAX_WORKERS       = 8       # was 25 — measured-safe figure from LSTM_FULL_PICTURE.md
                             # §3 (8 workers on this same class of machine); the two
                             # freezes both happened at higher worker counts.
MEM_FLOOR_MB       = 6000   # pause launching new jobs below this MemAvailable
LOAD_CEILING_FRAC  = 0.85   # pause launching new jobs above nproc * this
POLL_INTERVAL_S    = 5
NICE_LEVEL         = 10


def build_env():
    env = os.environ.copy()
    existing = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{LIB_PATH}:{existing}" if existing else LIB_PATH
    return env


def job_label(attack_number: int, pct: int, seed: int) -> str:
    """Label for this launcher's own log filenames only — NOT the CSV naming
    convention. lstm_logger.h writes Attack{N}_{pct}[_d{X}ms]_seed{S}.csv (see
    csv_glob_pattern() below); a run's log file is free to use a different,
    friendlier label since nothing else parses it."""
    return f"A{attack_number}_pct{pct}_seed{seed}"


def csv_glob_pattern(attack_number: int, pct: int, seed: int) -> str:
    """Glob matching the CSV filename lstm_logger.h actually writes:
    Attack{N}_{pct}[_d{X}ms]_seed{S}.csv (attacks 1/2 get an extra _d{X}ms
    delay segment; the wildcard absorbs it). Must stay in sync with
    lstm_logger.h's lstm_add_training_row() path construction and with the
    equivalent glob in run_training_sweep.py."""
    return f"Attack{attack_number}_{pct}*_seed{seed}.csv"


def build_cmd(attack_number: int, pct: int, seed: int, sim_time: int) -> list:
    # active_attack_variant is synced automatically from attack_number inside routing.cc.
    # attack_number=0 means benign: omit the flag entirely so routing.cc keeps its
    # default active_attack_variant=-1 (no attack), matching run_training_sweep.py's
    # convention. attack_percentage is meaningless without an attack, so it's forced
    # to 0 regardless of what pct was requested for this job.
    cmd = ["nice", f"-n{NICE_LEVEL}", str(BINARY), "--training=1"]
    if attack_number > 0:
        cmd.append(f"--attack_number={attack_number}")
        cmd.append(f"--attack_percentage={pct}")
    else:
        cmd.append("--attack_percentage=0")
    cmd.append(f"--sim_seed={seed}")
    cmd.append(f"--simTime={sim_time}")
    return cmd


def is_job_complete(attack_number: int, pct: int, seed: int, sim_time: int) -> bool:
    """True if every RSU's CSV for this job already has a header plus close to
    sim_time rows of data. lstm_logger.h pre-creates all N_RSUS per-RSU
    directories and writes one row per RSU per cycle (data_transmission_frequency
    is fixed at 1 Hz), so a complete run has ~sim_time rows; a killed/partial run
    leaves short files. The threshold is scaled to sim_time (not a fixed small
    constant) specifically because a short interrupted run can otherwise clear a
    fixed row-count bar and be misdetected as complete — confirmed happening in
    testing with a fixed min_rows=3 before this fix."""
    min_rows = max(3, int(sim_time * 0.9))
    pattern = csv_glob_pattern(attack_number, pct, seed)
    if not LSTM_DIR.is_dir():
        return False
    found = 0
    for rsu_dir in LSTM_DIR.glob("RSU_*"):
        matches = list(rsu_dir.glob(pattern))
        if not matches:
            continue
        f = matches[0]
        try:
            with open(f) as fh:
                n_lines = sum(1 for _ in fh)
        except OSError:
            continue
        if n_lines >= min_rows + 1:   # +1 for header
            found += 1
    return found >= N_RSUS


def clear_partial_output(attack_number: int, pct: int, seed: int):
    """Delete any existing (necessarily-partial, since is_job_complete already
    said no) CSV for this job across all RSU dirs before (re)launching it.
    lstm_logger.h opens in std::ios::app — without this, a job that is
    interrupted partway (crash, environment reset, freeze) and then resumed
    would have its fresh cycle-0-onward rows appended on top of the old
    partial rows instead of replacing them, corrupting the file with
    duplicate cycle numbers. Confirmed happening live: a 300s job sitting at
    139/270 rows got silently queued for a full re-run by the resumability
    check, and the relaunch was seconds from appending onto it before this
    fix — is_job_complete() only decides whether to run, it was never
    responsible for leaving a clean slate to run into."""
    pattern = csv_glob_pattern(attack_number, pct, seed)
    if not LSTM_DIR.is_dir():
        return
    for rsu_dir in LSTM_DIR.glob("RSU_*"):
        for f in rsu_dir.glob(pattern):
            f.unlink()


def read_mem_available_mb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def system_has_headroom(mem_floor_mb: int, load_ceiling_frac: float):
    mem_mb = read_mem_available_mb()
    if mem_mb is not None and mem_mb < mem_floor_mb:
        return False, f"MemAvailable={mem_mb}MB < floor={mem_floor_mb}MB"
    load1 = os.getloadavg()[0]
    ceiling = (os.cpu_count() or 1) * load_ceiling_frac
    if load1 > ceiling:
        return False, f"load1={load1:.1f} > ceiling={ceiling:.1f}"
    return True, ""


def protect_from_oom(pid: int):
    """Bias the kernel OOM killer away from our simulation processes, so that
    under system-wide memory pressure it reclaims someone else's process
    before ours. Best-effort: a non-owned/already-exited pid, or a sandbox
    that disallows the write, is not fatal to the job itself."""
    try:
        with open(f"/proc/{pid}/oom_score_adj", "w") as f:
            f.write("-500")
    except OSError:
        pass


def launch(attack_number: int, pct: int, seed: int, env: dict, sim_time: int) -> dict:
    label = job_label(attack_number, pct, seed)
    cmd = build_cmd(attack_number, pct, seed, sim_time)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_fh = open(LOGS_DIR / f"{label}.log", "w")
    proc = subprocess.Popen(cmd, cwd=str(NS3_DIR), stdout=subprocess.DEVNULL,
                             stderr=log_fh, env=env)
    protect_from_oom(proc.pid)
    return {"label": label, "proc": proc, "log_fh": log_fh, "t0": time.time()}


def main(args):
    attacks = args.attack if args.attack else ATTACKS
    pcts    = args.pct    if args.pct    else PERCENTAGES
    seeds   = args.seed   if args.seed   else SEEDS

    # attack_number=0 (benign) always forces --attack_percentage=0 in build_cmd
    # regardless of pct (percentage is meaningless without an attack), so every
    # pct value in a sweep collapses to the *same* command. Without this
    # collapse, len(pcts) identical benign processes get launched concurrently
    # per seed, all writing the same output file at once (wasted compute and a
    # concurrent-write race, not just redundant work) — so benign always gets
    # exactly one pct value (0) per seed, independent of what --pct requested.
    all_jobs = [(a, p, s) for a in attacks
                           for p in ([0] if a == 0 else pcts)
                           for s in seeds]

    if args.force:
        pending, skipped = list(all_jobs), []
    else:
        pending, skipped = [], []
        for job in all_jobs:
            (skipped if is_job_complete(*job, args.sim_time) else pending).append(job)

    print("MOBIGUARD LSTM Attack Training Launcher")
    print(f"  Binary       : {BINARY}")
    print(f"  Jobs total   : {len(all_jobs)}  ({len(attacks)} attacks × "
          f"{len(pcts)} pcts × {len(seeds)} seeds, minus pct-collapse for "
          f"benign attack=0 if present)")
    print(f"  Already done : {len(skipped)}  (skipped — pass --force to re-run)")
    print(f"  To run       : {len(pending)}")
    print(f"  Workers      : {args.workers}  (mem floor {args.mem_floor}MB, "
          f"load ceiling {args.load_ceiling}×{os.cpu_count()} cores)")
    print(f"  simTime      : {args.sim_time}s")
    if args.dry_run:
        print("  Mode         : DRY RUN (no simulations launched)\n")
        for (a, p, s) in pending:
            print(f"  [DRY] {' '.join(build_cmd(a, p, s, args.sim_time))}")
        return
    print(f"  Logs         : {LOGS_DIR}/\n")

    if not BINARY.exists():
        sys.exit(f"Binary not found: {BINARY}\nRun: cd {NS3_DIR} && ./waf build")
    if not pending:
        print("Nothing to do — all requested jobs already have complete output.")
        return

    env     = build_env()
    active  = []          # list of dicts from launch()
    failed  = []
    done    = 0
    t_start = time.time()
    queue   = list(pending)
    paused_reason = None

    def reap():
        nonlocal done
        still_active = []
        for job in active:
            rc = job["proc"].poll()
            if rc is None:
                still_active.append(job)
                continue
            job["log_fh"].close()
            elapsed = time.time() - job["t0"]
            status = "OK" if rc == 0 else f"FAIL(rc={rc})"
            print(f"  [{status}] {job['label']}  {elapsed/60:.1f} min")
            if rc != 0:
                failed.append(job["label"])
            done += 1
        active[:] = still_active

    def shutdown(*_):
        print("\nInterrupted — terminating in-flight simulations (their partial "
              "output is safe; --force is NOT needed, just re-run to resume)...")
        for job in active:
            job["proc"].terminate()
        time.sleep(2)
        for job in active:
            if job["proc"].poll() is None:
                job["proc"].kill()
            job["log_fh"].close()
        sys.exit(130)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while queue or active:
        reap()

        while queue and len(active) < args.workers:
            ok, reason = system_has_headroom(args.mem_floor, args.load_ceiling)
            if not ok:
                if reason != paused_reason:
                    print(f"  [PAUSED] {reason} — waiting for headroom "
                          f"({len(active)} active, {len(queue)} queued)")
                    paused_reason = reason
                break
            paused_reason = None
            a, p, s = queue.pop(0)
            clear_partial_output(a, p, s)
            active.append(launch(a, p, s, env, args.sim_time))

        time.sleep(POLL_INTERVAL_S)

    elapsed_total = time.time() - t_start
    print(f"\n{'='*50}")
    print(f"Done: {done - len(failed)}/{done} succeeded, "
          f"{len(skipped)} already-complete skipped  "
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
                    help="Attack numbers to run (default: all 0-8)")
    ap.add_argument("--pct",     type=int, nargs="+",
                    help="Attack percentages (default: 0 20 40 60 80 100)")
    ap.add_argument("--seed",    type=int, nargs="+",
                    help="RNG seeds (default: 1 2 3 4 5)")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS,
                    help=f"Max parallel jobs (default {MAX_WORKERS})")
    ap.add_argument("--sim-time", type=int, default=SIM_TIME, dest="sim_time",
                    help=f"Simulated seconds per run (default {SIM_TIME})")
    ap.add_argument("--mem-floor", type=int, default=MEM_FLOOR_MB, dest="mem_floor",
                    help=f"Pause launching below this MemAvailable, in MB (default {MEM_FLOOR_MB})")
    ap.add_argument("--load-ceiling", type=float, default=LOAD_CEILING_FRAC, dest="load_ceiling",
                    help=f"Pause launching above load1 > nproc*this (default {LOAD_CEILING_FRAC})")
    ap.add_argument("--force", action="store_true",
                    help="Re-run jobs even if complete output already exists")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print commands without running")
    main(ap.parse_args())
