#!/usr/bin/env python3
"""
run_phantom_exp23.py — PHANTOM paper (Selective Time Delay, S1-S4) benchmarking
Experiments 2 (speed) and 3 (scalability). One script, parallel, resumable,
mem/load-throttled (modeled on run_training_attacks.py).

Exp 2 — Detection across vehicular speed (PRIMARY: settles the alpha_v sign Q):
    maxspeed in {10,60,100,140} km/h  (each = a distinct SUMO urban trace),
    N_Vehicles fixed at 200.
Exp 3 — Scalability:
    N_Vehicles in {100,200,300,400}, maxspeed fixed at 150 (default trace).
    Requires the total_size=468 build.

Each sweep point runs, at attack_percentage=40, seed 1, simTime=60 (30s warm-up
+ 30s scored), attack_delay_ms=100 (=2*Delta_max):
    - PHANTOM  : attacks {1,2,3,4}   -> MOBIGUARD_Attack<N>_40[_d100ms]_seed1_<tag>.csv
    - TAP base : attacks {1,2}       -> TAP_Attack<N>_40[_d100ms]_seed1_<tag>tap.csv
                 (--enable_tap=1 --enable_lrad_obu=0 --enable_lrad_rsu=0)
SFTO-Guard (S3/S4 comparator) is OFFLINE — produced separately from the S3/S4
tcam_snapshots via sfto_pipeline (see run_phantom_sfto.sh), not here.

Usage:
    python3 scripts/run_phantom_exp23.py --exp 2
    python3 scripts/run_phantom_exp23.py --exp 3
    python3 scripts/run_phantom_exp23.py --exp 2 3 --workers 8
    python3 scripts/run_phantom_exp23.py --exp 3 --dry-run
"""
import argparse, os, subprocess, sys, time
from pathlib import Path

NS3_DIR     = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BINARY      = NS3_DIR / "build/scratch/routing/routing"
LIB_PATH    = str(NS3_DIR / "build/lib")
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = Path(__file__).resolve().parent.parent / "logs" / "phantom_exp23"

# fixed settings (PHANTOM Table settings + sensitivity method)
SEED         = 1
SIM_TIME     = 300         # 30s warm-up + 270s scored (27 MCC blocks); standardised
                           # 2026-09-23 to match Exp 3/5 (was 60 -> only 3 blocks).
PCT          = 40          # default penetration for Exp 2/3 (Exp 1 sweeps it)
DELAY_MS     = 100         # 2 * Delta_max
N_RSUS       = 64
N_CTRL       = 4

SPEEDS       = [10, 60, 100, 140]     # Exp 2 (km/h) — distinct SUMO traces
# Exp 3 capped at the trace-supported range: the SUMO urban trace contains 200
# vehicles, so N>200 would leave vehicles with no mobility model (GetVelocity
# null-deref). {100,150,200} all index within the 200-vehicle trace. N>200
# (needing regenerated traces + a node-array-bounds generalization) is future work.
SCALES       = [100, 150, 200]        # Exp 3 (vehicles)
PHANTOM_ATT  = [1, 2, 3, 4]
TAP_ATT      = [1, 2]

MAX_WORKERS       = 8
MEM_FLOOR_MB      = 6000
LOAD_CEILING_FRAC = 0.85
POLL_INTERVAL_S   = 5
NICE_LEVEL        = 10


def build_env():
    env = os.environ.copy()
    ex = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{LIB_PATH}:{ex}" if ex else LIB_PATH
    return env


def mem_avail_mb():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 1 << 30


def load1():
    try:
        return os.getloadavg()[0]
    except OSError:
        return 0.0


def out_csv(kind, attack, tag):
    """Expected result CSV. delay suffix _d100ms applies to timing attacks 1/2;
    TCAM 3/4 have none. run_tag is always the final segment."""
    d = f"_d{DELAY_MS}ms" if attack in (1, 2) else ""
    return RESULTS_DIR / f"{kind}_Attack{attack}_{PCT}{d}_seed{SEED}_{tag}.csv"


def job_complete(kind, attack, tag):
    f = out_csv(kind, attack, tag)
    try:
        return f.is_file() and sum(1 for _ in open(f)) >= 2  # header + >=1 data row
    except OSError:
        return False


def make_jobs(exps):
    jobs = []
    if 2 in exps:
        for spd in SPEEDS:
            tag = f"exp2_s{spd}"
            for a in PHANTOM_ATT:
                jobs.append(dict(exp=2, kind="MOBIGUARD", attack=a, tag=tag,
                                 nveh=200, maxspeed=spd, tap=False))
            for a in TAP_ATT:
                jobs.append(dict(exp=2, kind="TAP", attack=a, tag=tag + "tap",
                                 nveh=200, maxspeed=spd, tap=True))
    if 3 in exps:
        for nv in SCALES:
            tag = f"exp3_nv{nv}"
            for a in PHANTOM_ATT:
                jobs.append(dict(exp=3, kind="MOBIGUARD", attack=a, tag=tag,
                                 nveh=nv, maxspeed=150, tap=False))
            for a in TAP_ATT:
                jobs.append(dict(exp=3, kind="TAP", attack=a, tag=tag + "tap",
                                 nveh=nv, maxspeed=150, tap=True))
    return jobs


def build_cmd(j):
    cmd = ["nice", f"-n{NICE_LEVEL}", str(BINARY),
           f"--N_Vehicles={j['nveh']}", f"--N_RSUs={N_RSUS}", f"--N_Controllers={N_CTRL}",
           "--mobility_scenario=0", f"--maxspeed={j['maxspeed']}",
           "--use_sumo_mobility=1", "--architecture=3",
           f"--simTime={SIM_TIME}", f"--attack_number={j['attack']}",
           f"--attack_percentage={PCT}", f"--attack_delay_ms={DELAY_MS}",
           f"--sim_seed={SEED}", f"--run_tag={j['tag']}"]
    # Exp2 (speed) plots MCC + FPR only (no latency panel), so crypto-off is
    # MCC/FPR-equivalent and ~13x faster (2026-10-02). Exp3 keeps crypto-on
    # (its latency panel needs the real crypto overhead).
    if j["exp"] == 2:
        cmd.append("--disable_crypto=1")
    if j["tap"]:
        # clean TAP baseline: MOBIGUARD's own detectors off, TAP has its own
        # avg_MCC column in TAP_*.csv, so no detector_windows needed here.
        cmd += ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0"]
    else:
        # PHANTOM arm: emit the detector_windows grid so m1_local.py can score
        # M1 (per-RSU, deduped 10s blocks) — the reporting-standard MCC.
        cmd += ["--enable_detector_windows=1"]
        # A1/A2 composite attribution fix (2026-10-02): covering-RSU + S1 fold-in,
        # matching the corrected SOTA table. Measurement-only; A3/A4 (TCAM) omit it.
        if j["attack"] in (1, 2):
            cmd.append("--dw_mark_suspect=1")
    return cmd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", type=int, nargs="+", choices=[2, 3], required=True)
    ap.add_argument("--workers", type=int, default=MAX_WORKERS)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    if not BINARY.is_file():
        sys.exit(f"ABORT: binary missing at {BINARY}")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    jobs = make_jobs(sorted(set(args.exp)))
    todo = [j for j in jobs if args.force or not job_complete(j["kind"], j["attack"], j["tag"])]
    skipped = len(jobs) - len(todo)
    print(f"exp={args.exp}  jobs={len(jobs)}  todo={len(todo)}  skipped(complete)={skipped}  workers={args.workers}")

    if args.dry_run:
        for j in todo:
            print("  " + " ".join(build_cmd(j)))
        return

    env = build_env()
    running = {}   # popen -> (job, logf, t0)
    queue = list(todo)         # FIFO of jobs still to launch
    done = 0; total = len(todo)

    def launch(j):
        logp = LOGS_DIR / f"exp{j['exp']}_{j['kind']}_A{j['attack']}_{j['tag']}.log"
        lf = open(logp, "w")
        p = subprocess.Popen(build_cmd(j), cwd=str(NS3_DIR), env=env,
                             stdout=lf, stderr=subprocess.STDOUT)
        running[p] = (j, lf, time.time())
        print(f"  launch exp{j['exp']} {j['kind']} A{j['attack']} {j['tag']} (pid {p.pid})", flush=True)

    while queue or running:
        # reap finished
        for p in list(running):
            if p.poll() is not None:
                j, lf, t0 = running.pop(p); lf.close(); done += 1
                ok = job_complete(j["kind"], j["attack"], j["tag"])
                print(f"  done  exp{j['exp']} {j['kind']} A{j['attack']} {j['tag']} "
                      f"rc={p.returncode} {'OK' if ok else 'NO-CSV'} "
                      f"({time.time()-t0:.0f}s)  [{done}/{total}]", flush=True)
        # fill slots (throttled)
        while queue and len(running) < args.workers:
            if mem_avail_mb() < MEM_FLOOR_MB or load1() > os.cpu_count() * LOAD_CEILING_FRAC:
                print(f"  throttle: mem={mem_avail_mb()}MB load={load1():.1f} — wait", flush=True)
                break
            launch(queue.pop(0))
        time.sleep(POLL_INTERVAL_S)

    print(f"ALL DONE  ({done}/{total})", flush=True)


if __name__ == "__main__":
    main()
