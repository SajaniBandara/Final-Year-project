#!/usr/bin/env python3
"""
run_phantom_exp14.py — PHANTOM paper Experiments 1 (penetration x intensity) and
4 (attack observable evidence / selectivity). Same engine as run_phantom_exp23.py
(direct binary, parallel, resumable, mem/load-throttled), but jobs carry their own
penetration, delay (intensity) and target-ratio.

Exp 1 — Detection under penetration x intensity:
    penetration p in {0,20,40,60,80,100}%, intensity in {55,100,200} ms
    (1.1/2/4 x Delta_max). Intensity only affects the timing variants (S1,S2);
    the flow-table variants (S3,S4) are run once per penetration at the default
    delay. macro MCC vs penetration, one line per intensity.
Exp 4 — Detection under decreasing observable evidence:
    selective target ratio in {0.10,0.25,0.75,1.00} (AOEI {0.25,0.5,0.75,1.0}),
    at default penetration 40%, delay 100ms. The ratio gates HIGH-priority
    targeting (selective_time_delay.h), so it bites on S1/S2; S3/S4 are run at
    ratio 1.0 for the macro.

Usage:
    python3 scripts/run_phantom_exp14.py --exp 1
    python3 scripts/run_phantom_exp14.py --exp 4
    python3 scripts/run_phantom_exp14.py --exp 1 4 --workers 8 [--dry-run]
"""
import argparse, os, subprocess, sys, time
from pathlib import Path

NS3_DIR  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BINARY   = NS3_DIR / "build/scratch/routing/routing"
LIB_PATH = str(NS3_DIR / "build/lib")
RESULTS  = NS3_DIR / "results_routing"
LOGS_DIR = Path(__file__).resolve().parent.parent / "logs" / "phantom_exp14"

# SIM_TIME=300 (30 s warm-up + 270 s scored -> 27 non-overlapping 10 s MCC blocks),
# standardised 2026-09-23 to match Exp 3/5 and the finalised config. The old 60 s
# (3 scored blocks) was not comparable to the 300 s headline results and violated
# the paper's own "state run length; detection quality is not stable across it" rule.
SEED, SIM_TIME, N_RSUS, N_CTRL = 1, 180, 64, 4   # supervisor directive 2026-10-08: 180 s, single seed
PENS       = [0, 20, 40, 60, 80, 100]      # Exp 1 penetration
INTENSITIES = [55, 100, 200]               # Exp 1 delay (ms) = 1.1/2/4 x Delta_max
RATIOS     = [0.10, 0.25, 0.75, 1.00]      # Exp 4 target ratio
DEF_PCT, DEF_DELAY = 40, 100

MAX_WORKERS, MEM_FLOOR_MB, LOAD_CEILING_FRAC, POLL, NICE = 8, 6000, 0.85, 5, 10


def build_env():
    env = os.environ.copy(); ex = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{LIB_PATH}:{ex}" if ex else LIB_PATH
    return env

def mem_mb():
    try:
        for l in open("/proc/meminfo"):
            if l.startswith("MemAvailable:"): return int(l.split()[1]) // 1024
    except OSError: pass
    return 1 << 30

def load1():
    try: return os.getloadavg()[0]
    except OSError: return 0.0

def out_csv(kind, attack, pct, delay, tag):
    d = f"_d{delay}ms" if attack in (1, 2) else ""
    return RESULTS / f"{kind}_Attack{attack}_{pct}{d}_seed{SEED}_{tag}.csv"

def done(kind, attack, pct, delay, tag):
    f = out_csv(kind, attack, pct, delay, tag)
    try: return f.is_file() and sum(1 for _ in open(f)) >= 2
    except OSError: return False


def make_jobs(exps):
    jobs = []
    if 1 in exps:
        for p in PENS:
            if p == 0:
                # Benign anchor: independent of attack and delay. It used to be launched 12x
                # under one filename (Attack0_0_seed1_<tag>), which APPENDED 12 runs
                # into one CSV (2616 rows, 892 cycle-counter restarts) and never matched
                # the Attack{a} lookup, hence the blank p=0 row. Run it ONCE.
                jobs.append(dict(exp=1, kind="MOBIGUARD", attack=0, pct=0, delay=DEF_DELAY,
                                 ratio=1.0, tap=False, tag="e180_exp1_p0"))
                jobs.append(dict(exp=1, kind="TAP", attack=0, pct=0, delay=DEF_DELAY,
                                 ratio=1.0, tap=True, tag="e180_exp1_p0tap"))
                continue
            # timing variants: full intensity sweep
            for delay in INTENSITIES:
                tag = f"e180_exp1_p{p}_d{delay}"
                for a in (1, 2):
                    jobs.append(dict(exp=1, kind="MOBIGUARD", attack=a, pct=p, delay=delay,
                                     ratio=1.0, tap=False, tag=tag))
                    jobs.append(dict(exp=1, kind="TAP", attack=a, pct=p, delay=delay,
                                     ratio=1.0, tap=True, tag=tag + "tap"))
            # flow-table variants: intensity-independent, run once per penetration
            tagf = f"e180_exp1_p{p}"
            for a in (3, 4):
                jobs.append(dict(exp=1, kind="MOBIGUARD", attack=a, pct=p, delay=DEF_DELAY,
                                 ratio=1.0, tap=False, tag=tagf))
    if 4 in exps:
        for r in RATIOS:
            rt = str(r).replace(".", "p")
            tag = f"e180_exp4_r{rt}"
            for a in (1, 2, 3, 4):
                jobs.append(dict(exp=4, kind="MOBIGUARD", attack=a, pct=DEF_PCT, delay=DEF_DELAY,
                                 ratio=(r if a in (1, 2) else 1.0), tap=False, tag=tag))
            for a in (1, 2):
                jobs.append(dict(exp=4, kind="TAP", attack=a, pct=DEF_PCT, delay=DEF_DELAY,
                                 ratio=r, tap=True, tag=tag + "tap"))
    return jobs


SMOKE = False
KEEP_HEAVY = False

def build_cmd(j):
    cmd = ["nice", f"-n{NICE}", str(BINARY),
           # Crypto-off: detection MCC is crypto-neutral (validated byte-identical
           # crypto-on vs off, 2026-09-23), and Exp 1/4 report only MCC/FPR (no
           # latency panel — that's Exp 2, run crypto-on). ~3x faster.
           "--disable_crypto=1",
           "--N_Vehicles=200", f"--N_RSUs={N_RSUS}", f"--N_Controllers={N_CTRL}",
           "--mobility_scenario=0", "--maxspeed=150", "--use_sumo_mobility=1",
           "--architecture=3", f"--simTime={SIM_TIME}",
           f"--attack_percentage={j['pct']}", f"--attack_delay_ms={j['delay']}",
           f"--selective_target_ratio={j['ratio']}", f"--sim_seed={SEED}",
           f"--run_tag={j['tag']}"]
    # p=0 is benign: omit --attack_number so active_attack_variant stays -1
    if j["pct"] != 0 or j["exp"] == 4:
        cmd.append(f"--attack_number={j['attack']}")
    if j["tap"]:
        cmd += ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0"]
    else:
        cmd += ["--enable_detector_windows=1"]
        # A1/A2 composite attribution fix (2026-10-01): attribute the composite
        # to the accused's covering RSU + fold S1 into the OR-composite, matching
        # the SOTA-table numbers (A2 0.594->0.920). Measurement-only, scoped to
        # the timing variants; A3/A4 (TCAM) are unaffected and omit the flag.
        if j["attack"] in (1, 2):
            cmd.append("--dw_mark_suspect=1")
    if SMOKE:
        cmd.append("--attack_start_time=2")
    return cmd


RESULTS_DIR_PURGE = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"


def _purge_heavy(tag):
    if KEEP_HEAVY: return
    """Disk guard (2026-10-08: a 138-job batch wrote 42 GB and filled the disk). These
    logs are not read by any Exp 1-5 scorer; delete them when the job ends."""
    import glob
    for pat in ("tcam_snapshots_*", "bc_detection_log_*"):
        for f in glob.glob(str(RESULTS_DIR_PURGE / (pat + tag + "*"))):
            try: os.unlink(f)
            except OSError: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", type=int, nargs="+", choices=[1, 4], required=True)
    ap.add_argument("--workers", type=int, default=MAX_WORKERS)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--smoke", type=int, default=0, help="debug run of N seconds (attack_start_time=2, tags smk_*)")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--attacks", type=int, nargs="+", help="only MOBIGUARD jobs for these attack numbers (0=benign)")
    ap.add_argument("--keep-heavy", action="store_true", help="do not purge tcam_snapshots/bc_detection_log (needed for SFTO scoring)")
    a = ap.parse_args()
    if not BINARY.is_file(): sys.exit(f"ABORT: binary missing {BINARY}")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    jobs = make_jobs(sorted(set(a.exp)))
    global SIM_TIME, SMOKE, KEEP_HEAVY
    KEEP_HEAVY = a.keep_heavy
    if a.smoke:
        SIM_TIME, SMOKE = a.smoke, True
        for j in jobs: j["tag"] = j["tag"].replace("e180_", "smk_", 1)
    # a reused tag APPENDS to the result CSV and corrupts per-cycle series: wipe stale partials
    for j in jobs:
        pass
    if a.attacks:
        jobs = [j for j in jobs if j["kind"] == "MOBIGUARD" and j["attack"] in a.attacks]
    todo = [j for j in jobs if a.force or not done(j["kind"], j["attack"], j["pct"], j["delay"], j["tag"])]
    print(f"exp={a.exp} jobs={len(jobs)} todo={len(todo)} skipped={len(jobs)-len(todo)} workers={a.workers}")
    if a.dry_run:
        for j in todo: print("  " + " ".join(build_cmd(j)))
        return

    env = build_env(); running = {}; queue = list(todo); n = 0; tot = len(todo)
    def launch(j):
        lp = LOGS_DIR / f"exp{j['exp']}_{j['kind']}_A{j['attack']}_{j['tag']}.log"
        lf = open(lp, "w")
        try: out_csv(j["kind"], j["attack"], j["pct"], j["delay"], j["tag"]).unlink()
        except FileNotFoundError: pass
        p = subprocess.Popen(build_cmd(j), cwd=str(NS3_DIR), env=env, stdout=lf, stderr=subprocess.STDOUT)
        running[p] = (j, lf, time.time())
        print(f"  launch e{j['exp']} {j['kind']} A{j['attack']} {j['tag']} (pid {p.pid})", flush=True)
    while queue or running:
        for p in list(running):
            if p.poll() is not None:
                j, lf, t0 = running.pop(p); lf.close(); n += 1
                _purge_heavy(j["tag"])
                ok = done(j["kind"], j["attack"], j["pct"], j["delay"], j["tag"])
                print(f"  done  e{j['exp']} {j['kind']} A{j['attack']} {j['tag']} rc={p.returncode} "
                      f"{'OK' if ok else 'NO-CSV'} ({time.time()-t0:.0f}s) [{n}/{tot}]", flush=True)
        while queue and len(running) < a.workers:
            if mem_mb() < MEM_FLOOR_MB or load1() > os.cpu_count() * LOAD_CEILING_FRAC:
                print(f"  throttle mem={mem_mb()} load={load1():.1f}", flush=True); break
            launch(queue.pop(0))
        time.sleep(POLL)
    print(f"ALL DONE ({n}/{tot})", flush=True)


if __name__ == "__main__":
    main()
