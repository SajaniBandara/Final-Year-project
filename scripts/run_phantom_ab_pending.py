#!/usr/bin/env python3
"""
run_phantom_ab_pending.py — PHANTOM ablations AB7, AB9, AB10, AB12 (seed 1 only,
simTime 300, delay 100 ms, crypto ON because M5/M6 need the real overhead).
Same engine as run_phantom_exp14.py: direct binary, resumable, mem/load throttled.

Arms (all penetration points in {0,20,40,60,80,100}%; p=0 is benign and run once per arm):
  AB7   ab7full : enable_quarantine=1 + enforcement     A1..A4   p in {0,20..100}
        ab7off  : enable_quarantine=0 (detection only)  A1..A4   p in {0,20..100}
  The three compromise-model capabilities (supervisor-approved 2026-10-05; active only
  at p >= 33, so p in {40,60,80,100} differ from the full arm, p<=20 reuse it):
  AB9   ab9sub  : --ab9_no_isolation=1   (+enforcement)   A1,A3   p in {40..100}
  AB12  ab12sub : --ab12_legitimize=1    (+enforcement)   A1,A3   p in {40..100}
  AB10  ab10sub : --ab10_false_keys=1 --ab_compromise_model=1   A1,A2,A3   p in {40..100}
                  (enforcement OFF: M1 is the reference, enforcement deflates it)
Full-arm reference for AB9/AB12 = ab7full (A1/A3). Full-arm M1 reference for AB10 = the
existing Exp 1 runs (crypto-off, MCC crypto-neutral, validated byte-identical 2026-09-23).

Usage:
    python3 scripts/run_phantom_ab_pending.py --workers 12 [--dry-run] [--only ab7 ab9 ab10 ab12]
"""
import argparse, os, subprocess, sys, time
from pathlib import Path

NS3_DIR  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BINARY   = NS3_DIR / "build/scratch/routing/routing"
LIB_PATH = str(NS3_DIR / "build/lib")
RESULTS  = NS3_DIR / "results_routing"
LOGS_DIR = Path(__file__).resolve().parent.parent / "logs" / "phantom_ab_pending"

SEED, SIM_TIME, DELAY = 1, 300, 100
PENS_ALL = [0, 20, 40, 60, 80, 100]
PENS_CAP = [40, 60, 80, 100]            # capabilities are active only at p >= 33
MAX_WORKERS, MEM_FLOOR_MB, LOAD_CEILING_FRAC, POLL, NICE = 12, 6000, 0.85, 5, 10


def make_jobs(only):
    jobs = []
    def add(ab, tag, attack, pct, extra):
        jobs.append(dict(ab=ab, tag=f"{tag}_p{pct}", attack=attack, pct=pct, extra=extra))
    if "ab7" in only:
        for arm, q in (("ab7full", 1), ("ab7off", 0)):
            ex = [f"--enable_quarantine={q}", "--enable_quarantine_enforcement=1"]
            add("ab7", arm, 0, 0, ex)                       # benign, once per arm
            for a in (1, 2, 3, 4):
                for p in PENS_ALL[1:]:
                    add("ab7", arm, a, p, ex)
    if "ab9" in only:
        for a in (1, 3):
            for p in PENS_CAP:
                add("ab9", "ab9sub", a, p, ["--ab9_no_isolation=1", "--enable_quarantine_enforcement=1"])
    if "ab12" in only:
        for a in (1, 3):
            for p in PENS_CAP:
                add("ab12", "ab12sub", a, p, ["--ab12_legitimize=1", "--enable_quarantine_enforcement=1"])
    if "ab10" in only:
        for a in (1, 2, 3):
            for p in PENS_CAP:
                add("ab10", "ab10sub", a, p, ["--ab10_false_keys=1", "--ab_compromise_model=1"])
    return jobs


def out_csv(j):
    a = j["attack"]
    d = f"_d{DELAY}ms" if a in (1, 2) else ""
    return RESULTS / f"MOBIGUARD_Attack{a}_{j['pct']}{d}_seed{SEED}_{j['tag']}.csv"

def done(j):
    f = out_csv(j)
    try: return f.is_file() and sum(1 for _ in open(f)) >= 2
    except OSError: return False


def build_cmd(j):
    cmd = ["nice", f"-n{NICE}", str(BINARY),
           "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4",
           "--mobility_scenario=0", "--maxspeed=150", "--use_sumo_mobility=1",
           "--architecture=3", f"--simTime={SIM_TIME}", f"--attack_percentage={j['pct']}",
           f"--attack_delay_ms={DELAY}", f"--sim_seed={SEED}", f"--run_tag={j['tag']}",
           "--enable_detector_windows=1"]
    if j["attack"] != 0:                      # p=0 is benign: omit --attack_number
        cmd.append(f"--attack_number={j['attack']}")
    if j["attack"] in (1, 2):                 # A1/A2 composite attribution fix (2026-10-01)
        cmd.append("--dw_mark_suspect=1")
    return cmd + j["extra"]


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+", default=["ab7", "ab9", "ab10", "ab12"],
                    choices=["ab7", "ab9", "ab10", "ab12"])
    ap.add_argument("--workers", type=int, default=MAX_WORKERS)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if not BINARY.is_file(): sys.exit(f"ABORT: binary missing {BINARY}")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    jobs = make_jobs(set(a.only))
    todo = [j for j in jobs if a.force or not done(j)]
    print(f"only={a.only} jobs={len(jobs)} todo={len(todo)} skipped={len(jobs)-len(todo)} workers={a.workers}")
    if a.dry_run:
        for j in todo: print("  " + " ".join(build_cmd(j)))
        return
    env = build_env(); running = {}; queue = list(todo); n = 0; tot = len(todo)
    def launch(j):
        lp = LOGS_DIR / f"{j['ab']}_A{j['attack']}_{j['tag']}.log"
        lf = open(lp, "w")
        p = subprocess.Popen(build_cmd(j), cwd=str(NS3_DIR), env=env, stdout=lf, stderr=subprocess.STDOUT)
        running[p] = (j, lf, time.time())
        print(f"  launch {j['ab']} A{j['attack']} {j['tag']} (pid {p.pid})", flush=True)
    while queue or running:
        for p in list(running):
            if p.poll() is not None:
                j, lf, t0 = running.pop(p); lf.close(); n += 1
                print(f"  done  {j['ab']} A{j['attack']} {j['tag']} rc={p.returncode} "
                      f"{'OK' if done(j) else 'NO-CSV'} ({time.time()-t0:.0f}s) [{n}/{tot}]", flush=True)
        while queue and len(running) < a.workers:
            if mem_mb() < MEM_FLOOR_MB or load1() > os.cpu_count() * LOAD_CEILING_FRAC:
                print(f"  throttle mem={mem_mb()} load={load1():.1f}", flush=True); break
            launch(queue.pop(0))
        time.sleep(POLL)
    print(f"ALL DONE ({n}/{tot})", flush=True)


if __name__ == "__main__":
    main()
