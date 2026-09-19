#!/usr/bin/env python3
"""
run_phantom_sig.py — PHANTOM five-seed significance sweep (Statistical
Significance subsection). Default operating point (N=200, maxspeed=150, 40%,
100ms), seeds 1-5 (each = a distinct SUMO mobility realisation
mobility_urban_150_seed{1..5}.tcl). PHANTOM S1-S4 (detector_windows for M1) and
TAP S1-S4, per seed. Scored + paired-tested by score_phantom_sig.py.

Usage: python3 scripts/run_phantom_sig.py [--workers 8] [--dry-run]
"""
import argparse, os, subprocess, sys, time
from pathlib import Path

NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN = NS3 / "build/scratch/routing/routing"
LIB = str(NS3 / "build/lib")
RES = NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "phantom_sig"
SEEDS = [1, 2, 3, 4, 5]
PCT, DELAY, SIM = 40, 100, 60
MEM_FLOOR, LOAD_FR, POLL, NICE = 6000, 0.85, 5, 10


def env():
    e = os.environ.copy(); x = e.get("LD_LIBRARY_PATH", "")
    e["LD_LIBRARY_PATH"] = f"{LIB}:{x}" if x else LIB; return e

def mem():
    try:
        for l in open("/proc/meminfo"):
            if l.startswith("MemAvailable:"): return int(l.split()[1])//1024
    except OSError: pass
    return 1<<30

def load():
    try: return os.getloadavg()[0]
    except OSError: return 0.0

def out(kind, a, seed, tag):
    d = f"_d{DELAY}ms" if a in (1,2) else ""
    return RES / f"{kind}_Attack{a}_{PCT}{d}_seed{seed}_{tag}.csv"

def done(kind, a, seed, tag):
    f = out(kind, a, seed, tag)
    try: return f.is_file() and sum(1 for _ in open(f)) >= 2
    except OSError: return False

def jobs():
    js = []
    for s in SEEDS:
        for a in (1,2,3,4):
            js.append(dict(kind="MOBIGUARD", a=a, seed=s, tap=False, tag=f"sig_s{s}"))
            js.append(dict(kind="TAP", a=a, seed=s, tap=True, tag=f"sig_s{s}tap"))
    return js

def cmd(j):
    c = ["nice", f"-n{NICE}", str(BIN), "--N_Vehicles=200", "--N_RSUs=64",
         "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150",
         "--use_sumo_mobility=1", "--architecture=3", f"--simTime={SIM}",
         f"--attack_number={j['a']}", f"--attack_percentage={PCT}",
         f"--attack_delay_ms={DELAY}", f"--sim_seed={j['seed']}", f"--run_tag={j['tag']}"]
    if j["tap"]: c += ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0"]
    else: c += ["--enable_detector_windows=1"]
    return c

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if not BIN.is_file(): sys.exit("ABORT: binary missing")
    LOGS.mkdir(parents=True, exist_ok=True)
    js = jobs()
    todo = [j for j in js if a.force or not done(j["kind"], j["a"], j["seed"], j["tag"])]
    print(f"jobs={len(js)} todo={len(todo)} workers={a.workers}")
    if a.dry_run:
        for j in todo: print("  " + " ".join(cmd(j)))
        return
    e = env(); run = {}; q = list(todo); n = 0; tot = len(todo)
    def launch(j):
        lf = open(LOGS / f"{j['kind']}_A{j['a']}_{j['tag']}.log", "w")
        p = subprocess.Popen(cmd(j), cwd=str(NS3), env=e, stdout=lf, stderr=subprocess.STDOUT)
        run[p] = (j, lf, time.time()); print(f"  launch {j['kind']} A{j['a']} {j['tag']} (pid {p.pid})", flush=True)
    while q or run:
        for p in list(run):
            if p.poll() is not None:
                j, lf, t0 = run.pop(p); lf.close(); n += 1
                ok = done(j["kind"], j["a"], j["seed"], j["tag"])
                print(f"  done {j['kind']} A{j['a']} {j['tag']} rc={p.returncode} {'OK' if ok else 'NO-CSV'} ({time.time()-t0:.0f}s) [{n}/{tot}]", flush=True)
        while q and len(run) < a.workers:
            if mem() < MEM_FLOOR or load() > os.cpu_count()*LOAD_FR:
                print(f"  throttle mem={mem()} load={load():.1f}", flush=True); break
            launch(q.pop(0))
        time.sleep(POLL)
    print(f"ALL DONE ({n}/{tot})", flush=True)

if __name__ == "__main__":
    main()
