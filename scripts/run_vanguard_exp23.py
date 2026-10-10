#!/usr/bin/env python3
"""
run_vanguard_exp23.py — VANGUARD-HF paper (Hidden Forwarding, S5-S8) Experiments
2 (speed) and 3 (scalability). Same engine as run_phantom_exp23.py. VANGUARD arm
runs the full MOBIGUARD HF stack with the federated LSTM as PRIMARY detector
(--enable_lstm_inference=1) + detector_windows for M1; FADE baseline arm isolates
eFADE (--enable_lrad_obu=0 --enable_lrad_rsu=0). TAP/SFTO are N/A for HF.

Exp 2: maxspeed {10,60,100,140} km/h (reuses PHANTOM's SUMO traces), N=200.
Exp 3: N_Vehicles {100,150,200} (capped at the 200-vehicle trace, per paper's
       "reuse PHANTOM's runs where possible"; N>200 = future work), maxspeed 150.
The Exp 3 N=200 point doubles as Exp 5's default-settings row.

Usage: python3 scripts/run_vanguard_exp23.py --exp 2 3 [--workers 8] [--dry-run]
"""
import argparse, os, subprocess, sys, time
from pathlib import Path

NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN = NS3 / "build/scratch/routing/routing"
LIB = str(NS3 / "build/lib")
RES = NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "vanguard_exp23"

SEED, SIM, PCT, N_RSUS, N_CTRL = 1, 60, 40, 64, 4
SPEEDS = [10, 60, 100, 140]
SCALES = [100, 150, 200]
HF_ATT = [5, 6, 7, 8]
PENS = [0, 20, 40, 60, 80, 100]
INTENS = [0.25, 0.5, 1.0]
AOEI_TARGET = [0.10, 0.25, 0.75, 1.00]
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

def out(kind, a, tag, pct=PCT):
    # HF attacks 5-8 carry no delay suffix
    return RES / f"{kind}_Attack{a}_{pct}_seed{SEED}_{tag}.csv"

def done(kind, a, tag, pct=PCT):
    f = out(kind, a, tag, pct)
    try: return f.is_file() and sum(1 for _ in open(f)) >= 2
    except OSError: return False

def make_jobs(exps):
    js = []
    def add(exp, nveh, spd, tagbase, pct=PCT, inten=1.0):
        for a in HF_ATT:
            js.append(dict(exp=exp, kind="MOBIGUARD", a=a, nveh=nveh, spd=spd,
                           fade=False, tag=tagbase, pct=pct, inten=inten))
        for a in HF_ATT:
            js.append(dict(exp=exp, kind="FADE", a=a, nveh=nveh, spd=spd,
                           fade=True, tag=tagbase + "fade", pct=pct, inten=inten))
    # Exp 1: penetration x forwarding intensity (--hf_forward_intensity, added 2026-10-08)
    if 1 in exps:
        for pc in PENS:
            for it in INTENS: add(1, 200, 60, f"vg_exp1_p{pc}_i{int(it*100)}", pc, it)
    # Exp 4: targeting axis only (fraction of eligible packets forwarded). The d_div
    # axis (copy-destination divergence) has NO CLI knob yet and the paper withholds
    # Exp 4 pending the data-provenance question, so this is the plumbing only.
    if 4 in exps:
        for it in AOEI_TARGET: add(4, 200, 60, f"vg_exp4_t{int(it*100)}", PCT, it)
    if 2 in exps:
        for s in SPEEDS: add(2, 200, s, f"vg_exp2_s{s}")
    if 3 in exps:
        for n in SCALES: add(3, n, 150, f"vg_exp3_nv{n}")
    return js

def cmd(j):
    c = ["nice", f"-n{NICE}", str(BIN), f"--N_Vehicles={j['nveh']}",
         f"--N_RSUs={N_RSUS}", f"--N_Controllers={N_CTRL}", "--mobility_scenario=0",
         f"--maxspeed={j['spd']}", "--use_sumo_mobility=1", "--architecture=3",
         f"--simTime={SIM}", f"--attack_number={j['a']}", f"--attack_percentage={j.get('pct', PCT)}",
         f"--hf_forward_intensity={j.get('inten', 1.0)}",
         f"--sim_seed={SEED}", f"--run_tag={j['tag']}"]
    if j["fade"]:
        c += ["--enable_lrad_obu=0", "--enable_lrad_rsu=0"]   # activates eFADE, MOBIGUARD off
    else:
        c += ["--enable_lstm_inference=1", "--enable_detector_windows=1"]  # LSTM-primary + M1 grid
    return c

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", type=int, nargs="+", choices=[1, 2, 3, 4], required=True)
    ap.add_argument("--sim", type=int, default=None, help="simTime (supervisor directive 2026-10-08: 180)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    global SIM
    if a.sim: SIM = a.sim
    if not BIN.is_file(): sys.exit("ABORT: binary missing")
    LOGS.mkdir(parents=True, exist_ok=True)
    js = make_jobs(sorted(set(a.exp)))
    todo = [j for j in js if a.force or not done(j["kind"], j["a"], j["tag"], j.get("pct", PCT))]
    print(f"exp={a.exp} jobs={len(js)} todo={len(todo)} workers={a.workers}")
    if a.dry_run:
        for j in todo: print("  " + " ".join(cmd(j)))
        return
    e = env(); run = {}; q = list(todo); n = 0; tot = len(todo)
    def launch(j):
        lf = open(LOGS / f"e{j['exp']}_{j['kind']}_A{j['a']}_{j['tag']}.log", "w")
        p = subprocess.Popen(cmd(j), cwd=str(NS3), env=e, stdout=lf, stderr=subprocess.STDOUT)
        run[p] = (j, lf, time.time()); print(f"  launch e{j['exp']} {j['kind']} A{j['a']} {j['tag']} (pid {p.pid})", flush=True)
    while q or run:
        for p in list(run):
            if p.poll() is not None:
                j, lf, t0 = run.pop(p); lf.close(); n += 1
                ok = done(j["kind"], j["a"], j["tag"], j.get("pct", PCT))
                print(f"  done e{j['exp']} {j['kind']} A{j['a']} {j['tag']} rc={p.returncode} {'OK' if ok else 'NO-CSV'} ({time.time()-t0:.0f}s) [{n}/{tot}]", flush=True)
        while q and len(run) < a.workers:
            if mem() < MEM_FLOOR or load() > os.cpu_count()*LOAD_FR:
                print(f"  throttle mem={mem()} load={load():.1f}", flush=True); break
            launch(q.pop(0))
        time.sleep(POLL)
    print(f"ALL DONE ({n}/{tot})", flush=True)

if __name__ == "__main__":
    main()
