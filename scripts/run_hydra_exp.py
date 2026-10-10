#!/usr/bin/env python3
"""
run_hydra_exp.py -- Hydra letter ("ieee letter.tex") attack-effectiveness experiment.

SURROGATE, NOT THE PAPER'S DESIGN: the letter specifies all eight variants active
at once. The simulator has no joint 8-variant mode (attack_declaration.h:144), so
this runs the eight variants as eight separate single-variant sims per
configuration and pools their breach rates. It is a smoke/plumbing harness plus a
first-order estimate; it cannot show cross-variant interaction.

Configurations (letter Sec. V): neither / mobility / compromise / both
  mobility    -> --maxspeed 140 (else 10)
  compromise  -> --ab_compromise_model=1 (3 approved capabilities, p>=33 only)
Breach proxies (per-cycle columns of MOBIGUARD_*.csv, detector-independent):
  chi_tau (S1-S4): cur_TVR  (share of safety-critical hops over Delta_max)
  chi_D   (S5-S8): cur_UCR  (share of observed packets eavesdropped)
Pooled breach = mean over the 8 variants of the per-variant mean(cur_*)/100,
per-cycle series kept so 95% CIs can be taken across cycles.

Usage: run_hydra_exp.py --sim 5 --pcts 40 [--workers 16] [--tag-prefix hyd]
"""
import argparse, os, subprocess, statistics as st
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN = NS3 / "build/scratch/routing/routing"
RES = NS3 / "results_routing"
CFG = {"neither": (10, 0), "mobility": (140, 0), "compromise": (10, 1), "both": (140, 1)}

def cmd(cfg, a, p, sim, tag, start):
    spd, comp = CFG[cfg]
    c = [str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0",
         f"--maxspeed={spd}", "--use_sumo_mobility=1", "--architecture=3", f"--simTime={sim}",
         f"--attack_start_time={start}", f"--attack_number={a}", f"--attack_percentage={p}",
         "--sim_seed=1", f"--run_tag={tag}", "--enable_detector_windows=1", "--enable_lstm_inference=1"]
    if comp: c.append("--ab_compromise_model=1")
    return c

def csv_path(a, p, tag):
    d = "_d100ms" if a in (1, 2) else ""
    return RES / f"MOBIGUARD_Attack{a}_{p}{d}_seed1_{tag}.csv"

def series(f, col):
    rows = [l for l in open(f)]
    h = [x.strip() for x in rows[0].lstrip("# ").split(",")]
    i = h.index(col)
    return [float(r.split(",")[i]) for r in rows[1:] if not r.startswith("#")]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sim", type=int, default=180); ap.add_argument("--pcts", type=int, nargs="+", default=[0,20,40,60,80,100])
    ap.add_argument("--workers", type=int, default=8); ap.add_argument("--tag-prefix", default="hyd")
    ap.add_argument("--start", type=float, default=None)
    a = ap.parse_args()
    start = a.start if a.start is not None else (2 if a.sim <= 10 else 10)
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = str(NS3 / "build/lib") + ":" + env.get("LD_LIBRARY_PATH", "")
    jobs = [(c, v, p) for c in CFG for p in a.pcts for v in range(1, 9)]
    def run(j):
        c, v, p = j; tag = f"{a.tag_prefix}_{c}_p{p}_t{a.sim}"
        if csv_path(v, p, tag).exists(): return j, "skip"
        r = subprocess.run(cmd(c, v, p, a.sim, tag, start), cwd=NS3, env=env, capture_output=True)
        return j, r.returncode
    with ThreadPoolExecutor(a.workers) as ex: res = list(ex.map(run, jobs))
    print("failures:", [(j, rc) for j, rc in res if rc not in (0, "skip")])
    print("config,p,variant,metric,cycles,mean_breach,std_breach")
    for c in CFG:
        for p in a.pcts:
            per = []
            for v in range(1, 9):
                col = "cur_TVR" if v <= 4 else "cur_UCR"
                f = csv_path(v, p, f"{a.tag_prefix}_{c}_p{p}_t{a.sim}")
                if not f.exists(): continue
                s = series(f, col); s = [x / 100.0 for x in s]
                per.append(st.mean(s))
                print(f"{c},{p},S{v},{col},{len(s)},{st.mean(s):.4f},{(st.pstdev(s) if len(s)>1 else 0):.4f}")
            if per: print(f"{c},{p},POOLED,breach,{len(per)},{st.mean(per):.4f},")
if __name__ == "__main__": main()
