#!/usr/bin/env python3
"""run_bio_test.py -- btmm_intended_only 0/1, A1-A8 p40, seeds 2,3, detection only, 181 s, 16 at a time."""
import os, subprocess, glob, sys
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"; BIN = NS3 / "build/scratch/routing/routing"; RES = NS3 / "results_routing"
env = os.environ.copy(); env["LD_LIBRARY_PATH"] = str(NS3 / "build/lib") + ":" + env.get("LD_LIBRARY_PATH", "")
J = []
for a in range(1, 5):
    for s in (2, 3):
        for bio in (0,):
            J.append((f"clw_A{a}_s{s}", a, s, bio))
def run(batch):
    ps = []
    for tag, a, s, bio in batch:
        for f in glob.glob(str(RES / f"*_{tag}.*")): os.remove(f)
        c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150",
             "--use_sumo_mobility=1", "--architecture=3", "--simTime=181", f"--attack_number={a}", "--attack_percentage=40", f"--sim_seed={s}",
             f"--run_tag={tag}", "--aux_logs=0", "--enable_lstm_inference=1", "--enable_lstm_cls=1", "--enable_quarantine_enforcement=1",
             "--witness_f=1", "--witness_window=10"]
        ps.append(subprocess.Popen(c, stdout=open(f"logs/bf/{tag}.log", "w"), stderr=subprocess.STDOUT, env=env))
    return [p.wait() for p in ps]
rc = []
for i in range(0, len(J), 16): rc += run(J[i:i+16])
print("rc", rc)
