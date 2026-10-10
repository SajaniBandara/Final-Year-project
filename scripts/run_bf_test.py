#!/usr/bin/env python3
"""run_bf_test.py -- batch_fallback on/off, A1/A2 p40, seeds 2,3, detection only, 181 s (audit: paper eq:batch_fallback)."""
import os, subprocess, glob
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"; BIN = NS3 / "build/scratch/routing/routing"; RES = NS3 / "results_routing"
env = os.environ.copy(); env["LD_LIBRARY_PATH"] = str(NS3 / "build/lib") + ":" + env.get("LD_LIBRARY_PATH", "")
ps = []
for a in (1, 2):
    for s in (2, 3):
        for bf in (1, 0):
            tag = f"bf{bf}_A{a}_s{s}"
            for f in glob.glob(str(RES / f"*_{tag}.*")): os.remove(f)
            c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150",
                 "--use_sumo_mobility=1", "--architecture=3", "--simTime=181", f"--attack_number={a}", "--attack_percentage=40", f"--sim_seed={s}",
                 f"--run_tag={tag}", "--aux_logs=0", "--enable_lstm_inference=1", "--enable_lstm_cls=1", "--enable_quarantine_enforcement=0",
                 f"--batch_fallback={bf}"]
            ps.append(subprocess.Popen(c, stdout=open(f"logs/bf/{tag}.log", "w"), stderr=subprocess.STDOUT, env=env))
rc = [p.wait() for p in ps]; print("rc", rc)
