#!/usr/bin/env python3
"""run_witness_audit.py -- audit (b): witness code default (f=2, W=11 s) vs paper (f=1, W=10 s) vs AB6 off, A7/A8 p40, seeds 2,3, detection only, 181 s."""
import os, subprocess, glob
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"; BIN = NS3 / "build/scratch/routing/routing"; RES = NS3 / "results_routing"
env = os.environ.copy(); env["LD_LIBRARY_PATH"] = str(NS3 / "build/lib") + ":" + env.get("LD_LIBRARY_PATH", "")
ARMS = {"code": ["--witness_f=2", "--witness_window=11"], "paper": ["--witness_f=1", "--witness_window=10"], "ab6off": ["--enable_witness_mechanism=0"]}
ps = []
for a in (7, 8):
    for s in (2, 3):
        for arm, extra in ARMS.items():
            tag = f"wa_{arm}_A{a}_s{s}"
            for f in glob.glob(str(RES / f"*_{tag}.*")): os.remove(f)
            c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150",
                 "--use_sumo_mobility=1", "--architecture=3", "--simTime=181", f"--attack_number={a}", "--attack_percentage=40", f"--sim_seed={s}",
                 f"--run_tag={tag}", "--aux_logs=0", "--enable_lstm_inference=1", "--enable_lstm_cls=1", "--enable_quarantine_enforcement=0"] + extra
            ps.append(subprocess.Popen(c, stdout=open(f"logs/bf/{tag}.log", "w"), stderr=subprocess.STDOUT, env=env))
print("rc", [p.wait() for p in ps])
