#!/usr/bin/env python3
"""run_lstm_collect.py -- LSTM training / validation / test data on the FROZEN build, detection only (supervisor 2026-10-09, night 2).
  train       seeds 6, 7, 8   benign only (the autoencoder is fitted on pure-benign windows)
  validation  seeds 2, 3      benign + A1-A8 x p in {20, 40, 60}
  test        seed 1          benign + A1-A8 x p in {20, 40, 60}  (the reported seed)
181 s, --training=1 (writes lstm_training/RSU_*/Attack{N}_{p}[_d100ms]_seed{S}.csv with the event / state label ev_label), --aux_logs=0, LSTM inference
OFF during collection. The previous lstm_training directory is MOVED ASIDE first (the append hazard documented in CLAUDE.md).
Use --dry-run to list the commands."""
import argparse, os, shutil, subprocess, time
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN, LIB, RES = NS3 / "build/scratch/routing/routing", str(NS3 / "build/lib"), NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "lstm_collect"
SIM, DELAY = 181, 100

def jobs():
    J = []
    for s in (6, 7, 8, 2, 3, 1): J.append(dict(attack=0, pct=0, seed=s))
    for s in (2, 3, 1):
        for a in range(1, 9):
            for p in (20, 40, 60): J.append(dict(attack=a, pct=p, seed=s))
    return J

def cmd(j):
    c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150", "--use_sumo_mobility=1",
         "--architecture=3", f"--simTime={SIM}", f"--attack_percentage={j['pct']}", f"--attack_delay_ms={DELAY}", f"--sim_seed={j['seed']}",
         "--training=1", "--aux_logs=0"]
    if j["attack"] != 0: c.append(f"--attack_number={j['attack']}")
    return c

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args(); J = jobs()
    if a.dry_run: print(len(J), "jobs"); [print(" ".join(cmd(j)[3:])) for j in J[:2]]; return
    old = RES / "lstm_training"
    if old.exists():
        dest = RES / "lstm_training_ARCHIVED_20261009_pre_final"; assert not dest.exists(); old.rename(dest); print("moved", old, "->", dest)
    LOGS.mkdir(parents=True, exist_ok=True); env = os.environ.copy(); env["LD_LIBRARY_PATH"] = LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    running, queue = [], list(J); print(len(J), "jobs", flush=True)
    while queue or running:
        still = []
        for p, j in running:
            if p.poll() is None: still.append((p, j))
            else: (LOGS / f"rc_A{j['attack']}_{j['pct']}_s{j['seed']}.txt").write_text(str(p.returncode))
        running = still
        while queue and len(running) < 12 and os.getloadavg()[0] < 28 and shutil.disk_usage("/").free > 15e9:
            j = queue.pop(0)
            p = subprocess.Popen(cmd(j), stdout=open(LOGS / f"A{j['attack']}_{j['pct']}_s{j['seed']}.log", "w"), stderr=subprocess.STDOUT, env=env)
            running.append((p, j)); print("started", j, flush=True)
        time.sleep(5)
    print("ALL DONE", flush=True)
if __name__ == "__main__": main()
