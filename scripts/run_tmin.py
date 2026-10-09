#!/usr/bin/env python3
"""run_tmin.py -- quarantine breakdown + T_min sweep (supervisor 2026-10-09, night 2). Validation seeds 2 and 3, detection only,
S1 suppression ON, U_thresh 0.37, simTime 181 so cycles 45..179 are all real routing cycles.
  tm<T>_A{0,1,3}_s{2,3}   T_min in {0.3, 0.5, 0.7} x benign / A1 / A3
  repro_old_A0_s2         benign seed 2 at the calibration settings (S1 off, U_thresh 0.20) that showed 61 / 67 quarantines
Run-tag rule: existing outputs of a tag are deleted before launch.   Use --dry-run to list the commands only."""
import argparse, glob, os, shutil, subprocess, time
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN, LIB, RES = NS3 / "build/scratch/routing/routing", str(NS3 / "build/lib"), NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "tmin"
SIM, P, DELAY = 181, 40, 100

def jobs():
    J = []
    for tm in (0.3, 0.5, 0.7):
        for a in (0, 1, 3):
            for s in (2, 3):
                J.append(dict(tag=f"tm{int(tm*10):02d}_A{a}_s{s}", attack=a, seed=s, extra=["--s1_suppress_handoff_fp=1", "--tcam_util_thresh=0.37", f"--trust_t_min={tm}"]))
    J.append(dict(tag="repro_old_A0_s2", attack=0, seed=2, extra=["--s1_suppress_handoff_fp=0", "--tcam_util_thresh=0.20", "--trust_t_min=0.7"]))
    return J

def cmd(j):
    c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150", "--use_sumo_mobility=1",
         "--architecture=3", f"--simTime={SIM}", f"--attack_percentage={0 if j['attack'] == 0 else P}", f"--attack_delay_ms={DELAY}",
         f"--sim_seed={j['seed']}", f"--run_tag={j['tag']}", "--aux_logs=0"]
    if j["attack"] != 0: c.append(f"--attack_number={j['attack']}")
    return c + j["extra"]

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args()
    J = jobs()
    if a.dry_run:
        print(len(J), "jobs"); [print(" ".join(cmd(j)[3:])) for j in J[:3]]; return
    LOGS.mkdir(parents=True, exist_ok=True); print(len(J), "jobs", flush=True)
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    running, queue = [], list(J)
    while queue or running:
        running = [(p, j) for p, j in running if p.poll() is None]
        while queue and len(running) < 12 and os.getloadavg()[0] < 28 and shutil.disk_usage("/").free > 15e9:   # never start a run on a nearly full disk
            j = queue.pop(0)
            for f in glob.glob(str(RES / f"*_{j['tag']}.*")): os.remove(f)
            p = subprocess.Popen(cmd(j), stdout=open(LOGS / (j["tag"] + ".log"), "w"), stderr=subprocess.STDOUT, env=env)
            running.append((p, j)); print("started", j["tag"], flush=True)
        time.sleep(5)
    print("ALL DONE", flush=True)
if __name__ == "__main__": main()
