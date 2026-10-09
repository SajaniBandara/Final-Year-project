#!/usr/bin/env python3
"""run_rematch.py -- benign runs on validation seeds 2, 3 with the LSTM ON, to (a) measure the full LRAD false-alarm rate and (b) re-match TAP's margin and
SFTO's theta to it (supervisor 2026-10-09). Detection only, simTime 181, --aux_logs=0.  rm_lrad_s<k>: LRAD + LSTM + SFTO series;  rm_tap_s<k>: TAP only."""
import glob, os, shutil, subprocess, time, argparse
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN, LIB, RES = NS3 / "build/scratch/routing/routing", str(NS3 / "build/lib"), NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "rematch"
def jobs():
    J = []
    for s in (2, 3):
        J.append(dict(tag=f"rm_lrad_s{s}", seed=s, extra=["--enable_lstm_inference=1", "--enable_sfto=1", "--ev_log_util=1"]))
        J.append(dict(tag=f"rm_tap_s{s}", seed=s, extra=["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0", "--ev_log_util=1"]))
    return J
def cmd(j):
    return ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150", "--use_sumo_mobility=1",
            "--architecture=3", "--simTime=181", "--attack_percentage=0", f"--sim_seed={j['seed']}", f"--run_tag={j['tag']}", "--aux_logs=0"] + j["extra"]
def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args(); J = jobs()
    if a.dry_run: print(len(J), "jobs"); [print(" ".join(cmd(j)[3:])) for j in J[:1]]; return
    LOGS.mkdir(parents=True, exist_ok=True); env = os.environ.copy(); env["LD_LIBRARY_PATH"] = LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    ps = []
    for j in J:
        for f in glob.glob(str(RES / f"*_{j['tag']}.*")): os.remove(f)
        ps.append((subprocess.Popen(cmd(j), stdout=open(LOGS / (j["tag"] + ".log"), "w"), stderr=subprocess.STDOUT, env=env), j)); print("started", j["tag"], flush=True)
    for p, j in ps:
        rc = p.wait(); (RES / f"rc_{j['tag']}.txt").write_text(str(rc))
    print("ALL DONE", flush=True)
if __name__ == "__main__": main()
