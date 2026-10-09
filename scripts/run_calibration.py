#!/usr/bin/env python3
"""run_calibration.py -- the one-off calibration batch on VALIDATION seeds 2 and 3 (reported seed is 1), supervisor 2026-10-09.
Detection-only (enforcement off), 180 s, p=40 for attack runs, --ev_log_util=1 so U_thresh / SFTO theta / TAP margin can be swept offline.
  cal_s1{0,1}_A0 / A1   S1 handoff-jitter suppression off / on, benign and A1   (also feeds S4 per-decision rates, SFTO prediction)
  cal_A3, cal_A4        U_thresh by the paper's rule (benign runs above + A3 + A4 under the state label)
  cal_tap_A0 / A2       TAP margin
  cal_fade_A0 / A6      eFADE (no threshold knob: its false-alarm rate is measured)
Run-tag rule: existing outputs of a tag are deleted before launch."""
import glob, os, subprocess, sys, time
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN, LIB, RES = NS3 / "build/scratch/routing/routing", str(NS3 / "build/lib"), NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "calibration"
SEEDS, SIM, P, DELAY = (2, 3), 180, 40, 100

def jobs():
    J = []
    def add(tag, attack, seed, extra):
        J.append(dict(tag=tag, attack=attack, seed=seed, extra=extra))
    for s in SEEDS:
        for sup in (0, 1):
            add(f"cal_s1{sup}_A0_s{s}", 0, s, [f"--s1_suppress_handoff_fp={sup}", "--enable_sfto=1", "--ev_log_util=1"])
            add(f"cal_s1{sup}_A1_s{s}", 1, s, [f"--s1_suppress_handoff_fp={sup}", "--dw_mark_suspect=1", "--ev_log_util=1"])
        add(f"cal_A3_s{s}", 3, s, ["--ev_log_util=1"])
        add(f"cal_A4_s{s}", 4, s, ["--ev_log_util=1", "--enable_sfto=1"])
        add(f"cal_tap_A0_s{s}", 0, s, ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0", "--ev_log_util=1"])
        add(f"cal_tap_A2_s{s}", 2, s, ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0", "--ev_log_util=1"])
        add(f"cal_fade_A0_s{s}", 0, s, ["--enable_lrad_obu=0", "--enable_lrad_rsu=0"])
        add(f"cal_fade_A6_s{s}", 6, s, ["--enable_lrad_obu=0", "--enable_lrad_rsu=0"])
    return J

def cmd(j):
    c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0", "--maxspeed=150",
         "--use_sumo_mobility=1", "--architecture=3", f"--simTime={SIM}", f"--attack_percentage={0 if j['attack'] == 0 else P}",
         f"--attack_delay_ms={DELAY}", f"--sim_seed={j['seed']}", f"--run_tag={j['tag']}", "--enable_detector_windows=1"]
    if j["attack"] != 0: c.append(f"--attack_number={j['attack']}")
    return c + j["extra"]

def main():
    J = jobs(); LOGS.mkdir(parents=True, exist_ok=True)
    print(len(J), "jobs", flush=True)
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    running, queue = [], list(J)
    while queue or running:
        running = [(p, j) for p, j in running if p.poll() is None]
        while queue and len(running) < 12 and os.getloadavg()[0] < 28:
            j = queue.pop(0)
            for f in glob.glob(str(RES / f"*_{j['tag']}.*")): os.remove(f)
            p = subprocess.Popen(cmd(j), stdout=open(LOGS / (j["tag"] + ".log"), "w"), stderr=subprocess.STDOUT, env=env)
            running.append((p, j)); print("started", j["tag"], flush=True)
        time.sleep(5)
    print("ALL DONE", flush=True)
if __name__ == "__main__": main()
