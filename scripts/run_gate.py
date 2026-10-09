#!/usr/bin/env python3
"""run_gate.py -- supervisor GATE (2026-10-08): PHANTOM AB7, AB8 (A3), AB9, AB12 at p=40, 180 s, seed 1,
full and ablated arm, each with enforcement ON and OFF, plus benign anchors at p=0 (LRAD, TAP, SFTO).

Enforcement switch: --enable_quarantine_enforcement. OFF = DETECTION ONLY (supervisor 2026-10-09): no quarantine action,
no controller revocation / failover / isolation, no baseline mitigation; every detector keeps running.

AB7 ablated arm = --enable_quarantine=0 (no trust updates, no SC.Quarantine), run with enforcement on and off.
Full arm (ab7full) = defaults, shared by AB7/AB8/AB9/AB12.

Run-tag rule (supervisor 2c): any existing output for a tag is DELETED before launch, never appended to.
"""
import argparse, glob, os, subprocess, sys, time
from pathlib import Path

NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN, LIB, RES = NS3 / "build/scratch/routing/routing", str(NS3 / "build/lib"), NS3 / "results_routing"
LOGS = Path(__file__).resolve().parent.parent / "logs" / "gate"
SIM, SEED, DELAY, P = 180, 1, 100, 40
ENF = {"on": "--enable_quarantine_enforcement=1", "off": "--enable_quarantine_enforcement=0"}

def jobs():
    J = []
    def add(tag, attack, pct, extra):
        J.append(dict(tag="gate2_" + tag, attack=attack, pct=pct, extra=extra))
    for a in (1, 3):
        for e in ("on", "off"):
            add(f"full_A{a}_enf{e}", a, P, [ENF[e]])                              # shared full arm
        for e in ("on", "off"):
            add(f"ab7abl_A{a}_enf{e}", a, P, ["--enable_quarantine=0", ENF[e]])
        for e in ("on", "off"):
            add(f"ab9abl_A{a}_enf{e}", a, P, ["--ab9_no_isolation=1", ENF[e]])
            add(f"ab12abl_A{a}_enf{e}", a, P, ["--ab12_legitimize=1", ENF[e]])
    for e in ("on", "off"):
        add(f"ab8abl_A3_enf{e}", 3, P, ["--ab8_single_rsu=1", ENF[e]])
    for e in ("on", "off"):
        add(f"anchor_lrad_enf{e}", 0, 0, [ENF[e]])                                # benign anchor, LRAD
    add("anchor_tap", 0, 0, ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0"])
    add("anchor_sfto", 0, 0, ["--enable_sfto=1"])
    return J

def cmd(j):
    c = ["nice", "-n10", str(BIN), "--N_Vehicles=200", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0",
         "--maxspeed=150", "--use_sumo_mobility=1", "--architecture=3", f"--simTime={SIM}",
         f"--attack_percentage={j['pct']}", f"--attack_delay_ms={DELAY}", f"--sim_seed={SEED}",
         f"--run_tag={j['tag']}", "--enable_detector_windows=1"]
    if j["attack"] != 0: c.append(f"--attack_number={j['attack']}")
    if j["attack"] in (1, 2): c.append("--dw_mark_suspect=1")
    return c + j["extra"]

def purge(tag):
    n = 0
    for f in glob.glob(str(RES / f"*_{tag}.csv")) + glob.glob(str(RES / f"*_{tag}.txt")):
        os.remove(f); n += 1
    return n

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args()
    J = jobs(); LOGS.mkdir(parents=True, exist_ok=True)
    print(f"{len(J)} jobs")
    if a.dry_run:
        for j in J: print(" ".join(cmd(j)[3:]))
        return
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    running, queue = [], list(J)
    while queue or running:
        running = [(p, j) for p, j in running if p.poll() is None]
        while queue and len(running) < a.workers and os.getloadavg()[0] < 28:
            j = queue.pop(0); purge(j["tag"])
            p = subprocess.Popen(cmd(j), stdout=open(LOGS / (j["tag"] + ".log"), "w"), stderr=subprocess.STDOUT, env=env)
            running.append((p, j)); print("started", j["tag"], flush=True)
        time.sleep(5)
    print("ALL DONE", flush=True)

if __name__ == "__main__":
    main()
