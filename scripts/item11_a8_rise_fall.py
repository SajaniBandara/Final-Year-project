#!/usr/bin/env python3
"""
item11_a8_rise_fall.py — P1 of docs/HPC_TASKS_2026-08-31.md.

The published A8 UCR curve was explained as "unauthorised copies surge at onset,
then quarantine drives them back to zero". Quarantine had NO enforcement path
when that curve was produced (g_quarantined[] was write-only, fixed in 6cb1189),
so quarantine cannot be the mechanism. This re-runs A8 @60%, 5 seeds, 300 s in
two arms:

  OFF arm (--enable_quarantine_enforcement=0) — reproduces the published curve
          and lets us find what actually causes the decline.
  ON  arm (--enable_quarantine_enforcement=1) — tests whether the *intended*
          mechanism reproduces the same shape.

Arms are separated by --run_tag so they cannot clobber each other's CSVs:
  results_routing/MOBIGUARD_Attack8_60_seed<S>_i11off<S>.csv
  results_routing/MOBIGUARD_Attack8_60_seed<S>_i11on<S>.csv
"""
import subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

NS3  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
LOGS = Path.home() / "ns3_g13/g13_project_repo/Final-Year-project/logs/item11_p1"
SEEDS = [1, 2, 3, 4, 5]

BASE = {
    "routing_test": "false", "N_Vehicles": 200, "N_RSUs": 64, "N_Controllers": 4,
    "mobility_scenario": 0, "maxspeed": 150, "use_sumo_mobility": 1,
    "architecture": 3, "simTime": 300, "attack_number": 8, "attack_percentage": 60,
}

def job(seed, enforce):
    arm = "on" if enforce else "off"
    p = dict(BASE)
    p["sim_seed"] = seed
    p["sim_run"]  = 1
    p["enable_quarantine_enforcement"] = 1 if enforce else 0
    p["run_tag"]  = f"i11{arm}{seed}"
    args = " ".join(f"--{k}={v}" for k, v in p.items())
    cmd  = ["./waf", "--run-no-build", f"scratch/routing/routing {args}"]
    log  = LOGS / f"A8_60_seed{seed}_{arm}.log"
    t0 = datetime.now()
    print(f"  [A8 seed{seed} enf={arm}] start {t0:%H:%M:%S}", flush=True)
    with open(log, "w") as f:
        f.write(f"# Command: {' '.join(cmd)}\n# Started: {t0.isoformat()}\n\n")
        f.flush()
        rc = subprocess.run(cmd, cwd=NS3, stdout=f, stderr=subprocess.STDOUT,
                            text=True).returncode
    el = (datetime.now() - t0).total_seconds()
    print(f"  [A8 seed{seed} enf={arm}] {'OK' if rc==0 else 'FAILED'} {el:.0f}s", flush=True)
    return (seed, arm, rc, el)

if __name__ == "__main__":
    jobs = [(s, e) for e in (False, True) for s in SEEDS]
    print(f"── item11 P1: {len(jobs)} runs (A8@60%, 300s, 5 seeds x 2 arms) ──", flush=True)
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(lambda a: job(*a), jobs))
    print(f"\n── done in {(time.time()-t0)/60:.1f} min ──", flush=True)
    bad = [r for r in res if r[2] != 0]
    print("all runs returned 0" if not bad else f"FAILED: {bad}", flush=True)
