#!/usr/bin/env python3
"""
run_ablation_sweep2.py — AB6, AB7, AB8, AB9, AB11 metrics sweep.

All five flags already exist and are functionally smoke-tested by
functional_verification.py; this script is the first thing that actually
collects METRICS for them.

Per-ablation attack scope (main.tex's own y-metric scoping, cross-checked
against the actual C++ — see 2026-08-30 session notes):

  AB6  (witness mechanism):        Attacks {7,8}      pct=60
       --enable_witness_mechanism=0/1
  AB7  (quarantine):                Attacks {1..8}     pct=60
       --enable_quarantine=0/1
  AB8  (endorsement/UFCR):          Attacks {1,3,5,7}  pct=60
       --enable_endorsement_requirement=0/1
  AB9  (controller failover):       Attacks {1,3}      pct=20  <-- NOT 60
       --enable_controller_failover=0/1
  AB11 (ZKP key rotation):          Attacks {5,6,7,8}  pct=60
       --enable_key_rotation=0/1

AB9's pct=20 is deliberate, not a typo: main.tex's AB9 x-variable is
"evaluated under ONE compromised controller" (singular). controller_compromised[]
(attack_declaration.h, routing.cc's Attack-3 init block) is populated by a
3-band threshold ladder keyed on attack_percentage, and only ever really
implemented for Attacks 1 and 3 (Attacks 5/7 are labeled "Control Plane" in
the attack_declaration.h switch but their init blocks never write
controller_compromised[] -- a real gap, tracked separately, NOT fixed by
this script). At pct=60 (this repo's other-ablations default) the ladder
compromises 2 of 4 controllers; the "exactly one" band is 0 < pct < 33, so
pct=20 is used for AB9 specifically to match main.tex's stated condition.
Verified both Attack 1's (attack_declaration.h:227-237) and Attack 3's
(routing.cc:115288-115295) ladders agree pct=20 -> num_compromised=1.

Filename uniqueness: uses --run_tag (see run_ablation_sweep.py's docstring
for the full two-bugs-found-before-this-fix history). --run_tag=AB6A etc.
makes every per-run output file unique from the moment it's opened --
no Python-side delete-before-run or rename-after-run, and critically no
risk of THIS script's cleanup deleting run_ablation_sweep.py's AB1/AB4
results (or vice versa) the way the tag-list approach did on 2026-08-30.

Usage:
  python3 scripts/run_ablation_sweep2.py --workers 8
  python3 scripts/run_ablation_sweep2.py --only ab9 --workers 2
"""

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

NS3_DIR     = Path.home() / "G_13/ns-allinone-3.35/ns-3.35"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = Path(__file__).resolve().parent.parent / "logs" / "ablation_sweep2"
BINARY_PATH = NS3_DIR / "build" / "scratch" / "routing" / "routing"

BASE_PARAMS = {
    "routing_test": "false", "N_Vehicles": 200, "N_RSUs": 64, "N_Controllers": 4,
    "mobility_scenario": 0, "maxspeed": 150, "use_sumo_mobility": 1, "architecture": 3,
    "simTime": 40, "sim_seed": 1, "sim_run": 1,
}

# name -> (configs, attacks, pct)
ABLATIONS = {
    "ab6":  ({"AB6A": {"enable_witness_mechanism": 0},
              "AB6B": {"enable_witness_mechanism": 1}},
             [7, 8], 60),
    "ab7":  ({"AB7A": {"enable_quarantine": 0},
              "AB7B": {"enable_quarantine": 1}},
             [1, 2, 3, 4, 5, 6, 7, 8], 60),
    "ab8":  ({"AB8A": {"enable_endorsement_requirement": 0},
              "AB8B": {"enable_endorsement_requirement": 1}},
             [1, 3, 5, 7], 60),
    "ab9":  ({"AB9A": {"enable_controller_failover": 0},
              "AB9B": {"enable_controller_failover": 1}},
             [1, 3], 20),
    "ab11": ({"AB11A": {"enable_key_rotation": 0},
              "AB11B": {"enable_key_rotation": 1}},
             [5, 6, 7, 8], 60),
}


def result_filename(attack_number: int, pct: int, seed: int, tag: str) -> str:
    suffix = "_d80ms" if attack_number in (1, 2) else ""
    return f"MOBIGUARD_Attack{attack_number}_{pct}{suffix}_seed{seed}_{tag}.csv"


def build_cmd(attack_number: int, pct: int, tag: str, extra: dict) -> list:
    params = dict(BASE_PARAMS)
    params["attack_number"]     = attack_number
    params["attack_percentage"] = pct
    params["run_tag"]           = tag
    if attack_number in (1, 2):
        params["attack_delay_ms"] = 80
        params["attack_delay_pseudo_random"] = 0
    params.update(extra)
    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    return ["nice", "-n", "15", "ionice", "-c2", "-n7",
            "./waf", "--run-no-build", f"scratch/routing/routing {param_str}"]


def run_lane(attack_number: int, pct: int, configs: dict) -> list:
    seed = BASE_PARAMS["sim_seed"]
    out = []
    for tag, extra in configs.items():
        label = f"A{attack_number}p{pct}_{tag}"
        log_path = LOGS_DIR / f"{label}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = build_cmd(attack_number, pct, tag, extra)
        start = datetime.now()
        print(f"  [{label}] started {start.strftime('%H:%M:%S')}")
        with open(log_path, "w") as logf:
            logf.write(f"# Command: {' '.join(cmd)}\n")
            proc = subprocess.run(cmd, cwd=NS3_DIR, stdout=logf, stderr=subprocess.STDOUT, text=True)
        elapsed = (datetime.now() - start).total_seconds()
        ok = proc.returncode == 0

        dst = RESULTS_DIR / result_filename(attack_number, pct, seed, tag)
        produced = dst.exists()
        print(f"  [{label}] {'OK' if ok else 'FAILED':<6} {elapsed:5.0f}s "
              f"{'-> ' + dst.name if produced else '(NO OUTPUT)'}")
        out.append({"label": label, "ok": ok, "renamed": produced})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8,
                     help="Parallel ns-3 runs (hard-capped at 10 per "
                          "2026-08-30 machine-safety guidance).")
    ap.add_argument("--only", choices=list(ABLATIONS) + ["all"], default="all")
    args = ap.parse_args()
    workers = min(args.workers, 10)

    if not BINARY_PATH.exists():
        raise SystemExit(f"{BINARY_PATH} not found — build first (./waf build).")

    selected = list(ABLATIONS) if args.only == "all" else [args.only]

    merged: dict[tuple[int, int], dict] = {}
    for name in selected:
        configs, attacks, pct = ABLATIONS[name]
        for a in attacks:
            key = (a, pct)
            merged.setdefault(key, {}).update(configs)

    total_runs = sum(len(c) for c in merged.values())
    print(f"-- Launching {len(merged)} lane(s), {total_runs} total runs, "
          f"workers={min(workers, len(merged))} --\n")

    wall_start = datetime.now()
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, len(merged))) as pool:
        futures = {pool.submit(run_lane, a, pct, cfg): (a, pct)
                   for (a, pct), cfg in merged.items()}
        for fut in as_completed(futures):
            results.extend(fut.result())

    wall = (datetime.now() - wall_start).total_seconds()
    passed = sum(1 for r in results if r["ok"] and r["renamed"])
    print(f"\n-- Summary (wall time: {wall:.0f}s) -- Passed: {passed}/{total_runs}")


if __name__ == "__main__":
    main()
