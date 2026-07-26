#!/usr/bin/env python3
"""
run_ablation_sweep.py — AB4 (STARK proof ablation) + M1 per-mode
(AB1-A/AB1-B OBU-only vs RSU-only) scoped verification sweep.

SCOPE (deliberately reduced from a full 6-pct x 3-seed grid, given per-run
wall-clock cost on this machine): single seed (1), single percentage (60%)
only. The "both on" / "AB1-C full dual-mode" baseline for both ablations
is already covered by the production 144-run rule-based sweep — this
script only collects the NEW configs that don't exist yet:

  AB4-A (no ZKP):        --enable_stark_delay=0 --enable_stark_hop=0
  AB4-B (delay only):    --enable_stark_delay=1 --enable_stark_hop=0
  AB4-C (hop only):      --enable_stark_delay=0 --enable_stark_hop=1
  AB4 scope: attacks 1,2,5,6,7,8 (STARK proofs aren't primary signals for
  the TCAM attacks 3/4, per main.tex's own AB4 y-metrics: M2/TVR sensitive
  to pi_delay, M3/UCR sensitive to pi_hop — both are Selective-Delay/HF
  metrics, not TCAM).

  AB1-A (rule-only, OBU):  --enable_lrad_rsu=0   (RSU engine off)
  AB1-B (LSTM-only, RSU):  --enable_lrad_obu=0   (OBU engine off)
  AB1 scope: all 8 attacks.

Filename-collision handling: write_security_metrics_csv() names files by
(attack_number, pct) only, regardless of which ablation flags were passed
— multiple configs targeting the SAME (attack, pct) would collide exactly
like the seed-contamination bug found earlier this session. Every config
touching a given (attack, pct) therefore runs in one SEQUENTIAL lane
(mirroring run_rule_based_sweep.py), renaming the result to embed a
config tag immediately after each run.

Usage:
  python3 scripts/run_ablation_sweep.py --workers 16
"""

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

NS3_DIR     = Path.home() / "ns3_g13_apsari/ns-allinone-3.35/ns-3.35"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = Path(__file__).resolve().parent.parent / "logs" / "ablation_sweep"
BINARY_PATH = NS3_DIR / "build" / "scratch" / "routing" / "routing"

FIXED_PARAMS = {
    "routing_test": "false", "N_Vehicles": 200, "N_RSUs": 64, "N_Controllers": 4,
    "mobility_scenario": 0, "maxspeed": 150, "use_sumo_mobility": 1, "architecture": 3,
    "simTime": 40, "attack_percentage": 60, "sim_seed": 1, "sim_run": 1,
}

AB4_CONFIGS = {
    "AB4A": {"enable_stark_delay": 0, "enable_stark_hop": 0},
    "AB4B": {"enable_stark_delay": 1, "enable_stark_hop": 0},
    "AB4C": {"enable_stark_delay": 0, "enable_stark_hop": 1},
}
AB4_ATTACKS = [1, 2, 5, 6, 7, 8]

AB1_CONFIGS = {
    "AB1A": {"enable_lrad_rsu": 0},   # rule-only (OBU)
    "AB1B": {"enable_lrad_obu": 0},   # LSTM-only (RSU)
}
AB1_ATTACKS = [1, 2, 3, 4, 5, 6, 7, 8]


def result_filename(attack_number: int) -> str:
    suffix = "_d80ms" if attack_number in (1, 2) else ""
    return f"MOBIGUARD_Attack{attack_number}_60{suffix}.csv"


def build_cmd(attack_number: int, extra: dict) -> list:
    params = dict(FIXED_PARAMS)
    params["attack_number"] = attack_number
    if attack_number in (1, 2):
        # Exact 80ms (filename tags "_d80ms") -- must disable the banded
        # pseudo-random draw (attack_delay_pseudo_random default=true as of
        # the mobility amplification fix, scratch/attack_variables.h) or
        # this sweep silently gets a random 72-88ms delay per packet instead.
        params["attack_delay_ms"] = 80
        params["attack_delay_pseudo_random"] = 0
    params.update(extra)
    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    return ["./waf", "--run-no-build", f"scratch/routing/routing {param_str}"]


def run_lane(attack_number: int, configs: dict) -> list:
    """Runs every config in `configs` for one attack SEQUENTIALLY (avoids
    the shared-filename collision), renaming each result immediately."""
    out = []
    for tag, extra in configs.items():
        label = f"A{attack_number}_{tag}"
        log_path = LOGS_DIR / f"{label}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = build_cmd(attack_number, extra)
        start = datetime.now()
        print(f"  [{label}] started {start.strftime('%H:%M:%S')}")
        with open(log_path, "w") as logf:
            logf.write(f"# Command: {' '.join(cmd)}\n")
            proc = subprocess.run(cmd, cwd=NS3_DIR, stdout=logf, stderr=subprocess.STDOUT, text=True)
        elapsed = (datetime.now() - start).total_seconds()
        ok = proc.returncode == 0

        src = RESULTS_DIR / result_filename(attack_number)
        dst = RESULTS_DIR / src.name.replace(".csv", f"_{tag}.csv")
        renamed = False
        if src.exists():
            src.rename(dst)
            renamed = True
        print(f"  [{label}] {'OK' if ok else 'FAILED':<6} {elapsed:5.0f}s "
              f"{'-> ' + dst.name if renamed else '(NO OUTPUT)'}")
        out.append({"label": label, "ok": ok, "renamed": renamed})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    if not BINARY_PATH.exists():
        raise SystemExit(f"{BINARY_PATH} not found — build first (./waf build).")

    lanes = [(a, AB4_CONFIGS) for a in AB4_ATTACKS] + [(a, AB1_CONFIGS) for a in AB1_ATTACKS]
    # AB4 and AB1 both touch attacks 1,2,5,6,7,8 — merge into ONE lane per
    # attack so the same (attack,pct) is never targeted by two lanes at once.
    merged = {}
    for a in set(AB4_ATTACKS) | set(AB1_ATTACKS):
        cfg = {}
        if a in AB4_ATTACKS:
            cfg.update(AB4_CONFIGS)
        if a in AB1_ATTACKS:
            cfg.update(AB1_CONFIGS)
        merged[a] = cfg
    total_runs = sum(len(c) for c in merged.values())
    print(f"-- Launching {len(merged)} lane(s), {total_runs} total runs, "
          f"workers={min(args.workers, len(merged))} --\n")

    wall_start = datetime.now()
    results = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(merged))) as pool:
        futures = {pool.submit(run_lane, a, cfg): a for a, cfg in merged.items()}
        for fut in as_completed(futures):
            results.extend(fut.result())

    wall = (datetime.now() - wall_start).total_seconds()
    passed = sum(1 for r in results if r["ok"] and r["renamed"])
    print(f"\n-- Summary (wall time: {wall:.0f}s) -- Passed: {passed}/{total_runs}")


if __name__ == "__main__":
    main()
