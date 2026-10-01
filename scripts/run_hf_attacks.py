#!/usr/bin/env python3
"""
run_hf_attacks.py — Parallel launcher for Hidden Forwarding (HF) attack sweeps.

Runs all four HF attack variants across all 6 attack percentages {0,20,40,60,80,100}
as concurrent subprocesses.

Attack mapping:
  attack_number=5  →  active_attack_variant=4  →  Attack 5 (HF CP)
  attack_number=6  →  active_attack_variant=5  →  Attack 6 (HF DP)
  attack_number=7  →  active_attack_variant=6  →  Attack 7 (HF CP variant)
  attack_number=8  →  active_attack_variant=7  →  Attack 8 (HF DP variant)

Attack 5-8 each get TWO runs per percentage, mirroring run_std_attacks.py's
TAP pattern: once as the normal MOBIGUARD run (full S1-S8 stack active,
FADE inactive), and once as an isolated FADE-baseline run (--enable_lrad_obu=0
--enable_lrad_rsu=0, MOBIGUARD's entire S1-S8 stack disabled). The isolation
matters because record_detection_event(v, n) — called by S1, S2, and S5-S8 —
uses the CLI-selected active_attack_variant as its bucket key regardless of
which signature actually fired; S1/S2 (Selective Time Delay, unrelated to
Hidden Forwarding) run unconditionally on every packet no matter which
--attack_number is selected, so without isolation their own always-on false
triggers get misattributed into whichever HF variant this run is testing,
corrupting MOBIGUARD's own reported MCC/FPR for that variant. Isolating
FADE's run the same way TAP already is removes that contamination from the
comparison. See routing.cc's fade_detection_active assignment and
write_security_metrics_csv()'s guard (both updated 2026-07-12).

Result CSVs written by the simulation:
  results_routing/MOBIGUARD_Attack<N>_<pct>_seed<S>.csv   — MOBIGUARD detector (normal run only)
  results_routing/FADE_Attack<N>_<pct>_seed<S>.csv        — eFADE detector (isolated run only)

Per-run files in the NS-3 working directory (tagged, no collision):
  fade_results_Attack<N>_<pct>_seed<S>.csv   — per-flow FADE detection detail
  fade_metrics_Attack<N>_<pct>_seed<S>.csv   — per-run FADE summary row

Per-run logs (stdout + stderr):
  logs/A<N>_pct<P>_seed<S>.log        — normal MOBIGUARD run
  logs/A<N>_pct<P>_seed<S>_FADE.log   — isolated FADE baseline run

Usage examples:
  # Run all 48 combinations (4 attacks × 6 percentages × 2 modes) in parallel:
  python3 scripts/run_hf_attacks.py

  # Sync headers + rebuild first, then run:
  python3 scripts/run_hf_attacks.py --build

  # Run only Attack 5 at 40%:
  python3 scripts/run_hf_attacks.py --attack 5 --percentage 40

  # Limit to 6 parallel jobs:
  python3 scripts/run_hf_attacks.py --workers 6

  # Clear old result CSVs before starting:
  python3 scripts/run_hf_attacks.py --clean
"""

import argparse
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent.parent
NS3_DIR     = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
SCRATCH_DIR = NS3_DIR / "scratch"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = PROJECT_DIR / "logs"
BINARY_PATH = NS3_DIR / "build" / "scratch" / "routing" / "routing"

# ---------------------------------------------------------------------------
# Simulation parameters
# ---------------------------------------------------------------------------
ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

ATTACKS = [
    {"attack_number": 5, "label": "Attack5_HF_CP"},
    {"attack_number": 6, "label": "Attack6_HF_DP"},
    {"attack_number": 7, "label": "Attack7_HF_CP_v2"},
    {"attack_number": 8, "label": "Attack8_HF_DP_v2"},
]

FIXED_PARAMS = {
    "routing_test":      "false",
    "N_Vehicles":        200,
    "N_RSUs":            64,
    "N_Controllers":     4,
    "mobility_scenario": 0,
    "maxspeed":          150,
    "use_sumo_mobility": 1,
    "architecture":      3,
    # 2026-09-30 (supervisor): emit per-window detector grid so A5-A8 are scored
    # on the SAME per-window M1 convention as A1-A4 (the old sweep used per-cycle
    # avg_MCC, which is not comparable). See detector_windows.h / m1_local.py.
    "enable_detector_windows": 1,
}

# FADE baseline isolation overrides — disables MOBIGUARD's entire S1-S8
# stack (see lrad.h; AB1's own ablation never sets both flags to 0
# simultaneously, so this doesn't collide with AB1 data collection).
# Mirrors run_std_attacks.py's TAP_PARAMS exactly. fade_detection_active
# (routing.cc) requires both flags 0 to auto-enable, so this is also what
# makes FADE actually produce output — the normal run below no longer
# does.
FADE_PARAMS = {
    "enable_lrad_obu": 0,
    "enable_lrad_rsu": 0,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sync_files() -> None:
    print("── Syncing project files to NS-3 scratch ──")
    routing_dir = SCRATCH_DIR / "routing"
    routing_dir.mkdir(parents=True, exist_ok=True)

    # A stale scratch/routing.cc (from before routing.cc was moved into
    # scratch/routing/) creates a second program also named 'routing', which
    # collides with the subdir target and breaks the build. Remove it.
    stale = SCRATCH_DIR / "routing.cc"
    if stale.exists():
        stale.unlink()
        print(f"  removed stale  {stale.relative_to(SCRATCH_DIR.parent)}")

    for src in sorted((PROJECT_DIR / "scratch").iterdir()):
        if not src.is_file():
            continue
        if src.name == "routing.cc" or src.suffix == ".h":
            # routing.cc builds as the 'routing' program from scratch/routing/.
            # Its #include "..." project headers must sit in the same directory,
            # because waf only adds the program's own dir to the include path.
            dest = routing_dir / src.name
        else:
            # .py helpers are loaded by routing.cc via hardcoded scratch/ paths.
            dest = SCRATCH_DIR / src.name
        
        # Avoid SameFileError for symlinked setups
        if dest.exists() and os.path.samefile(src, dest):
            print(f"  already synced  {src.name}")
            continue
            
        shutil.copy2(src, dest)
        print(f"  copied  {src.name}  →  {dest.relative_to(SCRATCH_DIR.parent)}")


def build_simulation() -> bool:
    print("\n── Building NS-3 simulation ──")
    result = subprocess.run(["./waf", "build"], cwd=NS3_DIR, text=True)
    if result.returncode != 0:
        print("ERROR: Build failed. Fix compilation errors before running.")
        return False
    print("Build successful.\n")
    return True


def clean_results(attack: int | None, percentage: int | None) -> None:
    attacks = [attack] if attack else [a["attack_number"] for a in ATTACKS]
    percs   = [percentage] if percentage is not None else ATTACK_PERCENTAGES

    removed = 0
    for a in attacks:
        for p in percs:
            # Glob rather than exact match: seed is now native to both filenames.
            for pat in (f"MOBIGUARD_Attack{a}_{p}_seed*.csv",
                        f"FADE_Attack{a}_{p}_seed*.csv"):
                for f in RESULTS_DIR.glob(pat):
                    f.unlink()
                    removed += 1
    if removed:
        print(f"── Removed {removed} old result file(s) ──\n")


def build_waf_command(attack_number: int, attack_percentage: int,
                      sim_time: int, seed: int, sim_run: int,
                      extra_params: dict | None = None) -> list[str]:
    params = dict(FIXED_PARAMS)
    params["simTime"]           = sim_time
    params["attack_number"]     = attack_number
    params["attack_percentage"] = attack_percentage
    params["sim_seed"]          = seed
    params["sim_run"]           = sim_run
    if extra_params:
        params.update(extra_params)

    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    # routing.cc lives in scratch/routing/, so waf registers the program as
    # 'scratch/routing/routing' (not 'scratch/routing').
    # --run-no-build: concurrent workers must not each do their own implicit
    # build check (races on the shared build dir — see run_std_attacks.py's
    # identical comment for the JSONDecodeError this caused live). Build
    # once via --build before running the sweep.
    return ["./waf", "--run-no-build", f"scratch/routing/routing {param_str}"]


def run_one(attack_number: int, attack_percentage: int,
            sim_time: int, seed: int, sim_run: int,
            log_path: Path, extra_params: dict | None = None,
            label_suffix: str = "") -> dict:
    label = f"A{attack_number}_pct{attack_percentage}{label_suffix}"
    cmd   = build_waf_command(attack_number, attack_percentage, sim_time, seed, sim_run, extra_params)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now()
    print(f"  [{label}] started  {start.strftime('%H:%M:%S')}  →  {log_path.name}")

    with open(log_path, "w") as logf:
        logf.write(f"# Command: {' '.join(cmd)}\n")
        logf.write(f"# Started: {start.isoformat()}\n\n")
        logf.flush()
        proc = subprocess.run(
            cmd,
            cwd=NS3_DIR,
            stdout=logf,
            stderr=subprocess.STDOUT,
            text=True,
        )

    elapsed = (datetime.now() - start).total_seconds()
    ok      = proc.returncode == 0
    print(f"  [{label}] {'OK' if ok else 'FAILED':<6}  {elapsed:5.0f}s  →  {log_path.name}")

    return {
        "label":             label,
        "attack_number":     attack_number,
        "attack_percentage": attack_percentage,
        "returncode":        proc.returncode,
        "elapsed_s":         elapsed,
        "log":               log_path,
        "ok":                ok,
    }


def check_results(scope_attacks: list[int], scope_percs: list[int], seed: int) -> None:
    print("\n── Result files ──")
    all_ok = True
    for a in scope_attacks:
        for p in scope_percs:
            for f in [
                RESULTS_DIR / f"MOBIGUARD_Attack{a}_{p}_seed{seed}.csv",
                RESULTS_DIR / f"FADE_Attack{a}_{p}_seed{seed}.csv",
            ]:
                exists = f.exists() and f.stat().st_size > 0
                mark   = "✓" if exists else "✗ MISSING"
                print(f"  {mark:<10}  {f.name}")
                if not exists:
                    all_ok = False
    if all_ok:
        print("\n  All expected result files present.")
    else:
        print("\n  Some files missing — check the corresponding log in logs/")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch Hidden Forwarding attack simulations in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--build", action="store_true",
        help="Build-only: sync project headers to scratch, run ./waf build, then EXIT "
             "without simulating. Re-run without --build to launch the sweep.",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Delete old result CSVs for the selected scope before running.",
    )
    parser.add_argument(
        "--attack", type=int, choices=[5, 6, 7, 8], default=None,
        help="Run only this attack number (default: all four 5–8).",
    )
    parser.add_argument(
        "--percentage", type=int, choices=ATTACK_PERCENTAGES, default=None,
        metavar="{0,20,40,60,80,100}",
        help="Run only this attack percentage (default: all six).",
    )
    parser.add_argument(
        "--sim-time", type=int, default=40,
        help="Simulation duration in seconds (default: 40 for quick testing; use 300 for thesis runs).",
    )
    parser.add_argument(
        "--seed", type=int, default=1,
        help="NS-3 RNG seed (default: 1).",
    )
    parser.add_argument(
        "--sim-run", type=int, default=1,
        help="NS-3 RNG run index (default: 1).",
    )
    parser.add_argument(
        "--workers", type=int, default=12,
        help="Maximum number of parallel simulation processes (default: 12).",
    )
    args = parser.parse_args()

    # --build is build-ONLY: sync, compile, then EXIT. It deliberately does
    # NOT fall through into the sweep (see run_std_attacks.py's identical
    # convention) — otherwise `--build` silently launches a full multi-hour
    # run, and concurrent sweep workers would each redo their own implicit
    # build check via plain `--run`, racing on the shared build dir.
    if args.build:
        sync_files()
        if not build_simulation():
            sys.exit(1)
        print("Build complete. Re-run without --build to launch the simulations.")
        sys.exit(0)

    if not BINARY_PATH.exists():
        print(f"ERROR: {BINARY_PATH} not found. Run with --build first.")
        sys.exit(1)

    scope_attacks = [args.attack] if args.attack else [a["attack_number"] for a in ATTACKS]
    scope_percs   = [args.percentage] if args.percentage is not None else ATTACK_PERCENTAGES

    if args.clean:
        clean_results(args.attack, args.percentage)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Two runs per (attack, pct): the normal MOBIGUARD run (full S1-S8,
    # writes MOBIGUARD_Attack<N>_<pct>_seed<S>.csv) and the isolated
    # FADE-baseline run (S1-S8 off via FADE_PARAMS, writes
    # FADE_Attack<N>_<pct>_seed<S>.csv). See module docstring for why
    # isolation is needed.
    runs = []
    for a in scope_attacks:
        for p in scope_percs:
            runs.append({
                "attack_number":     a,
                "attack_percentage": p,
                "extra_params":      None,
                "label_suffix":      "",
                "log": LOGS_DIR / f"A{a}_pct{p}_seed{args.seed}.log",
            })
            runs.append({
                "attack_number":     a,
                "attack_percentage": p,
                "extra_params":      FADE_PARAMS,
                "label_suffix":      "_FADE",
                "log": LOGS_DIR / f"A{a}_pct{p}_seed{args.seed}_FADE.log",
            })

    total = len(runs)
    print(
        f"\n── Launching {total} run(s)  "
        f"[attacks={scope_attacks}  percentages={scope_percs}  "
        f"simTime={args.sim_time}s  seed={args.seed}  "
        f"workers={min(args.workers, total)}] ──\n"
    )

    passed, failed = [], []
    wall_start = datetime.now()

    with ThreadPoolExecutor(max_workers=min(args.workers, total)) as pool:
        futures = {
            pool.submit(
                run_one,
                r["attack_number"],
                r["attack_percentage"],
                args.sim_time,
                args.seed,
                args.sim_run,
                r["log"],
                r["extra_params"],
                r["label_suffix"],
            ): r
            for r in runs
        }
        for fut in as_completed(futures):
            result = fut.result()
            (passed if result["ok"] else failed).append(result)

    wall_elapsed = (datetime.now() - wall_start).total_seconds()

    print(f"\n── Summary  (wall time: {wall_elapsed:.0f}s) ──")
    print(f"  Passed : {len(passed)}/{total}")
    if failed:
        print(f"  Failed : {len(failed)}")
        for r in failed:
            print(f"    {r['label']}  (returncode={r['returncode']})")
            print(f"      log → {r['log']}")

    check_results(scope_attacks, scope_percs, args.seed)
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
