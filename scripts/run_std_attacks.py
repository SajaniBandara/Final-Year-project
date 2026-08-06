#!/usr/bin/env python3
"""
run_std_attacks.py — Parallel launcher for Selective Time Delay attack sweeps.

Runs both attack variants across all 6 attack percentages {0,20,40,60,80,100}
as concurrent subprocesses so every combination finishes in the time of the
longest single run instead of serially.

Every attack runs TWICE per (percentage, delay): once as the normal MOBIGUARD
run, and once as a TAP baseline run (--enable_tap=1, MOBIGUARD's own S1-S8
detectors disabled via --enable_lrad_obu=0 --enable_lrad_rsu=0) — this is
what actually produces the TAP__Attack<N>_<pct>_seed<S>.csv files. Note:
scripts/plot_tap_results.py defaults to Attack 2 (--attack lets you pick
Attack 1 instead) — it plots one attack per run, not both at once.

Result CSVs written by the simulation:
  results_routing/MOBIGUARD_Attack1_<pct>[_d<X>ms]_seed<S>.csv  — Attack 1 (CP), MOBIGUARD S1 detector
  results_routing/TAP__Attack1_<pct>[_d<X>ms]_seed<S>.csv       — Attack 1 (CP), TAP baseline detector
  results_routing/MOBIGUARD_Attack2_<pct>[_d<X>ms]_seed<S>.csv  — Attack 2 (DP), MOBIGUARD S2 detector
  results_routing/TAP__Attack2_<pct>[_d<X>ms]_seed<S>.csv       — Attack 2 (DP), TAP baseline detector

Per-run logs (stdout + stderr):
  logs/A<N>_pct<P>[_d<X>ms]_seed<S>.log

Usage examples:
  # Run all 24 combinations (2 attacks × 6 percentages × MOBIGUARD+TAP) in parallel:
  python3 scripts/run_std_attacks.py

  # Sync headers + rebuild only, then exit (run again without --build to simulate):
  python3 scripts/run_std_attacks.py --build
  python3 scripts/run_std_attacks.py            # now launch the sweep with the fresh binary

  # Run only Attack 1 at 40%:
  python3 scripts/run_std_attacks.py --attack 1 --percentage 40

  # Sweep a fixed delay as an independent variable (threshold validation experiment):
  python3 scripts/run_std_attacks.py --delay 40 55 60 80 100 200

  # Shorthand for the full default delay sweep set:
  python3 scripts/run_std_attacks.py --delay-sweep

  # Combine delay sweep with a specific attack/percentage:
  python3 scripts/run_std_attacks.py --attack 2 --percentage 40 --delay 40 55 60 80 100

  # Use a different RNG seed / run index:
  python3 scripts/run_std_attacks.py --seed 2 --sim-run 3

  # Limit to 4 parallel jobs (useful on low-core machines):
  python3 scripts/run_std_attacks.py --workers 4

  # Clear old result CSVs before starting:
  python3 scripts/run_std_attacks.py --clean
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
PROJECT_DIR = Path(__file__).resolve().parent.parent          # …/Final-Year-project/
NS3_DIR     = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
SCRATCH_DIR = NS3_DIR / "scratch"
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = PROJECT_DIR / "logs"
BINARY_PATH = NS3_DIR / "build" / "scratch" / "routing" / "routing"

# ---------------------------------------------------------------------------
# Simulation parameters — mirrors run_attack2_sweep.sh conventions
# ---------------------------------------------------------------------------
ATTACK_PERCENTAGES = [0, 20, 40, 60, 80, 100]

ATTACKS = [
    {"attack_number": 1, "label": "Attack1_CP"},
    {"attack_number": 2, "label": "Attack2_DP"},
]

# Default delay sweep for --delay-sweep (ms). Chosen to straddle the S1/S2
# detection thresholds: S2 Δ_max = 50 ms, S1 baseline ~2 ms + 3σ.
DELAY_SWEEP_MS = [40, 50, 55, 60, 80, 100, 150, 200]

# Fixed topology / mobility parameters shared across all runs.
FIXED_PARAMS = {
    "routing_test":      "false",
    "N_Vehicles":        200,
    "N_RSUs":            64,
    "N_Controllers":     4,
    "mobility_scenario": 0,
    "maxspeed":          150,
    "use_sumo_mobility": 1,
    "architecture":      3,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def delay_suffix(delay_ms: int | None) -> str:
    """Return the filename suffix for a fixed delay, e.g. '_d80ms', or '' if none."""
    return f"_d{delay_ms}ms" if delay_ms is not None else ""


def sync_files() -> None:
    """Copy project scratch files into ns-3.35/scratch/routing/ (subdirectory form)."""
    print("── Syncing project files to NS-3 scratch ──")
    routing_dir = SCRATCH_DIR / "routing"
    routing_dir.mkdir(parents=True, exist_ok=True)

    # A stale scratch/routing.cc from before the move to the subdirectory
    # creates a second 'routing' program that collides with the subdir target.
    stale = SCRATCH_DIR / "routing.cc"
    if stale.exists():
        stale.unlink()
        print(f"  removed stale  scratch/routing.cc")

    for src in sorted((PROJECT_DIR / "scratch").iterdir()):
        if not src.is_file():
            continue
        if src.name == "routing.cc" or src.suffix == ".h":
            dest = routing_dir / src.name
        else:
            dest = SCRATCH_DIR / src.name
        
        # Avoid SameFileError for symlinked setups
        if dest.exists() and os.path.samefile(src, dest):
            print(f"  already synced  {src.name}")
            continue
            
        shutil.copy2(src, dest)
        print(f"  copied  {src.name}  →  {dest.relative_to(SCRATCH_DIR.parent)}")


def build_simulation() -> bool:
    """Run ./waf build. Returns True on success."""
    print("\n── Building NS-3 simulation ──")
    result = subprocess.run(["./waf", "build"], cwd=NS3_DIR, text=True)
    if result.returncode != 0:
        print("ERROR: Build failed. Fix compilation errors before running.")
        return False
    print("Build successful.\n")
    return True


def clean_results(attack: int | None, percentage: int | None,
                  delays: list[int | None]) -> None:
    """Remove old result CSVs that match the requested scope."""
    attacks = [attack] if attack else [1, 2]
    percs   = [percentage] if percentage is not None else ATTACK_PERCENTAGES

    removed = 0
    for a in attacks:
        for p in percs:
            for d in delays:
                sfx = delay_suffix(d)
                # Glob rather than an exact seed match — clean should catch
                # stale files from any prior seed, not just the one about to run.
                patterns = [
                    f"MOBIGUARD_Attack{a}_{p}{sfx}_seed*.csv",
                    f"TAP__Attack{a}_{p}{sfx}_seed*.csv",
                ]
                for pat in patterns:
                    for f in RESULTS_DIR.glob(pat):
                        f.unlink()
                        removed += 1
    if removed:
        print(f"── Removed {removed} old result file(s) ──\n")


# TAP baseline (Arsalan & Rehman FIT 2018) run overrides. Runs against both
# attacks: tap_process_packet() (tap_detection.h) is gated only on
# enable_tap and is_safety_critical_flow — its call site in routing.cc's
# MacRx receive path has no attack-number dependency — so TAP is exercised
# identically regardless of which attack is active. --enable_lrad_obu/
# --enable_lrad_rsu=0 disables MOBIGUARD's own S1-S8 signature detectors so
# the TAP run is a clean TAP-only baseline, not TAP+MOBIGUARD running
# simultaneously. scripts/plot_tap_results.py --attack 1|2 selects which
# attack's TAP__Attack<N>_*.csv to plot (default 2).
TAP_PARAMS = {
    "enable_tap":       1,
    "enable_lrad_obu":  0,
    "enable_lrad_rsu":  0,
}


def build_waf_command(attack_number: int, attack_percentage: int,
                      sim_time: int, seed: int, sim_run: int,
                      delay_ms: int | None,
                      extra_params: dict | None = None) -> list[str]:
    """Construct the full ./waf --run-no-build command for one simulation run."""
    params = dict(FIXED_PARAMS)
    params["simTime"]           = sim_time
    params["attack_number"]     = attack_number
    params["attack_percentage"] = attack_percentage
    params["sim_seed"]          = seed
    params["sim_run"]           = sim_run
    if delay_ms is not None:
        params["attack_delay_ms"] = delay_ms
        # §4.3 (docs/MOBILITY_AMPLIFICATION_FIX_PLAN.md) — this script is the
        # Experiment 1/2 run path; opt into the bounded pseudo-random band
        # around delay_ms explicitly. The C++ default is deterministic/off
        # (see attack_variables.h), so every OTHER caller of routing.cc
        # (run_ablation_sweep.py, run_rule_based_sweep.py, etc.) that never
        # passes this flag is unaffected and keeps exact deterministic delay.
        params["attack_delay_pseudo_random"] = 1
    if extra_params:
        params.update(extra_params)

    param_str = " ".join(f"--{k}={v}" for k, v in params.items())
    # --run-no-build (not --run): every sweep launches many of these at once
    # (up to --workers concurrently), and plain --run makes each invocation do
    # its own implicit build check first. Those concurrent implicit builds
    # raced on the shared build/compile_commands.json (clang_compilation_database
    # post-build hook), crashing whichever run lost the race before it ever
    # started simulating — confirmed live: an Attack-2 TAP run's log showed a
    # JSONDecodeError in that hook, seconds after launch, with zero simulation
    # output. --build already compiles the binary and exits before any sweep
    # runs, so re-checking the build here is redundant as well as unsafe.
    return ["./waf", "--run-no-build", f"scratch/routing/routing {param_str}"]


def run_one(attack_number: int, attack_percentage: int,
            sim_time: int, seed: int, sim_run: int,
            delay_ms: int | None, log_path: Path,
            extra_params: dict | None = None, label_suffix: str = "") -> dict:
    """Execute a single simulation run."""
    sfx   = delay_suffix(delay_ms)
    label = f"A{attack_number}_pct{attack_percentage}{sfx}{label_suffix}"
    cmd   = build_waf_command(attack_number, attack_percentage,
                               sim_time, seed, sim_run, delay_ms, extra_params)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now()
    print(f"  [{label}] started  {start.strftime('%H:%M:%S')}  →  {log_path.name}")

    with open(log_path, "w") as logf:
        logf.flush()
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
    status  = "OK" if ok else "FAILED"
    print(f"  [{label}] {status:<6}  {elapsed:5.0f}s  →  {log_path.name}")

    return {
        "label":             label,
        "attack_number":     attack_number,
        "attack_percentage": attack_percentage,
        "delay_ms":          delay_ms,
        "returncode":        proc.returncode,
        "elapsed_s":         elapsed,
        "log":               log_path,
        "ok":                ok,
    }


def check_results(scope_attacks: list[int], scope_percs: list[int],
                  scope_delays: list[int | None], seed: int) -> None:
    """Print a table showing which expected result CSVs were produced."""
    print("\n── Result files ──")
    all_ok = True
    for d in scope_delays:
        sfx = delay_suffix(d)
        if d is not None:
            print(f"  delay={d}ms:")
        for a in scope_attacks:
            for p in scope_percs:
                files = [
                    RESULTS_DIR / f"MOBIGUARD_Attack{a}_{p}{sfx}_seed{seed}.csv",
                    RESULTS_DIR / f"TAP__Attack{a}_{p}{sfx}_seed{seed}.csv",
                ]
                for f in files:
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
        description="Launch Selective Time Delay attack simulations in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--build", action="store_true",
        help="Build-only: sync project files to scratch, run ./waf build, then EXIT "
             "without simulating. Re-run the script without --build to launch the sweep.",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Delete old result CSVs for the selected scope before running.",
    )
    parser.add_argument(
        "--attack", type=int, choices=[1, 2], default=None,
        help="Run only this attack number (default: both 1 and 2).",
    )
    parser.add_argument(
        "--percentage", type=int, choices=ATTACK_PERCENTAGES, default=None,
        metavar="{0,20,40,60,80,100}",
        help="Run only this attack percentage (default: all six).",
    )
    parser.add_argument(
        "--delay", type=int, nargs="+", default=None, metavar="MS",
        help=(
            "Fix the attack delay ANCHOR to one or more specific values in ms. Each "
            "value becomes a separate set of runs with result files named "
            "MOBIGUARD_Attack1_<pct>_d<X>ms.csv etc. Default: 80 ms (matches the "
            "C++ attack_delay_ms default). NOTE (§4.3, docs/MOBILITY_AMPLIFICATION_"
            "FIX_PLAN.md): this script always passes --attack_delay_pseudo_random=1, "
            "so the actual per-instance delay is drawn from a +/-10% band around "
            "this anchor, not applied exactly — see attack_delay_band_fraction."
        ),
    )
    parser.add_argument(
        "--delay-sweep", action="store_true",
        help=(
            f"Sweep the full default delay set {DELAY_SWEEP_MS} ms. "
            "Shorthand for --delay " + " ".join(map(str, DELAY_SWEEP_MS)) + "."
        ),
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
        help="Maximum number of parallel simulation processes (default: 12; the full "
             "default sweep is 24 runs, so it goes out in two waves of 12).",
    )
    args = parser.parse_args()

    # ── Optional sync + build ────────────────────────────────────────────────
    # --build is build-ONLY: it syncs, compiles, then EXITS. It deliberately does
    # NOT fall through into the sweep — otherwise `--build` (intended as a compile
    # check) silently launches a full multi-hour run. To actually simulate, re-run
    # the script without --build (the freshly built binary is reused).
    if args.build:
        sync_files()
        if not build_simulation():
            sys.exit(1)
        print("Build complete. Re-run without --build to launch the simulations.")
        sys.exit(0)

    # Runs use --run-no-build (see build_waf_command) so concurrent sweep
    # processes don't race on waf's implicit build check. That means there is
    # no fallback that builds the binary for you — check it exists now, with
    # one clear message, instead of launching a dozen runs that would each
    # fail separately with a raw waf "program not found" error.
    if not BINARY_PATH.exists():
        print(f"ERROR: {BINARY_PATH} not found. Run with --build first.")
        sys.exit(1)

    # ── Resolve scope ────────────────────────────────────────────────────────
    scope_attacks = [args.attack] if args.attack else [a["attack_number"] for a in ATTACKS]
    scope_percs   = [args.percentage] if args.percentage is not None else ATTACK_PERCENTAGES

    if args.delay_sweep:
        scope_delays = DELAY_SWEEP_MS
    elif args.delay:
        scope_delays = args.delay
    else:
        scope_delays = [80]   # matches C++ default attack_delay_ms=80ms so filenames are consistent

    if args.clean:
        clean_results(args.attack, args.percentage, scope_delays)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Build run list ───────────────────────────────────────────────────────
    # Every attack gets TWO runs per (percentage, delay): the normal MOBIGUARD
    # run, plus a TAP-baseline run (--enable_tap=1, MOBIGUARD's own S1-S8
    # disabled) — check_results()/clean_results() expect TAP__Attack<N>_<pct>.csv
    # to exist for every attack; this is what actually produces it.
    runs = []
    for a in scope_attacks:
        for p in scope_percs:
            for d in scope_delays:
                runs.append({
                    "attack_number":     a,
                    "attack_percentage": p,
                    "delay_ms":          d,
                    "extra_params":      None,
                    "label_suffix":      "",
                    "log": LOGS_DIR / (
                        f"A{a}_pct{p}{delay_suffix(d)}_seed{args.seed}.log"
                    ),
                })
                runs.append({
                    "attack_number":     a,
                    "attack_percentage": p,
                    "delay_ms":          d,
                    "extra_params":      TAP_PARAMS,
                    "label_suffix":      "_TAP",
                    "log": LOGS_DIR / (
                        f"A{a}_pct{p}{delay_suffix(d)}_seed{args.seed}_TAP.log"
                    ),
                })

    total = len(runs)
    delay_desc = (
        f"delays={scope_delays}ms" if scope_delays != [None] else "delay=random"
    )
    print(
        f"\n── Launching {total} run(s)  "
        f"[attacks={scope_attacks}  percentages={scope_percs}  "
        f"{delay_desc}  simTime={args.sim_time}s  seed={args.seed}  "
        f"workers={min(args.workers, total)}] ──\n"
    )

    # ── Run in parallel ──────────────────────────────────────────────────────
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
                r["delay_ms"],
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

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n── Summary  (wall time: {wall_elapsed:.0f}s) ──")
    print(f"  Passed : {len(passed)}/{total}")
    if failed:
        print(f"  Failed : {len(failed)}")
        for r in failed:
            print(f"    {r['label']}  (returncode={r['returncode']})")
            print(f"      log → {r['log']}")

    check_results(scope_attacks, scope_percs, scope_delays, args.seed)

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
