#!/usr/bin/env python3
"""
run_exp3_scale.py — PHANTOM Experiment 3 (scalability) sweep launcher + scorer.

Runs the full-system detector (Q6, enforcement OFF for detection scoring) at a
set of vehicle counts, ALL driven from ONE 400-vehicle base trace via
--mobility_trace_file (supervisor method, 2026-09-21): vehicle count is the only
variable across scale points, not trace-to-trace randomness. Derived subsets are
just --N_Vehicles set down from the 400 base; the base must contain >= max(N).

Config matches the main results: crypto ON, seed 1, simTime 300, attack_percentage
60, per-window M1 (detector_windows) scoring. Attacks 1/2 add the 80 ms delay.

Robustness (the reason this exists): each run's stdout goes to /dev/null but
STDERR is captured, and the process exit code is recorded, so a crash is
diagnosable instead of vanishing:
    rc 0   + detector_windows present -> OK
    rc 124 -> TIMEOUT (raise --timeout or reduce concurrency)
    rc 139 -> SEGV     (a real bug; see the per-run .err log / rerun with stdout)
    rc 134 -> ABORT/NS_ASSERT (see .err log)
    rc 0   but no detector_windows -> died before Simulator::Destroy

Usage:
    python3 scripts/run_exp3_scale.py                       # full sweep N={100,200,300,400}, A1-4
    python3 scripts/run_exp3_scale.py --N 400 --attacks 2 3 4   # just some cells
    python3 scripts/run_exp3_scale.py --score-only          # (re)score whatever CSVs exist
    python3 scripts/run_exp3_scale.py --crypto-off          # disable_crypto=1 (faster, note the caveat)
    python3 scripts/run_exp3_scale.py --dry-run             # print commands, launch nothing
"""
import argparse, os, subprocess, sys, math
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

NS3_DIR   = Path("/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35")
BIN       = NS3_DIR / "build/scratch/routing/routing"
RESULTS   = NS3_DIR / "results_routing"
TRACE     = Path("/home/sdvn_hidden_attacks/ns3_g13/mobility/mobility_urban_scale400.tcl")
LOGS      = Path(__file__).resolve().parent.parent / "logs" / "exp3_scale"
M1        = Path(__file__).resolve().parent / "m1_local.py"

# Full-system Q6, enforcement OFF (detection-quality scoring — see the
# prevention/detection decoupling note in the methodology).
Q6 = {
    "g_disable_s1_s2": 0, "g_disable_s3_s4": 0, "g_disable_s5_s6": 0,
    "g_disable_s7_s8": 0, "g_disable_ranom": 0, "enable_lstm_inference": 1,
    "enable_witness_mechanism": 1, "g_disable_btmm_trust": 0,
}
BUNDLE = {"s1_suppress_handoff_fp": 1, "enable_quarantine_enforcement": 0,
          "hf_truth_latched": 1, "s7_epsilon_vol": 0.1}


def tag(N):            return f"Exp3_N{N}"
def dw_name(a, N):
    delay = "_d80ms" if a in (1, 2) else ""
    return RESULTS / f"detector_windows_Attack{a}_60{delay}_seed1_{tag(N)}.csv"


def build_cmd(a, N, crypto_off):
    p = {
        "routing_test": "false", "N_Vehicles": N, "N_RSUs": 64, "N_Controllers": 4,
        "mobility_scenario": 0, "maxspeed": 150, "use_sumo_mobility": 1,
        "architecture": 3, "simTime": 300, "attack_percentage": 60,
        "sim_seed": 1, "sim_run": 1, "enable_detector_windows": 1,
        "enable_lstm_cls": 1, "mobility_trace_file": str(TRACE),
        "disable_crypto": 1 if crypto_off else 0,
        "attack_number": a, "run_tag": tag(N),
    }
    p.update(Q6); p.update(BUNDLE)
    if a in (1, 2):
        p["attack_delay_ms"] = 80; p["attack_delay_pseudo_random"] = 0
    args = " ".join(f"--{k}={v}" for k, v in p.items())
    return [str(BIN)] + args.split()


def run_cell(a, N, timeout, crypto_off, dry):
    label = f"N{N}_A{a}"
    cmd = build_cmd(a, N, crypto_off)
    if dry:
        print(f"  [{label}] timeout {timeout} {' '.join(cmd)}"); return (label, "DRY")
    LOGS.mkdir(parents=True, exist_ok=True)
    err = LOGS / f"{label}.err"
    env = dict(os.environ, LD_LIBRARY_PATH=str(NS3_DIR / "build/lib"))
    start = datetime.now()
    print(f"  [{label}] started {start:%H:%M:%S}")
    with open(err, "w") as ef:
        rc = subprocess.run(["timeout", str(timeout)] + cmd, cwd=str(NS3_DIR),
                            stdout=subprocess.DEVNULL, stderr=ef, env=env).returncode
    mins = (datetime.now() - start).total_seconds() / 60
    have = dw_name(a, N).exists()
    status = {0: ("OK" if have else "NO_OUTPUT"), 124: "TIMEOUT",
              139: "SEGV", 134: "ABORT"}.get(rc, f"rc{rc}")
    print(f"  [{label}] {status} ({mins:.0f} min, rc={rc}, detector_windows={'yes' if have else 'NO'})")
    return (label, status)


def score(Ns):
    """Score each N with m1_local into a scaling table (isolated per-N dirs)."""
    import tempfile, shutil, re
    print("\n=== Exp 3 scaling table (macro MCC, per-window M1) ===")
    print(f"{'N':>5} | {'macro':>6} | {'A1':>5} {'A2':>5} {'A3':>5} {'A4':>5}")
    for N in Ns:
        d = Path(tempfile.mkdtemp(prefix=f"exp3_N{N}_"))
        cells = [dw_name(a, N) for a in (1, 2, 3, 4)]
        present = [c for c in cells if c.exists()]
        for c in present:
            shutil.copy(c, d)
        if not present:
            print(f"{N:>5} | (no cells yet)"); shutil.rmtree(d); continue
        out = subprocess.run([sys.executable, str(M1), "--results-dir", str(d),
                              "--tag", tag(N)], capture_output=True, text=True).stdout
        mcc = {}
        for line in out.splitlines():
            m = re.match(r"^(A[1-4])\s+(-?[0-9.]+)", line)
            if m: mcc[m.group(1)] = float(m.group(2))
            mm = re.match(r"^ALL\(macro\)\s+(-?[0-9.]+)", line)
            if mm: macro = float(mm.group(1))
        vals = " ".join(f"{mcc.get('A'+str(i), float('nan')):>5.2f}" for i in (1,2,3,4))
        tail = "" if len(present) == 4 else f"  ({len(present)}/4 cells)"
        print(f"{N:>5} | {macro:>6.3f} | {vals}{tail}")
        shutil.rmtree(d)


def main():
    ap = argparse.ArgumentParser(description="PHANTOM Exp 3 scalability sweep")
    ap.add_argument("--N", type=int, nargs="+", default=[100, 200, 300, 400])
    ap.add_argument("--attacks", type=int, nargs="+", default=[1, 2, 3, 4])
    ap.add_argument("--timeout", type=int, default=21600, help="per-run wall-clock cap (s)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--crypto-off", action="store_true", help="disable_crypto=1 (faster; note caveat)")
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not BIN.exists():
        sys.exit(f"ERROR: binary missing at {BIN} — run ./waf build first")
    maxN = max(args.N)
    if maxN > 200 and not args.score_only:
        # The base trace must contain >= maxN vehicles.
        try:
            import re
            txt = TRACE.read_text()
            nv = len(set(re.findall(r"\$node_\((\d+)\)", txt)))
        except Exception:
            nv = -1
        if nv >= 0 and nv < maxN:
            sys.exit(f"ERROR: base trace {TRACE} has {nv} vehicles < requested max {maxN}")
        print(f"# base trace {TRACE.name}: {nv} vehicles (need >= {maxN})")

    if args.score_only:
        score(args.N); return

    jobs = [(a, N) for N in args.N for a in args.attacks
            if not dw_name(a, N).exists()]
    skip = [(a, N) for N in args.N for a in args.attacks if dw_name(a, N).exists()]
    if skip:
        print(f"# skipping {len(skip)} already-complete cells: "
              + ", ".join(f"N{N}_A{a}" for a, N in skip))
    print(f"# launching {len(jobs)} cells, {args.workers} workers, "
          f"crypto {'OFF' if args.crypto_off else 'ON'}, timeout {args.timeout}s")
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(run_cell, a, N, args.timeout, args.crypto_off, args.dry_run)
                for a, N in jobs]
        for f in futs:
            results.append(f.result())
    if args.dry_run:
        return
    bad = [(lbl, st) for lbl, st in results if st not in ("OK",)]
    if bad:
        print("\n!!! non-OK cells (inspect logs/exp3_scale/<label>.err):")
        for lbl, st in bad:
            print(f"    {lbl}: {st}")
    score(args.N)


if __name__ == "__main__":
    main()
