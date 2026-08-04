#!/usr/bin/env python3
"""
run_q1q6_ablation.py — Q1-Q6 component-isolation ablation (supervisor diagnostic).

DISTINCT FROM THE THESIS AB* ABLATIONS. run_ablation_sweep.py covers AB1
(OBU/RSU engine modes) and AB4 (STARK proof variants); ab3_feature_ablation.py
covers AB3 (LSTM feature set). This script covers the supervisor's separate
Q1-Q6 grid, which isolates DETECTION COMPONENTS (rule signatures / crypto /
LSTM / witness) rather than engine modes or feature sets.

Scope per the supervisor's spec: 30 s, 60 % attack, 1 seed, all 8 variants,
6 configs => 48 runs. Report TP/FP/FN/TN per variant only.

  Q1  Rule-based signatures only   (S1-S4 live; S5-S8 off; LSTM off; crypto forced pass; witness off)
  Q2  Cryptographic layer only     (S1-S4 off; S5-S8 live; LSTM off; crypto natural;     witness off)
  Q3  LSTM anomaly detector only   (S1-S8 off;             LSTM on;  crypto forced pass; witness off)
  Q4  Witness monitoring only      (S1-S8 off;             LSTM off; crypto forced pass; witness ON)
  Q5  Rule + Crypto combined       (S1-S8 live;            LSTM off; crypto natural;     witness off)
  Q6  Full system                  (everything on / natural)

FLAG SEMANTICS -- read before interpreting results:
  * g_disable_s5_s6 / g_disable_s7_s8 gate the SIGNATURE COMPUTATION, so the
    flags, D_RSU, the BTMM trust penalty and the BC.Write record all go silent
    together. Required for Q2/Q4 to isolate anything at all.
  * g_disable_s3_s4 gates ONLY the confusion-matrix recording, NOT flag_s3 /
    flag_s4. Those still publish g_tcam_flag_s3_last/s4_last, which lrad_rsu()
    reads as the eq:lstm_gate (main.tex:3317-3326) LSTM suppression gate. The
    gate's rationale is structural (TCAM residual occupancy), so it must stay
    live even while S3/S4's own output is disabled -- this is what makes Q3's
    "LSTM gated off for A3/A4" behaviour observable.
  * disable_crypto=1 is how "b_batch=1 and b_hop=1 everywhere" is achieved:
    mldsa87_verify() and stark_verify_hop() both short-circuit to true.
  * enable_witness_mechanism DEFAULTS TO TRUE, so every non-witness config must
    pass 0 explicitly or the witness path leaks into it.

KNOWN INTERPRETATION CAVEATS (state these when reporting):
  * Q3 runs the LSTM on 9 effective features, not 8. zkp_hop_fail zeroes out
    (stark_verify_hop short-circuits under disable_crypto) but zkp_delay_fail
    does NOT -- it is a raw wall-clock comparison at routing.cc:121884 with no
    crypto gate.
  * D_div / A_tp / r_anom are packet-delivery counters with no crypto gate and
    stay non-constant in every config, including the "crypto forced pass" ones.

Usage:
  python3 scripts/run_q1q6_ablation.py --dry-run     # print the plan + commands, launch nothing
  python3 scripts/run_q1q6_ablation.py --table       # print the flag mapping table and exit
  python3 scripts/run_q1q6_ablation.py --workers 8   # execute

NS3_DIR defaults to the shared cluster path this repo stores. Override locally
WITHOUT committing:  NS3_DIR=~/ns-allinone-3.35/ns-3.35 python3 scripts/run_q1q6_ablation.py ...
"""

import argparse
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

NS3_DIR     = Path(os.environ.get("NS3_DIR", Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"))
RESULTS_DIR = NS3_DIR / "results_routing"
LOGS_DIR    = Path(__file__).resolve().parent.parent / "logs" / "q1q6_ablation"
BINARY_PATH = NS3_DIR / "build" / "scratch" / "routing" / "routing"

ATTACKS = [1, 2, 3, 4, 5, 6, 7, 8]

# Every flag is written explicitly in every config -- no config relies on a
# default. This is deliberate: the whole point of the grid is that a reader can
# verify isolation by reading one row, without cross-referencing defaults.
Q_CONFIGS = {
    "Q1": {  # rule-based signatures only
        "g_disable_s1_s2": 0, "g_disable_s3_s4": 0,
        "g_disable_s5_s6": 1, "g_disable_s7_s8": 1,
        "enable_lstm_inference": 0, "enable_witness_mechanism": 0,
        "disable_crypto": 1,
    },
    "Q2": {  # cryptographic layer only
        "g_disable_s1_s2": 1, "g_disable_s3_s4": 1,
        "g_disable_s5_s6": 0, "g_disable_s7_s8": 0,
        "enable_lstm_inference": 0, "enable_witness_mechanism": 0,
        "disable_crypto": 0,
    },
    "Q3": {  # LSTM anomaly detector only (gate stays live -- see header)
        "g_disable_s1_s2": 1, "g_disable_s3_s4": 1,
        "g_disable_s5_s6": 1, "g_disable_s7_s8": 1,
        "enable_lstm_inference": 1, "enable_witness_mechanism": 0,
        "disable_crypto": 1,
    },
    "Q4": {  # witness monitoring only
        "g_disable_s1_s2": 1, "g_disable_s3_s4": 1,
        "g_disable_s5_s6": 1, "g_disable_s7_s8": 1,
        "enable_lstm_inference": 0, "enable_witness_mechanism": 1,
        "disable_crypto": 1,
    },
    "Q5": {  # rule + crypto combined
        "g_disable_s1_s2": 0, "g_disable_s3_s4": 0,
        "g_disable_s5_s6": 0, "g_disable_s7_s8": 0,
        "enable_lstm_inference": 0, "enable_witness_mechanism": 0,
        "disable_crypto": 0,
    },
    "Q6": {  # full system (deployed configuration)
        "g_disable_s1_s2": 0, "g_disable_s3_s4": 0,
        "g_disable_s5_s6": 0, "g_disable_s7_s8": 0,
        "enable_lstm_inference": 1, "enable_witness_mechanism": 1,
        "disable_crypto": 0,
    },
}

FLAG_ORDER = ["g_disable_s1_s2", "g_disable_s3_s4", "g_disable_s5_s6",
              "g_disable_s7_s8", "enable_lstm_inference",
              "enable_witness_mechanism", "disable_crypto"]

SHORT = {"g_disable_s1_s2": "S1/S2", "g_disable_s3_s4": "S3/S4",
         "g_disable_s5_s6": "S5/S6", "g_disable_s7_s8": "S7/S8",
         "enable_lstm_inference": "LSTM", "enable_witness_mechanism": "witness",
         "disable_crypto": "crypto"}


def human(flag: str, value: int) -> str:
    """Render a raw flag value as its DETECTION-LAYER meaning.

    The g_disable_* flags are inverted relative to the enable_* ones, and
    disable_crypto=1 means 'forced pass' rather than 'absent', so a raw 0/1
    grid is genuinely misread-prone. Translate once, here.
    """
    if flag.startswith("g_disable_"):
        return "off" if value else "live"
    if flag == "disable_crypto":
        return "forced pass" if value else "natural"
    return "on" if value else "off"


def print_table(params: dict):
    print("Q1-Q6 flag mapping — detection-layer meaning (raw flag value in parens)\n")
    w = 16
    hdr = f"{'':<5}" + "".join(f"{SHORT[f]:>{w}}" for f in FLAG_ORDER)
    print(hdr)
    print("-" * len(hdr))
    for q, cfg in Q_CONFIGS.items():
        row = f"{q:<5}"
        for f in FLAG_ORDER:
            row += f"{human(f, cfg[f]) + f' ({cfg[f]})':>{w}}"
        print(row)
    print("\nFixed parameters: " + ", ".join(f"{k}={v}" for k, v in sorted(params.items())))
    print(f"Grid: {len(Q_CONFIGS)} configs x {len(ATTACKS)} attacks = "
          f"{len(Q_CONFIGS) * len(ATTACKS)} runs")
    print("\nNote: g_disable_s3_s4 gates confusion-matrix recording ONLY; flag_s3/flag_s4\n"
          "still publish the eq:lstm_gate LSTM suppression signal. See module docstring.")


def fixed_params(args) -> dict:
    return {
        "routing_test": "false", "N_Vehicles": 200, "N_RSUs": 64, "N_Controllers": 4,
        "mobility_scenario": 0, "maxspeed": 150, "use_sumo_mobility": 1,
        "architecture": 3, "simTime": args.sim_time,
        "attack_percentage": args.percentage,
        "sim_seed": args.seed, "sim_run": 1,
    }


def result_filename(attack_number: int, pct: int) -> str:
    # write_security_metrics_csv() names by (attack_number, pct) only -- the
    # ablation tag is NOT in the name, so two configs on the same (attack, pct)
    # would overwrite each other. Hence one sequential lane per attack + an
    # immediate rename after each run (same approach as run_ablation_sweep.py).
    suffix = "_d80ms" if attack_number in (1, 2) else ""
    return f"MOBIGUARD_Attack{attack_number}_{pct}{suffix}.csv"


def build_cmd(attack_number: int, extra: dict, params: dict) -> list:
    p = dict(params)
    p["attack_number"] = attack_number
    if attack_number in (1, 2):
        # Exact 80 ms: the banded pseudo-random draw must be disabled or this
        # sweep silently gets 72-88 ms per packet (see run_ablation_sweep.py).
        p["attack_delay_ms"] = 80
        p["attack_delay_pseudo_random"] = 0
    p.update(extra)
    param_str = " ".join(f"--{k}={v}" for k, v in p.items())
    return ["./waf", "--run-no-build", f"scratch/routing/routing {param_str}"]


def run_lane(attack_number: int, params: dict, dry_run: bool) -> list:
    out = []
    for tag, extra in Q_CONFIGS.items():
        label = f"A{attack_number}_{tag}"
        cmd = build_cmd(attack_number, extra, params)
        if dry_run:
            print(f"  [{label}] {' '.join(cmd)}")
            out.append({"label": label, "ok": True, "renamed": True})
            continue

        log_path = LOGS_DIR / f"{label}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        start = datetime.now()
        print(f"  [{label}] started {start.strftime('%H:%M:%S')}")
        with open(log_path, "w") as logf:
            logf.write(f"# Command: {' '.join(cmd)}\n")
            proc = subprocess.run(cmd, cwd=NS3_DIR, stdout=logf,
                                  stderr=subprocess.STDOUT, text=True)
        elapsed = (datetime.now() - start).total_seconds()
        ok = proc.returncode == 0

        src = RESULTS_DIR / result_filename(attack_number, params["attack_percentage"])
        dst = RESULTS_DIR / src.name.replace(".csv", f"_{tag}.csv")
        renamed = False
        if src.exists():
            src.rename(dst)
            renamed = True
        print(f"  [{label}] {'OK' if ok else 'FAILED':<6} {elapsed:5.0f}s "
              f"{'-> ' + dst.name if renamed else '(NO OUTPUT)'}")
        out.append({"label": label, "ok": ok, "renamed": renamed})
    return out


def mcc(tp, fp, fn, tn):
    """Matthews correlation coefficient. Returns 0.0 when the denominator
    degenerates (any row/column of the 2x2 all-zero) -- the conventional
    convention, and the case that actually arises here whenever a config
    detects nothing at all (e.g. the expected Q2 all-zero result)."""
    import math
    num = tp * tn - fp * fn
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return 0.0 if den == 0 else num / den


def read_confusion(path):
    """Pull the final-row TP/FP/FN/TN out of one MOBIGUARD results CSV.
    Column names are matched case-insensitively and tolerate the TP/FP/FN/TN
    vs true_positive/... spellings that appear across writer versions."""
    import csv as _csv
    if not path.exists():
        return None
    rows = list(_csv.DictReader(open(path)))
    if not rows:
        return None
    last = rows[-1]
    keys = {k.lower().strip(): k for k in last if k}
    def grab(*cands):
        for c in cands:
            if c in keys:
                try:
                    return int(float(last[keys[c]]))
                except (TypeError, ValueError):
                    return None
        return None
    tp = grab("tp", "true_positive", "true_positives")
    fp = grab("fp", "false_positive", "false_positives")
    fn = grab("fn", "false_negative", "false_negatives")
    tn = grab("tn", "true_negative", "true_negatives")
    if None in (tp, fp, fn, tn):
        return None
    return tp, fp, fn, tn


def analyse(params):
    """Emit the per-variant confusion matrices + MCC per config, then the
    cumulative-addition MCC table the supervisor asked for (Q1 / Q3 / Q4 / Q5
    standalone, then Q6 full)."""
    pct = params["attack_percentage"]
    print("\n" + "=" * 78)
    print("PER-CONFIG CONFUSION MATRICES AND MCC")
    print("=" * 78)
    table = {}
    for q in Q_CONFIGS:
        print(f"\n{q}:")
        print(f"  {'variant':<9}{'TP':>6}{'FP':>6}{'FN':>6}{'TN':>6}{'MCC':>9}")
        table[q] = {}
        for a in ATTACKS:
            src = RESULTS_DIR / result_filename(a, pct).replace(".csv", f"_{q}.csv")
            got = read_confusion(src)
            if got is None:
                print(f"  A{a:<8}{'--':>6}{'--':>6}{'--':>6}{'--':>6}{'MISSING':>9}")
                continue
            tp, fp, fn, tn = got
            m = mcc(tp, fp, fn, tn)
            table[q][a] = m
            print(f"  A{a:<8}{tp:>6}{fp:>6}{fn:>6}{tn:>6}{m:>9.4f}")

    print("\n" + "=" * 78)
    print("CUMULATIVE MCC BY COMPONENT (standalone configs, then full system)")
    print("=" * 78)
    order = ["Q1", "Q3", "Q4", "Q5", "Q6"]
    hdr = f"{'variant':<9}" + "".join(f"{q:>9}" for q in order)
    print(hdr)
    print("-" * len(hdr))
    for a in ATTACKS:
        row = f"A{a:<8}"
        for q in order:
            v = table.get(q, {}).get(a)
            row += f"{v:>9.4f}" if v is not None else f"{'--':>9}"
        print(row)
    print("\nQ2 omitted from the cumulative table (expected all-zero: b_batch cannot"
          "\ngo false in simulation, so no crypto-only signature can fire).")
    print("\nREPORTING CAVEAT — state this with any Q3/Q6 figure:")
    print("  The LSTM used here is PRE-RETRAIN, trained on stale data. zkp_delay_fail")
    print("  was identically zero for A2 across all 1792 training rows, and A6/A8")
    print("  labels were corrupted before the label fix. Q3/Q6 LSTM numbers are")
    print("  LOWER BOUNDS on real contribution, not final figures.")


def main():
    ap = argparse.ArgumentParser(description="Q1-Q6 component-isolation ablation")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--sim-time", type=int, default=30, help="supervisor spec: 30 s")
    ap.add_argument("--percentage", type=int, default=60, help="supervisor spec: 60 %%")
    ap.add_argument("--seed", type=int, default=1, help="supervisor spec: 1 seed")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and every command, launch nothing")
    ap.add_argument("--table", action="store_true",
                    help="print the flag mapping table and exit")
    ap.add_argument("--analyse", action="store_true",
                    help="skip running; read existing per-config CSVs and emit "
                         "the MCC + cumulative-addition tables")
    args = ap.parse_args()

    params = fixed_params(args)

    if args.table:
        print_table(params)
        return

    if args.analyse:
        analyse(params)
        return

    print_table(params)
    print()

    if args.dry_run:
        print("-- DRY RUN: no simulations will be launched --\n")
    elif not BINARY_PATH.exists():
        raise SystemExit(f"{BINARY_PATH} not found — build first, or set NS3_DIR.")

    total = len(Q_CONFIGS) * len(ATTACKS)
    print(f"-- {len(ATTACKS)} lane(s), {total} total runs, "
          f"workers={min(args.workers, len(ATTACKS))} --\n")

    wall_start = datetime.now()
    results = []
    if args.dry_run:
        for a in ATTACKS:
            results.extend(run_lane(a, params, True))
    else:
        with ThreadPoolExecutor(max_workers=min(args.workers, len(ATTACKS))) as pool:
            futures = {pool.submit(run_lane, a, params, False): a for a in ATTACKS}
            for fut in as_completed(futures):
                results.extend(fut.result())

    wall = (datetime.now() - wall_start).total_seconds()
    passed = sum(1 for r in results if r["ok"] and r["renamed"])
    print(f"\n-- Summary (wall {wall:.0f}s) -- Passed: {passed}/{total}")
    if not args.dry_run:
        print(f"Results: {RESULTS_DIR}/MOBIGUARD_Attack<N>_{args.percentage}[_d80ms]_Q<n>.csv")
        analyse(params)


if __name__ == "__main__":
    main()
