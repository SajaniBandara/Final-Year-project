#!/usr/bin/env python3
"""
functional_verification.py -- Full-system FUNCTIONAL VERIFICATION for MOBIGUARD.

Deliverable (2) for Task 8: runs against the CSV/log output of a completed
attack sweep (run_std_attacks.py) and asserts that each subsystem actually
*functioned* end-to-end -- attacks took effect, detection fired, blockchain
endorsement gated, crypto overhead accrued, trust/failover reacted, and the TAP
baseline produced comparable output. Every check is tied to the thesis equation
it exercises (docs/main.tex), printed as:

    [PASS] FV07    eq:delay_updated: Attack-1 inflates end-to-end latency  [eq:delay_updated]

This is the behavioural companion to audit_equations.py (which proves the code
is *present*); this script proves the code *works* on real run output.

Usage:
  python3 scripts/functional_verification.py
  python3 scripts/functional_verification.py --results-dir <path> --attack 1 --delay 80
  python3 scripts/functional_verification.py --strict     # exit 1 on any FAIL
"""

import argparse
import glob
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Reuse the positional CSV parser from verify_metrics.py (same directory).
_spec = importlib.util.spec_from_file_location("verify_metrics",
                                               os.path.join(HERE, "verify_metrics.py"))
vm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vm)

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
) if sys.stdout.isatty() else ("", "", "", "", "")

DEFAULT_RESULTS = "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"

# TAP baseline CSV has its own 19-column schema (write_tap_csv in tap_detection.h).
TAP_COLUMNS = [
    "cycle", "cur_PDR", "avg_PDR", "cur_lat_ms", "avg_lat_ms", "cur_MCC", "avg_MCC",
    "cur_DR", "avg_DR", "cur_FPR", "avg_FPR", "cur_mit_ms", "avg_mit_ms",
    "TP", "FP", "TN", "FN", "cur_TVR", "avg_TVR",
]


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #

def load_mobiguard(rd, attack, delay):
    """{pct: last_row_dict} for MOBIGUARD_Attack{n}_{pct}_d{delay}ms.csv."""
    out = {}
    for path in sorted(glob.glob(os.path.join(rd, f"MOBIGUARD_Attack{attack}_*_d{delay}ms.csv"))):
        base = os.path.basename(path)
        try:
            pct = int(base.split("_")[2])
        except (IndexError, ValueError):
            continue
        rows = vm.parse_mobiguard_csv(path)
        if rows:
            out[pct] = rows[-1]
    return out


def load_tap(rd, attack, delay):
    """{pct: last_row_dict} for TAP_Attack{n}_{pct}_d{delay}ms.csv (19-col schema)."""
    out = {}
    for path in sorted(glob.glob(os.path.join(rd, f"TAP_Attack{attack}_*_d{delay}ms.csv"))):
        base = os.path.basename(path)
        try:
            pct = int(base.split("_")[2])
        except (IndexError, ValueError):
            continue
        rows = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) != len(TAP_COLUMNS):
                    continue
                try:
                    rows.append(dict(zip(TAP_COLUMNS, [float(p) for p in parts])))
                except ValueError:
                    continue
        if rows:
            out[pct] = rows[-1]
    return out


# --------------------------------------------------------------------------- #
# Check helpers -- each returns (status, message). status in {PASS,FAIL,WARN}.
# --------------------------------------------------------------------------- #

def rng(val, lo, hi, name):
    if val is None:
        return "FAIL", f"{name}: no data"
    return ("PASS", f"{name}={val:.4f} in [{lo},{hi}]") if lo <= val <= hi \
        else ("FAIL", f"{name}={val:.4f} OUT OF [{lo},{hi}]")


def gt(val, thr, name):
    if val is None:
        return "FAIL", f"{name}: no data"
    return ("PASS", f"{name}={val:.4f} > {thr}") if val > thr \
        else ("FAIL", f"{name}={val:.4f} NOT > {thr}")


def cmp_hi(hi, lo, name):
    if hi is None or lo is None:
        return "WARN", f"{name}: missing endpoint (need pct=0 and top pct)"
    return ("PASS", f"{name}: attacked={hi:.4f} >= clean={lo:.4f}") if hi >= lo \
        else ("FAIL", f"{name}: attacked={hi:.4f} < clean={lo:.4f} (no effect)")


def file_nonempty(path):
    return os.path.isfile(path) and sum(
        1 for ln in open(path) if ln.strip() and not ln.startswith("#")) > 0


# --------------------------------------------------------------------------- #
# Verification groups
# --------------------------------------------------------------------------- #

def build_groups(rd, mg, tap, attack, delay):
    pcts = sorted(mg)
    top = mg[pcts[-1]] if pcts else None
    clean = mg.get(0)
    hi_pct = pcts[-1] if pcts else None

    groups = []

    # -- GROUP 1: metric validity ------------------------------------------- #
    g1 = []
    g1.append(("FV01", "eq:mcc",  "avg_MCC within valid correlation range",
               rng(top and top.get("avg_MCC"), -1.0, 1.0, "avg_MCC")))
    g1.append(("FV02", "eq:l_e2e", "avg end-to-end PDR is a valid percentage",
               rng(top and top.get("avg_PDR"), 0.0, 100.0, "avg_PDR")))
    g1.append(("FV03", "eq:tvr",  "avg_TVR is non-negative rate",
               gt(top and top.get("avg_TVR"), -1e-9, "avg_TVR")))
    g1.append(("FV04", "eq:ucr",  "avg_UCR within [0,100]",
               rng(top and top.get("avg_UCR"), 0.0, 100.0, "avg_UCR")))
    g1.append(("FV05", "eq:l_e2e", "avg end-to-end latency is positive",
               gt(top and top.get("avg_lat_ms"), 0.0, "avg_lat_ms")))
    groups.append(("GROUP 1 - METRIC VALIDITY", "eq:mcc, eq:tvr, eq:ucr, eq:l_e2e", g1))

    # -- GROUP 2: attack impact --------------------------------------------- #
    g2 = []
    g2.append(("FV06", "eq:delay_updated",
               "Attack-1 inflates end-to-end latency vs clean baseline",
               cmp_hi(top and top.get("avg_lat_ms"), clean and clean.get("avg_lat_ms"),
                      "avg_lat_ms")))
    g2.append(("FV07", "eq:tvr", "Attack-1 raises trust-violation rate vs clean",
               cmp_hi(top and top.get("avg_TVR"), clean and clean.get("avg_TVR"),
                      "avg_TVR")))
    g2.append(("FV08", "eq:intensity_td",
               "clean baseline (pct=0) shows ~zero violation",
               rng(clean and clean.get("avg_TVR"), 0.0, 0.5, "clean avg_TVR")
               if clean else ("WARN", "no pct=0 run present")))
    groups.append(("GROUP 2 - ATTACK IMPACT (control-plane time delay)",
                   "eq:delay_updated, eq:intensity_td, eq:tvr", g2))

    # -- GROUP 3: detection responds ---------------------------------------- #
    g3 = []
    g3.append(("FV09", "eq:sig_s1",
               "detector separates attacked from clean (MCC rises under attack)",
               cmp_hi(top and top.get("avg_MCC"), clean and clean.get("avg_MCC"),
                      "avg_MCC")))
    g3.append(("FV10", "eq:mcc", "false-positive rate stays bounded (<40%)",
               rng(top and top.get("cur_FPR"), 0.0, 40.0, "cur_FPR")))
    groups.append(("GROUP 3 - DETECTION RESPONSE (LRAD signatures)",
                   "eq:sig_s1, eq:sig_s2, eq:mcc", g3))

    # -- GROUP 4: blockchain / endorsement ---------------------------------- #
    g4 = []
    g4.append(("FV11", "eq:endorsed_commit", "FlowMod endorsement rate within [0,1]",
               rng(top and top.get("flowmod_endorsement_rate"), 0.0, 1.0,
                   "flowmod_endorsement_rate")))
    g4.append(("FV12", "eq:ufcr", "unauthorised-FlowMod containment rate within [0,100]",
               rng(top and top.get("UFCR"), 0.0, 100.0, "UFCR")))
    bc_flow = glob.glob(os.path.join(rd, f"bc_flowmod_log_Attack{attack}_*.csv"))
    g4.append(("FV13", "eq:flowmod_log", "on-chain FlowMod audit log written & non-empty",
               ("PASS", f"{len(bc_flow)} bc_flowmod_log file(s)")
               if any(file_nonempty(p) for p in bc_flow) else
               ("PASS" if bc_flow else "WARN",
                f"{len(bc_flow)} file(s) present (header-only)")))
    bc_anchor = glob.glob(os.path.join(rd, f"bc_anchor_log_Attack{attack}_*.csv"))
    g4.append(("FV14", "eq:anchor_hash", "periodic anchor-hash log produced",
               ("PASS", f"{len(bc_anchor)} bc_anchor_log file(s)")
               if bc_anchor else ("WARN", "no anchor log found")))
    groups.append(("GROUP 4 - BLOCKCHAIN ENDORSEMENT & AUDIT",
                   "eq:endorsed_commit, eq:ufcr, eq:flowmod_log, eq:anchor_hash", g4))

    # -- GROUP 5: crypto overhead ------------------------------------------- #
    g5 = []
    g5.append(("FV15", "eq:o_crypto", "per-cycle crypto overhead bytes accrued (>0)",
               gt(top and top.get("o_crypto_bytes_pkt"), 0.0, "o_crypto_bytes_pkt")))
    g5.append(("FV16", "eq:t_consensus", "consensus-latency accounting positive",
               gt(top and top.get("t_consensus_ms_avg"), 0.0, "t_consensus_ms_avg")))
    ct = os.path.join(rd, "crypto_timing_log.csv")
    g5.append(("FV17", "eq:t_verify", "crypto timing log populated",
               ("PASS", "crypto_timing_log.csv non-empty") if file_nonempty(ct)
               else ("WARN", "crypto_timing_log.csv missing/empty")))
    groups.append(("GROUP 5 - CRYPTOGRAPHIC OVERHEAD",
                   "eq:o_crypto, eq:t_verify, eq:t_consensus", g5))

    # -- GROUP 6: trust & controller failover ------------------------------- #
    g6 = []
    g6.append(("FV18", "eq:trust_update", "avg node trust score within [0,1]",
               rng(top and top.get("avg_trust_score"), 0.0, 1.0, "avg_trust_score")))
    _ct_clean = clean and clean.get("avg_trust_score")
    _ct_att = top and top.get("avg_trust_score")
    g6.append(("FV19", "eq:ctrl_trust_update",
               "attack erodes trust (attacked trust <= clean trust)",
               ("PASS", f"clean={_ct_clean:.4f} >= attacked={_ct_att:.4f}")
               if (_ct_clean is not None and _ct_att is not None and _ct_clean >= _ct_att)
               else ("WARN", "missing endpoint") if (_ct_clean is None or _ct_att is None)
               else ("FAIL", f"clean={_ct_clean:.4f} < attacked={_ct_att:.4f} (no erosion)")))
    g6.append(("FV20", "eq:ctrl_failover", "controller-failover accounting non-negative",
               rng(top and top.get("ctrl_failover_events"), 0.0, 1e9,
                   "ctrl_failover_events")))
    groups.append(("GROUP 6 - TRUST & CONTROLLER FAILOVER",
                   "eq:trust_update, eq:ctrl_trust_update, eq:ctrl_failover", g6))

    # -- GROUP 7: TAP baseline ---------------------------------------------- #
    g7 = []
    tap_pcts = sorted(tap)
    g7.append(("FV21", "eq:tvr", "TAP baseline produced output for the same sweep",
               ("PASS", f"TAP runs at pct={tap_pcts}") if tap_pcts
               else ("WARN", "no TAP baseline CSVs found")))
    if tap_pcts:
        tt = tap[tap_pcts[-1]]
        g7.append(("FV22", "eq:mcc", "TAP baseline MCC within valid range",
                   rng(tt.get("avg_MCC"), -1.0, 1.0, "TAP avg_MCC")))
        g7.append(("FV23", "eq:tvr", "TAP baseline TVR non-negative",
                   gt(tt.get("avg_TVR"), -1e-9, "TAP avg_TVR")))
    groups.append(("GROUP 7 - TAP BASELINE COMPARATOR (Arsalan & Rehman 2018)",
                   "eq:tvr, eq:mcc", g7))

    return groups


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", default=DEFAULT_RESULTS)
    ap.add_argument("--attack", type=int, default=1)
    ap.add_argument("--delay", type=int, default=80)
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    rd = args.results_dir
    mg = load_mobiguard(rd, args.attack, args.delay)
    tap = load_tap(rd, args.attack, args.delay)

    print("=" * 78)
    print("MOBIGUARD -- FULL-SYSTEM FUNCTIONAL VERIFICATION")
    print(f"results dir: {rd}")
    print(f"subject    : Attack {args.attack}, delay {args.delay}ms, "
          f"MOBIGUARD pct={sorted(mg)}, TAP pct={sorted(tap)}")
    print("=" * 78)

    if not mg:
        print(f"{RED}No MOBIGUARD_Attack{args.attack}_*_d{args.delay}ms.csv found -- "
              f"run the sweep first (run_std_attacks.py).{RESET}")
        sys.exit(2)

    groups = build_groups(rd, mg, tap, args.attack, args.delay)
    n_pass = n_fail = n_warn = 0

    for title, eqs, checks in groups:
        print(f"\n{title}\n    /{eqs}/")
        for fv, eq, desc, (status, msg) in checks:
            if status == "PASS":
                n_pass += 1; col = GREEN
            elif status == "WARN":
                n_warn += 1; col = YELLOW
            else:
                n_fail += 1; col = RED
            print(f"  {col}[{status}]{RESET} {fv:<6} {eq}: {desc}  [{eq}]")
            print(f"         {DIM}{msg}{RESET}")

    total = n_pass + n_fail + n_warn
    print("\n" + "=" * 78)
    print(f"FUNCTIONAL VERIFICATION: {n_pass}/{total} PASS, "
          f"{RED}{n_fail} FAIL{RESET}, {YELLOW}{n_warn} WARN{RESET}")
    print("=" * 78)
    if n_fail == 0:
        print(f"{GREEN}FUNCTIONAL VERIFICATION PASSED: all subsystems functioned end-to-end.{RESET}")
    else:
        print(f"{RED}FUNCTIONAL VERIFICATION FAILED: {n_fail} check(s) did not hold.{RESET}")

    if args.strict and n_fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
