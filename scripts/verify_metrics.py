#!/usr/bin/env python3
"""
verify_metrics.py — Automated post-run checker for MOBIGUARD's 12 performance
metrics (docs/main.tex Section 4.6), companion to docs/METRICS_VERIFICATION_RUNBOOK.md.

write_security_metrics_csv() (scratch/routing.cc) writes a FIXED-ORDER,
comma-separated row per cycle, with a multi-line '#'-prefixed comment block
as a header (not a real CSV header pandas can auto-detect) — so this script
parses by COLUMN POSITION, not by name lookup. Two possible row lengths:
  - 51 columns: all variants except 2, 3, and baseline (no TCAM block)
  - 60 columns: variants 2, 3 (TCAM attacks), and baseline (+9 TCAM columns)

If you add/remove a column in routing.cc's write_security_metrics_csv(),
update COLUMNS_NO_TCAM / COLUMNS_TCAM below to match, in the same order.

Usage:
  python3 verify_metrics.py --file results_routing/MOBIGUARD_Attack1_40_d200ms.csv --mode sweep
  python3 verify_metrics.py --dir results_routing --mode full-report
  python3 verify_metrics.py --file lstm_pipeline/poison_sweep_results.json --mode m8
"""

import argparse
import glob
import json
import os
import sys

# ── Fixed column layouts (must match routing.cc:117447-117461 exactly) ──────

COLUMNS_NO_TCAM = [
    "cycle", "cur_PDR", "avg_PDR", "cur_lat_ms", "avg_lat_ms", "cur_MCC", "avg_MCC",
    "cur_DR", "avg_DR", "cur_FPR", "avg_FPR", "cur_mit_ms", "avg_mit_ms",
    "TP", "FP", "TN", "FN", "cur_TVR", "avg_TVR", "cur_UCR", "avg_UCR",
    "sig_valid_rate", "avg_trust_score", "stark_timing_fail_count", "stark_hop_fail_count",
    "flowmod_endorsement_rate", "rsu_chain_len", "global_chain_len",
    "witness_da_count", "witness_nfa_count", "d_obu_count", "d_rsu_count", "escalation_count",
    "ctrl_failover_max_ms", "ctrl_failover_events", "ctrl_failover_reassigned",
    "o_crypto_bytes_pkt", "t_batch_ms_avg", "batch_B_avg", "t_consensus_ms_avg",
    "witness_TP_W", "witness_FP_W", "witness_FN_W", "WAP_precision", "WAP_recall",
    "eps_ref_s", "avg_eps_ref_s", "time_ref_f_bad",
    "ufcr_unauth_total", "ufcr_blocked", "UFCR",
]  # 51 columns

_TCAM_BLOCK = [
    "max_tcam_util", "avg_tcam_util", "total_lambda_fm", "total_lambda_pi",
    "total_malicious", "s3_fired_count", "s4_fired_count", "any_s3", "any_s4",
]

COLUMNS_TCAM = COLUMNS_NO_TCAM[:21] + _TCAM_BLOCK + COLUMNS_NO_TCAM[21:]  # 60 columns

EXPECTED_LENGTHS = {len(COLUMNS_NO_TCAM): COLUMNS_NO_TCAM, len(COLUMNS_TCAM): COLUMNS_TCAM}


# ── CSV parsing (positional, not pandas-header-based — see module docstring) ─

def parse_mobiguard_csv(path: str) -> list[dict]:
    """Returns a list of {column_name: float_value} dicts, one per data row."""
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            columns = EXPECTED_LENGTHS.get(len(parts))
            if columns is None:
                print(f"  [WARN] {path}: row has {len(parts)} columns, "
                      f"expected {sorted(EXPECTED_LENGTHS.keys())} — skipping row "
                      f"(did routing.cc's column list change without updating this script?)")
                continue
            try:
                values = [float(p) for p in parts]
            except ValueError:
                continue  # malformed row (e.g. truncated write), skip
            rows.append(dict(zip(columns, values)))
    return rows


def last_row(rows: list[dict]) -> dict | None:
    return rows[-1] if rows else None


# ── Per-metric checks. Each returns (status, message); status in {PASS,WARN,FAIL} ──

def check_range(value, lo, hi, name):
    if value is None:
        return "FAIL", f"{name}: no data"
    if lo <= value <= hi:
        return "PASS", f"{name}={value:.4f} (in [{lo},{hi}])"
    return "FAIL", f"{name}={value:.4f} OUT OF RANGE [{lo},{hi}]"


def m1_mcc(row: dict):
    mcc = row.get("cur_MCC")
    tp, fp, tn, fn = row.get("TP", 0), row.get("FP", 0), row.get("TN", 0), row.get("FN", 0)
    if mcc is None:
        return "FAIL", "M1: cur_MCC missing"
    if not (-1.0 - 1e-6 <= mcc <= 1.0 + 1e-6):
        return "FAIL", f"M1: cur_MCC={mcc:.4f} outside [-1,1]"
    if (tp + fp + tn + fn) <= 0:
        return "WARN", "M1: confusion matrix all-zero (no detection activity observed)"
    return "PASS", f"M1: cur_MCC={mcc:.4f}, TP={tp:.0f} FP={fp:.0f} TN={tn:.0f} FN={fn:.0f}"


def m2_tvr(row: dict, expect_nonzero: bool):
    tvr = row.get("cur_TVR")
    if tvr is None:
        return "FAIL", "M2: cur_TVR missing"
    if not (0.0 <= tvr <= 100.0):
        return "FAIL", f"M2: cur_TVR={tvr:.4f} outside [0,100]"
    if expect_nonzero and tvr == 0.0:
        return "FAIL", "M2: cur_TVR is exactly 0% under an active delay attack — " \
                       "the dead-counter bug may have regressed"
    return "PASS", f"M2: cur_TVR={tvr:.4f}%"


def m3_ucr(row: dict, expect_nonzero: bool):
    ucr = row.get("cur_UCR")
    if ucr is None:
        return "FAIL", "M3: cur_UCR missing"
    if not (0.0 <= ucr <= 100.0):
        return "FAIL", f"M3: cur_UCR={ucr:.4f} outside [0,100]"
    if expect_nonzero and ucr == 0.0:
        return "WARN", "M3: cur_UCR is 0% under an HF attack — check attack actually fired"
    return "PASS", f"M3: cur_UCR={ucr:.4f}%"


def m4_lmit(row: dict):
    lmit = row.get("cur_mit_ms")
    if lmit is None:
        return "FAIL", "M4: cur_mit_ms missing"
    if lmit < 0:
        return "FAIL", f"M4: cur_mit_ms={lmit:.4f} negative (impossible)"
    if lmit == 0:
        return "WARN", "M4: cur_mit_ms=0 — no quarantine fired yet (may need longer simTime " \
                        "or higher attack_percentage)"
    status = "PASS" if lmit <= 100.0 else "WARN"
    return status, f"M4: cur_mit_ms={lmit:.4f} (target <=100ms)"


def m5_lfailover(row: dict):
    events = row.get("ctrl_failover_events")
    max_ms = row.get("ctrl_failover_max_ms")
    if events is None or max_ms is None:
        return "FAIL", "M5: ctrl_failover_events/max_ms missing"
    if events == 0:
        return "WARN", "M5: no controller failover events observed in this run"
    if max_ms < 0:
        return "FAIL", f"M5: ctrl_failover_max_ms={max_ms:.4f} negative (impossible)"
    status = "PASS" if max_ms <= 100.0 else "WARN"
    return status, f"M5: events={events:.0f} max_ms={max_ms:.4f} (target <=100ms)"


def m6_le2e(row: dict):
    lat = row.get("cur_lat_ms")
    if lat is None:
        return "FAIL", "M6: cur_lat_ms missing"
    if lat < 0:
        return "FAIL", f"M6: cur_lat_ms={lat:.4f} negative (impossible)"
    if lat == 0:
        return "WARN", "M6: cur_lat_ms=0 — no packets delivered this cycle"
    status = "PASS" if lat <= 100.0 else "WARN"
    return status, f"M6: cur_lat_ms={lat:.4f} (target <=100ms)"


def m7_overhead(row: dict):
    o_crypto = row.get("o_crypto_bytes_pkt")
    t_batch  = row.get("t_batch_ms_avg")
    t_cons   = row.get("t_consensus_ms_avg")
    if o_crypto is None:
        return "FAIL", "M7: o_crypto_bytes_pkt missing"
    # ML-DSA-87 sig (4627 B, CRYPTO_CORRECTIONS.md DOC-1) + 64 B pi_delay commitment
    expected = 4627 + 64
    if o_crypto == 0:
        return "WARN", "M7: o_crypto_bytes_pkt=0 — no packets signed yet this run"
    if abs(o_crypto - expected) > 1.0:
        return "WARN", f"M7: o_crypto_bytes_pkt={o_crypto:.1f}, expected ~{expected} " \
                        "(check mldsa87_sign()'s sig_len)"
    if t_batch is None or t_batch < 0 or t_cons is None or t_cons < 0:
        return "FAIL", "M7: t_batch_ms_avg/t_consensus_ms_avg missing or negative"
    return "PASS", f"M7: o_crypto={o_crypto:.1f}B t_batch={t_batch:.4f}ms t_consensus={t_cons:.4f}ms"


def m9_eps_ref(rows_by_fbad: dict[int, float], n_rsus: int = 64):
    """rows_by_fbad: {f_bad_int: eps_ref_value} collected from a sweep."""
    issues = []
    for f_bad, eps in sorted(rows_by_fbad.items()):
        if f_bad < n_rsus / 2:
            if abs(eps) > 1e-6:
                issues.append(f"f_bad={f_bad}: eps_ref={eps:.4f}, expected ~0 "
                               f"(f_bad < N_RSUs/2={n_rsus/2})")
        else:
            if abs(eps) < 1e-6:
                issues.append(f"f_bad={f_bad}: eps_ref={eps:.4f}, expected >0 "
                               f"(f_bad >= N_RSUs/2={n_rsus/2}, bound should fail here)")
    if issues:
        return "FAIL", "M9: " + "; ".join(issues)
    return "PASS", f"M9: eps_ref boundary behavior correct across f_bad={sorted(rows_by_fbad.keys())}"


def m11_ufcr(row: dict, expect: float | None):
    ufcr = row.get("UFCR")
    total = row.get("ufcr_unauth_total")
    if ufcr is None:
        return "FAIL", "M11: UFCR missing"
    if total == 0:
        return "WARN", "M11: no unauthorized FlowMod attempts recorded — " \
                       "check active_attack_variant is a control-plane variant (1,3,5,7)"
    if expect is not None and abs(ufcr - expect) > 1.0:
        return "FAIL", f"M11: UFCR={ufcr:.4f}, expected ~{expect}"
    return "PASS", f"M11: UFCR={ufcr:.4f}% (unauth_total={total:.0f})"


def m12_wapr(row: dict):
    prec = row.get("WAP_precision")
    rec  = row.get("WAP_recall")
    tp_w, fp_w = row.get("witness_TP_W", 0), row.get("witness_FP_W", 0)
    if prec is None or rec is None:
        return "FAIL", "M12: WAP_precision/WAP_recall missing"
    if not (0.0 <= prec <= 100.0) or not (0.0 <= rec <= 100.0):
        return "FAIL", f"M12: precision={prec:.4f} or recall={rec:.4f} outside [0,100]"
    if (tp_w + fp_w) == 0:
        return "WARN", "M12: no witness threshold events fired (TP_W+FP_W=0) — " \
                       "check this is a passive HF run (Attack 7 or 8)"
    return "PASS", f"M12: precision={prec:.4f}% recall={rec:.4f}% (TP_W={tp_w:.0f} FP_W={fp_w:.0f})"


def m8_poisoning(json_path: str):
    with open(json_path) as fh:
        results = json.load(fh)
    lines, worst = [], "PASS"
    for mode, sweep in results.items():
        for key, entry in sweep.items():
            rho = float(key.replace("rho_", ""))
            delta = entry.get("delta_poison")
            if delta is None:
                continue
            if mode == "brfa" and rho < (1.0 / 3.0):
                if abs(delta) >= 0.05:
                    lines.append(f"FAIL [brfa rho={rho}] delta_poison={delta:.4f} "
                                 f">= 0.05 (target: robust below f<1/3 bound)")
                    worst = "FAIL"
                else:
                    lines.append(f"PASS [brfa rho={rho}] delta_poison={delta:.4f}")
            else:
                lines.append(f"INFO [{mode} rho={rho}] delta_poison={delta:.4f}")
    return worst, "M8:\n    " + "\n    ".join(lines)


# ── CLI / orchestration ──────────────────────────────────────────────────────

def find_one(pattern: str) -> str | None:
    matches = glob.glob(pattern)
    return matches[0] if matches else None


def run_single_file(path: str, mode: str, args):
    rows = parse_mobiguard_csv(path)
    row = last_row(rows)
    if row is None:
        print(f"[FAIL] {path}: no valid data rows parsed")
        return 1

    checks = []
    if mode in ("baseline", "sweep", "full-report"):
        checks.append(m1_mcc(row))
        checks.append(m2_tvr(row, expect_nonzero=("Attack1" in path or "Attack2" in path)))
        checks.append(m3_ucr(row, expect_nonzero=any(f"Attack{v}" in path for v in (5, 6, 7, 8))))
        checks.append(m4_lmit(row))
        checks.append(m6_le2e(row))
        checks.append(m7_overhead(row))
        checks.append(m5_lfailover(row))
        checks.append(m12_wapr(row))
    if mode == "m7":
        checks.append(m7_overhead(row))
    if mode == "m11":
        checks.append(m11_ufcr(row, args.expect_ufcr))
    if mode == "m12":
        checks.append(m12_wapr(row))

    worst = "PASS"
    for status, msg in checks:
        print(f"  [{status}] {msg}")
        if status == "FAIL":
            worst = "FAIL"
        elif status == "WARN" and worst != "FAIL":
            worst = "WARN"
    return 0 if worst != "FAIL" else 1


def run_m9_sweep(directory: str):
    files = sorted(glob.glob(os.path.join(directory, "MOBIGUARD_baseline_fbad*.csv")))
    if not files:
        print("[FAIL] M9: no MOBIGUARD_baseline_fbad*.csv files found — "
              "run Part 3's M9 sweep first")
        return 1
    rows_by_fbad = {}
    for f in files:
        rows = parse_mobiguard_csv(f)
        row = last_row(rows)
        if row is None:
            continue
        f_bad = int(row.get("time_ref_f_bad", -1))
        rows_by_fbad[f_bad] = row.get("eps_ref_s")
    status, msg = m9_eps_ref(rows_by_fbad)
    print(f"  [{status}] {msg}")
    return 0 if status != "FAIL" else 1


def run_full_report(directory: str):
    print("=" * 70)
    print("FULL METRICS REPORT")
    print("=" * 70)
    pattern_map = {
        "M1/M2/M3/M4/M6/M7 (baseline)": os.path.join(directory, "MOBIGUARD_baseline.csv"),
        "M2 TVR (Attack1)":  os.path.join(directory, "MOBIGUARD_Attack1_*.csv"),
        "M3 UCR (Attack5)":  os.path.join(directory, "MOBIGUARD_Attack5_*.csv"),
        "M12 WAP-R (Attack7)": os.path.join(directory, "MOBIGUARD_Attack7_*.csv"),
    }
    overall = 0
    for label, pattern in pattern_map.items():
        path = find_one(pattern)
        print(f"\n--- {label} ---")
        if path is None:
            print(f"  [FAIL] no file matching {pattern}")
            overall = 1
            continue
        rc = run_single_file(path, "sweep", argparse.Namespace(expect_ufcr=None))
        overall = overall or rc

    print("\n--- M9 (time-ref sweep) ---")
    rc = run_m9_sweep(directory)
    overall = overall or rc

    m8_path = os.path.join(os.path.dirname(directory) or ".", "lstm_pipeline", "poison_sweep_results.json")
    print("\n--- M8 (poisoning sweep) ---")
    if os.path.exists(m8_path):
        status, msg = m8_poisoning(m8_path)
        print(f"  [{status}] {msg}")
        overall = overall or (1 if status == "FAIL" else 0)
    else:
        print(f"  [WARN] {m8_path} not found — run Part 4 first")

    print("\n" + "=" * 70)
    print("OVERALL:", "FAIL — see above" if overall else "ALL CHECKS PASSED OR WARNED (no FAILs)")
    print("=" * 70)
    return overall


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", help="Single CSV or JSON file to check")
    ap.add_argument("--dir", help="Directory of result CSVs (for sweep/m9/full-report modes)")
    ap.add_argument("--mode", required=True,
                    choices=["baseline", "sweep", "m7", "m8", "m9", "m11", "m12", "full-report"])
    ap.add_argument("--expect-ufcr", type=float, default=None,
                    help="Expected UFCR value for --mode m11 (e.g. 0 or 100)")
    args = ap.parse_args()

    if args.mode == "m8":
        path = args.file or "lstm_pipeline/poison_sweep_results.json"
        status, msg = m8_poisoning(path)
        print(f"[{status}] {msg}")
        sys.exit(1 if status == "FAIL" else 0)

    if args.mode == "m9":
        sys.exit(run_m9_sweep(args.dir or "results_routing"))

    if args.mode == "full-report":
        sys.exit(run_full_report(args.dir or "results_routing"))

    path = args.file
    if path and "*" in path:
        resolved = find_one(path)
        if resolved is None:
            print(f"[FAIL] no file matching {path}")
            sys.exit(1)
        path = resolved
    if not path:
        print("[FAIL] --file (or --dir for sweep modes) required")
        sys.exit(1)

    sys.exit(run_single_file(path, args.mode, args))


if __name__ == "__main__":
    main()
