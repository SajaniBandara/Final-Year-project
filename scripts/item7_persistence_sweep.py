#!/usr/bin/env python3
"""
item7_persistence_sweep.py — item 7 within-window persistence (supervisor, 2026-08-30).

The ask: "Build a version that requires the delay condition to hold across
several cycles within the same window before that window counts as positive,
not just one cycle out of ten. Sweep two or three small values ... and report
false alarm rate and recall for each value side by side."

Reads the score_cycles / score_primary_cycles columns added to
detector_windows.csv (detector_windows.h, 2026-08-30) — the number of DISTINCT
CYCLES inside each window in which the detector fired. A window is positive
under persistence-M iff that count >= M, so M sweeps entirely offline from ONE
run per configuration instead of one 90-minute run per candidate M. M=1
reproduces today's OR behaviour exactly and is printed as the baseline row.

WHY DISTINCT CYCLES AND NOT FIRING COUNT: an earlier version of this analysis
counted raw firings per window and showed only ~1.3x benign/attack separation,
which would have argued against the whole approach. Counting distinct cycles
shows ~10x at M=3. Benign false positives are bursts inside a single cycle;
genuine attacks persist across cycles. The distinction is the entire result.

FPR is measured on OBU rows of a ZERO-ATTACK run (every firing is a false
positive by definition), matching how the 18.86% / 17.11% figures in
SUPERVISOR_UPDATE_2026-08-30.md were computed.

Recall is measured on RSU rows via score_primary against the truth column.
Printed BOTH un-deduplicated (matching the published A1/A2 table, n=3712) and
deduplicated (results_table.py's eq:eval_dedup convention, n=1856) because the
two conventions differ by 2x in absolute counts and mixing them silently is an
easy way to compare numbers that were never comparable.

Usage:
  python3 scripts/item7_persistence_sweep.py --results-dir <dir> \
      --baseline detector_windows_Attack0_0_seed1_pers_base.csv \
      --attack   detector_windows_Attack1_60_d80ms_seed1_pers_a1.csv \
      --attack   detector_windows_Attack2_60_d80ms_seed1_pers_a2.csv
"""
import argparse, csv, math, sys
from pathlib import Path

MAXM = 6

def _rows(path, mode, dedup):
    rows = [r for r in csv.DictReader(open(path)) if r.get("mode") == mode]
    if not rows:
        return []
    if "score_primary_cycles" not in rows[0]:
        sys.exit(f"ERROR: {Path(path).name} has no persistence columns.\n"
                 "       It predates detector_windows.h's 2026-08-30 change; re-run it.")
    if dedup:
        starts = sorted({float(r["w_start"]) for r in rows})
        keep = set(starts[::2])      # non-overlapping 10s blocks
        rows = [r for r in rows if float(r["w_start"]) in keep]
    return rows

def _int(v):
    try:    return int(float(v or 0))
    except (TypeError, ValueError): return 0

def fpr_sweep(path):
    """Zero-attack: every fired window is a false positive."""
    rows = _rows(path, "OBU", dedup=False)
    tot = len(rows)
    out = []
    for M in range(1, MAXM + 1):
        fp = sum(1 for r in rows if _int(r.get("score_cycles")) >= M)
        out.append((M, fp, tot, fp / tot * 100 if tot else float("nan")))
    return out

def recall_sweep(path, dedup):
    rows = _rows(path, "RSU", dedup)
    out = []
    for M in range(1, MAXM + 1):
        tp = fp = fn = tn = 0
        for r in rows:
            fired = _int(r.get("score_primary_cycles")) >= M
            truth = (r.get("truth") or "0") == "1"
            if   truth and fired:     tp += 1
            elif truth:               fn += 1
            elif fired:               fp += 1
            else:                     tn += 1
        den = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
        out.append(dict(M=M, tp=tp, fp=fp, fn=fn, tn=tn,
                        recall=tp/(tp+fn)*100 if tp+fn else float("nan"),
                        fpr=fp/(fp+tn)*100 if fp+tn else float("nan"),
                        prec=tp/(tp+fp)*100 if tp+fp else float("nan"),
                        mcc=(tp*tn-fp*fn)/den if den else 0.0))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True, type=Path)
    ap.add_argument("--baseline", default=None,
                    help="zero-attack detector_windows csv (for FPR)")
    ap.add_argument("--attack", action="append", default=[],
                    help="attack detector_windows csv (for recall); repeatable")
    a = ap.parse_args()

    if a.baseline:
        p = a.results_dir / a.baseline
        print("=" * 72)
        print(f"FALSE ALARM RATE — zero attack, OBU windows — {p.name}")
        print("=" * 72)
        print(f"{'M':>3} {'FP windows':>12} {'total':>8} {'window FPR':>12}")
        for M, fp, tot, pct in fpr_sweep(p):
            tag = "   <- today (OR)" if M == 1 else ("   <- clears 1% target" if pct <= 1.0 else "")
            print(f"{M:>3} {fp:>12} {tot:>8} {pct:>11.2f}%{tag}")
        print()

    for name in a.attack:
        p = a.results_dir / name
        for dedup, label in ((False, "un-deduplicated (matches the published A1/A2 table)"),
                             (True,  "deduplicated (results_table.py / eq:eval_dedup)")):
            print("=" * 72)
            print(f"RECALL — {p.name}")
            print(f"  {label}")
            print("=" * 72)
            print(f"{'M':>3} {'TP':>6}{'FP':>6}{'FN':>6}{'TN':>6} {'recall':>9} {'FPR':>8} {'prec':>8} {'MCC':>8}")
            for r in recall_sweep(p, dedup):
                tag = "  <- today" if r["M"] == 1 else ""
                print(f"{r['M']:>3} {r['tp']:>6}{r['fp']:>6}{r['fn']:>6}{r['tn']:>6} "
                      f"{r['recall']:>8.2f}% {r['fpr']:>7.2f}% {r['prec']:>7.2f}% {r['mcc']:>8.4f}{tag}")
            print()

if __name__ == "__main__":
    main()
