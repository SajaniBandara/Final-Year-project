#!/usr/bin/env python3
"""
window_level_mcc.py — Supervisor Fix 2 (2026-08-19): compute Q1-Q6 MCC from
detector_windows.csv (eq:eval_dedup: non-overlapping 10s blocks, max-pooled)
instead of the sticky-latch per-node confusion matrix.

Same dedup method as evaluator.py's deduplicate_windows() (10s block =
floor(w_start/10), grouped by (node, variant, block), max-pooled score and
truth), applied here to the live NS-3 detector_windows.csv output rather
than the offline LSTM test split.

NOTE: detector_windows_Attack<N>_*.csv uses a fixed filename (not tagged by
Q-config), so it reflects whichever config last ran for that attack number.
Run this immediately after a Q-config finishes, before the next config
overwrites it, or pass --dir to read from a saved copy.
"""
import argparse
import csv
import glob
import math
from collections import defaultdict
from pathlib import Path

RESULTS_DIR = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"


def confusion_and_mcc(rows):
    """rows: list of (truth, pred) already block-deduplicated."""
    tp = sum(1 for t, p in rows if t == 1 and p == 1)
    fp = sum(1 for t, p in rows if t == 0 and p == 1)
    fn = sum(1 for t, p in rows if t == 1 and p == 0)
    tn = sum(1 for t, p in rows if t == 0 and p == 0)
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = 0.0 if denom == 0 else (tp * tn - fp * fn) / denom
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
    dr = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, MCC=mcc, FPR=fpr, DR=dr)


def dedup_and_score(path, variant):
    """Load one detector_windows.csv, filter to `variant`, dedup into
    non-overlapping 10s blocks (max-pooled), return per-block (truth, pred)."""
    blocks = defaultdict(lambda: [0, 0])  # (node, block_idx) -> [truth_max, pred_max]
    with open(path) as fh:
        for row in csv.DictReader(fh):
            if int(row["variant"]) != variant:
                continue
            block_idx = int(float(row["w_start"]) // 10)
            key = (row["node"], block_idx)
            truth = int(row.get("truth", 0) or 0)
            pred = 1 if float(row["score"]) > 0.5 else 0
            b = blocks[key]
            b[0] = max(b[0], truth)
            b[1] = max(b[1], pred)
    return [(t, p) for t, p in blocks.values()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(RESULTS_DIR))
    ap.add_argument("--tag", default="", help="label for this run, e.g. Q5")
    args = ap.parse_args()

    print(f"{'variant':<10}{'TP':>6}{'FP':>6}{'FN':>6}{'TN':>6}{'MCC':>9}{'FPR%':>8}{'DR%':>8}")
    print("-" * 60)
    mccs = []
    for a in range(1, 9):
        pattern = str(Path(args.dir) / f"detector_windows_Attack{a}_*.csv")
        files = glob.glob(pattern)
        if not files:
            print(f"A{a:<9}  NO FILE")
            continue
        path = sorted(files, key=lambda p: Path(p).stat().st_mtime)[-1]
        rows = dedup_and_score(path, a)
        if not rows:
            print(f"A{a:<9}  NO ROWS for variant={a} in {Path(path).name}")
            continue
        m = confusion_and_mcc(rows)
        mccs.append(m["MCC"])
        print(f"A{a:<9}{m['TP']:6d}{m['FP']:6d}{m['FN']:6d}{m['TN']:6d}"
              f"{m['MCC']:9.4f}{100*m['FPR']:8.2f}{100*m['DR']:8.2f}"
              f"   ({Path(path).name}, mtime={Path(path).stat().st_mtime:.0f})")
    if mccs:
        print(f"\nmacro-MCC ({args.tag or 'this snapshot'}, "
              f"n={len(mccs)}/8 variants available): {sum(mccs)/len(mccs):.4f}")


if __name__ == "__main__":
    main()
