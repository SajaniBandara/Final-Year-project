#!/usr/bin/env python3
"""results_table.py — the reporting surface for the paper's detection numbers.

Implements supervisor decisions 2, 3 and 5 (2026-08-27) in one place so the
three cannot drift apart:

  ITEM 3  Window-level ONLY. The per-node whole-run confusion matrix never
          appears here. It is a sticky-latch statistic: one false firing marks
          a node wrong for the remainder of the run, so FP accumulates with
          run length while TP saturates, mechanically dragging precision down
          the longer you run (measured: same config 55.6% at 20 s, 26.6% at
          90 s). Keep using it to hunt bugs; it is not a results number.
          This script deliberately provides no way to emit it.

  ITEM 2  Recall is reported BOTH ways, always, side by side:
            recall_declared — against every declared attacker
            recall_acted    — against attackers that actually acted
          Reading the acted-only number alone flatters the system; reading the
          declared-only number alone penalises it for nodes that were never
          detectable because they never did anything. Both, plainly, together.
          Requires the truth_declared column (detector_windows.h, 2026-08-27);
          files predating it can only report recall_acted, and this script
          says so rather than silently reporting one as the other.

  ITEM 5  Monotonicity is checked per variant along that variant's OWN ladder,
          not across one global six-column grid. A witness-only config scoring
          zero on a timing attack is an empty cell, not a finding.

Scoring follows eq:eval_dedup: RSU rows, primary-detector column,
non-overlapping blocks. The emitter's grid is W=10 s stride=5 s (50% overlap),
so every second window is taken to make the blocks tile.

Usage:
  python3 scripts/results_table.py --results-dir <dir> --suffix _fixed
"""
import argparse
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

# ── Item 5: per-variant applicable ladders ────────────────────────────────
# Each entry is (rung label, Q-config tag). Monotonic non-decrease is required
# left to right. Variants are NOT required to have a value in configs whose
# detectors were never built to catch them.
LADDERS = {
    1: [("rule-only", "Q1"), ("full", "Q6")],
    2: [("rule-only", "Q1"), ("full", "Q6")],
    3: [("rule-only", "Q1"), ("full", "Q6")],
    4: [("rule-only", "Q1"), ("full", "Q6")],
    5: [("crypto-only", "Q2"), ("full", "Q6")],
    6: [("crypto-only", "Q2"), ("full", "Q6")],
    7: [("witness", "Q4"), ("full", "Q6")],
    8: [("witness", "Q4"), ("full", "Q6")],
}

# A7/A8's first rung is specified as "witness + R_anom". No existing Q-config
# is exactly that: Q4 is witness-only (S7/S8 off, and the R_anom zero-tolerance
# rule rides the S7/S8 path), while Q2 carries R_anom but also the whole crypto
# layer. Q4 is used here and the gap is reported rather than silently papered
# over -- if the intended rung is "witness + R_anom and nothing else", it needs
# a new config in run_q1q6_ablation.py.
LADDER_CAVEATS = {
    7: "first rung is Q4 (witness only); 'witness+R_anom' has no exact config",
    8: "first rung is Q4 (witness only); 'witness+R_anom' has no exact config",
}

VARIANT_FILE = {
    1: "detector_windows_Attack1_60_d80ms_seed{seed}{suffix}.csv",
    2: "detector_windows_Attack2_60_d80ms_seed{seed}{suffix}.csv",
    3: "detector_windows_Attack3_60_seed{seed}{suffix}.csv",
    4: "detector_windows_Attack4_60_seed{seed}{suffix}.csv",
    5: "detector_windows_Attack5_60_seed{seed}{suffix}.csv",
    6: "detector_windows_Attack6_60_seed{seed}{suffix}.csv",
    7: "detector_windows_Attack7_60_seed{seed}{suffix}.csv",
    8: "detector_windows_Attack8_60_seed{seed}{suffix}.csv",
}


def mcc(tp, fp, fn, tn):
    d = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return ((tp * tn - fp * fn) / math.sqrt(d)) if d > 0 else 0.0


def score_file(path):
    """Score one detector_windows CSV. Returns a dict, or None if unreadable.

    RSU rows only, score_primary column, non-overlapping blocks (eq:eval_dedup).
    """
    rows = []
    has_declared = False
    with open(path, newline="") as fh:
        rdr = csv.DictReader(fh)
        has_declared = "truth_declared" in (rdr.fieldnames or [])
        for r in rdr:
            if r.get("mode") != "RSU":
                continue
            rows.append(r)
    if not rows:
        return None

    # Non-overlapping blocks: the grid is stride-5 / window-10, so distinct
    # w_start values step by 5 s and every second one tiles without overlap.
    starts = sorted({float(r["w_start"]) for r in rows})
    keep = set(starts[::2])

    tp = fp = fn = tn = 0
    # Item 2: the declared-set confusion matrix, scored on the same windows.
    d_tp = d_fn = 0
    for r in rows:
        if float(r["w_start"]) not in keep:
            continue
        fired = float(r.get("score_primary") or 0.0) >= 0.5
        truth = (r.get("truth") or "0") == "1"
        if truth and fired:
            tp += 1
        elif not truth and fired:
            fp += 1
        elif truth and not fired:
            fn += 1
        else:
            tn += 1
        if has_declared:
            td = (r.get("truth_declared") or "0") == "1"
            if td and fired:
                d_tp += 1
            elif td and not fired:
                d_fn += 1

    out = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "mcc": mcc(tp, fp, fn, tn),
        "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
        "recall_acted": tp / (tp + fn) if (tp + fn) else float("nan"),
        "recall_declared": (d_tp / (d_tp + d_fn)) if has_declared and (d_tp + d_fn)
                           else float("nan"),
        "has_declared": has_declared,
    }
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", required=True, type=Path)
    ap.add_argument("--suffix", default="",
                    help="config-tag suffix on the filenames, e.g. _fixed")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    print("MOBIGUARD detection results -- window level (eq:eval_dedup), "
          f"seed {args.seed}")
    print("Per-node whole-run matrix intentionally absent (item 3).\n")

    missing = []
    any_declared = False
    ladder_rows = {}

    for v in sorted(LADDERS):
        ladder_rows[v] = []
        for label, qtag in LADDERS[v]:
            name = VARIANT_FILE[v].format(seed=args.seed,
                                          suffix=f"_{qtag}{args.suffix}")
            path = args.results_dir / name
            if not path.exists():
                missing.append(name)
                ladder_rows[v].append((label, qtag, None))
                continue
            res = score_file(path)
            any_declared = any_declared or (res or {}).get("has_declared", False)
            ladder_rows[v].append((label, qtag, res))

    # ── Item 5: per-variant ladders with monotonicity verdicts ─────────────
    print("=" * 78)
    print("PER-VARIANT LADDERS (item 5) -- monotonic non-decrease required")
    print("=" * 78)
    hdr = f"{'variant':<9}{'rung':<14}{'cfg':<6}{'MCC':>9}{'prec':>9}" \
          f"{'rec_acted':>11}{'rec_declared':>14}"
    print(hdr)
    print("-" * len(hdr))
    for v in sorted(ladder_rows):
        prev = None
        broke = False
        for label, qtag, res in ladder_rows[v]:
            if res is None:
                print(f"A{v:<8}{label:<14}{qtag:<6}{'MISSING':>9}")
                continue
            print(f"A{v:<8}{label:<14}{qtag:<6}{res['mcc']:>9.4f}"
                  f"{res['precision']:>9.3f}{res['recall_acted']:>11.3f}"
                  f"{res['recall_declared']:>14.3f}")
            if prev is not None and res["mcc"] < prev - 1e-9:
                broke = True
            prev = res["mcc"]
        if broke:
            print(f"{'':<9}^^ MONOTONICITY VIOLATED on A{v}")
        if v in LADDER_CAVEATS:
            print(f"{'':<9}note: {LADDER_CAVEATS[v]}")
        print()

    # ── Item 2: the dual-recall statement, called out explicitly ───────────
    print("=" * 78)
    print("RECALL, BOTH WAYS (item 2)")
    print("=" * 78)
    if not any_declared:
        print("truth_declared column ABSENT from every file read.")
        print("Only recall_acted is available; these files predate the column")
        print("(detector_windows.h, 2026-08-27). Re-run to report both.")
    else:
        print("recall_acted    = against attackers that actually acted in the window")
        print("recall_declared = against every declared attacker, acted or not")
        print("Report both. Neither alone is the honest number.")
    print()

    if missing:
        print(f"MISSING FILES ({len(missing)}):")
        for m in missing:
            print(f"  {m}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
