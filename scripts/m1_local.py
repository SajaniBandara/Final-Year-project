#!/usr/bin/env python3
"""
m1_local.py — LOCAL RE-IMPLEMENTATION of M1 (eq:mcc / eq:eval_dedup).

WHY THIS EXISTS (2026-08-31)
----------------------------
The documented M1 route is two stages:

    scripts/m1_from_detector_windows.py   -> combined detector_windows.csv
    python3 -m metrics.run_metrics <dir>  -> M1

**Stage two does not exist on this host.** There is no `metrics/` package in
`ns3_g13`, none in `ns3_g13_apsari`, no `run_metrics.py` or
`m01_detection_quality.py` anywhere under $HOME, and it was never tracked in
this repo's git history -- despite `detector_windows.h` and
`m1_from_detector_windows.py` both citing `metrics/config.py` and
`metrics/README.md` as though present. So the simulator emits valid window
grids that nothing on this machine can score.

This script closes that gap by computing M1 directly from the grid.

*** READ THIS BEFORE QUOTING A NUMBER FROM IT ***

This is a RE-IMPLEMENTATION from the documented definition, not the canonical
`metrics/` code. It has never been reconciled against that code, because that
code is not available to reconcile against. Therefore:

  - DO NOT compare its output to the historical canonical M1 = 0.2721
    (Q6 full-system, 60%, seed 1). A difference could be this script, the
    canonical one, or a real change -- you cannot tell which.
  - DO use it for A/B comparisons where both arms are scored by THIS script
    on runs from the SAME binary. Any constant offset cancels, so the delta
    between arms is meaningful even if the absolute level is not.

Definition implemented (per docs/WHICH_MCC_TO_REPORT.md / eq:eval_dedup):

  - RSU rows only. OBU rows excluded.
  - Warm-up excluded: windows starting within WARMUP_S of the run's first
    window are dropped (the EWMA baselines have not converged).
  - Non-overlapping 10 s blocks. detector_windows.h emits W=10 s at stride
    5 s (50 % overlap, lines 53-54), so the de-duplicated grid is every
    SECOND window: those with round((w_start - t0)/stride) even.
  - MCC over (score, truth) on the surviving rows.

`t0` is taken per FILE, because each run's grid starts at its own first cycle
time (e.g. 1.998 s), not at zero.
"""

import argparse
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

WINDOW_S = 10.0
STRIDE_S = 5.0
WARMUP_S = 30.0


def mcc(tp: int, fp: int, fn: int, tn: int) -> float:
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / den if den else 0.0


def load(path: Path, mode: str, score_col: str, warmup: float, dedup: bool,
         persistence: int = 1, truth_semantics: str = "event"):
    """Yield (variant, score, truth) for surviving rows of one run's grid.

    persistence M (item 7, detector_windows.h 2026-08-30): a window counts as
    positive iff the detector fired in >= M DISTINCT CYCLES inside it, read
    from the `{score_col}_cycles` column. M=1 reproduces the plain OR exactly.
    Grids written before 2026-08-30 have no *_cycles column; M>1 is refused
    there rather than silently falling back to OR semantics, which would look
    like "persistence changed nothing".
    """
    with open(path) as fh:
        rdr = list(csv.DictReader(fh))
    if not rdr:
        return
    cyc_col = f"{score_col}_cycles"
    have_cycles = cyc_col in rdr[0]
    if persistence > 1 and not have_cycles:
        raise SystemExit(
            f"ERROR: {path.name} has no '{cyc_col}' column (pre-2026-08-30 "
            f"grid), so --persistence {persistence} cannot be evaluated on it. "
            f"Re-run the sim with the current binary, or use --persistence 1.")
    starts = [float(r["w_start"]) for r in rdr]
    t0 = min(starts)
    # LATCH: positive from a node's FIRST fire onward. Computed here, offline,
    # as a cumulative max of `truth` per node within this run -- the same
    # semantics as preprocessor.py:229's np.maximum.accumulate(hfgt > 0) on
    # y_indep. Requires NO simulator change and touches nothing but this score.
    # Rows must be walked in time order for the accumulation to be causal.
    if truth_semantics == "latch":
        rdr = sorted(rdr, key=lambda r: (r["node"], float(r["w_start"])))
        _seen = {}
        for r in rdr:
            k = r["node"]
            if float(r.get("truth") or 0) > 0.5:
                _seen[k] = 1
            r["_latch"] = _seen.get(k, 0)
    for r in rdr:
        if r["mode"] != mode:
            continue
        ws = float(r["w_start"])
        if ws < t0 + warmup:
            continue
        if dedup:
            # Non-overlapping lattice: keep every second stride step.
            k = round((ws - t0) / STRIDE_S)
            if k % 2:
                continue
        if truth_semantics == "latch":
            t = r.get("_latch", 0)
        elif truth_semantics == "declared":
            t = r.get("truth_declared", "")
        else:
            t = r.get("truth", "")
        if t == "" or t is None:
            continue
        if persistence > 1:
            c = r.get(cyc_col, "")
            if c == "":
                continue
            pred = int(float(c) >= persistence)
        else:
            s = r.get(score_col, "")
            if s == "":
                continue
            pred = int(float(s) > 0.5)
        yield int(r["variant"]), pred, int(float(t) > 0.5)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", type=Path, required=True)
    ap.add_argument("--tag", default="",
                    help="substring filter on filename, e.g. '_Q6'")
    ap.add_argument("--mode", default="RSU", choices=["RSU", "OBU"])
    ap.add_argument("--score-col", default="score",
                    choices=["score", "score_primary"],
                    help="'score' = D_RSU OR-composite (includes flag_LSTM); "
                         "'score_primary' = the variant's primary detector "
                         "(EXCLUDES the LSTM for every variant -- lrad.h)")
    ap.add_argument("--warmup", type=float, default=WARMUP_S)
    ap.add_argument("--truth-semantics", default="event",
                    choices=["event", "latch", "declared"],
                    help="event: `truth` as emitted (declared AND fired this "
                         "cycle) -- the current convention. latch: positive from "
                         "the node's FIRST fire onward, computed offline as a "
                         "cumulative max of `truth` per (variant,node); matches "
                         "S5-S8's persistent-state semantics and the latch "
                         "preprocessor.py:229 already applies to y_indep. "
                         "declared: `truth_declared`, positive for the whole run "
                         "-- over-counts PRE-ONSET windows, use only as a bound.")
    ap.add_argument("--persistence", type=int, default=1, metavar="M",
                    help="window positive iff detector fired in >= M distinct "
                         "cycles (reads {score_col}_cycles). M=1 = plain OR. "
                         "Needs a grid from the 2026-08-30+ binary.")
    ap.add_argument("--no-dedup", action="store_true",
                    help="keep all overlapping windows (NOT M1; diagnostic only)")
    ap.add_argument("--label", default="", help="printed in the header")
    a = ap.parse_args()

    pat = f"detector_windows_*{a.tag}*.csv" if a.tag else "detector_windows_*.csv"
    files = sorted(a.results_dir.glob(pat))
    if not files:
        print(f"ERROR: no files matching {pat} in {a.results_dir}", file=sys.stderr)
        return 1

    # counts[variant] = [tp, fp, fn, tn]
    counts = defaultdict(lambda: [0, 0, 0, 0])
    tot = [0, 0, 0, 0]
    for f in files:
        for variant, s, t in load(f, a.mode, a.score_col, a.warmup,
                                  not a.no_dedup, a.persistence,
                                  a.truth_semantics):
            idx = 0 if (t and s) else 1 if (not t and s) else 2 if (t and not s) else 3
            counts[variant][idx] += 1
            tot[idx] += 1

    if sum(tot) == 0:
        print("ERROR: 0 rows survived. Runs likely too short: a window needs "
              "10 s inside the run and the first "
              f"{a.warmup:.0f} s are dropped as warm-up.", file=sys.stderr)
        return 1

    hdr = f"M1 ({a.mode}, {a.score_col}, truth={a.truth_semantics}, warmup={a.warmup:.0f}s, " \
          f"persistence M={a.persistence}, " \
          f"{'deduped 10s blocks' if not a.no_dedup else 'OVERLAPPING - not M1'})"
    if a.label:
        hdr += f"  [{a.label}]"
    print(hdr)
    print(f"  files: {len(files)}")
    print("  NOTE: local re-implementation -- compare arm-to-arm, "
          "NOT against the canonical 0.2721. See module docstring.")
    print()
    print(f"{'variant':<10}{'MCC':>9}{'DR':>9}{'FPR':>9}"
          f"{'TP':>8}{'FP':>8}{'FN':>8}{'TN':>8}")
    for v in sorted(counts):
        tp, fp, fn, tn = counts[v]
        dr = 100 * tp / (tp + fn) if tp + fn else float("nan")
        fpr = 100 * fp / (fp + tn) if fp + tn else float("nan")
        name = "benign" if v == 0 else f"A{v}"
        print(f"{name:<10}{mcc(tp, fp, fn, tn):>9.4f}{dr:>8.1f}%{fpr:>8.1f}%"
              f"{tp:>8}{fp:>8}{fn:>8}{tn:>8}")
    tp, fp, fn, tn = tot
    dr = 100 * tp / (tp + fn) if tp + fn else float("nan")
    fpr = 100 * fp / (fp + tn) if fp + tn else float("nan")
    print("-" * 69)
    print(f"{'ALL':<10}{mcc(tp, fp, fn, tn):>9.4f}{dr:>8.1f}%{fpr:>8.1f}%"
          f"{tp:>8}{fp:>8}{fn:>8}{tn:>8}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
