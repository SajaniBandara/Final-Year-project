#!/usr/bin/env python3
"""
m1_from_detector_windows.py — compute the PAPER's M1 (eq:mcc / eq:mcc_variant)
from the per-window detector grid emitted by scratch/detector_windows.h.

WHY THIS EXISTS
---------------
Two different MCCs have been reported in this project and they are not
comparable:

  * PER-NODE   — the inline confusion matrix in routing.cc
                 (calculate_security_detection_metrics), 268 nodes, sticky
                 latches, whole-run. This is what the Q1-Q6 ablation prints.
  * PER-WINDOW — what the thesis actually defines: 10 s windows stratified by
                 variant and mode (OBU/RSU), which metrics/m01_detection_quality.py
                 computes. metrics/README.md lists this as blocked on a
                 `detector_windows.csv` the simulator never wrote.

Measured 2026-08-06 on the same Q6 configuration: 0.264 per-node against ~0.895
per-window on the LSTM pipeline's own evaluator. Neither is wrong; only the
per-window one is M1.

The simulator now emits detector_windows_A{v}_pct{p}_seed{s}.csv per run. This
script stitches a set of those into the single `detector_windows.csv` that
metrics/run_metrics.py expects and runs M1 over it. Concatenating is correct
rather than a shortcut: m01's View 2 groups by the `variant` column, so one
combined file yields the aggregate topline AND the per-variant/per-mode
breakdown in a single pass.

USAGE
  python3 scripts/m1_from_detector_windows.py \
      --results-dir ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing \
      --tag pct60_seed1 \
      --out-dir /tmp/m1_q6

  # then, from the ns-3 tree root (metrics/ is a package there):
  python3 -m metrics.run_metrics /tmp/m1_q6
"""

import argparse
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", type=Path, required=True,
                    help="directory holding detector_windows_A*.csv")
    ap.add_argument("--tag", default="",
                    help="filter, e.g. 'pct60_seed1' (default: all files)")
    ap.add_argument("--out-dir", type=Path, required=True,
                    help="run dir to create, containing the combined detector_windows.csv")
    args = ap.parse_args()

    pattern = f"detector_windows_A*{args.tag}*.csv" if args.tag else "detector_windows_A*.csv"
    files = sorted(args.results_dir.glob(pattern))
    if not files:
        print(f"ERROR: no files matching {pattern} in {args.results_dir}", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / "detector_windows.csv"

    header = None
    rows = 0
    with open(out, "w") as w:
        for f in files:
            with open(f) as r:
                h = r.readline().rstrip("\n")
                if header is None:
                    header = h
                    w.write(header + "\n")
                elif h != header:
                    print(f"ERROR: header mismatch in {f.name}\n"
                          f"  expected: {header}\n  got:      {h}", file=sys.stderr)
                    return 1
                n = 0
                for line in r:
                    if line.strip():
                        w.write(line)
                        n += 1
            print(f"  {f.name}: {n} rows")
            rows += n

    if rows == 0:
        print("\nERROR: 0 data rows. The runs were almost certainly too short — a\n"
              "window needs a full 10 s inside the run, and evaluator-style warm-up\n"
              "exclusion wants >= 90 s. Re-run with --sim-time 90 or more.",
              file=sys.stderr)
        return 1

    print(f"\nwrote {rows} rows from {len(files)} file(s) -> {out}")
    print("\nNow run M1 from the ns-3 tree root:")
    print(f"  python3 -m metrics.run_metrics {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
