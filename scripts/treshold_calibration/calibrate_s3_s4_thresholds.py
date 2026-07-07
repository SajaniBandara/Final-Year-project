#!/usr/bin/env python3
"""
calibrate_s3_s4_thresholds.py

Calibrates the S3/S4 (TCAM exhaustion) rule-engine thresholds
    lambda_thresh  (PACKET_IN flood-rate threshold, lambda_PI)
    U_thresh       (TCAM utilisation threshold, U_TCAM)
from benign-only (0% attack) per-RSU baseline data, following the
10s sliding-window / 5s-stride convention from the report's Data
Preprocessing section.

*** PROVISIONAL CALIBRATION NOTICE ***
This run is intended for baselines captured at ~31s per seed (5 seeds).
That is enough to unblock a first pass, but it is short relative to the
9-22s RSU zone residence window and yields few windows per RSU. Treat
all output as PROVISIONAL and re-run this exact script, unmodified,
once the longer (e.g. 300s) 5-seed baseline is available -- do not
carry these numbers into the report as final without doing so.

Input:
    A directory containing MOBIGUARD_PerRSU_baseline_seed{1..5}.csv
    (or any matching glob), each with header:
        cycle,sim_time_s,rsu_id,seed,tcam_util,lambda_fm,lambda_pi

Output:
    - <outdir>/s3_s4_threshold_candidates_per_rsu.csv
    - <outdir>/s3_s4_threshold_candidates_pooled.csv
    - a printed summary with recommended provisional values and caveats

Usage:
    python3 calibrate_s3_s4_thresholds.py \
        --input-dir /path/to/results_routing \
        --glob "MOBIGUARD_PerRSU_baseline_seed*.csv" \
        --window-s 10 --stride-s 5 \
        --outdir /path/to/output
"""

import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd

REQUIRED_COLS = ["cycle", "sim_time_s", "rsu_id", "seed",
                  "tcam_util", "lambda_fm", "lambda_pi"]

# Candidate calibration methods applied to each feature's benign window
# distribution. k-sigma mirrors the report's existing S1 (k in {1,2,3})
# and beta grid-search convention; percentiles are the alternative the
# report explicitly allows ("Percentile: 95th/99th percentile of benign
# U_TCAM, whichever gives cleaner separation").
K_SIGMA_CANDIDATES = [1, 2, 3]
PERCENTILE_CANDIDATES = [90, 95, 99]

# Existing hardcoded values found in the live detection code, printed
# alongside the calibrated candidates purely as a sanity reference point
# -- NOT used in any calculation.
CODE_REFERENCE_VALUES = {
    "lambda_pi": 15.0,   # ComputeTcamDetection(): lambda_pi > 15
    "tcam_util": 0.80,   # 80% of TCAM_HW_SIZE=256 (~205 rules)
}


def load_per_rsu_data(input_dir: str, glob_pattern: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(input_dir, glob_pattern)))
    if not paths:
        sys.exit(f"No files matched {glob_pattern!r} under {input_dir}")

    frames = []
    for p in paths:
        df = pd.read_csv(p, comment="#")
        df.columns = [c.strip() for c in df.columns]
        missing = set(REQUIRED_COLS) - set(df.columns)
        if missing:
            sys.exit(f"{p} is missing required columns: {sorted(missing)}")
        df["__source_file"] = os.path.basename(p)
        frames.append(df)

    full = pd.concat(frames, ignore_index=True)
    n_seeds = full["seed"].nunique()
    n_rsus = full["rsu_id"].nunique()
    print(f"[load] {len(paths)} file(s), {n_seeds} seed(s), "
          f"{n_rsus} RSU(s), {len(full)} raw rows total.")
    return full


def window_aggregate(df: pd.DataFrame, window_s: float, stride_s: float) -> pd.DataFrame:
    """
    Applies the report's 10s window / 5s stride convention per (seed, rsu_id)
    group. For each window, computes MEAN and MAX of tcam_util, lambda_fm,
    lambda_pi -- MAX is what matters for threshold calibration (a rule fires
    on a peak within a window, not the window average), MEAN is kept for
    reference/sanity-checking.
    """
    windows = []
    for (seed, rsu_id), g in df.groupby(["seed", "rsu_id"]):
        g = g.sort_values("sim_time_s")
        t_min, t_max = g["sim_time_s"].min(), g["sim_time_s"].max()
        if t_max - t_min < window_s:
            # Not enough data for even one full window at this RSU/seed.
            # Fall back to treating the whole available span as one window
            # so thin baselines still produce a candidate, flagged via
            # the 'partial_window' column.
            starts = [t_min]
            partial = True
        else:
            starts = np.arange(t_min, t_max - window_s + 1e-9, stride_s)
            partial = False

        for w_start in starts:
            w_end = w_start + window_s
            wdf = g[(g["sim_time_s"] >= w_start) & (g["sim_time_s"] < w_end)]
            if wdf.empty:
                continue
            windows.append({
                "seed": seed,
                "rsu_id": rsu_id,
                "window_start_s": w_start,
                "window_end_s": w_end,
                "n_samples": len(wdf),
                "partial_window": partial or (len(wdf) < window_s * 0.5),
                "tcam_util_mean": wdf["tcam_util"].mean(),
                "tcam_util_max": wdf["tcam_util"].max(),
                "lambda_fm_mean": wdf["lambda_fm"].mean(),
                "lambda_fm_max": wdf["lambda_fm"].max(),
                "lambda_pi_mean": wdf["lambda_pi"].mean(),
                "lambda_pi_max": wdf["lambda_pi"].max(),
            })

    wdf_all = pd.DataFrame(windows)
    print(f"[window] {len(wdf_all)} window(s) built "
          f"({window_s:.0f}s window / {stride_s:.0f}s stride).")
    if wdf_all["partial_window"].any():
        n_partial = int(wdf_all["partial_window"].sum())
        print(f"[window] WARNING: {n_partial} window(s) are partial "
              f"(less than a full {window_s:.0f}s of data) -- "
              f"expected given the short baseline duration.")
    return wdf_all


def candidates_from_series(values: pd.Series) -> dict:
    """Computes mean/std/percentile-based threshold candidates for one
    feature's window-level distribution. Returns a flat dict of columns."""
    values = values.dropna()
    out = {"n_windows": len(values)}

    if len(values) == 0:
        return out

    mean = values.mean()
    std = values.std(ddof=1) if len(values) > 1 else 0.0
    out["mean"] = mean
    out["std"] = std
    out["is_degenerate"] = bool(std == 0.0)

    for k in K_SIGMA_CANDIDATES:
        out[f"k{k}sigma"] = mean + k * std

    for p in PERCENTILE_CANDIDATES:
        out[f"p{p}"] = np.percentile(values, p)

    return out


def calibrate(wdf: pd.DataFrame, group_cols):
    rows = []
    for key, g in wdf.groupby(group_cols):
        key = key if isinstance(key, tuple) else (key,)
        row = dict(zip(group_cols, key))
        for feature in ["tcam_util_max", "lambda_fm_max", "lambda_pi_max"]:
            cand = candidates_from_series(g[feature])
            for k, v in cand.items():
                row[f"{feature}__{k}"] = v
        rows.append(row)
    return pd.DataFrame(rows)


def print_summary(pooled_row: dict):
    print("\n" + "=" * 72)
    print("PROVISIONAL S3/S4 THRESHOLD CANDIDATES (pooled across all RSUs/seeds)")
    print("=" * 72)

    def show(feature_label, col_prefix, code_ref_key):
        n = pooled_row.get(f"{col_prefix}__n_windows", 0)
        degenerate = pooled_row.get(f"{col_prefix}__is_degenerate", False)
        print(f"\n{feature_label}  (n={n} windows)"
              + ("  [DEGENERATE: zero variance in benign data]" if degenerate else ""))
        if n == 0:
            print("  no data")
            return
        for k in K_SIGMA_CANDIDATES:
            print(f"  mean + {k}-sigma : {pooled_row.get(f'{col_prefix}__k{k}sigma'):.4f}")
        for p in PERCENTILE_CANDIDATES:
            print(f"  p{p}          : {pooled_row.get(f'{col_prefix}__p{p}'):.4f}")
        ref = CODE_REFERENCE_VALUES.get(code_ref_key)
        if ref is not None:
            print(f"  (current hardcoded value in detection code: {ref})")

    show("U_TCAM  (tcam_util_max)", "tcam_util_max", "tcam_util")
    show("lambda_PI  (lambda_pi_max)", "lambda_pi_max", "lambda_pi")
    show("lambda_FM  (lambda_fm_max, informational only)", "lambda_fm_max", None)

    print("\n" + "-" * 72)
    print("CAVEATS -- read before using these numbers:")
    print("-" * 72)
    print("""
1. PROVISIONAL: calibrated from ~31s/seed baselines (5 seeds). Re-run this
   script unchanged once the longer baseline (e.g. 300s x 5 seeds) exists,
   and use those numbers as the ones that go in the report.

2. This script only performs the BENIGN-DATA statistical calibration step.
   It does NOT do the report's final selection step: "grid search on the
   validation split, optimizing MCC under a strict <=1% FPR constraint."
   That step needs labeled attack-percentage runs (not just 0%) and should
   be run separately once those are available.

3. If lambda_PI shows as DEGENERATE (std=0, i.e. always 0 in benign data),
   any k-sigma or percentile candidate will also equal 0 or be undefined --
   this is expected (no PACKET_IN flooding without an attack) but means
   ANY positive lambda_PI observation would trip a purely-statistical
   threshold. You likely want a small, domain-chosen floor value here
   (e.g. the code's existing 15.0) rather than a value derived from an
   all-zero distribution -- flagging for your judgment call, not deciding
   it for you.

4. Per-RSU candidates (see the per-RSU CSV output) are based on very few
   windows per RSU given the short baseline -- treat the POOLED numbers
   above as more statistically trustworthy for now, and only move to
   per-RSU thresholds once the longer baseline gives each RSU enough
   windows individually.

5. Robustness check (per your report's plan): once you're ready, sweep
   +/-{10%,20%,30%} of whichever candidate you pick and re-measure FPR on
   an actual attack-percentage=0 run at each perturbed value. This script
   does not measure FPR itself -- it only proposes candidate values from
   the benign distribution.
""")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input-dir", required=True,
                    help="Directory containing the per-RSU baseline CSVs")
    ap.add_argument("--glob", default="MOBIGUARD_PerRSU_baseline_seed*.csv",
                    help="Glob pattern to match per-RSU baseline files")
    ap.add_argument("--window-s", type=float, default=10.0,
                    help="Sliding window size in seconds (report default: 10)")
    ap.add_argument("--stride-s", type=float, default=5.0,
                    help="Sliding window stride in seconds (report default: 5)")
    ap.add_argument("--outdir", default=".",
                    help="Directory to write output CSVs to")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    raw = load_per_rsu_data(args.input_dir, args.glob)
    windows = window_aggregate(raw, args.window_s, args.stride_s)

    if windows.empty:
        sys.exit("No windows could be built from the input data -- aborting.")

    per_rsu = calibrate(windows, group_cols=["rsu_id"])
    per_rsu_path = os.path.join(args.outdir, "s3_s4_threshold_candidates_per_rsu.csv")
    per_rsu.to_csv(per_rsu_path, index=False)
    print(f"[write] per-RSU candidates -> {per_rsu_path}")

    # Pooled: treat every window from every RSU/seed as one distribution.
    windows_pooled = windows.copy()
    windows_pooled["__pool"] = "all"
    pooled = calibrate(windows_pooled, group_cols=["__pool"])
    pooled_path = os.path.join(args.outdir, "s3_s4_threshold_candidates_pooled.csv")
    pooled.to_csv(pooled_path, index=False)
    print(f"[write] pooled candidates    -> {pooled_path}")

    print_summary(pooled.iloc[0].to_dict())


if __name__ == "__main__":
    main()
