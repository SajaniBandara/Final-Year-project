#!/usr/bin/env python3
"""
rule_calibrator.py — Calibrate S1 detection parameters from benign SUMO traces.

Implements §Simulation settings calibration procedure:
  1. OLS regression: fit δ₀, α_ρ, α_v from benign CSVs
  2. β sweep {0.7, 0.8, 0.9, 0.95}: select for fastest σ²(t) convergence in 22s window
  3. k sweep {1, 2, 3}: select for best MCC at FPR ≤ 1%
  4. Robustness check: perturb each param by ±{10%, 20%, 30%}, record ΔFPR

Input:  lstm_training/RSU_*/Attack0_0_seed*.csv  (benign runs, label=0)
Output: lstm_pipeline/calibrated_params.json
        lstm_pipeline/calibration_report.txt

Usage:
  python3 lstm_pipeline/src/rule_calibrator.py
  python3 lstm_pipeline/src/rule_calibrator.py --data-dir /path/to/lstm_training
  python3 lstm_pipeline/src/rule_calibrator.py --val-fraction 0.3
"""

import argparse
import json
import math
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.metrics import matthews_corrcoef

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR   = Path(__file__).resolve().parent
PIPELINE_DIR = SCRIPT_DIR.parent
# Must include "ns3_g13": Path.home() / "ns-allinone-3.35" resolves
# through a symlink into a DIFFERENT group's ns-3 checkout on this shared
# account (same issue found and fixed in lstm_logger.h's C++ path helpers).
NS3_DIR      = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
DEFAULT_DATA = NS3_DIR / "results_routing" / "lstm_training"
OUTPUT_JSON  = PIPELINE_DIR / "calibrated_params.json"
OUTPUT_REPORT = PIPELINE_DIR / "calibration_report.txt"

# Proposal sweep spaces
BETA_CANDIDATES = [0.7, 0.8, 0.9, 0.95]
K_CANDIDATES    = [1.0, 2.0, 3.0]
PERTURBATIONS   = [0.10, 0.20, 0.30]   # ±10%, ±20%, ±30%
# --- beta selection criterion (supervisor review, 2026-08-04) -------------
# These two were previously ONE parameter (RSU_ZONE_WINDOW), which conflated a
# stability test with an acceptance bound and produced the wrong answer.
#
# The old code passed a single `window` into ewma_convergence_time(), where it
# served as BOTH the number of consecutive stable cycles required AND the start
# offset of the search, with the result reported as (i - window). Raising it
# from 9 to 22 therefore did not "look for convergence within 22 s" -- it made
# the stability test three times stricter and pushed every beta's measured
# convergence LATER. That is the "converges to a fixed 22 s" failure mode the
# supervisor flagged, not faster genuine convergence.
#
# Correct criterion: fastest stable convergence of sigma_r^2(t) ANYWHERE inside
# the 9-22 s band, with 22 s a hard rejection ceiling.
#   STABILITY_WINDOW  - consecutive cycles that must sit within 1 % of the final
#                       value before convergence is declared. This is a
#                       smoothness test; it is NOT an acceptance bound.
#   CONVERGENCE_CEILING - maximum acceptable convergence time. A beta that
#                       cannot converge inside this is rejected outright: 22 s
#                       is the maximum RSU zone residence time at highway speed
#                       (main.tex: vehicles reside in a zone 10-30 s), so a beta
#                       slower than this never stabilises before the vehicle has
#                       already left the zone, and is useless in deployment.
# Units: data transmission and routing run at 1 Hz (main.tex sec:simulation),
# so one cycle == one second and these are directly comparable.
STABILITY_WINDOW    = 9
CONVERGENCE_CEILING = 22

# Relative tolerance for "sigma^2 has settled": every cycle in the stability
# window must be within this fraction of the final value.
#
# *** OPEN ISSUE — RAISE WITH SUPERVISOR BEFORE TRUSTING ANY BETA ***
# This was hardcoded at 0.01 (1 %). On realistic noisy input that criterion
# essentially NEVER latches: the EWMA variance of a fluctuating delay series is
# itself a fluctuating series, so it does not sit within 1 % of its final value
# for 9 consecutive cycles. Measured on synthetic stationary white noise, only
# beta=0.99 converges at 1 %; every beta in BETA_CANDIDATES never does.
#
# The OLD code hid this. On failure it fell through to
#     return float(len(sigma2_history))
# i.e. the series length, so a beta that never converged was scored as if it
# converged at the last cycle. Every non-converging beta then tied, and the
# sweep's min() picked essentially arbitrarily. The beta currently compiled into
# s1_detection.h (0.8) may have come from exactly such a degenerate sweep and
# should not be assumed meaningful.
#
# This module now returns inf and REJECTS rather than silently ranking, so the
# problem is visible instead of producing a confident wrong answer. If the real
# benign baseline also yields "no beta converges", the criterion itself needs
# rethinking -- the principled alternative is the EWMA effective window
# N_eff = 1/(1-beta) (beta=0.9 -> 10 cycles, 0.95 -> 20), which is deterministic
# and lands naturally inside the 9-22 s band. That is a spec decision, not an
# implementation one: do not change it unilaterally.
CONVERGENCE_TOL = 0.01


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_benign_data(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load all Attack0_0_seed*.csv files across all RSU dirs into one DataFrame."""
    dfs = []
    pattern = list(data_dir.glob("RSU_*/Attack0_0_seed*.csv"))
    if not pattern:
        sys.exit(f"ERROR: No benign CSVs found in {data_dir}\n"
                 "       Run Step 2 benign simulations first.")

    for p in sorted(pattern):
        try:
            df = pd.read_csv(p)
            # Extract RSU id from directory name and seed from filename
            rsu_id  = int(p.parent.name.split("_")[1])
            seed_id = int(p.stem.split("seed")[1])   # "Attack0_0_seed3" → 3
            df["rsu_dir"] = rsu_id
            df["seed"]    = seed_id
            dfs.append(df)
        except Exception as e:
            print(f"  WARNING: skipping {p.name}: {e}")

    df_all = pd.concat(dfs, ignore_index=True)
    print(f"Loaded {len(df_all):,} rows from {len(pattern)} benign CSVs "
          f"({data_dir.parent.name}/lstm_training/RSU_*/Attack0_0_seed*.csv)")

    # Sanity checks
    assert (df_all["label"] == 0).all(), "Benign CSVs contain label=1 rows — check data"
    required = ["delta_t", "rho", "v_bar", "cycle", "rsu_id"]
    missing  = [c for c in required if c not in df_all.columns]
    if missing:
        sys.exit(f"ERROR: Missing columns in CSVs: {missing}")

    # ── Filter: keep only rows with real traffic at this RSU this cycle.
    # When rho=0 (no vehicles near RSU), lstm_logger writes delta_t=s1_delta0=0.002
    # as a fallback (see routing.cc: obs_delay = s1_delta0 when obs_count==0).
    # These "null" rows have delta_t=const, rho=0, v_bar=14.0 (fallbacks) and
    # dominate the OLS, washing out the mobility signal → alpha_rho=0, alpha_v=0.
    # Only rows with rho > 0 represent cycles where real packets were observed.
    n_total = len(df_all)
    df_traffic = df_all[df_all["rho"] > 0].copy()
    n_null = n_total - len(df_traffic)
    null_pct = 100.0 * n_null / n_total if n_total > 0 else 0.0
    print(f"  Null (rho=0) rows filtered: {n_null:,} / {n_total:,} ({null_pct:.1f}%)")
    print(f"  Rows with real traffic (rho>0): {len(df_traffic):,}")

    if len(df_traffic) < 100:
        print("  WARNING: fewer than 100 traffic rows — calibration may be unreliable.")
        print("           Using all rows as fallback.")
        df_traffic = df_all.copy()

    # Drop rows with zero v_bar (undefined 1/v_bar)
    n_before = len(df_traffic)
    df_traffic = df_traffic[df_traffic["v_bar"] > 0.1].copy()
    dropped = n_before - len(df_traffic)
    if dropped:
        print(f"  Dropped {dropped} rows with v_bar ≤ 0.1 m/s")

    df_traffic["inv_v_bar"] = 1.0 / df_traffic["v_bar"]
    # df_traffic (rho>0) feeds the S1 OLS; df_all (every benign row, including
    # zero-traffic cycles) feeds the S3/S4 percentile thresholds.
    return df_traffic, df_all


# ---------------------------------------------------------------------------
# Step 1 — OLS regression: δ̄(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
# ---------------------------------------------------------------------------

def fit_ols(df: pd.DataFrame) -> tuple[float, float, float, float]:
    """Fit δ₀, α_ρ, α_v via OLS. Returns (delta0, alpha_rho, alpha_v, r2)."""
    X = df[["rho", "inv_v_bar"]].values
    y = df["delta_t"].values

    reg = LinearRegression(fit_intercept=True)
    reg.fit(X, y)

    delta0    = float(reg.intercept_)
    alpha_rho = float(reg.coef_[0])
    alpha_v   = float(reg.coef_[1])
    r2        = float(reg.score(X, y))

    print(f"\n── Step 1: OLS regression ──")
    print(f"  δ₀      = {delta0:.6f} s")
    print(f"  α_ρ     = {alpha_rho:.6f} s/vehicle")
    print(f"  α_v     = {alpha_v:.6f} s²/m")
    print(f"  R²      = {r2:.4f}")
    return delta0, alpha_rho, alpha_v, r2


# ---------------------------------------------------------------------------
# Step 2 — β sweep: fastest σ²(t) convergence within 9s window
# ---------------------------------------------------------------------------

def ewma_convergence_time(series: np.ndarray, beta: float,
                           delta_bar_series: np.ndarray,
                           stability_window: int = STABILITY_WINDOW,
                           tol: float = CONVERGENCE_TOL) -> float:
    """
    Run the eq:ewma_variance update over `series` and return the CYCLE INDEX at
    which sigma^2(t) is declared converged: the first cycle after which
    `stability_window` consecutive values all sit within 1 % of the final value.

    Returns the index of the first cycle OF THE STABLE RUN (not the end of it),
    so the number means "sigma^2 had settled by cycle N". Lower = faster.

    `stability_window` is a smoothness test only. The acceptance bound
    (CONVERGENCE_CEILING) is applied by the caller, deliberately kept separate:
    folding them together is what made every beta look like it converged at the
    bound. Returns inf if it never stabilises, so the caller can reject rather
    than silently ranking a non-converging beta.
    """
    sigma2 = 0.0
    sigma2_history = []
    for obs, db in zip(series, delta_bar_series):
        dev     = obs - db
        sigma2  = beta * sigma2 + (1 - beta) * dev * dev
        sigma2_history.append(sigma2)

    n = len(sigma2_history)
    if n < stability_window:
        return float("inf")          # too short to judge — do not count as fast

    final = sigma2_history[-1]
    if final == 0:
        return float("inf")          # degenerate (no variance signal at all)

    # Earliest start index whose following `stability_window` cycles are all
    # within 1 % of the final value.
    for start in range(0, n - stability_window + 1):
        chunk = sigma2_history[start: start + stability_window]
        if max(abs(v - final) / (abs(final) + 1e-12) for v in chunk) < tol:
            return float(start)

    return float("inf")              # never stabilised


def sweep_beta(df: pd.DataFrame, delta0: float,
               alpha_rho: float, alpha_v: float) -> float:
    """Select β with fastest average σ²(t) convergence across all RSU time-series."""
    print(f"\n── Step 2: β sweep {BETA_CANDIDATES} ──")

    results = {}
    for beta in BETA_CANDIDATES:
        conv_times = []
        for (rsu_id, seed), grp in df.groupby(["rsu_id", "seed"] if "seed" in df.columns
                                               else ["rsu_id", "rsu_dir"]):
            grp_sorted = grp.sort_values("cycle")
            obs        = grp_sorted["delta_t"].values
            delta_bar  = (delta0
                          + alpha_rho * grp_sorted["rho"].values
                          + alpha_v   * grp_sorted["inv_v_bar"].values)
            ct = ewma_convergence_time(obs, beta, delta_bar)
            conv_times.append(ct)

        finite = [c for c in conv_times if np.isfinite(c)]
        mean_ct = float(np.mean(finite)) if finite else float("inf")
        n_fail  = len(conv_times) - len(finite)
        results[beta] = mean_ct
        note = f"  ({n_fail}/{len(conv_times)} series never stabilised)" if n_fail else ""
        shown = f"{mean_ct:.1f}" if np.isfinite(mean_ct) else "never"
        print(f"  β={beta}  mean convergence = {shown} cycles{note}")

    # Acceptance bound applied HERE, separately from the stability test above.
    # A beta that cannot converge within CONVERGENCE_CEILING is rejected: it
    # never settles before the vehicle has left the RSU zone.
    eligible = {b: c for b, c in results.items()
                if np.isfinite(c) and c <= CONVERGENCE_CEILING}
    rejected = {b: c for b, c in results.items() if b not in eligible}

    for b, c in sorted(rejected.items()):
        shown = f"{c:.1f}" if np.isfinite(c) else "never"
        print(f"  β={b}: REJECTED — converges at {shown} cycles "
              f"(> {CONVERGENCE_CEILING}s ceiling)")

    if not eligible:
        raise SystemExit(
            f"No β in {BETA_CANDIDATES} converges within the "
            f"{CONVERGENCE_CEILING}s ceiling (stability window "
            f"{STABILITY_WINDOW} cycles). Widen BETA_CANDIDATES or re-examine "
            f"the benign baseline — do NOT silently pick the least-bad β.")

    best_beta = min(eligible, key=eligible.__getitem__)
    print(f"  → Selected β = {best_beta}  "
          f"(converges at {eligible[best_beta]:.1f} cycles ≈ {eligible[best_beta]:.1f}s; "
          f"stability window {STABILITY_WINDOW}, ceiling {CONVERGENCE_CEILING}s)")
    print(f"    eligible: {sorted(eligible.items())}")
    return best_beta


# ---------------------------------------------------------------------------
# Step 3 — k sweep: best MCC at FPR ≤ 1%
# ---------------------------------------------------------------------------

def simulate_s1_detection(df: pd.DataFrame,
                           delta0: float, alpha_rho: float, alpha_v: float,
                           beta: float, k: float,
                           val_fraction: float = 0.3) -> dict:
    """
    Simulate S1 EWMA detection on a held-out validation split of the benign data.
    Since all rows are benign (label=0), any detection is a false positive.
    Returns FPR and MCC (MCC=0 if no positives — expected for benign-only data).
    """
    # Use last val_fraction of cycles as validation (later cycles = more stable EWMA)
    max_cycle  = int(df["cycle"].max())
    val_start  = int(max_cycle * (1 - val_fraction))
    val_df     = df[df["cycle"] >= val_start].copy()
    train_df   = df[df["cycle"] <  val_start].copy()

    # Compute σ² per RSU from training portion (warm-up the EWMA)
    sigma2_per_rsu: dict[int, float] = {}
    for rsu_id, grp in train_df.groupby("rsu_id"):
        sigma2 = 0.0
        for _, row in grp.sort_values("cycle").iterrows():
            db  = delta0 + alpha_rho * row["rho"] + alpha_v * row["inv_v_bar"]
            dev = row["delta_t"] - db
            sigma2 = beta * sigma2 + (1 - beta) * dev * dev
        sigma2_per_rsu[rsu_id] = sigma2

    # Evaluate on validation portion
    y_true, y_pred = [], []
    for _, row in val_df.iterrows():
        rsu_id = int(row["rsu_id"])
        db     = delta0 + alpha_rho * row["rho"] + alpha_v * row["inv_v_bar"]
        sigma  = math.sqrt(max(sigma2_per_rsu.get(rsu_id, 0.0), 0.0))
        thresh = db + k * sigma
        detected = 1 if row["delta_t"] > thresh else 0
        y_true.append(int(row["label"]))   # always 0 for benign
        y_pred.append(detected)

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    # MCC undefined when all predictions same sign (benign-only data, no TP/FN)
    try:
        mcc = matthews_corrcoef(y_true, y_pred) if (tp + fn) > 0 else float("nan")
    except Exception:
        mcc = float("nan")

    return {"fpr": fpr, "mcc": mcc, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "n_val": len(y_true)}


def sweep_k(df: pd.DataFrame, delta0: float, alpha_rho: float,
            alpha_v: float, beta: float,
            val_fraction: float = 0.3) -> float:
    """Select k that minimises FPR while satisfying FPR ≤ 1%. Fallback: max k."""
    print(f"\n── Step 3: k sweep {K_CANDIDATES} (val_fraction={val_fraction}) ──")
    print("  Note: benign-only data → MCC undefined; minimise FPR ≤ 1%.")

    results = {}
    for k in K_CANDIDATES:
        r = simulate_s1_detection(df, delta0, alpha_rho, alpha_v, beta, k, val_fraction)
        results[k] = r
        print(f"  k={k}  FPR={r['fpr']:.4f}  FP={r['fp']}  n_val={r['n_val']}")

    # Select k with FPR ≤ 1% (smallest k that still satisfies constraint → most sensitive)
    valid = {k: r for k, r in results.items() if r["fpr"] <= 0.01}
    if valid:
        best_k = min(valid)   # smallest k at FPR ≤ 1% (highest sensitivity)
    else:
        best_k = max(K_CANDIDATES)  # all k fail → use most conservative
        print(f"  WARNING: no k achieves FPR ≤ 1%. Using k={best_k} (fallback).")

    print(f"  → Selected k = {best_k}  (FPR={results[best_k]['fpr']:.4f})")
    return float(best_k)


# ---------------------------------------------------------------------------
# Step 4 — Robustness check: perturb params, record ΔFPR
# ---------------------------------------------------------------------------

def robustness_check(df: pd.DataFrame, delta0: float, alpha_rho: float,
                     alpha_v: float, beta: float, k: float) -> list[dict]:
    """Perturb each of δ₀, α_ρ, α_v by ±{10%,20%,30%} and record ΔFPR."""
    print(f"\n── Step 4: Robustness check (perturbations ±{[int(p*100) for p in PERTURBATIONS]}%) ──")
    baseline = simulate_s1_detection(df, delta0, alpha_rho, alpha_v, beta, k)
    baseline_fpr = baseline["fpr"]
    print(f"  Baseline FPR = {baseline_fpr:.4f}")

    records = []
    for param_name, base_val in [("delta0", delta0), ("alpha_rho", alpha_rho),
                                  ("alpha_v", alpha_v)]:
        for sign in [+1, -1]:
            for pct in PERTURBATIONS:
                perturbed = base_val * (1 + sign * pct)
                args = dict(delta0=delta0, alpha_rho=alpha_rho, alpha_v=alpha_v)
                args[param_name] = perturbed
                r       = simulate_s1_detection(df, beta=beta, k=k, **args)
                delta_fpr = r["fpr"] - baseline_fpr
                label   = f"{param_name} {'+' if sign>0 else '-'}{int(pct*100)}%"
                records.append({"param": label, "perturbed_val": perturbed,
                                 "fpr": r["fpr"], "delta_fpr": delta_fpr})
                print(f"  {label:<22}  perturbed={perturbed:.6f}  "
                      f"FPR={r['fpr']:.4f}  ΔFPR={delta_fpr:+.4f}")

    max_delta = max(abs(r["delta_fpr"]) for r in records)
    print(f"  Max |ΔFPR| across all perturbations = {max_delta:.4f}")
    return records


# ---------------------------------------------------------------------------
# Step 5 — S3/S4 TCAM thresholds: benign 99th percentile (FPR ≤ 1% budget)
# ---------------------------------------------------------------------------

def calibrate_s3_s4(df_all: pd.DataFrame) -> dict:
    """
    Calibrate the S3/S4 detection thresholds from benign feature distributions,
    mirroring the S1 philosophy: pick the benign 99th percentile so at most 1%
    of benign observations exceed the threshold (FPR ≤ 1% budget per signal;
    S4 requires BOTH signals to fire, so its joint benign FPR is far lower).

    lambda_pi_thresh : S4 PACKET_IN rate threshold      (from lambda_PI column)
    tcam_util_thresh : S3/S4 shared utilisation threshold (from U_TCAM column)
    lambda_fm_thresh : S3 FlowMod rate — NOT in the LSTM CSVs; the hardcoded
                       initial value is retained and flagged for documentation.
    """
    print(f"\n── Step 5: S3/S4 threshold calibration (benign p99) ──")
    out = {"lambda_fm_thresh": 10.0,
           "lambda_fm_source": "initial estimate retained (FlowMod rate not logged in LSTM CSVs)"}

    for col, default, key in [("lambda_PI", 15.0, "lambda_pi_thresh"),
                               ("U_TCAM",    0.80, "tcam_util_thresh")]:
        vals = df_all[col].astype(float).values
        vmax = float(np.max(vals))
        if vmax <= 1e-12:
            out[key] = default
            out[f"{key}_source"] = "default retained (benign signal all zero — no distribution to calibrate)"
            print(f"  {col:<10} benign max=0 → keeping default {default} (flagged)")
            continue
        p99  = float(np.percentile(vals, 99))
        exceed = float(np.mean(vals > p99))
        out[key] = round(p99, 6)
        out[f"{key}_source"] = "benign p99"
        out[f"{key}_benign_exceed"] = round(exceed, 4)
        print(f"  {col:<10} p99={p99:.6f}  max={vmax:.6f}  "
              f"benign exceedance at p99 = {exceed*100:.2f}%")
        # Robustness: ±10/20/30% threshold perturbation → benign exceedance
        for sign in (+1, -1):
            for pct in PERTURBATIONS:
                t = p99 * (1 + sign * pct)
                ex = float(np.mean(vals > t))
                print(f"    {col} thresh {'+' if sign>0 else '-'}{int(pct*100)}%"
                      f" = {t:.6f} → benign exceedance {ex*100:.2f}%")
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate S1 detection parameters from benign SUMO traces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA,
                        help=f"Path to lstm_training/ directory (default: {DEFAULT_DATA})")
    parser.add_argument("--val-fraction", type=float, default=0.3,
                        help="Fraction of cycles used as validation for k sweep (default: 0.3)")
    parser.add_argument("--output", type=Path, default=OUTPUT_JSON,
                        help=f"Output JSON path (default: {OUTPUT_JSON})")
    args = parser.parse_args()

    print("=" * 60)
    print("  MOBIGUARD S1 Parameter Calibration (rule_calibrator.py)")
    print("=" * 60)

    # Load data
    df, df_all = load_benign_data(args.data_dir)

    # Add seed column if not present
    if "seed" not in df.columns:
        df["seed"] = df.get("rsu_dir", 0)

    # ── Step 1: OLS
    delta0, alpha_rho, alpha_v, r2 = fit_ols(df)

    # ── Step 2: β sweep
    best_beta = sweep_beta(df, delta0, alpha_rho, alpha_v)

    # ── Step 3: k sweep
    best_k = sweep_k(df, delta0, alpha_rho, alpha_v, best_beta, args.val_fraction)

    # ── Step 4: Robustness
    robustness = robustness_check(df, delta0, alpha_rho, alpha_v, best_beta, best_k)

    # ── Step 5: S3/S4 TCAM thresholds
    s3s4 = calibrate_s3_s4(df_all)

    # ── Save results
    result = {
        "delta0":    round(delta0,    8),
        "alpha_rho": round(alpha_rho, 8),
        "alpha_v":   round(alpha_v,   8),
        "beta":      best_beta,
        "k":         best_k,
        "ols_r2":    round(r2, 4),
        "robustness_max_delta_fpr": round(
            max(abs(r["delta_fpr"]) for r in robustness), 4),
        "s3_s4": s3s4,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2))
    print(f"\n── Calibrated parameters saved → {args.output} ──")
    print(json.dumps(result, indent=2))

    # ── Print s1_detection.h update snippet
    print("\n── Update s1_detection.h with these values ──")
    print(f"  double s1_delta0    = {result['delta0']};")
    print(f"  double s1_alpha_rho = {result['alpha_rho']};")
    print(f"  double s1_alpha_v   = {result['alpha_v']};")
    print(f"  double s1_beta      = {result['beta']};")
    print(f"  double s1_k         = {result['k']};")

    # ── Print routing.cc ComputeTcamDetection update snippet
    print("\n── Update ComputeTcamDetection() call in routing.cc with these values ──")
    print(f"  lambda_fm_thresh = {s3s4['lambda_fm_thresh']}   // {s3s4['lambda_fm_source']}")
    print(f"  lambda_pi_thresh = {s3s4['lambda_pi_thresh']}   // {s3s4.get('lambda_pi_thresh_source','')}")
    print(f"  tcam_util_thresh = {s3s4['tcam_util_thresh']}   // {s3s4.get('tcam_util_thresh_source','')}")

    # ── Write text report
    report_lines = [
        "MOBIGUARD S1 Parameter Calibration Report",
        "=" * 50,
        f"Data source : {args.data_dir}",
        f"Total rows  : {len(df):,}",
        "",
        "Step 1 — OLS regression",
        f"  delta0    = {result['delta0']}  (s)",
        f"  alpha_rho = {result['alpha_rho']}  (s/vehicle)",
        f"  alpha_v   = {result['alpha_v']}  (s²/m)",
        f"  R²        = {result['ols_r2']}",
        "",
        f"Step 2 — β selection: {result['beta']}",
        f"Step 3 — k selection: {result['k']}",
        f"Step 4 — Max |ΔFPR|: {result['robustness_max_delta_fpr']}",
        "",
        "Robustness details:",
    ] + [f"  {r['param']:<22}  ΔFPR={r['delta_fpr']:+.4f}" for r in robustness] + [
        "",
        "Step 5 — S3/S4 TCAM thresholds (benign p99, FPR ≤ 1% budget per signal):",
        f"  lambda_fm_thresh = {s3s4['lambda_fm_thresh']}  ({s3s4['lambda_fm_source']})",
        f"  lambda_pi_thresh = {s3s4['lambda_pi_thresh']}  ({s3s4.get('lambda_pi_thresh_source','')})",
        f"  tcam_util_thresh = {s3s4['tcam_util_thresh']}  ({s3s4.get('tcam_util_thresh_source','')})",
    ]

    OUTPUT_REPORT.write_text("\n".join(report_lines))
    print(f"\n── Full report → {OUTPUT_REPORT} ──")


if __name__ == "__main__":
    main()
