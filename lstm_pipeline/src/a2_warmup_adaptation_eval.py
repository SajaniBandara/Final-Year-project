"""
a2_warmup_adaptation_eval.py — Q2 (A2 FPR) diagnostic: online threshold
warm-up adaptation, per main.tex's Eq.~theta_adapt.

Supervisor's proposal: seed-to-seed mobility variance at interior RSUs means
theta calibrated on seeds 1-4 underestimates the benign tail on a fresh test
seed. Each RSU observes its OWN benign traffic for the first 30s of a run
and adapts its threshold online using that run's live reconstruction
errors, rather than relying solely on the training-seed calibration.
Warm-up windows are excluded from evaluation (they're used to CALIBRATE,
not scored).

theta_adapted = pct99(A_benign U A_warmup) per the thesis equation. We don't
have the raw A_benign calibration population saved (only mu/sigma/theta in
fed_summary.json), so this approximates with the same Gaussian formula used
everywhere else in the pipeline (mu_warmup + Z_ALPHA*sigma_warmup), and
takes max(original_theta, warmup_theta) -- warm-up can only WIDEN the
threshold, never narrow it below what training already established, since
a thin warm-up sample (few windows) could otherwise produce an
under-estimated sigma and make things worse, not better.

This is a standalone diagnostic script -- does NOT modify evaluator.py's
main path or evaluation_results.json. Run, inspect the effect, then decide
whether to fold it into the real pipeline.
"""
import json
from pathlib import Path

import numpy as np
import torch

from evaluator import (
    load_global_model, predict_test, deduplicate_windows,
    compute_clf_metrics, ATTACK_NAMES,
)
from fed_aggregator import Z_ALPHA  # same z used everywhere else (3.5)

REPO = Path(__file__).resolve().parents[2]
WARMUP_CYCLES = 30   # matches Eq.~theta_adapt's 30s warm-up window
MIN_WARMUP_WINDOWS = 2   # skip adaptation if too few benign warm-up samples


def compute_adaptive_theta(scores: np.ndarray, meta: np.ndarray, y_true: np.ndarray,
                            per_rsu_theta: dict, global_theta: float):
    rsu_ids, av_ids, pct_ids, seed_ids, start_cycle = (
        meta[:, 0], meta[:, 1], meta[:, 2], meta[:, 3], meta[:, 4]
    )
    is_warmup = start_cycle < WARMUP_CYCLES
    keys = np.stack([rsu_ids, av_ids, pct_ids, seed_ids], axis=1)
    _, run_idx = np.unique(keys, axis=0, return_inverse=True)
    n_runs = run_idx.max() + 1

    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids], dtype=float)
    n_adapted = 0
    for run in range(n_runs):
        run_mask = run_idx == run
        warm_mask = run_mask & is_warmup & (y_true == 0)
        if warm_mask.sum() < MIN_WARMUP_WINDOWS:
            continue
        warm_scores = scores[warm_mask]
        mu_w, sig_w = float(warm_scores.mean()), float(warm_scores.std())
        theta_w = mu_w + Z_ALPHA * sig_w
        rsu_this_run = int(rsu_ids[run_mask][0])
        base_theta = per_rsu_theta.get(rsu_this_run, global_theta)
        if theta_w > base_theta:
            theta_arr[run_mask] = theta_w
            n_adapted += 1

    keep = ~is_warmup   # warm-up windows excluded from evaluation
    return theta_arr, keep, n_adapted, n_runs


def main():
    print("Loading global federated model …")
    model, per_rsu_theta, global_theta = load_global_model()

    print("Running inference on test split …")
    y_true, y_pred_orig, scores, meta = predict_test(model, per_rsu_theta, global_theta)

    theta_adapted, keep, n_adapted, n_runs = compute_adaptive_theta(
        scores, meta, y_true, per_rsu_theta, global_theta)
    print(f"  Warm-up adaptation applied to {n_adapted}/{n_runs} runs "
          f"(>= {MIN_WARMUP_WINDOWS} benign warm-up windows, "
          f"raised theta above the base per-RSU value)")

    y_pred_adapted = (scores > theta_adapted).astype(np.int8)

    # Compare BOTH baseline and adapted on the SAME non-warmup population
    # (apples to apples -- warmup windows dropped from both).
    yt_k, yp_orig_k, meta_k = y_true[keep], y_pred_orig[keep], meta[keep]
    yp_adapt_k = y_pred_adapted[keep]

    yt_d, yp_orig_d, meta_d = deduplicate_windows(yt_k, yp_orig_k, meta_k)
    _, yp_adapt_d, _ = deduplicate_windows(yt_k, yp_adapt_k, meta_k)

    print(f"\n{'Attack':30s} {'Baseline':>28s}   {'Warm-up adapted':>28s}")
    attack_variants = sorted(set(meta_d[:, 1].tolist()))
    for av in attack_variants:
        mask = meta_d[:, 1] == av
        if mask.sum() == 0:
            continue
        base = compute_clf_metrics(yt_d[mask], yp_orig_d[mask])
        adap = compute_clf_metrics(yt_d[mask], yp_adapt_d[mask])
        print(f"{ATTACK_NAMES.get(av, f'A{av}'):30s} "
              f"MCC={base['M1_MCC']:+.3f} DR={base['M2_DR']:.3f} FPR={base['M3_FPR']:.3f}   "
              f"MCC={adap['M1_MCC']:+.3f} DR={adap['M2_DR']:.3f} FPR={adap['M3_FPR']:.3f}")

    attack_mask = meta_d[:, 1] > 0
    base_all = compute_clf_metrics(yt_d[attack_mask], yp_orig_d[attack_mask])
    adap_all = compute_clf_metrics(yt_d[attack_mask], yp_adapt_d[attack_mask])
    print(f"{'Overall':30s} "
          f"MCC={base_all['M1_MCC']:+.3f} DR={base_all['M2_DR']:.3f} FPR={base_all['M3_FPR']:.3f}   "
          f"MCC={adap_all['M1_MCC']:+.3f} DR={adap_all['M2_DR']:.3f} FPR={adap_all['M3_FPR']:.3f}")

    out = {
        "n_adapted_runs": int(n_adapted), "n_total_runs": int(n_runs),
        "baseline_overall": base_all, "adapted_overall": adap_all,
    }
    out_path = REPO / "lstm_pipeline" / "a2_warmup_adaptation_results.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved -> {out_path}")


if __name__ == "__main__":
    main()
