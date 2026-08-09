"""
eval_val_offline.py — offline LSTM-alone MCC/FPR on the VAL split (seed4).

evaluator.py hardcodes predict_test() to load test_X.npy/test_y.npy
(TEST_SEEDS={5}), which isn't collected yet. Seed4 (VAL) is fully
collected, so this reuses evaluator.py's exact scoring, deduplication and
metric logic against val_X.npy/val_y.npy/val_meta.npy instead — same
methodology (per-RSU static theta, W=10/stride=5 dedup, eq:eval_dedup),
different split. NOT a substitute for the eventual TEST-split number;
seed4 also fed the model's own threshold calibration, so this is not a
fully held-out read the way TEST is.
"""

import numpy as np
import torch
from pathlib import Path

from evaluator import (
    load_global_model, deduplicate_windows, compute_clf_metrics,
    compute_adaptive_theta, ATTACK_NAMES,
)

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def predict_val(model, per_rsu_theta, global_theta):
    X    = np.load(PRE / "val_X.npy")
    y    = np.load(PRE / "val_y.npy")
    meta = np.load(PRE / "val_meta.npy")
    bs   = 512
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    rsu_ids = meta[:, 0].astype(int)
    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids])
    y_pred = (scores > theta_arr).astype(np.int8)
    return y, y_pred, scores, meta


def main():
    print("Loading global federated model …")
    model, per_rsu_theta, global_theta = load_global_model()

    print("Running inference on VAL split (seed4) …")
    y_true, y_pred, scores, meta = predict_val(model, per_rsu_theta, global_theta)

    theta_adapted, keep, n_adapted, n_runs = compute_adaptive_theta(
        scores, meta, y_true, per_rsu_theta, global_theta)
    print(f"  eq:theta_adapt applied to {n_adapted}/{n_runs} runs "
          f"(warm-up raised theta above the base per-RSU value)")
    y_pred_adapted = (scores > theta_adapted).astype(np.int8)

    yt_k, yp_base_k, meta_k = y_true[keep], y_pred[keep], meta[keep]
    yp_adapt_k = y_pred_adapted[keep]

    yt_d, yp_base_d, meta_d = deduplicate_windows(yt_k, yp_base_k, meta_k)
    _, yp_adapt_d, _         = deduplicate_windows(yt_k, yp_adapt_k, meta_k)

    print(f"\n{'Attack':26s} {'-- static theta --':>28s}   {'-- theta_adapt --':>28s}")
    print(f"{'':26s} {'MCC':>7s} {'DR':>7s} {'FPR':>7s}   {'MCC':>7s} {'DR':>7s} {'FPR':>7s}")
    attack_variants = sorted(set(meta_d[:, 1].tolist()))
    for av in attack_variants:
        if av == 0:
            continue
        mask = meta_d[:, 1] == av
        if mask.sum() == 0:
            continue
        mb = compute_clf_metrics(yt_d[mask], yp_base_d[mask])
        ma = compute_clf_metrics(yt_d[mask], yp_adapt_d[mask])
        print(f"{ATTACK_NAMES.get(av, f'A{av}'):26s} "
              f"{mb['M1_MCC']:+7.4f} {mb['M2_DR']:7.4f} {mb['M3_FPR']:7.4f}   "
              f"{ma['M1_MCC']:+7.4f} {ma['M2_DR']:7.4f} {ma['M3_FPR']:7.4f}")

    attack_mask = meta_d[:, 1] > 0
    ob = compute_clf_metrics(yt_d[attack_mask], yp_base_d[attack_mask])
    oa = compute_clf_metrics(yt_d[attack_mask], yp_adapt_d[attack_mask])
    print(f"\n{'OVERALL (pooled)':26s} "
          f"{ob['M1_MCC']:+7.4f} {ob['M2_DR']:7.4f} {ob['M3_FPR']:7.4f}   "
          f"{oa['M1_MCC']:+7.4f} {oa['M2_DR']:7.4f} {oa['M3_FPR']:7.4f}")

    print("\nNOTE: VAL split (seed4) — same seed used to calibrate per-RSU "
          "theta, so this is NOT a held-out read the way TEST (seed5) will "
          "be. Treat as a preview, not the final reportable number. Warm-up "
          "windows (first 30 cycles) excluded from both columns.")


if __name__ == "__main__":
    main()
