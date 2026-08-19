"""
diag_a8_fp.py — one-off diagnostic (2026-08-19): among A8's negative-labeled
(y_true==0) test windows, what distinguishes the ~340 that the model flags
(FP, score > theta) from the ~358 it correctly clears (TN)? Since z_alpha
sweeping doesn't move A8's FPR, the split must be feature-driven, not
threshold-driven -- compare per-feature window means between the two groups.
"""
import numpy as np
import torch
from pathlib import Path
from evaluator import load_global_model

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
A8 = 8

FEATURES = ["delta_t", "lambda_PI", "U_TCAM", "zkp_delay_fail", "zkp_hop_fail",
            "rho", "v_bar", "d_div", "a_tp", "r_anom", "delta_t_exceeded"]


def main():
    model, per_rsu_theta, global_theta = load_global_model()
    X    = np.load(PRE / "test_X.npy")
    y    = np.load(PRE / "test_y.npy")
    meta = np.load(PRE / "test_meta.npy")

    scores = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X), 512):
            xb = torch.from_numpy(X[i:i+512]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)

    rsu_ids = meta[:, 0].astype(int)
    av      = meta[:, 1].astype(int)
    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids])
    y_pred = (scores > theta_arr).astype(np.int8)

    neg_mask = (av == A8) & (y == 0)
    fp_mask  = neg_mask & (y_pred == 1)
    tn_mask  = neg_mask & (y_pred == 0)
    print(f"A8 negative-labeled windows: {neg_mask.sum()} "
          f"(FP={fp_mask.sum()}, TN={tn_mask.sum()})")

    print(f"\nScore distribution (theta ~ {np.median(theta_arr[neg_mask]):.4f} median for these RSUs):")
    print(f"  FP scores: mean={scores[fp_mask].mean():.4f} "
          f"min={scores[fp_mask].min():.4f} max={scores[fp_mask].max():.4f}")
    print(f"  TN scores: mean={scores[tn_mask].mean():.4f} "
          f"min={scores[tn_mask].min():.4f} max={scores[tn_mask].max():.4f}")

    # X is (N, window, n_features), scaled (z-score). Use the window MEAN and
    # MAX per feature (mirrors what feeds the LSTM's own reconstruction).
    print(f"\n{'feature':<18} {'FP mean':>10} {'TN mean':>10} {'FP max_mean':>12} {'TN max_mean':>12}")
    print("-" * 66)
    for i, feat in enumerate(FEATURES):
        fp_win_mean = X[fp_mask, :, i].mean()
        tn_win_mean = X[tn_mask, :, i].mean()
        fp_win_max  = X[fp_mask, :, i].max(axis=1).mean()
        tn_win_max  = X[tn_mask, :, i].max(axis=1).mean()
        print(f"{feat:<18} {fp_win_mean:10.3f} {tn_win_mean:10.3f} {fp_win_max:12.3f} {tn_win_max:12.3f}")

    # rsu/pct/seed/start_cycle distribution -- are FPs clustered on specific
    # RSUs, percentages, or near attack onset (low start_cycle)?
    print(f"\nFP windows by percentage:")
    for pct in sorted(set(meta[fp_mask, 2])):
        n = int((meta[fp_mask, 2] == pct).sum())
        print(f"  pct{pct}: {n}")
    print(f"\nFP windows by start_cycle (bucketed /50):")
    sc = meta[fp_mask, 4]
    for lo in range(0, 310, 50):
        n = int(((sc >= lo) & (sc < lo+50)).sum())
        print(f"  cycle {lo}-{lo+49}: {n}")
    print(f"\nTN windows by start_cycle (bucketed /50), for comparison:")
    sc_tn = meta[tn_mask, 4]
    for lo in range(0, 310, 50):
        n = int(((sc_tn >= lo) & (sc_tn < lo+50)).sum())
        print(f"  cycle {lo}-{lo+49}: {n}")

    print(f"\nFP windows by RSU (top 10 by count):")
    fp_rsus = meta[fp_mask, 0]
    vals, counts = np.unique(fp_rsus, return_counts=True)
    order = np.argsort(-counts)[:10]
    for idx in order:
        print(f"  RSU {vals[idx]}: {counts[idx]}")


if __name__ == "__main__":
    main()
