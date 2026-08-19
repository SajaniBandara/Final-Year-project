"""
test_stratified_theta_a8.py — Candidate Fix (2026-08-19), TEST ONLY.

Root cause confirmed: the theta calibration population (y_va==0 windows,
seed4) is 94% A1-A4 (structurally different traffic than Hidden Forwarding),
while A8 contributes only 35 windows (all pct80, zero pct60/pct100) and A7
only 52. A5/A6 contribute zero. Per-RSU theta = mu_a + z*sig_a ends up
reflecting mostly A1-A4's quiet distribution, not A8's.

This script does NOT touch fed_summary.json, global.pt, or
lstm_weights_cpp.bin -- it only recomputes theta in-memory from cached
numpy arrays and re-scores the cached test-split inference, to see whether
a GLOBAL (not per-RSU -- 87 HF-quiet windows spread across 64 RSUs is too
sparse to split further) HF-context-only calibration population moves A8's
FPR/DR/MCC before this is exported anywhere live. Read-only, safe to run
alongside the Q3 ablation (no NS-3/GPU contention, no shared file writes).
"""
import json
import numpy as np
import torch
from pathlib import Path
from evaluator import load_global_model

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
Z_ALPHA = 3.5
A8 = 8
HF_VARIANTS = {5, 6, 7, 8}


def confusion(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
    dr  = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    denom = np.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc = ((tp*tn - fp*fn) / denom) if denom > 0 else 0.0
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, FPR=fpr, DR=dr, MCC=mcc)


def main():
    print("Loading global model + baseline per-RSU theta …")
    model, per_rsu_theta, global_theta = load_global_model()

    # ── Baseline: current per-RSU theta (already exported, A1-A4-dominated) ──
    X_test    = np.load(PRE / "test_X.npy")
    y_test    = np.load(PRE / "test_y.npy")
    meta_test = np.load(PRE / "test_meta.npy")

    scores = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X_test), 512):
            xb = torch.from_numpy(X_test[i:i+512]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)

    rsu_test = meta_test[:, 0].astype(int)
    av_test  = meta_test[:, 1].astype(int)
    a8_mask  = av_test == A8

    theta_baseline = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_test])
    y_pred_baseline = (scores > theta_baseline).astype(np.int8)
    base_metrics = confusion(y_test[a8_mask], y_pred_baseline[a8_mask])
    print(f"\nBASELINE (current per-RSU theta, A1-A4-dominated calibration):")
    print(f"  {base_metrics}")

    # ── Candidate: HF-context-only calibration pool (A5-A8 quiet windows) ────
    X_val    = np.load(PRE / "val_X.npy")
    y_val    = np.load(PRE / "val_y.npy")
    meta_val = np.load(PRE / "val_meta.npy")
    av_val   = meta_val[:, 1].astype(int)

    hf_quiet_mask = (y_val == 0) & np.isin(av_val, list(HF_VARIANTS))
    n_hf_quiet = int(hf_quiet_mask.sum())
    print(f"\nHF-context-only calibration pool: {n_hf_quiet} windows "
          f"(vs {int((y_val==0).sum())} in the full A1-A4-dominated pool)")

    if n_hf_quiet < 10:
        print("Too few HF-quiet windows to calibrate on -- aborting candidate test.")
        return

    with torch.no_grad():
        xv = torch.from_numpy(X_val[hf_quiet_mask]).float().to(DEVICE)
        hf_errs = model.anomaly_score(xv).cpu().numpy()
    mu_hf, sig_hf = float(hf_errs.mean()), float(hf_errs.std())
    print(f"  mu_hf={mu_hf:.4f} sig_hf={sig_hf:.4f}")

    for z in [Z_ALPHA, 3.0, 4.0, 4.5]:
        theta_hf = mu_hf + z * sig_hf
        # Candidate A: replace A8's theta entirely with the HF-pooled value
        theta_candA = np.where(av_test == A8, theta_hf, theta_baseline)
        y_pred_candA = (scores > theta_candA).astype(np.int8)
        mA = confusion(y_test[a8_mask], y_pred_candA[a8_mask])

        # Candidate B: take the MAX of baseline per-RSU theta and the HF-pooled
        # value (more conservative -- never lowers an already-adequate theta)
        theta_candB = np.where(av_test == A8, np.maximum(theta_baseline, theta_hf), theta_baseline)
        y_pred_candB = (scores > theta_candB).astype(np.int8)
        mB = confusion(y_test[a8_mask], y_pred_candB[a8_mask])

        print(f"\nz={z}: theta_hf={theta_hf:.4f}")
        print(f"  Candidate A (replace): {mA}")
        print(f"  Candidate B (max w/ baseline): {mB}")


if __name__ == "__main__":
    main()
