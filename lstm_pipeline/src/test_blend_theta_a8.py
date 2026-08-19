"""
test_blend_theta_a8.py — check whether blending each RSU's normal
calibration population WITH the shared 87-window HF-quiet pool (staying
per-RSU, architecturally consistent with the live system) works as well as
the tested "full replace" (single global HF-pooled theta, ignores RSU
identity -- what test_stratified_theta_a8.py validated at FPR=0%).
"""
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
    model, per_rsu_theta, global_theta = load_global_model()

    X_val    = np.load(PRE / "val_X.npy")
    y_val    = np.load(PRE / "val_y.npy")
    meta_val = np.load(PRE / "val_meta.npy")
    av_val   = meta_val[:, 1].astype(int)
    rsu_val  = meta_val[:, 0].astype(int)

    val_scores = []
    with torch.no_grad():
        for i in range(0, len(X_val), 512):
            xb = torch.from_numpy(X_val[i:i+512]).float().to(DEVICE)
            val_scores.append(model.anomaly_score(xb).cpu().numpy())
    val_scores = np.concatenate(val_scores)

    # Blended per-RSU theta: each RSU's own quiet windows (all attack types,
    # same population fed_aggregator.py already uses) PLUS the shared
    # HF-quiet pool (87 windows across all RSUs).
    hf_pool_mask = (y_val == 0) & np.isin(av_val, list(HF_VARIANTS))
    theta_blend = {}
    for rsu in np.unique(rsu_val):
        own_mask = (rsu_val == rsu) & (y_val == 0)
        combined_mask = own_mask | hf_pool_mask
        errs = val_scores[combined_mask]
        mu_a, sig_a = float(errs.mean()), float(errs.std())
        theta_blend[int(rsu)] = mu_a + Z_ALPHA * sig_a
    global_blend = float(np.mean(list(theta_blend.values())))

    X_test    = np.load(PRE / "test_X.npy")
    y_test    = np.load(PRE / "test_y.npy")
    meta_test = np.load(PRE / "test_meta.npy")
    av_test   = meta_test[:, 1].astype(int)
    rsu_test  = meta_test[:, 0].astype(int)

    test_scores = []
    with torch.no_grad():
        for i in range(0, len(X_test), 512):
            xb = torch.from_numpy(X_test[i:i+512]).float().to(DEVICE)
            test_scores.append(model.anomaly_score(xb).cpu().numpy())
    test_scores = np.concatenate(test_scores)

    theta_arr_blend = np.array([theta_blend.get(r, global_blend) for r in rsu_test])
    y_pred_blend = (test_scores > theta_arr_blend).astype(np.int8)

    a8_mask = av_test == A8
    print("BLENDED (per-RSU own population + shared HF pool, architecturally live-compatible):")
    print(f"  A8: {confusion(y_test[a8_mask], y_pred_blend[a8_mask])}")

    # Sanity check impact on A1-A4 (should barely move, since their own
    # per-RSU population dominates -- HF pool is tiny, 87 windows, relative
    # to A1-A4's own thousands per RSU).
    theta_arr_baseline = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_test])
    y_pred_baseline = (test_scores > theta_arr_baseline).astype(np.int8)
    for a in [1, 2, 3, 4]:
        mask = av_test == a
        base = confusion(y_test[mask], y_pred_baseline[mask])
        blend = confusion(y_test[mask], y_pred_blend[mask])
        print(f"  A{a} baseline FPR={base['FPR']*100:.2f}% DR={base['DR']*100:.2f}%  "
              f"-> blend FPR={blend['FPR']*100:.2f}% DR={blend['DR']*100:.2f}%")


if __name__ == "__main__":
    main()
