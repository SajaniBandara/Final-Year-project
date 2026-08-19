"""
eval_finetuned_a1a2.py — evaluate Fix B's fine-tuned model on A1/A2, TEST ONLY.

Recomputes per-RSU theta (same mu+3.5*sigma formula, fed_aggregator.compute_theta)
using the FINE-TUNED model against the RELABELED benign calibration population,
then scores A1/A2's test-split windows (also relabeled). Compares against the
documented pre-Fix-B baseline (A1 DR=2.7%, A2 DR=4.6%).
"""
import json
import numpy as np
import torch
from pathlib import Path

from lstm_model import LSTMAutoencoder, N_FEATURES
from fed_aggregator import compute_theta

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


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


def load_model(path):
    ckpt = torch.load(path, map_location=DEVICE, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    return model


def score(model, X):
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), 512):
            xb = torch.from_numpy(X[i:i + 512]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    return np.concatenate(scores)


def main():
    X_val    = np.load(PRE / "val_X.npy")
    y_val    = np.load(PRE / "val_y.npy")
    meta_val = np.load(PRE / "val_meta.npy")
    av_val   = meta_val[:, 1].astype(int)
    rsu_val  = meta_val[:, 0].astype(int)

    X_test    = np.load(PRE / "test_X.npy")
    y_test    = np.load(PRE / "test_y.npy")
    meta_test = np.load(PRE / "test_meta.npy")
    av_test   = meta_test[:, 1].astype(int)
    rsu_test  = meta_test[:, 0].astype(int)

    for label, path in [("BASELINE (pre-Fix-B, original global.pt on relabeled data)",
                          MODEL_DIR / "global.pt"),
                         ("FIX B (fine-tuned fc_recon on relabeled A1/A2 benign)",
                          MODEL_DIR / "global_finetuned_a1a2.pt")]:
        print(f"\n{'='*70}\n{label}\n{'='*70}")
        model = load_model(path)

        # Per-RSU theta, recomputed on the (relabeled) benign VAL population --
        # same standard formula, just re-run with this model + the fresh labels.
        val_scores = score(model, X_val)
        per_rsu_theta = {}
        for rsu in np.unique(rsu_val):
            m = (rsu_val == rsu) & (y_val == 0)
            if m.sum() < 5:
                continue
            errs = val_scores[m]
            mu_a, sig_a = float(errs.mean()), float(errs.std())
            per_rsu_theta[int(rsu)] = mu_a + 3.5 * sig_a
        global_theta = float(np.mean(list(per_rsu_theta.values())))

        test_scores = score(model, X_test)
        theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_test])
        y_pred = (test_scores > theta_arr).astype(np.int8)

        for a, name in [(1, "A1"), (2, "A2")]:
            mask = av_test == a
            m = confusion(y_test[mask], y_pred[mask])
            print(f"  {name}: {m}")


if __name__ == "__main__":
    main()
