"""
local_trainer.py — MOBIGUARD per-RSU hyperparameter grid search (spec §4.2)

For each RSU k, searches (eta, batch, local epochs E) and selects the combo
with the HIGHEST MCC on the RSU's labelled validation windows, subject to a
hard FPR <= 1% constraint — combos exceeding 1% FPR are rejected outright,
even if their reconstruction loss looks good (loss alone rewards predicting
"benign" on this heavily imbalanced dataset and can miss most attacks).

This is a one-time, per-RSU, LOCAL-ONLY search run before federation starts —
it does NOT train the model that eventually gets deployed. The actual
federated training (E local epochs per round starting from the current
GLOBAL weights, R global aggregation rounds, BRFA-v2 aggregation every
round) happens in fed_aggregator.py, which also selects R by monitoring the
GLOBAL model's validation loss convergence, and calibrates the per-RSU
detection threshold theta^(k) against the final global model.

Output: lstm_pipeline/hparams.json  {rsu_id: {lr, batch, epochs, n_train, grid_mcc, grid_fpr}}
"""

import os, json, argparse
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES, seed_everything

REPO       = Path(__file__).resolve().parents[2]
PRE        = REPO / "lstm_pipeline" / "preprocessed"
TARGET_FPR       = 0.01
TARGET_PRECISION = 0.95
# Grid search spaces (spec §4.2)
LR_GRID    = [1e-4, 1e-3, 1e-2]
BATCH_GRID = [32, 64, 128]
EPOCH_GRID = [1, 3, 5]           # local epochs E per federated round
DEVICE     = "cuda" if torch.cuda.is_available() else "cpu"
MIN_BENIGN = 20    # skip RSU if too few benign windows


def load_split(split: str):
    X    = np.load(PRE / f"{split}_X.npy")
    y    = np.load(PRE / f"{split}_y.npy")
    meta = np.load(PRE / f"{split}_meta.npy")   # cols: rsu_id, attack_v, pct, seed, start_cycle
    return X, y, meta


def train_local_epochs(model, X_train: np.ndarray, lr: float,
                       batch: int, local_epochs: int) -> float:
    """Train model for E local epochs; return mean loss."""
    opt     = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    ds      = TensorDataset(torch.from_numpy(X_train).float())
    loader  = DataLoader(ds, batch_size=batch, shuffle=True)
    model.train()
    total_loss = 0.0
    for _ in range(local_epochs):
        for (xb,) in loader:
            xb = xb.to(DEVICE)
            opt.zero_grad()
            x_hat, _ = model(xb)
            loss = loss_fn(x_hat, xb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total_loss += loss.item() * len(xb)
    return total_loss / max(len(X_train) * local_epochs, 1)


Z_ALPHA = 2.3263478740408408   # z_{0.99}, scipy.stats.norm.ppf(1 - 0.01)


def compute_theta(model, X_val_benign: np.ndarray) -> tuple:
    """Hybrid threshold: theta(k) = max(Gaussian, non-parametric P99) per
    RSU — see fed_aggregator.py's compute_theta() for the full rationale
    (P99 alone underestimates the tail on small per-RSU samples and gave a
    WORSE empirical FPR than the original Gaussian formula). Kept
    consistent here so grid search selects hparams under the SAME
    thresholding rule that will actually be deployed."""
    model.eval()
    with torch.no_grad():
        xv   = torch.from_numpy(X_val_benign).float().to(DEVICE)
        errs = model.anomaly_score(xv).cpu().numpy()
    mu_a        = float(errs.mean())
    sig_a       = float(errs.std())
    theta_gauss = mu_a + Z_ALPHA * sig_a
    theta_pctl  = float(np.percentile(errs, 99))
    theta = max(theta_gauss, theta_pctl)
    return theta, mu_a, sig_a


def eval_clf(model, X_val_full: np.ndarray, y_val_full: np.ndarray, theta: float) -> dict:
    """MCC / FPR / precision / DR of `model` at threshold `theta` on labelled validation windows."""
    model.eval()
    with torch.no_grad():
        xv     = torch.from_numpy(X_val_full).float().to(DEVICE)
        scores = model.anomaly_score(xv).cpu().numpy()
    y_pred = (scores > theta).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_val_full, y_pred, labels=[0, 1]).ravel()
    mcc  = matthews_corrcoef(y_val_full, y_pred) if len(set(y_val_full.tolist())) > 1 else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    dr   = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return {"mcc": mcc, "fpr": fpr, "precision": prec, "dr": dr}


def grid_search_hparams(rsu_id: int, X_train: np.ndarray, X_val_benign: np.ndarray,
                        X_val_full: np.ndarray, y_val_full: np.ndarray) -> dict:
    """
    Grid search over LR x batch x local_epochs.
    Selection criterion (spec §4.2): highest MCC on the labelled validation
    windows, subject to FPR <= 1%. Combos exceeding 1% FPR are rejected
    outright regardless of reconstruction loss.
    """
    feasible = []   # combos meeting FPR <= 1%
    all_seen = []   # every combo tried, for the fallback path

    for lr in LR_GRID:
        for batch in BATCH_GRID:
            for ep in EPOCH_GRID:
                model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
                train_local_epochs(model, X_train, lr, batch, ep * 3)  # 3 trial rounds
                theta, _, _ = compute_theta(model, X_val_benign)
                clf = eval_clf(model, X_val_full, y_val_full, theta)
                hp  = {"lr": lr, "batch": batch, "epochs": ep}
                row = {**hp, **clf}
                all_seen.append(row)
                if clf["fpr"] <= TARGET_FPR:
                    feasible.append(row)

    if feasible:
        best = max(feasible, key=lambda r: r["mcc"])
        print(f"    RSU {rsu_id:3d} best hparams (MCC-selected, FPR<=1%): "
              f"lr={best['lr']} batch={best['batch']} epochs={best['epochs']} "
              f"MCC={best['mcc']:.4f} FPR={best['fpr']:.4f}")
    else:
        best = min(all_seen, key=lambda r: r["fpr"])
        print(f"    RSU {rsu_id:3d} WARNING: no hparam combo met FPR<=1% during "
              f"grid search — falling back to lowest-FPR combo: "
              f"lr={best['lr']} batch={best['batch']} epochs={best['epochs']} "
              f"MCC={best['mcc']:.4f} FPR={best['fpr']:.4f}")

    return {"lr": best["lr"], "batch": best["batch"], "epochs": best["epochs"],
            "grid_mcc": best["mcc"], "grid_fpr": best["fpr"]}


def main(args):
    seed_everything(0)   # reproducible M1/M8 metrics
    print(f"Loading preprocessed data from {PRE} …")
    X_tr, y_tr, meta_tr = load_split("train")
    X_va, y_va, meta_va = load_split("val")

    rsu_ids = sorted(set(meta_tr[:, 0]))
    print(f"Grid-searching hyperparameters for {len(rsu_ids)} RSUs on {DEVICE} …")

    summary = {}
    for rsu_id in rsu_ids:
        # Train the autoencoder ONLY on pure-benign A0 runs (meta col 1 = attack_v).
        # Using y==0 leaked label-0 windows from attack runs into training — for
        # selective-delay attacks those "benign-labeled" cycles still contain delay
        # spikes, inflating benign reconstruction error (std 71, θ≈49) and crushing DR.
        mask_tr_benign = (meta_tr[:, 0] == rsu_id) & (meta_tr[:, 1] == 0)
        mask_va_benign = (meta_va[:, 0] == rsu_id) & (meta_va[:, 1] == 0)  # pure-benign A0 for θ calibration
        mask_va_all    = (meta_va[:, 0] == rsu_id)

        X_rsu_tr        = X_tr[mask_tr_benign]
        X_rsu_va_benign = X_va[mask_va_benign]
        X_rsu_va_full   = X_va[mask_va_all]
        y_rsu_va_full   = y_va[mask_va_all]

        if len(X_rsu_tr) < MIN_BENIGN:
            print(f"  RSU {rsu_id:3d}: skipped (only {len(X_rsu_tr)} benign windows)")
            continue

        if len(X_rsu_va_benign) == 0:
            X_rsu_va_benign = X_rsu_tr   # fall back to train set for threshold calibration
        if len(X_rsu_va_full) == 0:
            X_rsu_va_full = X_rsu_va_benign
            y_rsu_va_full = np.zeros(len(X_rsu_va_benign), dtype=np.int8)

        print(f"  RSU {rsu_id:3d}: {len(X_rsu_tr)} train, {len(X_rsu_va_benign)} val(benign) windows")
        best = grid_search_hparams(rsu_id, X_rsu_tr, X_rsu_va_benign, X_rsu_va_full, y_rsu_va_full)
        summary[int(rsu_id)] = {**best, "n_train": len(X_rsu_tr)}

    with open(REPO / "lstm_pipeline" / "hparams.json", "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nSearched hyperparameters for {len(summary)} RSUs → lstm_pipeline/hparams.json")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    main(ap.parse_args())
