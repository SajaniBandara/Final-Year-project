"""
local_trainer.py — MOBIGUARD per-RSU local LSTM training (eq:lstm_detection, eq:lstm_threshold)

For each RSU k:
  1. Train LSTMAutoencoder on benign windows (label == 0) from that RSU
  2. Compute detection threshold θ^(k) = μ_A + z_α · σ_A  (eq:lstm_threshold)
     where μ_A, σ_A are from the benign validation reconstruction errors
     and z_α = 2.326 corresponds to target FPR α = 0.01 (1%)
  3. Save model weights and threshold to models/rsu_{k}.pt

Outputs
  lstm_pipeline/models/rsu_{k}.pt   per-RSU weight dict + threshold
  lstm_pipeline/local_results.json  per-RSU training summary
"""

import os, json, argparse
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
from scipy.stats import norm as scipy_norm

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO       = Path(__file__).resolve().parents[2]
PRE        = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR  = REPO / "lstm_pipeline" / "models"
Z_ALPHA    = scipy_norm.ppf(1 - 0.01)   # z_{0.99} ≈ 2.326 for 1% FPR
# Grid search spaces (spec §4.2)
LR_GRID    = [1e-4, 1e-3, 1e-2]
BATCH_GRID = [32, 64, 128]
EPOCH_GRID = [1, 3, 5]           # local epochs E per federated round
ROUNDS     = 100                 # default global rounds R; sweep {50,100,150} via --rounds
DEVICE     = "cuda" if torch.cuda.is_available() else "cpu"
MIN_BENIGN = 20    # skip RSU if too few benign windows


def load_split(split: str):
    X    = np.load(PRE / f"{split}_X.npy")
    y    = np.load(PRE / f"{split}_y.npy")
    meta = np.load(PRE / f"{split}_meta.npy")   # cols: rsu_id, attack_v, pct, seed, start_cycle
    return X, y, meta


def train_local_epochs(model, X_train: np.ndarray, lr: float,
                       batch: int, local_epochs: int) -> float:
    """Train model for E local epochs; return mean loss. Used per federated round."""
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


def grid_search_hparams(rsu_id: int, X_train: np.ndarray,
                        X_val: np.ndarray) -> dict:
    """Grid search over LR × batch × local_epochs; pick best val loss."""
    best = {"val_loss": float("inf"), "lr": 1e-3, "batch": 64, "epochs": 3}
    loss_fn = nn.MSELoss()
    for lr in LR_GRID:
        for batch in BATCH_GRID:
            for ep in EPOCH_GRID:
                model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
                train_local_epochs(model, X_train, lr, batch, ep * 3)  # 3 trial rounds
                model.eval()
                with torch.no_grad():
                    xv  = torch.from_numpy(X_val).float().to(DEVICE)
                    xh, _ = model(xv)
                    vl  = loss_fn(xh, xv).item()
                if vl < best["val_loss"]:
                    best = {"val_loss": vl, "lr": lr, "batch": batch, "epochs": ep}
    print(f"    RSU {rsu_id:3d} best hparams: lr={best['lr']} "
          f"batch={best['batch']} epochs={best['epochs']} val_loss={best['val_loss']:.6f}")
    return best


def train_one_rsu(rsu_id: int, X_train: np.ndarray, X_val: np.ndarray,
                  args) -> dict:
    # Grid search for best hyperparameters
    best = grid_search_hparams(rsu_id, X_train, X_val)

    # Full federated-round training with selected hparams
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    for rnd in range(args.rounds):
        loss = train_local_epochs(model, X_train,
                                  best["lr"], best["batch"], best["epochs"])
        if (rnd + 1) % 25 == 0:
            print(f"    RSU {rsu_id:3d}  round {rnd+1:3d}/{args.rounds}"
                  f"  loss={loss:.6f}")

    # Threshold calibration — eq:lstm_threshold (≥95% precision, ≤1% FPR)
    model.eval()
    with torch.no_grad():
        xv   = torch.from_numpy(X_val).float().to(DEVICE)
        errs = model.anomaly_score(xv).cpu().numpy()
    mu_a  = float(errs.mean())
    sig_a = float(errs.std())
    theta = mu_a + Z_ALPHA * sig_a

    return {"weights": model.state_dict(), "theta": theta,
            "mu_a": mu_a, "sig_a": sig_a, "n_train": len(X_train),
            "best_hparams": best}


def main(args):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading preprocessed data from {PRE} …")
    X_tr, y_tr, meta_tr = load_split("train")
    X_va, y_va, meta_va = load_split("val")

    rsu_ids = sorted(set(meta_tr[:, 0]))
    print(f"Training local models for {len(rsu_ids)} RSUs on {DEVICE} …")

    summary = {}
    for rsu_id in rsu_ids:
        # Benign-only training data for this RSU
        mask_tr = (meta_tr[:, 0] == rsu_id) & (y_tr == 0)
        mask_va = (meta_va[:, 0] == rsu_id) & (y_va == 0)
        X_rsu_tr = X_tr[mask_tr]
        X_rsu_va = X_va[mask_va]

        if len(X_rsu_tr) < MIN_BENIGN:
            print(f"  RSU {rsu_id:3d}: skipped (only {len(X_rsu_tr)} benign windows)")
            continue

        if len(X_rsu_va) == 0:
            X_rsu_va = X_rsu_tr   # fall back to train set for threshold

        print(f"  RSU {rsu_id:3d}: {len(X_rsu_tr)} train, {len(X_rsu_va)} val windows")
        result = train_one_rsu(rsu_id, X_rsu_tr, X_rsu_va, args)

        torch.save({"weights": result["weights"],
                    "theta":   result["theta"],
                    "mu_a":    result["mu_a"],
                    "sig_a":   result["sig_a"]},
                   MODEL_DIR / f"rsu_{rsu_id}.pt")

        summary[int(rsu_id)] = {
            "theta": result["theta"], "mu_a": result["mu_a"],
            "sig_a": result["sig_a"], "n_train": result["n_train"]
        }

    with open(REPO / "lstm_pipeline" / "local_results.json", "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nTrained {len(summary)} RSU models → {MODEL_DIR}/")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=ROUNDS,
                    help="Global federated rounds R ∈ {50,100,150}")
    main(ap.parse_args())
