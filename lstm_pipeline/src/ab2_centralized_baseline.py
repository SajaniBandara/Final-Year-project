"""
ab2_centralized_baseline.py — AB2: Federated vs Centralised LSTM
(main.tex Sec. ab2)

AB2-A (Centralised): pools ALL 64 RSUs' raw per-window training data onto
  one training server and trains a single global LSTM directly on the
  pooled dataset — no per-RSU local training, no weight-sharing, no
  aggregation round structure.
AB2-B (Federated, proposed): each RSU trains locally; only weight updates
  are transmitted and FedAvg'd. Reported here using the SAME simplified,
  fixed-hyperparameter scheme as ab3_feature_ablation.py's federated runs
  (R=30 rounds, lr=1e-3, batch=64, local_epochs=3) for a fair, matched
  comparison — comparing AB2-A against the fully-tuned production model
  (150-round BRFA-v2 + per-RSU grid search) would stack a bigger tuning
  budget onto one side of the ablation.

y metrics: M1 (MCC — does federated match centralised detection quality?).
M10 (privacy leakage) is architectural/qualitative (main.tex: AB2-A
exposes raw flow metadata, AB2-B does not — MOBIGUARD's federated design
never centralises raw features by construction) and isn't a runtime
number to compute here.

Usage:
  python3 ab2_centralized_baseline.py
"""

import json
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
from scipy.stats import norm as scipy_norm
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES, seed_everything

REPO   = Path(__file__).resolve().parents[2]
PRE    = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Matches ab3_feature_ablation.py's fixed federated config exactly.
LR, BATCH, LOCAL_EPOCHS, R_ROUNDS = 1e-3, 64, 3, 30
CENTRALIZED_EPOCHS = R_ROUNDS * LOCAL_EPOCHS   # same total epoch-budget, single pass
Z_ALPHA    = scipy_norm.ppf(1 - 0.01)
MIN_BENIGN = 20

ATTACK_NAMES = {0: "Benign", 1: "A1", 2: "A2", 3: "A3", 4: "A4",
                5: "A5", 6: "A6", 7: "A7", 8: "A8"}


def load_split(split):
    return (np.load(PRE / f"{split}_X.npy"), np.load(PRE / f"{split}_y.npy"),
            np.load(PRE / f"{split}_meta.npy"))


def train_epochs(model, X_train, lr, batch, epochs, label=""):
    opt, loss_fn = torch.optim.Adam(model.parameters(), lr=lr), nn.MSELoss()
    loader = DataLoader(TensorDataset(torch.from_numpy(X_train).float()), batch_size=batch, shuffle=True)
    model.train()
    for ep in range(epochs):
        total_loss = 0.0
        for (xb,) in loader:
            xb = xb.to(DEVICE)
            opt.zero_grad()
            x_hat, _ = model(xb)
            loss = loss_fn(x_hat, xb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total_loss += loss.item() * len(xb)
        if label and (ep + 1) % 10 == 0:
            print(f"  [{label}] epoch {ep + 1}/{epochs}  loss={total_loss / len(X_train):.6f}")


def evaluate(model, theta, X_te, y_te, meta_te):
    scores = []
    with torch.no_grad():
        for i in range(0, len(X_te), 512):
            xb = torch.from_numpy(X_te[i:i + 512]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    y_pred = (scores > theta).astype(np.int8)

    results = {}
    for av in sorted(set(meta_te[:, 1].tolist())):
        mask = meta_te[:, 1] == av
        if mask.sum() == 0:
            continue
        tn, fp, fn, tp = confusion_matrix(y_te[mask], y_pred[mask], labels=[0, 1]).ravel()
        mcc = matthews_corrcoef(y_te[mask], y_pred[mask])
        results[ATTACK_NAMES.get(av, f"A{av}")] = {
            "MCC": round(float(mcc), 4),
            "DR": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
            "FPR": round(fp / (fp + tn), 4) if (fp + tn) else 0.0}
    attack_mask = meta_te[:, 1] > 0
    tn, fp, fn, tp = confusion_matrix(y_te[attack_mask], y_pred[attack_mask], labels=[0, 1]).ravel()
    results["Overall"] = {"MCC": round(float(matthews_corrcoef(y_te[attack_mask], y_pred[attack_mask])), 4),
                          "DR": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
                          "FPR": round(fp / (fp + tn), 4) if (fp + tn) else 0.0}
    return results


def run_centralized() -> dict:
    print(f"\n=== AB2-A: Centralised (pooled, {CENTRALIZED_EPOCHS} epochs, lr={LR}, batch={BATCH}) ===")
    seed_everything(0)
    X_tr, y_tr, meta_tr = load_split("train")
    X_va, y_va, meta_va = load_split("val")

    # Pool ALL RSUs' benign training windows into one dataset (AB2-A: raw
    # per-packet feature logs centralised onto one training server).
    benign_mask = meta_tr[:, 1] == 0
    X_pooled = X_tr[benign_mask]
    print(f"  pooled benign training windows: {len(X_pooled):,} (all 64 RSUs combined)")

    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    train_epochs(model, X_pooled, LR, BATCH, CENTRALIZED_EPOCHS, label="centralized")
    model.eval()

    # Single global theta from the pooled benign validation windows (no
    # per-RSU calibration — the centralised model has no per-RSU concept).
    benign_va_mask = meta_va[:, 1] == 0
    with torch.no_grad():
        xv = torch.from_numpy(X_va[benign_va_mask]).float().to(DEVICE)
        errs = model.anomaly_score(xv).cpu().numpy()
    theta = float(errs.mean() + Z_ALPHA * errs.std())
    print(f"  theta = {theta:.6f}")

    X_te, y_te, meta_te = load_split("test")
    return evaluate(model, theta, X_te, y_te, meta_te)


def flatten(sd):
    return np.concatenate([v.detach().cpu().numpy().ravel() for v in sd.values()])


def unflatten(flat, ref):
    out, off = {}, 0
    for k, v in ref.items():
        n = v.numel()
        out[k] = torch.from_numpy(flat[off:off + n].reshape(v.shape))
        off += n
    return out


def run_federated() -> dict:
    print(f"\n=== AB2-B: Federated (R={R_ROUNDS} rounds x E={LOCAL_EPOCHS} local epochs, matched budget) ===")
    seed_everything(0)
    X_tr, y_tr, meta_tr = load_split("train")
    X_va, y_va, meta_va = load_split("val")
    rsu_ids = sorted(set(meta_tr[:, 0]))

    rsu_data = {}
    for rsu_id in rsu_ids:
        mask_tr = (meta_tr[:, 0] == rsu_id) & (meta_tr[:, 1] == 0)
        mask_va = (meta_va[:, 0] == rsu_id) & (meta_va[:, 1] == 0)
        X_rsu_tr = X_tr[mask_tr]
        if len(X_rsu_tr) < MIN_BENIGN:
            continue
        rsu_data[int(rsu_id)] = {"X_tr": X_rsu_tr,
                                 "X_va": X_va[mask_va] if mask_va.sum() else X_rsu_tr,
                                 "n_train": len(X_rsu_tr)}
    ids = sorted(rsu_data.keys())
    print(f"  {len(ids)} RSUs participating")

    global_model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    global_sd = {k: v.clone() for k, v in global_model.state_dict().items()}
    for rnd in range(1, R_ROUNDS + 1):
        flat_list, n_list = [], []
        for rsu_id in ids:
            m = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
            m.load_state_dict(global_sd)
            train_epochs(m, rsu_data[rsu_id]["X_tr"], LR, BATCH, LOCAL_EPOCHS)
            flat_list.append(flatten(m.state_dict()))
            n_list.append(rsu_data[rsu_id]["n_train"])
        total = sum(n_list)
        global_flat = sum(w * (n / total) for w, n in zip(flat_list, n_list))
        global_sd = unflatten(global_flat, global_model.state_dict())
        if rnd % 10 == 0:
            print(f"  round {rnd}/{R_ROUNDS}")

    global_model.load_state_dict(global_sd)
    global_model.eval()
    thetas, weights = [], []
    with torch.no_grad():
        for rsu_id in ids:
            xv = torch.from_numpy(rsu_data[rsu_id]["X_va"]).float().to(DEVICE)
            errs = global_model.anomaly_score(xv).cpu().numpy()
            thetas.append(errs.mean() + Z_ALPHA * errs.std())
            weights.append(len(xv))
    theta = float(np.average(thetas, weights=weights))
    print(f"  theta = {theta:.6f}")

    X_te, y_te, meta_te = load_split("test")
    return evaluate(global_model, theta, X_te, y_te, meta_te)


def main():
    res_a = run_centralized()
    res_b = run_federated()

    print("\n=== AB2 comparison (MCC) ===")
    print(f"{'Variant':<10}{'Central. (A)':>14}{'Federated (B)':>14}{'Delta':>10}")
    for k in res_b:
        a = res_a.get(k, {}).get("MCC", float("nan"))
        b = res_b[k]["MCC"]
        print(f"{k:<10}{a:>14.4f}{b:>14.4f}{b - a:>10.4f}")

    out = {"AB2_A_centralized": res_a, "AB2_B_federated": res_b,
           "config": {"lr": LR, "batch": BATCH, "local_epochs": LOCAL_EPOCHS,
                     "rounds": R_ROUNDS, "centralized_epochs": CENTRALIZED_EPOCHS},
           "note": "M10 (privacy leakage) is architectural/qualitative, not computed here — "
                   "see main.tex AB2 M10 discussion: AB2-A centralises raw flow metadata by "
                   "design, AB2-B never does, regardless of these runtime MCC numbers."}
    out_path = REPO / "lstm_pipeline" / "ab2_centralized_vs_federated_results.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nResults -> {out_path}")


if __name__ == "__main__":
    main()
