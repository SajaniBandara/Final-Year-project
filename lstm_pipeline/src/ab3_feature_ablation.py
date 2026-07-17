"""
ab3_feature_ablation.py — AB3: ZKP Failure Indicators as LSTM Features
(main.tex Sec. ab3)

Compares:
  AB3-A (5-feature baseline): [delta_t, lambda_PI, U_TCAM, rho, v_bar]
  AB3-B (7-feature proposed):  + [zkp_delay_fail, zkp_hop_fail]  (eq:lstm_input)

Isolates the two ZKP failure indicators' contribution to MCC, particularly
for Variants 5-8 where they are the primary cryptographic signal.

Both configs use the SAME simplified single-hyperparameter federated
training scheme (fixed lr/batch/epochs, R=30 FedAvg rounds, no BRFA-v2 —
AB3 isolates the FEATURE set, not the aggregation algorithm, which AB5
already covers separately) for a fair, matched comparison — full grid
search + R=150 + BRFA-v2 is the production config already reported
elsewhere and would make a 7-feature-vs-5-feature comparison unfair if
only one side got the full tuning budget.

Reuses the already-preprocessed train/val/test split (preprocessor.py) —
no new NS-3 simulations needed; zkp_delay_fail/zkp_hop_fail are simply
zeroed out of the AB3-A feature view rather than reloaded.

Usage:
  python3 ab3_feature_ablation.py
"""

import json
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
from scipy.stats import norm as scipy_norm
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, seed_everything

REPO   = Path(__file__).resolve().parents[2]
PRE    = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# preprocessor.py FEATURES order: [delta_t, lambda_PI, U_TCAM, zkp_delay_fail, zkp_hop_fail, rho, v_bar]
ALL_FEATURE_NAMES = ["delta_t", "lambda_PI", "U_TCAM", "zkp_delay_fail", "zkp_hop_fail", "rho", "v_bar"]
FIVE_FEATURE_IDX  = [0, 1, 2, 5, 6]          # AB3-A: drop zkp_delay_fail, zkp_hop_fail
SEVEN_FEATURE_IDX = [0, 1, 2, 3, 4, 5, 6]    # AB3-B: full eq:lstm_input

# Fixed, matched hyperparameters (no grid search — see module docstring)
LR, BATCH, LOCAL_EPOCHS = 1e-3, 64, 3
R_ROUNDS   = 30
Z_ALPHA    = scipy_norm.ppf(1 - 0.01)
MIN_BENIGN = 20

ATTACK_NAMES = {0: "Benign", 1: "A1", 2: "A2", 3: "A3", 4: "A4",
                5: "A5", 6: "A6", 7: "A7", 8: "A8"}


def load_rsu_data(feature_idx: list) -> dict:
    X_tr, y_tr, meta_tr = (np.load(PRE / f"train_{n}.npy") for n in ["X", "y", "meta"])
    X_va, y_va, meta_va = (np.load(PRE / f"val_{n}.npy")   for n in ["X", "y", "meta"])
    X_tr, X_va = X_tr[:, :, feature_idx], X_va[:, :, feature_idx]

    rsu_ids = sorted(set(meta_tr[:, 0]))
    data = {}
    for rsu_id in rsu_ids:
        mask_tr_benign = (meta_tr[:, 0] == rsu_id) & (meta_tr[:, 1] == 0)
        mask_va_benign = (meta_va[:, 0] == rsu_id) & (meta_va[:, 1] == 0)
        mask_va_all    = (meta_va[:, 0] == rsu_id)
        X_rsu_tr = X_tr[mask_tr_benign]
        if len(X_rsu_tr) < MIN_BENIGN:
            continue
        X_rsu_va_benign = X_va[mask_va_benign] if mask_va_benign.sum() else X_rsu_tr
        data[int(rsu_id)] = {"X_tr": X_rsu_tr, "X_va_benign": X_rsu_va_benign,
                             "n_train": len(X_rsu_tr)}
    return data


def train_local(model, X_train, lr, batch, epochs):
    opt, loss_fn = torch.optim.Adam(model.parameters(), lr=lr), nn.MSELoss()
    loader = DataLoader(TensorDataset(torch.from_numpy(X_train).float()), batch_size=batch, shuffle=True)
    model.train()
    for _ in range(epochs):
        for (xb,) in loader:
            xb = xb.to(DEVICE)
            opt.zero_grad()
            x_hat, _ = model(xb)
            loss = loss_fn(x_hat, xb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()


def flatten(sd):
    return np.concatenate([v.detach().cpu().numpy().ravel() for v in sd.values()])


def unflatten(flat, ref):
    out, off = {}, 0
    for k, v in ref.items():
        n = v.numel()
        out[k] = torch.from_numpy(flat[off:off + n].reshape(v.shape))
        off += n
    return out


def run_config(n_features: int, feature_idx: list, tag: str) -> dict:
    print(f"\n=== AB3-{tag}: {n_features}-feature config {[ALL_FEATURE_NAMES[i] for i in feature_idx]} ===")
    seed_everything(0)
    rsu_data = load_rsu_data(feature_idx)
    rsu_ids  = sorted(rsu_data.keys())
    print(f"  {len(rsu_ids)} RSUs with >= {MIN_BENIGN} benign training windows")

    global_model = LSTMAutoencoder(n_features=n_features).to(DEVICE)
    global_sd = {k: v.clone() for k, v in global_model.state_dict().items()}

    for rnd in range(1, R_ROUNDS + 1):
        flat_list, n_list = [], []
        for rsu_id in rsu_ids:
            m = LSTMAutoencoder(n_features=n_features).to(DEVICE)
            m.load_state_dict(global_sd)
            train_local(m, rsu_data[rsu_id]["X_tr"], LR, BATCH, LOCAL_EPOCHS)
            flat_list.append(flatten(m.state_dict()))
            n_list.append(rsu_data[rsu_id]["n_train"])
        total = sum(n_list)
        global_flat = sum(w * (n / total) for w, n in zip(flat_list, n_list))
        global_sd = unflatten(global_flat, global_model.state_dict())
        if rnd % 10 == 0 or rnd == R_ROUNDS:
            print(f"  round {rnd}/{R_ROUNDS}")

    global_model.load_state_dict(global_sd)
    global_model.eval()

    # theta = sample-weighted mean of per-RSU thetas (eq:lstm_threshold)
    thetas, weights = [], []
    with torch.no_grad():
        for rsu_id in rsu_ids:
            xv = torch.from_numpy(rsu_data[rsu_id]["X_va_benign"]).float().to(DEVICE)
            errs = global_model.anomaly_score(xv).cpu().numpy()
            thetas.append(errs.mean() + Z_ALPHA * errs.std())
            weights.append(len(xv))
    theta = float(np.average(thetas, weights=weights))
    print(f"  theta = {theta:.6f}")

    # Evaluate on held-out test split, per attack variant
    X_te = np.load(PRE / "test_X.npy")[:, :, feature_idx]
    y_te = np.load(PRE / "test_y.npy")
    meta_te = np.load(PRE / "test_meta.npy")

    scores = []
    with torch.no_grad():
        for i in range(0, len(X_te), 512):
            xb = torch.from_numpy(X_te[i:i + 512]).float().to(DEVICE)
            scores.append(global_model.anomaly_score(xb).cpu().numpy())
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
            "FPR": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        }
    attack_mask = meta_te[:, 1] > 0
    tn, fp, fn, tp = confusion_matrix(y_te[attack_mask], y_pred[attack_mask], labels=[0, 1]).ravel()
    results["Overall"] = {"MCC": round(float(matthews_corrcoef(y_te[attack_mask], y_pred[attack_mask])), 4),
                          "DR": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
                          "FPR": round(fp / (fp + tn), 4) if (fp + tn) else 0.0}
    return results


def main():
    res_5 = run_config(5, FIVE_FEATURE_IDX, "A")
    res_7 = run_config(7, SEVEN_FEATURE_IDX, "B")

    print("\n=== AB3 comparison (MCC) ===")
    print(f"{'Variant':<10}{'5-feat (A)':>12}{'7-feat (B)':>12}{'Delta':>10}")
    for k in res_7:
        a, b = res_5.get(k, {}).get("MCC", float("nan")), res_7[k]["MCC"]
        print(f"{k:<10}{a:>12.4f}{b:>12.4f}{b - a:>10.4f}")

    out = {"AB3_A_5feature": res_5, "AB3_B_7feature": res_7,
           "config": {"lr": LR, "batch": BATCH, "local_epochs": LOCAL_EPOCHS, "rounds": R_ROUNDS}}
    out_path = REPO / "lstm_pipeline" / "ab3_feature_ablation_results.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nResults -> {out_path}")


if __name__ == "__main__":
    main()
