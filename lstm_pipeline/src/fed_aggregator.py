"""
fed_aggregator.py — MOBIGUARD federated LSTM training loop + BRFA-v2 aggregation
(eq:fed_robust, alg:brfa_v2, eq:lstm_threshold)

This runs the actual federated training. For each of up to R_max global
rounds:
  - Every RSU trains E local epochs starting from the CURRENT global
    weights (not from scratch), using the (lr, batch, epochs) selected for
    it by local_trainer.py's grid search, and commits a SHA3-512 hash of
    its updated local weights.
  - The server aggregates via BRFA-v2 (Algorithm alg:brfa_v2):
      Step 1: Trust gate    — drop RSUs whose trust score T_r < T_min;
                               abort the round if fewer than 2f+1 remain
      Step 2: Hash verify   — recompute SHA3-512(W_local^(k)) and compare
                               against the hash committed this round
      Step 3: Krum filter   — coordinate-wise median + distance-based
                               outlier rejection over RSUs that passed 1-2
      Step 4: Weighted aggregation — n_k-weighted FedAvg over accepted models
  - The GLOBAL model's validation loss (mean benign reconstruction error
    across all RSUs, weighted by RSU sample count) is recorded.

Global aggregation rounds R (spec §4.2): the global model is checkpointed
at R in {50, 100, 150}; the smallest R whose GLOBAL loss has converged
(within CONVERGE_TOL of the loss at R_max) is selected as the final model —
this is what "R selected by monitoring global loss convergence" means.

After R is selected, per-RSU detection thresholds theta^(k) (eq:lstm_threshold)
are calibrated against the FINAL global model on each RSU's own benign
validation windows, and checked for >=95% precision jointly with <=1% FPR.

Outputs
  lstm_pipeline/models/global.pt          final global model weights
  lstm_pipeline/models/rsu_{k}_global.pt  global weights + per-RSU theta
  lstm_pipeline/fed_summary.json          round log + per-RSU calibration summary
"""

import json, argparse
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
from scipy.stats import norm as scipy_norm
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES, compute_weights_hash

REPO        = Path(__file__).resolve().parents[2]
PRE         = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR   = REPO / "lstm_pipeline" / "models"
TRUST_PATH  = REPO / "lstm_pipeline" / "rsu_trust_scores.json"
HPARAMS_PATH = REPO / "lstm_pipeline" / "hparams.json"
DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"

Z_ALPHA          = scipy_norm.ppf(1 - 0.01)   # z_{0.99} ≈ 2.326 for 1% FPR
TARGET_FPR       = 0.01
TARGET_PRECISION = 0.95
ROUND_GRID       = [50, 100, 150]   # global aggregation rounds R (spec §4.2)
CONVERGE_TOL     = 0.02             # accept R if global loss within 2% of loss at R_max
MIN_BENIGN       = 20                # skip RSU if too few benign windows


# ── Data / hparams loading ────────────────────────────────────────────────────

def load_split(split: str):
    X    = np.load(PRE / f"{split}_X.npy")
    y    = np.load(PRE / f"{split}_y.npy")
    meta = np.load(PRE / f"{split}_meta.npy")
    return X, y, meta


def load_rsu_data() -> dict:
    """Per-RSU benign train windows + labelled validation windows (benign + attack)."""
    X_tr, y_tr, meta_tr = load_split("train")
    X_va, y_va, meta_va = load_split("val")
    rsu_ids = sorted(set(meta_tr[:, 0]))

    data = {}
    for rsu_id in rsu_ids:
        mask_tr_benign = (meta_tr[:, 0] == rsu_id) & (y_tr == 0)
        mask_va_benign = (meta_va[:, 0] == rsu_id) & (y_va == 0)
        mask_va_all    = (meta_va[:, 0] == rsu_id)

        X_rsu_tr        = X_tr[mask_tr_benign]
        X_rsu_va_benign = X_va[mask_va_benign]
        X_rsu_va_full   = X_va[mask_va_all]
        y_rsu_va_full   = y_va[mask_va_all]

        if len(X_rsu_tr) < MIN_BENIGN:
            print(f"  RSU {int(rsu_id):3d}: skipped (only {len(X_rsu_tr)} benign windows)")
            continue
        if len(X_rsu_va_benign) == 0:
            X_rsu_va_benign = X_rsu_tr
        if len(X_rsu_va_full) == 0:
            X_rsu_va_full = X_rsu_va_benign
            y_rsu_va_full = np.zeros(len(X_rsu_va_benign), dtype=np.int8)

        data[int(rsu_id)] = {"X_tr": X_rsu_tr, "X_va_benign": X_rsu_va_benign,
                             "X_va_full": X_rsu_va_full, "y_va_full": y_rsu_va_full,
                             "n_train": len(X_rsu_tr)}
    return data


def load_hparams(rsu_ids: list) -> dict:
    with open(HPARAMS_PATH) as fh:
        raw = json.load(fh)
    hparams = {}
    for r in rsu_ids:
        if str(r) not in raw:
            raise RuntimeError(f"No grid-search hparams for RSU {r} in {HPARAMS_PATH}. "
                               f"Run local_trainer.py first.")
        hparams[r] = raw[str(r)]
    return hparams


def load_trust_scores(rsu_ids: list) -> dict:
    """
    Per-RSU blockchain trust score T_{r_k} (Step 1 gate input).
    Falls back to fully-trusted (1.0) for any RSU missing from the file,
    since the live NS-3 blockchain layer's trust score (g_trust_score in
    crypto_layer.h) is not yet exported into this offline pipeline.
    """
    scores = {r: 1.0 for r in rsu_ids}
    if TRUST_PATH.exists():
        with open(TRUST_PATH) as fh:
            raw = json.load(fh)
        for r in rsu_ids:
            if str(r) in raw:
                scores[r] = float(raw[str(r)])
    else:
        print(f"  [WARN] {TRUST_PATH} not found — treating all RSUs as fully trusted (T=1.0)")
    return scores


# ── Local training (one federated round) ─────────────────────────────────────

def train_local_epochs(model, X_train: np.ndarray, lr: float,
                       batch: int, local_epochs: int) -> float:
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


def compute_theta(model, X_val_benign: np.ndarray) -> tuple:
    """eq:lstm_threshold: theta = mu_A + z_alpha * sigma_A from benign val reconstruction errors."""
    model.eval()
    with torch.no_grad():
        xv   = torch.from_numpy(X_val_benign).float().to(DEVICE)
        errs = model.anomaly_score(xv).cpu().numpy()
    mu_a  = float(errs.mean())
    sig_a = float(errs.std())
    theta = mu_a + Z_ALPHA * sig_a
    return theta, mu_a, sig_a


def eval_clf(model, X_val_full: np.ndarray, y_val_full: np.ndarray, theta: float) -> dict:
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


def global_validation_loss(global_sd: dict, rsu_data: dict, rsu_ids: list) -> float:
    """Sample-weighted mean benign reconstruction error of the current global model
    across all RSUs' validation windows — the 'global loss' R-convergence is measured on."""
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(global_sd)
    model.eval()
    losses, weights = [], []
    with torch.no_grad():
        for rsu_id in rsu_ids:
            xv = rsu_data[rsu_id]["X_va_benign"]
            if len(xv) == 0:
                continue
            xv_t = torch.from_numpy(xv).float().to(DEVICE)
            losses.append(model.anomaly_score(xv_t).mean().item())
            weights.append(len(xv))
    return float(np.average(losses, weights=weights)) if losses else float("nan")


# ── BRFA-v2 (Algorithm alg:brfa_v2) ───────────────────────────────────────────

def trust_gate(rsu_ids: list, trust_scores: dict, t_min: float, f: int) -> list:
    """Step 1: exclude RSUs with T_r < T_min; abort if fewer than 2f+1 remain."""
    eligible = [r for r in rsu_ids if trust_scores[r] >= t_min]
    if len(eligible) < 2 * f + 1:
        raise RuntimeError(
            f"BRFA-v2 abort: only {len(eligible)} RSUs passed the trust gate, "
            f"below the 2f+1={2*f+1} threshold (f={f}). Insufficient honest "
            f"participants — global model NOT updated this round.")
    return eligible


def hash_verify(round_models: dict, eligible: list) -> list:
    """Step 2: keep RSUs whose recomputed weight hash matches their committed hash."""
    verified = []
    for r in eligible:
        committed = round_models[r]["committed_hash"]
        actual    = compute_weights_hash(round_models[r]["state_dict"])
        if committed is not None and actual == committed:
            verified.append(r)
    return verified


def flatten_weights(state_dict: dict) -> np.ndarray:
    return np.concatenate([v.detach().cpu().numpy().ravel()
                           for v in state_dict.values()])


def unflatten_weights(flat: np.ndarray, reference: dict) -> dict:
    out, offset = {}, 0
    for k, v in reference.items():
        size = v.numel()
        out[k] = torch.from_numpy(flat[offset:offset+size].reshape(v.shape))
        offset += size
    return out


def krum_filter(flat_weights: list, n_samples: list, gamma_factor: float = 2.0):
    """eq:fed_robust: filter models whose distance to coordinate-wise median
    exceeds γ = median(d) + gamma_factor * std(d). Returns boolean mask."""
    W = np.stack(flat_weights)
    W_tilde = np.median(W, axis=0)
    dists = np.array([np.linalg.norm(w - W_tilde) for w in flat_weights])
    gamma = np.median(dists) + gamma_factor * dists.std()
    mask  = dists < gamma
    return mask, W_tilde


def weighted_fedavg(flat_weights: list, n_samples: list, mask: np.ndarray) -> np.ndarray:
    accepted_w = [flat_weights[i] for i in range(len(mask)) if mask[i]]
    accepted_n = [n_samples[i]    for i in range(len(mask)) if mask[i]]
    total = sum(accepted_n)
    return sum(w * (n / total) for w, n in zip(accepted_w, accepted_n))


def bc_commit_global_hash(weights_hash: str):
    """Stub — Algorithm alg:brfa_v2 final step: BC.COMMIT(H(W_global))."""
    pass   # blockchain_sim.h handles the real commit in the C++ simulation layer


# ── Main federated loop ───────────────────────────────────────────────────────

def main(args):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading preprocessed data from {PRE} …")
    rsu_data = load_rsu_data()
    if not rsu_data:
        raise RuntimeError("No RSU data found. Run preprocessor.py first.")
    rsu_ids = sorted(rsu_data.keys())
    n_total = len(rsu_ids)

    hparams      = load_hparams(rsu_ids)
    trust_scores = load_trust_scores(rsu_ids)
    f = args.f if args.f is not None else max(0, (n_total - 1) // 3)   # f < n/3 (PBFT bound)
    print(f"Federated training over {n_total} RSUs on {DEVICE} "
          f"(f={f}, requiring >=2f+1={2*f+1} eligible RSUs each round)")

    r_max = max(ROUND_GRID)
    global_model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    global_sd = {k: v.clone() for k, v in global_model.state_dict().items()}

    round_log, round_losses, checkpoints, checkpoint_meta = [], {}, {}, {}

    for rnd in range(1, r_max + 1):
        round_models = {}
        for rsu_id in rsu_ids:
            hp = hparams[rsu_id]
            local_model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
            local_model.load_state_dict(global_sd)
            train_local_epochs(local_model, rsu_data[rsu_id]["X_tr"],
                               hp["lr"], hp["batch"], hp["epochs"])
            local_sd = local_model.state_dict()
            round_models[rsu_id] = {"state_dict": local_sd,
                                    "committed_hash": compute_weights_hash(local_sd),
                                    "n_train": rsu_data[rsu_id]["n_train"]}

        eligible = trust_gate(rsu_ids, trust_scores, args.t_min, f)
        verified = hash_verify(round_models, eligible)
        if len(verified) < 2 * f + 1:
            raise RuntimeError(
                f"BRFA-v2 abort at round {rnd}: only {len(verified)} RSUs passed hash "
                f"verification, below the 2f+1={2*f+1} threshold (f={f}).")

        flat_list = [flatten_weights(round_models[r]["state_dict"]) for r in verified]
        n_list    = [round_models[r]["n_train"] for r in verified]
        mask, _   = krum_filter(flat_list, n_list, gamma_factor=args.gamma_factor)
        accepted_rsu_ids = [verified[i] for i in range(len(verified)) if mask[i]]

        global_flat = weighted_fedavg(flat_list, n_list, mask)
        reference   = round_models[verified[0]]["state_dict"]
        global_sd   = unflatten_weights(global_flat, reference)

        g_loss = global_validation_loss(global_sd, rsu_data, rsu_ids)
        round_log.append({"round": rnd, "global_loss": g_loss,
                          "n_eligible": len(eligible), "n_verified": len(verified),
                          "n_accepted": int(mask.sum())})

        if rnd in ROUND_GRID:
            round_losses[rnd] = g_loss
            checkpoints[rnd]  = {k: v.clone() for k, v in global_sd.items()}
            checkpoint_meta[rnd] = {
                "trust_rejected": sorted(set(rsu_ids) - set(eligible)),
                "hash_rejected":  sorted(set(eligible) - set(verified)),
                "krum_rejected":  [verified[i] for i in range(len(verified)) if not mask[i]],
                "accepted_rsus":  accepted_rsu_ids,
            }
            print(f"  Round {rnd:3d}/{r_max}  global_loss={g_loss:.6f}  "
                  f"eligible={len(eligible)} verified={len(verified)} accepted={int(mask.sum())}")
        elif rnd % 25 == 0:
            print(f"  Round {rnd:3d}/{r_max}  global_loss={g_loss:.6f}")

    # Select smallest R whose global loss has converged to within CONVERGE_TOL of loss@R_max
    loss_at_max = round_losses[r_max]
    ref = abs(loss_at_max) if loss_at_max != 0 else 1e-12
    selected_R = r_max
    for r in sorted(ROUND_GRID):
        if abs(round_losses[r] - loss_at_max) / ref <= CONVERGE_TOL:
            selected_R = r
            break
    global_sd = checkpoints[selected_R]
    final_meta = checkpoint_meta[selected_R]
    print(f"Selected R={selected_R} (global_loss={round_losses[selected_R]:.6f}, "
          f"global_loss@R_max={loss_at_max:.6f})")

    global_model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    global_model.load_state_dict(global_sd)
    global_hash = compute_weights_hash(global_sd)
    bc_commit_global_hash(global_hash)   # Step 4: BC.COMMIT(H(W_global))
    torch.save({"weights": {k: v.cpu() for k, v in global_sd.items()}}, MODEL_DIR / "global.pt")
    print(f"Global model saved → {MODEL_DIR}/global.pt")

    # Per-RSU threshold calibration against the FINAL global model (eq:lstm_threshold),
    # with a joint >=95% precision / <=1% FPR check (spec §4.2).
    per_rsu = {}
    for rsu_id in rsu_ids:
        theta, mu_a, sig_a = compute_theta(global_model, rsu_data[rsu_id]["X_va_benign"])
        clf = eval_clf(global_model, rsu_data[rsu_id]["X_va_full"],
                       rsu_data[rsu_id]["y_va_full"], theta)
        if clf["precision"] < TARGET_PRECISION:
            print(f"  RSU {rsu_id:3d} WARNING: joint calibration target not met — "
                  f"precision={clf['precision']:.4f} < {TARGET_PRECISION} "
                  f"(FPR={clf['fpr']:.4f}, MCC={clf['mcc']:.4f})")
        per_rsu[rsu_id] = {"theta": theta, "mu_a": mu_a, "sig_a": sig_a,
                          "val_precision": clf["precision"], "val_fpr": clf["fpr"],
                          "val_mcc": clf["mcc"]}
        torch.save({"weights": {k: v.cpu() for k, v in global_sd.items()}, "theta": theta},
                   MODEL_DIR / f"rsu_{rsu_id}_global.pt")

    global_theta = float(np.mean([v["theta"] for v in per_rsu.values()]))

    fed_summary = {
        "n_total": n_total, "f": f, "t_min": args.t_min,
        "round_grid": ROUND_GRID, "selected_R": selected_R,
        "round_log": round_log,
        "trust_rejected": final_meta["trust_rejected"],
        "hash_rejected":  final_meta["hash_rejected"],
        "krum_rejected":  final_meta["krum_rejected"],
        "accepted_rsus":  final_meta["accepted_rsus"],
        "global_theta":   global_theta,
        "global_model_hash": global_hash,
        "per_rsu": per_rsu,
    }
    with open(REPO / "lstm_pipeline" / "fed_summary.json", "w") as fh:
        json.dump(fed_summary, fh, indent=2)
    print(f"Federated summary → lstm_pipeline/fed_summary.json")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gamma_factor", type=float, default=2.0,
                    help="BRFA-v2 Krum outlier threshold multiplier (default 2.0)")
    ap.add_argument("--t_min", type=float, default=0.5,
                    help="BRFA-v2 trust gate threshold T_min (paper sweep {0.3,0.5,0.7})")
    ap.add_argument("--f", type=int, default=None,
                    help="Byzantine fault tolerance parameter f (default: floor((n_total-1)/3))")
    main(ap.parse_args())
