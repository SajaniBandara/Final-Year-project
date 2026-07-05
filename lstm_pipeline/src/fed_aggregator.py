"""
fed_aggregator.py — BRFA-v2 Byzantine-Robust Federated Aggregation (eq:fed_robust, alg:brfa_v2)

Algorithm:
  1. Load per-RSU model weights W_local^(k) and sample counts n_k
  2. Compute coordinate-wise median W̃ across all local models
  3. Compute Euclidean distance d(W_local^(k), W̃) per model
  4. Filter: keep RSU k if d < γ  (γ = median(d) + 2·std(d))
  5. Weighted FedAvg over accepted models: n_k-weighted mean
  6. Save global model to models/global.pt
  7. Distribute global model back: save models/rsu_{k}_global.pt per RSU

eq:bc_model_verify stubs are called after aggregation (blockchain hash commit).
"""

import json, argparse
import numpy as np
import torch
from pathlib import Path
from lstm_model import LSTMAutoencoder, N_FEATURES

REPO      = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO / "lstm_pipeline" / "models"
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"


def load_local_models(model_dir: Path) -> dict:
    """Returns {rsu_id: {"state_dict": ..., "theta": ..., "n_train": ...}}"""
    models = {}
    local_results_path = REPO / "lstm_pipeline" / "local_results.json"
    with open(local_results_path) as fh:
        local_results = json.load(fh)

    for path in sorted(model_dir.glob("rsu_[0-9]*.pt")):
        rsu_id = int(path.stem.split("_")[1])
        ckpt   = torch.load(path, map_location="cpu")
        n      = local_results.get(str(rsu_id), {}).get("n_train", 1)
        models[rsu_id] = {"state_dict": ckpt["weights"],
                          "theta":      ckpt["theta"],
                          "n_train":    n}
    return models


def flatten_weights(state_dict: dict) -> np.ndarray:
    return np.concatenate([v.cpu().numpy().ravel()
                           for v in state_dict.values()])


def unflatten_weights(flat: np.ndarray, reference: dict) -> dict:
    out, offset = {}, 0
    for k, v in reference.items():
        size = v.numel()
        out[k] = torch.from_numpy(flat[offset:offset+size].reshape(v.shape))
        offset += size
    return out


def krum_filter(flat_weights: list[np.ndarray], n_samples: list[int],
                gamma_factor: float = 2.0):
    """
    eq:fed_robust: filter models whose distance to coordinate-wise median
    exceeds γ = median(d) + gamma_factor * std(d).
    Returns boolean mask of accepted models.
    """
    W = np.stack(flat_weights)                   # (K, D)
    W_tilde = np.median(W, axis=0)               # coordinate-wise median
    dists = np.array([np.linalg.norm(w - W_tilde) for w in flat_weights])
    gamma = np.median(dists) + gamma_factor * dists.std()
    mask  = dists < gamma
    print(f"  BRFA-v2: {mask.sum()}/{len(mask)} RSUs accepted "
          f"(γ={gamma:.4f}, dists min={dists.min():.4f} max={dists.max():.4f})")
    return mask, W_tilde


def weighted_fedavg(flat_weights: list[np.ndarray],
                    n_samples: list[int],
                    mask: np.ndarray) -> np.ndarray:
    accepted_w = [flat_weights[i] for i in range(len(mask)) if mask[i]]
    accepted_n = [n_samples[i]    for i in range(len(mask)) if mask[i]]
    total = sum(accepted_n)
    return sum(w * (n / total) for w, n in zip(accepted_w, accepted_n))


def bc_commit_model_hash(rsu_id: int, weights_hash: str):
    """Stub — eq:bc_model_verify: SC.CommitModelHash(H(W_local^(k)))"""
    pass   # blockchain_sim.h handles real commit in C++ simulation layer


def main(args):
    print(f"Loading local RSU models from {MODEL_DIR} …")
    models = load_local_models(MODEL_DIR)
    if not models:
        raise RuntimeError(f"No RSU models found in {MODEL_DIR}. Run local_trainer.py first.")

    rsu_ids     = sorted(models.keys())
    flat_list   = [flatten_weights(models[r]["state_dict"]) for r in rsu_ids]
    n_list      = [models[r]["n_train"] for r in rsu_ids]
    print(f"  {len(rsu_ids)} RSU models loaded")

    mask, _ = krum_filter(flat_list, n_list, gamma_factor=args.gamma_factor)

    global_flat = weighted_fedavg(flat_list, n_list, mask)
    reference   = models[rsu_ids[0]]["state_dict"]
    global_sd   = unflatten_weights(global_flat, reference)

    global_model = LSTMAutoencoder(n_features=N_FEATURES)
    global_model.load_state_dict(global_sd)
    torch.save({"weights": global_sd}, MODEL_DIR / "global.pt")
    print(f"  Global model saved → {MODEL_DIR}/global.pt")

    # Aggregate thresholds: weighted mean of accepted RSU thresholds (eq:lstm_threshold)
    accepted_rsu_ids = [rsu_ids[i] for i in range(len(rsu_ids)) if mask[i]]
    thresholds = {r: models[r]["theta"] for r in accepted_rsu_ids}
    global_theta = float(np.mean(list(thresholds.values())))

    # Distribute global model back to each RSU (overwrite with federated weights)
    for rsu_id in rsu_ids:
        bc_commit_model_hash(rsu_id, str(hash(global_flat.tobytes())))
        torch.save({"weights": global_sd,
                    "theta":   thresholds.get(rsu_id, global_theta)},
                   MODEL_DIR / f"rsu_{rsu_id}_global.pt")

    fed_summary = {
        "accepted_rsus":  accepted_rsu_ids,
        "rejected_rsus":  [rsu_ids[i] for i in range(len(rsu_ids)) if not mask[i]],
        "global_theta":   global_theta,
        "n_accepted":     int(mask.sum()),
        "n_total":        len(rsu_ids),
    }
    with open(REPO / "lstm_pipeline" / "fed_summary.json", "w") as fh:
        json.dump(fed_summary, fh, indent=2)
    print(f"  Federated summary → lstm_pipeline/fed_summary.json")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gamma_factor", type=float, default=2.0,
                    help="BRFA-v2 outlier threshold multiplier (default 2.0)")
    main(ap.parse_args())
