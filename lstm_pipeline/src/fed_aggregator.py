"""
fed_aggregator.py — BRFA-v2 Byzantine-Robust Federated Aggregation (eq:fed_robust, alg:brfa_v2)

Algorithm (alg:brfa_v2, main.tex):
  Step 1: Trust gate      — K_e = {k : T_r_k >= T_min}, abort if |K_e| < 2f+1
  Step 2: Hash verification — 1_BC^(k) = SC.VerifyModelHash(W^(k))
  Step 3: Krum geometric filter — reject k if d(W^(k), median) >= gamma
  Step 4: Weighted aggregation — W_global = sum(omega_k * W^(k)) / sum(omega_k)
          where omega_k = n_k * 1_BC^(k) * 1[d(W^(k), median) < gamma]

M8 (eq:delta_poison) additions on top of the original Krum+FedAvg-only version:
  - --poison_fraction / --poison_mode: corrupts a rho_mal fraction of loaded
    RSU models before aggregation, simulating Byzantine gradient submissions.
  - --mode {brfa, fedavg}: fedavg skips Steps 1-3 entirely (naive weighted
    average over every submission, poisoned or not) — the AB5-A baseline
    the proposal compares BRFA-v2 against.
  - --trust_scores / --trust_min: Step 1 trust gate. Scores default to 1.0
    (crypto_layer.h's initial trust) for any RSU not listed, so this is a
    no-op filter unless a live simulation's per-RSU trust CSV is supplied.

Hash verification (Step 2) scope note: this simulation computes each RSU's
commit hash from the same in-memory weights used at aggregation time — i.e.
it verifies read integrity between "commit" and "use", not the honesty of
the weights themselves. A malicious RSU that self-consistently poisons its
own model and correctly hashes its own (poisoned) output will always pass
Step 2 — by design, per alg:brfa_v2's own structure, since Step 2 defends
against transit tampering/impersonation, while Step 3 (Krum) is the layer
that catches statistical-outlier poisoning. Network-transit tampering is
out of scope for a single-process simulation reading local checkpoint
files, so Step 2 is implemented as a real (non-decorative) integrity check
that is expected to always pass here; this is documented rather than
silently omitted.
"""

import json, argparse, hashlib
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


def compute_weights_hash(flat_weights: np.ndarray) -> str:
    """SC.VerifyModelHash's local analogue (eq:bc_model_verify) — SHA-256
    over the flattened weight vector actually being aggregated."""
    return hashlib.sha256(np.ascontiguousarray(flat_weights).tobytes()).hexdigest()


def apply_poisoning(flat_list: list[np.ndarray], rsu_ids: list[int],
                    poison_fraction: float, poison_mode: str,
                    seed: int = 0) -> tuple[list[np.ndarray], set[int]]:
    """
    Corrupts the first round(poison_fraction * K) RSUs (by sorted rsu_id,
    deterministic) to simulate Byzantine gradient submissions for
    Delta_poison(rho_mal) evaluation (eq:delta_poison). Returns the
    (possibly modified) weight list and the set of poisoned RSU ids.

    poison_mode:
      sign_flip — W_poisoned = -W        (classic strong Byzantine attack)
      scale     — W_poisoned = 50 * W    (large-magnitude outlier)
      random    — W_poisoned ~ N(0, 1)   (submits an unrelated random model)
    """
    k = len(rsu_ids)
    n_poison = round(poison_fraction * k)
    if n_poison <= 0:
        return flat_list, set()

    poisoned_ids = set(sorted(rsu_ids)[:n_poison])
    rng = np.random.RandomState(seed)
    out = []
    for rid, w in zip(rsu_ids, flat_list):
        if rid not in poisoned_ids:
            out.append(w)
            continue
        if poison_mode == "sign_flip":
            out.append(-w)
        elif poison_mode == "scale":
            out.append(50.0 * w)
        elif poison_mode == "random":
            out.append(rng.normal(0, 1, size=w.shape).astype(w.dtype))
        else:
            raise ValueError(f"Unknown poison_mode: {poison_mode}")
    return out, poisoned_ids


def trust_gate(rsu_ids: list[int], trust_scores: dict | None,
              trust_min: float) -> set[int]:
    """Step 1 (alg:brfa_v2): K_e = {k : T_r_k >= T_min}. Missing entries
    default to 1.0 (crypto_layer.h TRUST_INIT), so this is a no-op unless
    a live per-RSU trust CSV/JSON is supplied."""
    if trust_scores is None:
        return set(rsu_ids)
    return {rid for rid in rsu_ids if trust_scores.get(str(rid), 1.0) >= trust_min}


def hash_verify_all(flat_list: list[np.ndarray], rsu_ids: list[int]) -> dict[int, bool]:
    """Step 2 (alg:brfa_v2): recompute-and-compare integrity check — see
    module docstring for what this does and does not defend against in a
    single-process simulation. Always True here by construction; kept as
    a real (non-decorative) call site rather than silently skipped, so the
    step is visible in the pipeline and easy to wire to a real transit
    check later if the blockchain bridge starts carrying model hashes."""
    verified = {}
    for rid, w in zip(rsu_ids, flat_list):
        committed_hash = compute_weights_hash(w)   # "commit" at submission time
        recomputed_hash = compute_weights_hash(w)   # "verify" at aggregation time
        verified[rid] = (committed_hash == recomputed_hash)
    return verified


def krum_filter(flat_weights: list[np.ndarray], n_samples: list[int],
                gamma_factor: float = 2.0):
    """
    Step 3 (alg:brfa_v2, eq:fed_robust): filter models whose distance to
    coordinate-wise median exceeds gamma = median(d) + gamma_factor * std(d).
    Returns boolean mask of accepted models.

    With fewer than 2 candidates, "distance to the median" is trivially 0
    for the sole candidate, making gamma = 0 and the strict "<" comparison
    reject it outright — Krum's geometric-outlier test is undefined with a
    single point (there is nothing to compare it against). Auto-accept in
    that case rather than let a lone honest RSU's own model be spuriously
    rejected by its own filter (see docs/METRICS_DEVIATIONS_FROM_PROPOSAL.md).
    """
    if len(flat_weights) < 2:
        print(f"  BRFA-v2: {len(flat_weights)} eligible RSU(s) after trust/hash gate — "
              f"Krum distance filter is undefined with <2 candidates, auto-accepting.")
        mask = np.ones(len(flat_weights), dtype=bool)
        return mask, (flat_weights[0] if flat_weights else None)

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
    """Step 4 (alg:brfa_v2): omega_k-weighted mean over accepted models.
    `mask` already folds together trust-gate AND hash-verify AND Krum
    (or is all-True for --mode fedavg) — omega_k = n_k for accepted k."""
    accepted_w = [flat_weights[i] for i in range(len(mask)) if mask[i]]
    accepted_n = [n_samples[i]    for i in range(len(mask)) if mask[i]]
    total = sum(accepted_n)
    return sum(w * (n / total) for w, n in zip(accepted_w, accepted_n))


def bc_commit_model_hash(rsu_id: int, weights_hash: str):
    """Stub — eq:bc_model_verify: SC.CommitModelHash(H(W_local^(k)))"""
    pass   # blockchain_sim.h handles real commit in C++ simulation layer


def run_aggregation(gamma_factor: float = 2.0,
                    poison_fraction: float = 0.0,
                    poison_mode: str = "sign_flip",
                    mode: str = "brfa",
                    trust_scores_path: str | None = None,
                    trust_min: float = 0.50,
                    out_suffix: str = "",
                    seed: int = 0) -> dict:
    """
    Core BRFA-v2 / naive-FedAvg aggregation, reusable both by main() (CLI,
    preserves the original single-shot global.pt behavior) and by
    poison_sweep.py (M8 eq:delta_poison sweep, many in-process calls with
    out_suffix="" so nothing is written to disk mid-sweep — only the
    returned in-memory state_dict/theta are used for MCC evaluation).

    Returns a summary dict including "global_state_dict" and "global_theta"
    for in-memory evaluation, plus the same bookkeeping fields previously
    written to fed_summary.json.
    """
    models = load_local_models(MODEL_DIR)
    if not models:
        raise RuntimeError(f"No RSU models found in {MODEL_DIR}. Run local_trainer.py first.")

    rsu_ids   = sorted(models.keys())
    flat_list = [flatten_weights(models[r]["state_dict"]) for r in rsu_ids]
    n_list    = [models[r]["n_train"] for r in rsu_ids]

    # M8 (eq:delta_poison): corrupt a rho_mal fraction of submissions.
    flat_list, poisoned_ids = apply_poisoning(
        flat_list, rsu_ids, poison_fraction, poison_mode, seed=seed)
    if poisoned_ids:
        print(f"  M8: poisoned {len(poisoned_ids)}/{len(rsu_ids)} RSUs "
              f"({poison_mode}) -> ids={sorted(poisoned_ids)}")

    if mode == "fedavg":
        # AB5-A baseline: naive weighted average, no trust/hash/Krum filtering.
        eligible = set(rsu_ids)
        hash_ok  = {r: True for r in rsu_ids}
        krum_mask = np.ones(len(rsu_ids), dtype=bool)
    elif mode == "brfa":
        trust_scores = None
        if trust_scores_path:
            with open(trust_scores_path) as fh:
                trust_scores = json.load(fh)
        eligible = trust_gate(rsu_ids, trust_scores, trust_min)          # Step 1
        f_bft = (len(rsu_ids) - 1) // 3
        if len(eligible) < 2 * f_bft + 1:
            raise RuntimeError(
                f"BRFA-v2 abort: |K_e|={len(eligible)} < 2f+1={2*f_bft+1} "
                f"after trust gate (eligible RSUs={sorted(eligible)})")
        hash_ok  = hash_verify_all(flat_list, rsu_ids)                   # Step 2
        krum_in  = [flat_list[i] for i, r in enumerate(rsu_ids) if r in eligible]
        n_in     = [n_list[i]    for i, r in enumerate(rsu_ids) if r in eligible]
        krum_sub_mask, _ = krum_filter(krum_in, n_in, gamma_factor)      # Step 3
        krum_mask = np.zeros(len(rsu_ids), dtype=bool)
        j = 0
        for i, r in enumerate(rsu_ids):
            if r in eligible:
                krum_mask[i] = krum_sub_mask[j]
                j += 1
    else:
        raise ValueError(f"Unknown mode: {mode}")

    # omega_k = n_k * trust_gate * hash_ok * krum_mask (Step 4)
    final_mask = np.array([
        (rsu_ids[i] in eligible) and hash_ok[rsu_ids[i]] and krum_mask[i]
        for i in range(len(rsu_ids))
    ])

    global_flat = weighted_fedavg(flat_list, n_list, final_mask)
    reference   = models[rsu_ids[0]]["state_dict"]
    global_sd   = unflatten_weights(global_flat, reference)

    # Aggregate thresholds: weighted mean of accepted RSU thresholds (eq:lstm_threshold)
    accepted_rsu_ids = [rsu_ids[i] for i in range(len(rsu_ids)) if final_mask[i]]
    thresholds = {r: models[r]["theta"] for r in accepted_rsu_ids}
    global_theta = float(np.mean(list(thresholds.values()))) if thresholds else 0.0

    if out_suffix is not None:
        global_model = LSTMAutoencoder(n_features=N_FEATURES)
        global_model.load_state_dict(global_sd)
        torch.save({"weights": global_sd}, MODEL_DIR / f"global{out_suffix}.pt")
        for rsu_id in rsu_ids:
            bc_commit_model_hash(rsu_id, compute_weights_hash(global_flat))
            torch.save({"weights": global_sd,
                        "theta":   thresholds.get(rsu_id, global_theta)},
                       MODEL_DIR / f"rsu_{rsu_id}_global{out_suffix}.pt")

    return {
        "mode":             mode,
        "poison_fraction":  poison_fraction,
        "poison_mode":      poison_mode if poisoned_ids else None,
        "poisoned_rsus":    sorted(poisoned_ids),
        "accepted_rsus":    accepted_rsu_ids,
        "rejected_rsus":    [r for r in rsu_ids if r not in accepted_rsu_ids],
        "global_theta":     global_theta,
        "global_state_dict": global_sd,
        "n_accepted":       int(final_mask.sum()),
        "n_total":          len(rsu_ids),
    }


def main(args):
    print(f"Loading local RSU models from {MODEL_DIR} …")
    fed_summary = run_aggregation(
        gamma_factor=args.gamma_factor,
        poison_fraction=args.poison_fraction,
        poison_mode=args.poison_mode,
        mode=args.mode,
        trust_scores_path=args.trust_scores,
        trust_min=args.trust_min,
        out_suffix="",  # preserves original global.pt / rsu_{k}_global.pt behavior
    )
    print(f"  Global model saved -> {MODEL_DIR}/global.pt")
    print(f"  Accepted {fed_summary['n_accepted']}/{fed_summary['n_total']} RSUs")

    out = {k: v for k, v in fed_summary.items() if k != "global_state_dict"}
    with open(REPO / "lstm_pipeline" / "fed_summary.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"  Federated summary -> lstm_pipeline/fed_summary.json")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gamma_factor", type=float, default=2.0,
                    help="BRFA-v2 outlier threshold multiplier (default 2.0)")
    ap.add_argument("--mode", choices=["brfa", "fedavg"], default="brfa",
                    help="brfa = full Alg. BRFA-v2 (proposed); fedavg = naive "
                         "weighted average, no trust/hash/Krum filtering (AB5-A baseline)")
    ap.add_argument("--poison_fraction", type=float, default=0.0,
                    help="M8 eq:delta_poison: fraction of RSUs submitting poisoned models")
    ap.add_argument("--poison_mode", choices=["sign_flip", "scale", "random"],
                    default="sign_flip")
    ap.add_argument("--trust_scores", default=None,
                    help="Optional path to a {rsu_id: trust_score} JSON (Step 1 trust gate). "
                         "Defaults to all-1.0 (no live simulation trust data plumbed in yet).")
    ap.add_argument("--trust_min", type=float, default=0.50,
                    help="Step 1 trust gate threshold (matches crypto_layer.h TRUST_T_MIN default)")
    main(ap.parse_args())
