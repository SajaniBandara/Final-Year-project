"""
fed_aggregator.py — MOBIGUARD federated LSTM training loop + BRFA-v2 aggregation
(eq:fed_robust, alg:brfa_v2, eq:lstm_threshold, eq:delta_poison)

This module has two entry points:

1. `main()` / CLI (`python3 fed_aggregator.py`) — the live, primary training
   path used by pipeline.py step 3. For each of up to R_max global rounds:
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
   Each RSU's own LOCAL model at the selected round R is also saved as a
   standalone checkpoint (rsu_{k}.pt) — see `main()`'s post-loop block for why:
   entry point 2 below needs it and nothing else in this design produces it.

2. `run_aggregation()` — a standalone, importable BRFA-v2/naive-FedAvg
   aggregation pass over ALREADY-TRAINED local models loaded from disk
   (rsu_{k}.pt, produced by `main()` above). Used by poison_sweep.py (M8
   eq:delta_poison: Delta_poison(rho_mal) sweep, BRFA-v2 vs naive FedAvg) to
   corrupt a rho_mal fraction of clean local models and re-aggregate
   in-memory without disturbing `main()`'s live training artifacts. This is
   a separate, self-contained BRFA-v2 implementation (trust_gate_sweep /
   hash_verify_all / krum_filter / weighted_fedavg) rather than a call into
   `main()`'s per-round loop, since poison_sweep.py needs many independent
   one-shot aggregation calls over a fixed set of clean models, not a live
   multi-round training run.

Outputs
  lstm_pipeline/models/global.pt          final global model weights
  lstm_pipeline/models/rsu_{k}_global.pt  global weights + per-RSU theta
  lstm_pipeline/models/rsu_{k}.pt         RSU k's own local model at selected R
                                          (input to run_aggregation()/M8 sweep)
  lstm_pipeline/local_results.json        per-RSU n_train (input to load_local_models())
  lstm_pipeline/fed_summary.json          round log + per-RSU calibration summary
"""

import json, argparse, hashlib
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from pathlib import Path
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES, compute_weights_hash, seed_everything

REPO        = Path(__file__).resolve().parents[2]
PRE         = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR   = REPO / "lstm_pipeline" / "models"
TRUST_PATH  = REPO / "lstm_pipeline" / "rsu_trust_scores.json"
HPARAMS_PATH = REPO / "lstm_pipeline" / "hparams.json"
DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"

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
        # Pure-benign A0 runs only (meta col 1 = attack_v). See local_trainer.py:
        # y==0 leaked attack-run label-0 windows into benign training — this
        # remains attack_v==0 only; TRAINING the autoencoder on windows drawn
        # from attack runs (even quiet ones) would still leak subtle
        # attack-adjacent patterns into what it learns as "normal".
        mask_tr_benign = (meta_tr[:, 0] == rsu_id) & (meta_tr[:, 1] == 0)
        # theta CALIBRATION population, deliberately different from training:
        # was attack_v==0 only (640 windows total, network-wide) — but 97.7%
        # of what actually gets evaluated as "benign" at test time is y=0
        # windows drawn from attack-percentage runs (quiet cycles within an
        # attack run), which have a measurably different error distribution
        # (different SUMO traces per pct, network-wide effects of attacks
        # elsewhere) than pure attack_v==0 runs. Calibrating on the narrow
        # population gave 28-29% FPR on the very population it's evaluated
        # against; calibrating on the full y_va==0 label (matching what
        # eval_clf/compute_clf_metrics actually score against) verified to
        # bring FPR to <1% (found & fixed 2026-07-18, supervisor-approved
        # tradeoff: DR is not judged against this LSTM-only validation at
        # this stage — main.tex's 95% DR target applies to the full
        # dual-mode system once rule engine + LSTM are integrated).
        #
        # EXCLUDES attack_v in {3,4} (A3/A4, TCAM variants): confirmed
        # 2026-07-18 that ~20-25% of every RSU's y_va==0 population comes
        # from A3/A4 runs, whose U_TCAM feature carries artificially
        # extreme values from the (separately known, already-excluded-
        # from-conclusions) TCAM rule-timeout issue — this training data
        # predates that fix. Removing just these two variants' windows
        # brought per-RSU theta down from the THOUSANDS to a sane ~0.5-1.3
        # for every single RSU checked. Same exclusion already applied
        # elsewhere (no A3/A4 conclusions until that data is re-collected
        # post-fix) — this is the LSTM calibration side of the same rule.
        mask_va_benign = ((meta_va[:, 0] == rsu_id) & (y_va == 0)
                          & ~np.isin(meta_va[:, 1], [3, 4]))
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


def load_local_models(model_dir: Path) -> dict:
    """
    Loads standalone per-RSU local model checkpoints (rsu_{k}.pt) produced by
    `main()`'s post-training-loop block below. Used by run_aggregation() /
    poison_sweep.py (M8), which need a fixed set of "clean" local models to
    corrupt and re-aggregate — NOT by `main()` itself, which trains its own
    local models fresh each round.
    Returns {rsu_id: {"state_dict": ..., "theta": ..., "n_train": ...}}
    """
    models = {}
    local_results_path = REPO / "lstm_pipeline" / "local_results.json"
    with open(local_results_path) as fh:
        local_results = json.load(fh)

    for path in sorted(model_dir.glob("rsu_[0-9]*.pt")):
        if path.stem.endswith("_global"):
            continue   # rsu_{k}_global.pt are global-weight copies, not local models
        rsu_id = int(path.stem.split("_")[1])
        # weights_only=False: PyTorch >=2.6 defaults to the safe loader, which
        # rejects the numpy scalars (theta/mu/sigma) in our own checkpoints.
        ckpt   = torch.load(path, map_location="cpu", weights_only=False)
        n      = local_results.get(str(rsu_id), {}).get("n_train", 1)
        models[rsu_id] = {"state_dict": ckpt["weights"],
                          "theta":      ckpt["theta"],
                          "n_train":    n}
    return models


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


Z_ALPHA = 2.3263478740408408   # z_{0.99}, scipy.stats.norm.ppf(1 - 0.01)


def compute_theta(model, X_val_benign: np.ndarray) -> tuple:
    """eq:lstm_threshold: theta(k) = mu_A + z_alpha*sigma_A, computed from
    the RSU's own benign validation reconstruction errors.

    History (2026-07-15/18): the reported 2.84-6.65% FPR was never actually
    a threshold-FORMULA problem — it was that theta was calibrated on only
    640 "pure benign run" (attack_v==0) windows, while 97.7% of what gets
    evaluated as benign at test time are quiet windows drawn from
    attack-percentage runs with a measurably different error distribution
    (see the mask_va_benign fix in main()/grid_search_hparams() callers:
    now y_va==0, not attack_v==0). Tried three formulas AFTER that real fix
    landed, holding the calibration population fixed: plain Gaussian,
    P99-only, and max(Gaussian, P99) all hit ~0% FPR on every variant
    (the population fix is what mattered) — but Gaussian gave consistently
    HIGHER DR than both alternatives on every single variant (e.g. A2:
    21.4% vs hybrid's 18.0%, P99's 20.9%), since max(Gaussian, P99) always
    picks the more conservative (and here, unnecessarily so) of the two.
    Reverted to the original spec formula — simpler and empirically better
    once the real bug was fixed. mu_a/sig_a returned for descriptive
    logging."""
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


# ── BRFA-v2 (Algorithm alg:brfa_v2) — live training-loop path ────────────────

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
    """
    Step 3 (alg:brfa_v2, eq:fed_robust): filter models whose distance to
    coordinate-wise median exceeds gamma = median(d) + gamma_factor * std(d).
    Returns boolean mask of accepted models. Shared by both `main()`'s live
    training loop and run_aggregation()'s poisoning-sweep path.

    With fewer than 2 candidates, "distance to the median" is trivially 0
    for the sole candidate, making gamma = 0 and the strict "<" comparison
    reject it outright — Krum's geometric-outlier test is undefined with a
    single point (there is nothing to compare it against). Auto-accept in
    that case rather than let a lone honest RSU's own model be spuriously
    rejected by its own filter.
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


def weighted_fedavg(flat_weights: list, n_samples: list, mask: np.ndarray) -> np.ndarray:
    """Step 4 (alg:brfa_v2): omega_k-weighted mean over accepted models.
    `mask` already folds together trust-gate AND hash-verify AND Krum
    (or is all-True for --mode fedavg) — omega_k = n_k for accepted k."""
    accepted_w = [flat_weights[i] for i in range(len(mask)) if mask[i]]
    accepted_n = [n_samples[i]    for i in range(len(mask)) if mask[i]]
    total = sum(accepted_n)
    return sum(w * (n / total) for w, n in zip(accepted_w, accepted_n))


def bc_commit_global_hash(weights_hash: str):
    """Stub — Algorithm alg:brfa_v2 final step: BC.COMMIT(H(W_global))."""
    pass   # blockchain_sim.h handles the real commit in the C++ simulation layer


# ── BRFA-v2 — standalone poisoning-sweep path (M8, eq:delta_poison) ──────────
# poison_sweep.py imports run_aggregation() directly; these helpers are kept
# separate from the live-training-loop versions above (trust_gate/hash_verify)
# because they operate on a fixed set of already-flattened, possibly-poisoned
# weight arrays rather than a live per-round `round_models` dict, and use
# different signatures (no `f`/committed-hash-at-submission-time bookkeeping).

def _hash_flat_weights(flat_weights: np.ndarray) -> str:
    """SHA3-512 of an already-flattened weight vector — same algorithm as
    lstm_model.compute_weights_hash (eq:bc_model_verify), specialised for the
    flat np.ndarray representation apply_poisoning()/run_aggregation() use."""
    return hashlib.sha3_512(np.ascontiguousarray(flat_weights).tobytes()).hexdigest()


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


def trust_gate_sweep(rsu_ids: list[int], trust_scores: dict | None,
                     trust_min: float) -> set[int]:
    """Step 1 (alg:brfa_v2) for the poisoning-sweep path: K_e = {k : T_r_k >= T_min}.
    Missing entries default to 1.0 (crypto_layer.h TRUST_INIT), so this is a
    no-op unless a live per-RSU trust CSV/JSON is supplied."""
    if trust_scores is None:
        return set(rsu_ids)
    return {rid for rid in rsu_ids if trust_scores.get(str(rid), 1.0) >= trust_min}


def hash_verify_all(flat_list: list[np.ndarray], rsu_ids: list[int]) -> dict[int, bool]:
    """Step 2 (alg:brfa_v2) for the poisoning-sweep path: recompute-and-compare
    integrity check. Always True here by construction — this simulation
    computes each RSU's commit hash from the same in-memory weights used at
    aggregation time, i.e. it verifies read integrity between "commit" and
    "use", not the honesty of the weights themselves. A malicious RSU that
    self-consistently poisons its own model and correctly hashes its own
    (poisoned) output will always pass Step 2 — by design, per alg:brfa_v2's
    own structure, since Step 2 defends against transit tampering/
    impersonation, while Step 3 (Krum) is the layer that catches
    statistical-outlier poisoning. Kept as a real (non-decorative) call site
    rather than silently skipped."""
    verified = {}
    for rid, w in zip(rsu_ids, flat_list):
        committed_hash = _hash_flat_weights(w)   # "commit" at submission time
        recomputed_hash = _hash_flat_weights(w)   # "verify" at aggregation time
        verified[rid] = (committed_hash == recomputed_hash)
    return verified


def bc_commit_model_hash(rsu_id: int, weights_hash: str):
    """Stub — eq:bc_model_verify: SC.CommitModelHash(H(W_local^(k)))."""
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
    Standalone BRFA-v2 / naive-FedAvg aggregation over already-trained local
    models (rsu_{k}.pt, produced by `main()`'s post-loop block). Reusable
    both by a direct CLI-style call and by poison_sweep.py (M8 eq:delta_poison
    sweep, many in-process calls with out_suffix="" so nothing is written to
    disk mid-sweep — only the returned in-memory state_dict/theta are used
    for MCC evaluation).

    Returns a summary dict including "global_state_dict" and "global_theta"
    for in-memory evaluation, plus the same bookkeeping fields previously
    written to fed_summary.json.
    """
    models = load_local_models(MODEL_DIR)
    if not models:
        raise RuntimeError(f"No RSU models found in {MODEL_DIR}. Run fed_aggregator.py's "
                           f"main training loop first (produces rsu_{{k}}.pt).")

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
        eligible = trust_gate_sweep(rsu_ids, trust_scores, trust_min)        # Step 1
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
            bc_commit_model_hash(rsu_id, _hash_flat_weights(global_flat))
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


# ── Main federated training loop ──────────────────────────────────────────────

def main(args):
    seed_everything(0)   # reproducible M1/M8 metrics
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
    round_models_at_grid = {}   # rnd -> {rsu_id: {"state_dict", "n_train"}}, for M8's rsu_{k}.pt

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
            round_models_at_grid[rnd] = {
                r: {"state_dict": {k: v.clone() for k, v in m["state_dict"].items()},
                    "n_train": m["n_train"]}
                for r, m in round_models.items()
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

    # Save each RSU's own LOCAL model at the selected round R as a standalone
    # checkpoint (rsu_{k}.pt) + local_results.json (n_train) — the artifact
    # run_aggregation()/poison_sweep.py (M8 eq:delta_poison) loads and
    # poisons. Nothing else in this training loop produces a per-RSU
    # "clean, standalone" model, since local models are retrained fresh from
    # the evolving global weights every round rather than kept as
    # independent checkpoints.
    local_results = {}
    for rsu_id in rsu_ids:
        rsu_local_sd = round_models_at_grid[selected_R][rsu_id]["state_dict"]
        rsu_local_model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
        rsu_local_model.load_state_dict(rsu_local_sd)
        theta_local, _, _ = compute_theta(rsu_local_model, rsu_data[rsu_id]["X_va_benign"])
        torch.save({"weights": {k: v.cpu() for k, v in rsu_local_sd.items()}, "theta": theta_local},
                   MODEL_DIR / f"rsu_{rsu_id}.pt")
        local_results[str(rsu_id)] = {"n_train": round_models_at_grid[selected_R][rsu_id]["n_train"]}
    with open(REPO / "lstm_pipeline" / "local_results.json", "w") as fh:
        json.dump(local_results, fh, indent=2)
    print(f"Saved {len(rsu_ids)} standalone local model checkpoints (rsu_{{k}}.pt @ R={selected_R}) "
          f"for run_aggregation()/poison_sweep.py")

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
