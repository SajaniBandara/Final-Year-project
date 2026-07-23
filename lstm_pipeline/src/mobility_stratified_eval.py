"""
mobility_stratified_eval.py — MOBIGUARD M1 mobility-stratified MCC (eq:mcc_mobility)

main.tex Eq. mcc_mobility defines:
    MCC_s[rho_b, v_bar_b] = MCC evaluated when rho(t) in rho_b AND v_bar(t) in v_bar_b
with rho_b in {low, medium, high} (tertiles) and v_bar_b in {low, high} (median split),
to validate that the mobility-adjusted thresholds hold across density/speed regimes
rather than degrading at high-density, high-speed conditions.

This is pure post-processing over data evaluator.py already produces: rho_t and v_bar_t
are logged per-cycle in the LSTM training CSVs and survive preprocessing as two of the
7 window features (scaled). We recover each window's raw mean rho/v_bar via
scaler_params.json (mu/std), bin against tertile/median cut points fit on the TRAIN
split (never the test split, to avoid leaking test-set structure into the bin
boundaries), and recompute MCC per (attack_variant, rho_bin, v_bar_bin) cell on the
held-out test split — same global model + theta evaluator.py uses, no retraining.

Output: lstm_pipeline/mobility_stratified_results.json
"""

import json
import numpy as np
import torch
from pathlib import Path
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO      = Path(__file__).resolve().parents[2]
PRE       = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"

RHO_IDX   = 5   # FEATURES index of "rho"   (preprocessor.py FEATURES order)
VBAR_IDX  = 6   # FEATURES index of "v_bar"
MIN_CELL  = 20  # skip a stratum cell if it has too few windows for a stable MCC

# 5-8 match main.tex's own attack titles — see evaluator.py's ATTACK_NAMES
# comment for the full mapping to Attack 5-8 / S5-S8.
ATTACK_NAMES = {
    0: "Benign", 1: "A1 CP-SelectiveDelay", 2: "A2 DP-SelectiveDelay",
    3: "A3 CP-TCAM", 4: "A4 DP-TCAM", 5: "A5 CP-ActiveHF",
    6: "A6 DP-ActiveHF", 7: "A7 CP-PassiveHF", 8: "A8 DP-PassiveHF",
}


def load_split(split: str):
    X    = np.load(PRE / f"{split}_X.npy")
    y    = np.load(PRE / f"{split}_y.npy")
    meta = np.load(PRE / f"{split}_meta.npy")
    return X, y, meta


def load_global_model() -> tuple:
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    # eq:lstm_threshold: theta^(k) is per-RSU — see evaluator.py's
    # load_global_model() for the full rationale (this file had the same
    # single-global-theta bug, found & fixed 2026-07-18 alongside it).
    per_rsu_theta = {int(k): float(v["theta"]) for k, v in fed["per_rsu"].items()}
    return model, per_rsu_theta, float(fed["global_theta"])


def predict(model, per_rsu_theta, global_theta, X, rsu_ids) -> np.ndarray:
    bs, scores = 512, []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i + bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    theta_arr = np.array([per_rsu_theta.get(int(r), global_theta) for r in rsu_ids])
    return (scores > theta_arr).astype(np.int8)


def raw_mobility(X: np.ndarray, mu: dict, std: dict) -> tuple:
    """Un-scale each window's mean rho/v_bar back to raw units.
    X: (N, W, F) scaled features -> per-window mean over the W timesteps."""
    rho_scaled  = X[:, :, RHO_IDX].mean(axis=1)
    vbar_scaled = X[:, :, VBAR_IDX].mean(axis=1)
    rho_raw  = rho_scaled  * std["rho"]   + mu["rho"]
    vbar_raw = vbar_scaled * std["v_bar"] + mu["v_bar"]
    return rho_raw, vbar_raw


def fit_bin_edges(rho_train: np.ndarray, vbar_train: np.ndarray) -> dict:
    """rho -> tertiles (low/medium/high), v_bar -> median split (low/high).
    Edges fit on TRAIN split only, then applied to test — avoids leaking
    test-set distribution into the bin boundaries."""
    rho_edges  = np.quantile(rho_train,  [1 / 3, 2 / 3])
    vbar_edges = np.quantile(vbar_train, [0.5])
    return {"rho_edges": rho_edges.tolist(), "vbar_edges": vbar_edges.tolist()}


def bin_rho(rho: np.ndarray, edges: list) -> np.ndarray:
    return np.digitize(rho, edges)          # 0=low, 1=medium, 2=high


def bin_vbar(vbar: np.ndarray, edges: list) -> np.ndarray:
    return np.digitize(vbar, edges)         # 0=low, 1=high


def mcc_of(y_true, y_pred) -> dict:
    if len(y_true) < MIN_CELL or len(set(y_true.tolist())) < 2:
        return None
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    mcc = matthews_corrcoef(y_true, y_pred)
    dr  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"MCC": round(float(mcc), 4), "DR": round(dr, 4), "FPR": round(fpr, 4),
            "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn), "n": int(len(y_true))}


def main():
    with open(REPO / "lstm_pipeline" / "scaler_params.json") as fh:
        scaler = json.load(fh)
    mu, std = scaler["mu"], scaler["std"]

    print("Loading train split (for bin-edge fitting) and test split (for evaluation) …")
    X_tr, _, _   = load_split("train")
    X_te, y_te, meta_te = load_split("test")

    rho_tr, vbar_tr = raw_mobility(X_tr, mu, std)
    edges = fit_bin_edges(rho_tr, vbar_tr)
    print(f"  rho tertile edges  (veh/km-equiv units): {[round(e, 3) for e in edges['rho_edges']]}")
    print(f"  v_bar median edge  (m/s-equiv units):     {[round(e, 3) for e in edges['vbar_edges']]}")

    rho_te, vbar_te = raw_mobility(X_te, mu, std)
    rho_bin_te  = bin_rho(rho_te, edges["rho_edges"])
    vbar_bin_te = bin_vbar(vbar_te, edges["vbar_edges"])

    print("Loading global federated model …")
    model, per_rsu_theta, global_theta = load_global_model()
    y_pred = predict(model, per_rsu_theta, global_theta, X_te, meta_te[:, 0])

    RHO_LABELS  = ["low", "medium", "high"]
    VBAR_LABELS = ["low", "high"]

    results = {}
    attack_variants = sorted(set(meta_te[:, 1].tolist()))
    for av in attack_variants:
        av_name = ATTACK_NAMES.get(av, f"A{av}")
        av_mask = meta_te[:, 1] == av
        cell_results = {}
        for rb, rb_name in enumerate(RHO_LABELS):
            for vb, vb_name in enumerate(VBAR_LABELS):
                mask = av_mask & (rho_bin_te == rb) & (vbar_bin_te == vb)
                cell = mcc_of(y_te[mask], y_pred[mask])
                cell_results[f"rho={rb_name},v_bar={vb_name}"] = cell
        results[av_name] = cell_results

        printable = {k: (v["MCC"] if v else None) for k, v in cell_results.items()}
        print(f"\n  {av_name}:")
        for k, mcc in printable.items():
            print(f"    {k:28s} MCC={mcc if mcc is not None else 'insufficient data (n<'+str(MIN_CELL)+')'}")

    out = {"bin_edges": edges, "rho_labels": RHO_LABELS, "vbar_labels": VBAR_LABELS,
           "per_variant": results}
    out_path = REPO / "lstm_pipeline" / "mobility_stratified_results.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nMobility-stratified MCC (eq:mcc_mobility) -> {out_path}")


if __name__ == "__main__":
    main()
