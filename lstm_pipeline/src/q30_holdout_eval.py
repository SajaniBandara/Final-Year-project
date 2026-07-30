"""
q30_holdout_eval.py — Q30 diagnostic: pure-benign held-out-seed FPR check.

Seeds 6/7/8 (simTime=60) are benign-only (attack_v=0) runs that were NEVER
touched by preprocessing/training/validation/calibration (train=1,2,3,
val=4, test=5). Scoring the already-trained, already-calibrated global model
against them answers the supervisor's Q30: is A3/A4's 34-42% FPR seen on the
labelled test split genuine miscalibration, or an artifact of population
overlap/contamination between calibration and evaluation data? Since these
runs are 100% benign, ANY variant-specific behavior is ruled out here — this
measures pure baseline FPR of the deployed model/theta on fresh benign
traffic, independent of which attack variant a test window happened to be
paired with.

Reuses fit scaler (scaler_params.json, fit on original benign train data)
and the same W=10/stride=5 windowing rule as preprocessor.py — but applies
them only to the seed 6/7/8 CSVs, never refitting anything.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from preprocessor import FEATURES, WINDOW, STRIDE, apply_scaler, make_windows
from lstm_model import LSTMAutoencoder, N_FEATURES

REPO      = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO / "lstm_pipeline" / "models"
BASE      = Path("/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing")
HOLDOUT_SEEDS = {6, 7, 8}
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"


def load_holdout_csvs() -> pd.DataFrame:
    lstm_dir = BASE / "lstm_training"
    dfs = []
    for rsu_dir in sorted(lstm_dir.glob("RSU_*")):
        rsu_id = int(rsu_dir.name[4:])
        for seed in HOLDOUT_SEEDS:
            f = rsu_dir / f"A0_pct0_seed{seed}.csv"
            if not f.exists():
                continue
            df = pd.read_csv(f)
            df["attack_v"] = 0
            df["pct"] = 0
            df["seed"] = seed
            df["rsu_id"] = rsu_id
            dfs.append(df)
    if not dfs:
        raise FileNotFoundError("No seed 6/7/8 benign holdout CSVs found")
    return pd.concat(dfs, ignore_index=True)


def main():
    print("Loading seed 6/7/8 benign-holdout CSVs …")
    df = load_holdout_csvs()
    print(f"  {len(df):,} rows across {df['rsu_id'].nunique()} RSUs, "
          f"seeds={sorted(df['seed'].unique())}")

    df["is_spike"] = 0  # benign-only: no spike criterion needed, y_bin will be 0 regardless

    with open(REPO / "lstm_pipeline" / "scaler_params.json") as fh:
        scaler = json.load(fh)
    df = apply_scaler(df, scaler["mu"], scaler["std"])

    X, y_bin, _, meta = make_windows(df, WINDOW, STRIDE)
    print(f"  Windows built: {len(X):,} (all should be benign: y_bin.sum()={y_bin.sum()})")

    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    per_rsu_theta = {int(k): float(v["theta"]) for k, v in fed["per_rsu"].items()}
    global_theta = float(fed["global_theta"])

    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()

    bs = 512
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores) if scores else np.array([])

    rsu_ids = meta[:, 0].astype(int)
    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids])
    y_pred = (scores > theta_arr).astype(np.int8)

    # Q19-style dedup: collapse overlapping windows into non-overlapping 10s blocks
    block = meta[:, 4] // WINDOW
    keys = np.stack([meta[:, 0], meta[:, 1], meta[:, 2], meta[:, 3], block], axis=1)
    _, group_idx = np.unique(keys, axis=0, return_inverse=True)
    n_groups = group_idx.max() + 1
    yp_grouped = np.zeros(n_groups, dtype=np.int8)
    np.maximum.at(yp_grouped, group_idx, y_pred)

    fp_raw = int(y_pred.sum())
    fpr_raw = fp_raw / len(y_pred)
    fp_dedup = int(yp_grouped.sum())
    fpr_dedup = fp_dedup / n_groups

    print(f"\nQ30 RESULT (pure-benign held-out seeds 6/7/8, {len(X):,} raw windows / {n_groups:,} dedup blocks):")
    print(f"  Raw-window   FPR = {fp_raw}/{len(y_pred)} = {fpr_raw:.4%}")
    print(f"  Dedup-block  FPR = {fp_dedup}/{n_groups} = {fpr_dedup:.4%}")

    # Per-RSU breakdown of worst offenders, if any FPs at all
    if fp_raw > 0:
        fp_mask = y_pred == 1
        fp_rsus = pd.Series(rsu_ids[fp_mask]).value_counts()
        print("\n  Top FP-contributing RSUs (raw windows):")
        print(fp_rsus.head(10).to_string())

    out = {
        "n_windows_raw": int(len(y_pred)),
        "n_blocks_dedup": int(n_groups),
        "fp_raw": fp_raw,
        "fpr_raw": round(float(fpr_raw), 6),
        "fp_dedup": fp_dedup,
        "fpr_dedup": round(float(fpr_dedup), 6),
        "seeds": sorted(HOLDOUT_SEEDS),
    }
    out_path = REPO / "lstm_pipeline" / "q30_holdout_results.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved → {out_path}")


if __name__ == "__main__":
    main()
