"""
preprocessor.py — MOBIGUARD LSTM pipeline step 1
Loads eq:lstm_input CSVs, Z-score normalises, builds sliding-window sequences.

Input  : lstm_training/RSU_*/A{v}_pct{p}_seed{s}.csv
Output : preprocessed/{split}_X.npy, {split}_y.npy, {split}_meta.npy
         scaler_params.json   (fit on benign only, applied to all)
"""

import os, json, glob, argparse
import numpy as np
import pandas as pd
from pathlib import Path

FEATURES   = ["delta_t", "lambda_PI", "U_TCAM",
              "zkp_delay_fail", "zkp_hop_fail", "rho", "v_bar"]
WINDOW     = 10      # 10-second sliding window (1 Hz cycles)
STRIDE     = 5       # 5-second stride = 50% overlap (spec §3)
TRAIN_FRAC = 0.70
VAL_FRAC   = 0.15    # test = remaining 0.15
BENIGN_V   = 0       # attack_v == 0 → benign (A0)
# Seeds partitioned by role (spec: "partitioned by seed")
TRAIN_SEEDS = {1, 2, 3}
VAL_SEEDS   = {4}
TEST_SEEDS  = {5}

BASE = Path(os.environ.get("HOME", "/home/sdvn_hidden_attacks")) / \
       "ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"
REPO = Path(__file__).resolve().parents[2]
OUT  = REPO / "lstm_pipeline" / "preprocessed"


def load_all_csvs(lstm_dir: Path) -> pd.DataFrame:
    dfs = []
    pattern = str(lstm_dir / "RSU_*" / "A*_pct*_seed*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No CSVs found at {pattern}")
    for path in files:
        p = Path(path)
        parts = p.stem.split("_")
        attack_v = int(parts[0][1:])
        pct      = int(parts[1][3:])
        seed     = int(parts[2][4:])
        rsu_id   = int(p.parent.name[4:])
        df = pd.read_csv(path)
        df["attack_v"] = attack_v
        df["pct"]      = pct
        df["seed"]     = seed
        df["rsu_id"]   = rsu_id
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def fit_scaler(df: pd.DataFrame):
    benign = df[df["attack_v"] == BENIGN_V]
    mu  = benign[FEATURES].mean().to_dict()
    std = benign[FEATURES].std().to_dict()
    # avoid zero-std for binary indicator features
    for k in std:
        if std[k] < 1e-9:
            std[k] = 1.0
    return mu, std


def apply_scaler(df: pd.DataFrame, mu: dict, std: dict) -> pd.DataFrame:
    out = df.copy()
    for f in FEATURES:
        out[f] = (out[f] - mu[f]) / std[f]
    return out


def make_windows(df: pd.DataFrame, window: int, stride: int):
    """
    Builds (N, window, n_features) sequences with stride-based overlap.
    stride=5 gives 50% overlap on a 10-cycle window (spec §3).
    Groups by (rsu_id, attack_v, pct, seed) to avoid cross-run windows.
    Meta columns: rsu_id, attack_v, pct, seed, start_cycle.
    y_binary : 0/1  (any attacker in window)
    y_multi  : 0=benign, 1-8=attack variant
    """
    X_list, yb_list, ym_list, meta_list = [], [], [], []
    groups = df.groupby(["rsu_id", "attack_v", "pct", "seed"], sort=False)
    for (rsu, av, pct, seed), grp in groups:
        grp = grp.sort_values("cycle").reset_index(drop=True)
        vals   = grp[FEATURES].values.astype(np.float32)
        labels = grp["label"].values.astype(np.int8)
        cycles = grp["cycle"].values
        for i in range(0, len(grp) - window + 1, stride):
            X_list.append(vals[i:i+window])
            yb_list.append(int(labels[i:i+window].max()))   # binary
            ym_list.append(int(av) if labels[i:i+window].max() > 0 else 0)  # multi-class
            meta_list.append((rsu, av, pct, seed, int(cycles[i])))
    if not X_list:
        return (np.empty((0, window, len(FEATURES)), dtype=np.float32),
                np.empty(0, dtype=np.int8),
                np.empty(0, dtype=np.int8),
                np.empty((0, 5), dtype=np.int32))
    return (np.stack(X_list),
            np.array(yb_list, dtype=np.int8),
            np.array(ym_list, dtype=np.int8),
            np.array(meta_list, dtype=np.int32))


def split_indices(n: int, train_frac: float, val_frac: float, seed: int = 42):
    rng  = np.random.default_rng(seed)
    idx  = rng.permutation(n)
    t    = int(n * train_frac)
    v    = int(n * (train_frac + val_frac))
    return idx[:t], idx[t:v], idx[v:]


def main(args):
    lstm_dir = BASE / "lstm_training"
    print(f"Loading CSVs from {lstm_dir} …")
    df = load_all_csvs(lstm_dir)
    print(f"  Loaded {len(df):,} rows across {df['rsu_id'].nunique()} RSUs, "
          f"{df['attack_v'].nunique()} attack variants, "
          f"{df['seed'].nunique()} seeds")

    print("Fitting Z-score scaler on benign data …")
    mu, std = fit_scaler(df)
    df = apply_scaler(df, mu, std)

    print(f"Building W={WINDOW} stride={STRIDE} sliding-window sequences …")
    X, y_bin, y_multi, meta = make_windows(df, WINDOW, STRIDE)
    print(f"  Total windows: {len(X):,}  positives: {y_bin.sum():,} ({100*y_bin.mean():.1f}%)")

    # Seed-partitioned split (spec: "partitioned by seed, stratified by variant")
    OUT.mkdir(parents=True, exist_ok=True)
    for split, seed_set in [("train", TRAIN_SEEDS), ("val", VAL_SEEDS), ("test", TEST_SEEDS)]:
        idx = np.where(np.isin(meta[:, 3], list(seed_set)))[0]
        np.save(OUT / f"{split}_X.npy",       X[idx])
        np.save(OUT / f"{split}_y.npy",       y_bin[idx])
        np.save(OUT / f"{split}_y_multi.npy", y_multi[idx])
        np.save(OUT / f"{split}_meta.npy",    meta[idx])
        pos = y_bin[idx].sum()
        print(f"  {split:5s}: {len(idx):6,} windows  pos={pos} ({100*pos/max(len(idx),1):.1f}%)"
              f"  seeds={sorted(seed_set)}")

    scaler = {"mu": mu, "std": std, "features": FEATURES, "window": WINDOW}
    with open(REPO / "lstm_pipeline" / "scaler_params.json", "w") as fh:
        json.dump(scaler, fh, indent=2)

    print(f"\nDone. Outputs → {OUT}/")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=WINDOW)
    main(ap.parse_args())
