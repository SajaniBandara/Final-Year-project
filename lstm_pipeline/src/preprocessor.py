"""
preprocessor.py — MOBIGUARD LSTM pipeline step 1
Loads eq:lstm_input CSVs, Z-score normalises, builds sliding-window sequences.

Input  : lstm_training/RSU_*/Attack{v}_{pct}[_d{X}ms]_seed{s}.csv
Output : preprocessed/{split}_X.npy, {split}_y.npy, {split}_meta.npy
         scaler_params.json   (fit on benign only, applied to all)
"""

import os, json, glob, re, argparse
import numpy as np
import pandas as pd
from pathlib import Path

# Attack1/2's optional _d<X>ms delay segment is present or absent depending
# on whether the run passed --attack_number (see routing.cc's g_delay_suffix
# gating) - match it as optional rather than assuming a fixed field count.
FNAME_RE = re.compile(r"^Attack(?P<attack_v>\d+)_(?P<pct>\d+)(?:_d\d+ms)?_seed(?P<seed>\d+)$")

FEATURES   = ["delta_t", "lambda_PI", "U_TCAM",
              "zkp_delay_fail", "zkp_hop_fail", "rho", "v_bar",
              "d_div", "a_tp", "r_anom"]
WINDOW     = 10      # 10-second sliding window (1 Hz cycles)
STRIDE     = 5       # 5-second stride = 50% overlap (spec §3)
TRAIN_FRAC = 0.70
VAL_FRAC   = 0.15    # test = remaining 0.15
BENIGN_V   = 0       # attack_v == 0 → benign (Attack0)
# Seeds partitioned by role (spec: "partitioned by seed")
TRAIN_SEEDS = {1, 2, 3}
VAL_SEEDS   = {4}
TEST_SEEDS  = {5}
# Stabilized cycle range: originally 30-87 (v_bar ramps for the first ~30s
# while SUMO traffic gets moving; attack runs were 90s, cycles 0-87). A1-A4
# were re-collected at simTime=40 (cycles 0-~37) to get real seed4/5 data —
# never reaching cycle 30 — so the 30-87 window would drop virtually all of
# it. Widened to 0-200 to cover both; the SUMO cycle-0 startup transient this
# reintroduces is handled explicitly below (dropped per-window, not via this
# range) rather than by cutting the first 30s network-wide.
# Issue 3 fix (2026-08-02): runs are now simTime=300 (~cycles 0-299), not
# 90/40 — 200 would silently truncate the last ~1/3 of every re-collected
# run. Raised with headroom; any run shorter than this is unaffected since
# make_windows() only ever sees cycles that actually exist in that run's CSV.
MIN_CYCLE  = 0
MAX_CYCLE  = 310
# Cycle-level labeling: a window is attack-positive only if it contains a
# delta_t spike above the benign p99 (attack actually firing this window),
# not merely because it came from an attacker RSU's run. See make_windows().
SPIKE_QUANTILE = 0.99
# A5-A8 (hidden forwarding) perturb no delta_t signal — the delta_t-only
# spike criterion below leaves almost all HF windows unlabeled as positive,
# so DR against this ground truth is largely blind to when the attack is
# actually active. main.tex designed zkp_delay_fail/zkp_hop_fail exactly to
# carry HF's cryptographic evidence into the LSTM (eq:lstm_input, AB3
# rationale — main.tex:4648-4676) — use them as the HF spike criterion.
HF_VARIANTS = {5, 6, 7, 8}

BASE = Path(os.environ.get("HOME", "/home/nipuni")) / \
       "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
REPO = Path(__file__).resolve().parents[2]
OUT  = REPO / "lstm_pipeline" / "preprocessed"


def load_all_csvs(lstm_dir: Path) -> pd.DataFrame:
    dfs = []
    pattern = str(lstm_dir / "RSU_*" / "Attack*_seed*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No CSVs found at {pattern}")
    for path in files:
        p = Path(path)
        m = FNAME_RE.match(p.stem)
        if not m:
            raise ValueError(f"Unrecognized lstm_training filename shape: {p.name}")
        attack_v = int(m.group("attack_v"))
        pct      = int(m.group("pct"))
        seed     = int(m.group("seed"))
        rsu_id   = int(p.parent.name[4:])
        df = pd.read_csv(path)
        df["attack_v"] = attack_v
        df["pct"]      = pct
        df["seed"]     = seed
        df["rsu_id"]   = rsu_id
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def fit_scaler(df: pd.DataFrame):
    # Issue 7 fix (2026-08-02): must fit on TRAIN_SEEDS only. Fitting on all
    # 5 seeds (including VAL_SEEDS/TEST_SEEDS) leaked their distribution into
    # the frozen mu/std applied to val/test at apply_scaler() below.
    benign = df[(df["attack_v"] == BENIGN_V) & (df["seed"].isin(TRAIN_SEEDS))]
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

    y_binary : CYCLE-LEVEL label. A window is attack-positive iff it comes from
        an attack run AND actually contains attack activity in this window
        (the pre-computed row flag 'is_spike'). Selective-delay attacks only
        perturb a small fraction of cycles, so the coarse per-run CSV 'label'
        (RSU malicious for its whole run) marks ~85-99% of dormant-attack
        windows as positive — statistically identical to benign, capping AUC
        near 0.5. Spike-aligned labels lift held-out AUC from 0.54 -> 0.93.
    y_multi  : 0=benign, 1-8=attack variant (only where y_binary==1).
    """
    X_list, yb_list, ym_list, meta_list = [], [], [], []
    groups = df.groupby(["rsu_id", "attack_v", "pct", "seed"], sort=False)
    for (rsu, av, pct, seed), grp in groups:
        grp = grp.sort_values("cycle").reset_index(drop=True)
        vals   = grp[FEATURES].values.astype(np.float32)
        spikes = grp["is_spike"].values.astype(np.int8)   # per-row attack-active flag
        cycles = grp["cycle"].values
        for i in range(0, len(grp) - window + 1, stride):
            # Drop the window starting at cycle 0: SUMO's own startup
            # transient (vehicles at spawn, not yet moving) makes rho/v_bar
            # anomalous network-wide regardless of attack_v. Diagnostic
            # 2026-07-29: this single window accounted for 86% of A5's false
            # positives and 67% of A7's, cycle-0 FPR 8-48% vs <3% for the
            # rest of the run; A1-A4 were unaffected (confirmed not a
            # general fix, only removes the startup artifact).
            if cycles[i] == 0:
                continue
            # Attack-positive only if from an attack run (av>0) and a spike is
            # present in the window (attack was actually firing here).
            win_pos = 1 if (av > 0 and spikes[i:i+window].max() > 0) else 0
            X_list.append(vals[i:i+window])
            yb_list.append(win_pos)
            ym_list.append(int(av) if win_pos else 0)
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

    n_before = len(df)
    df = df[(df["cycle"] >= MIN_CYCLE) & (df["cycle"] <= MAX_CYCLE)].reset_index(drop=True)
    print(f"  Stabilized-range filter (cycles {MIN_CYCLE}-{MAX_CYCLE}): "
          f"kept {len(df):,} / {n_before:,} rows")

    # ── Cycle-level attack-activity flag (raw features, pre-scaling) ──────────
    # Selective-delay attacks fire on only a fraction of cycles, so a per-row
    # spike flag marks WHEN the attack is actually active. Threshold = benign
    # (attack_v==0) p99 of delta_t — the same ≤1% false-rate budget used for the
    # rule-based S1/S3 thresholds. delta_t carries the per-RSU signal for the
    # attacks the LSTM can see via timing (A1/A2); A3/A4 are excluded (label
    # fix pending). A5-A8 (hidden forwarding) perturb no delta_t signal, so
    # they use zkp_delay_fail/zkp_hop_fail OR r_anom instead (see HF_VARIANTS
    # comment above) — these are still ONLY windowing/ground-truth criteria,
    # separate from the model's own input features (FEATURES above).
    #
    # r_anom added 2026-07-26, REMOVED from this criterion 2026-08-02 (Issue 1
    # fix): r_anom is also fed to the LSTM as raw input feature #10 (FEATURES
    # above), so using it to define the ground-truth window label too let the
    # model trivially recover the label from its own input for every HF
    # window — inflating A5-A8 MCC without the model learning anything about
    # weaker precursor signals. Replaced with hf_send_gt: a send-side counter
    # (crypto_layer.h g_lstm_hf_sendgt_count, logged but deliberately
    # excluded from FEATURES) that fires at attack-injection time, before any
    # detection/receive logic runs — independent of every column the model
    # actually sees. zkp_delay_fail/zkp_hop_fail stay in the OR: they are
    # genuinely independent detection-side signals, not label-definitional.
    benign_delta = df.loc[df["attack_v"] == BENIGN_V, "delta_t"]
    spike_thr = float(benign_delta.quantile(SPIKE_QUANTILE))
    delta_spike = df["delta_t"] > spike_thr
    zkp_spike   = df["attack_v"].isin(HF_VARIANTS) & (
                      (df["zkp_delay_fail"] > 0) | (df["zkp_hop_fail"] > 0)
                      | (df["hf_send_gt"] > 0))
    df["is_spike"] = (delta_spike | zkp_spike).astype(np.int8)
    n_spike_atk = int(df.loc[df["attack_v"] != BENIGN_V, "is_spike"].sum())
    n_atk_rows  = int((df["attack_v"] != BENIGN_V).sum())
    n_hf_rows   = int(df["attack_v"].isin(HF_VARIANTS).sum())
    n_hf_spike  = int(zkp_spike.sum())
    print(f"  Cycle-level spike flag: delta_t > benign p{int(SPIKE_QUANTILE*100)} "
          f"= {spike_thr*1000:.3f} ms (A1/A2/A3/A4) OR zkp_delay_fail|zkp_hop_fail "
          f"(A5-A8) → {n_spike_atk:,}/{n_atk_rows:,} "
          f"({100*n_spike_atk/max(n_atk_rows,1):.1f}%) attack rows are active")
    print(f"  HF (A5-A8) spike breakdown: {n_hf_spike:,}/{n_hf_rows:,} "
          f"({100*n_hf_spike/max(n_hf_rows,1):.1f}%) rows flagged via ZKP failure")

    print(f"Fitting Z-score scaler on benign data from TRAIN_SEEDS={sorted(TRAIN_SEEDS)} only …")
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
