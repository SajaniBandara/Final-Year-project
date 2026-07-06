"""
features.py
-----------
Step 2 + 3 of the SFTO-Guard pipeline.

Step 2 — Per-rule features (computed per row):
    CB   = bytes          (already in CSV as 'bytes')
    CP   = packets        (already in CSV as 'packets')
    Time = duration       (already in CSV as 'duration')
    APIT = Time / CP      (if CP == 0 → APIT = Time)
    APS  = CB / CP        (if CP == 0 → APS = 0)

Step 3 — Aggregate 42 statistical features per (source, t) snapshot:
    For each of {CB, CP, APIT, APS, Time}:
        mean, median, std, CV, IQR, MAD, skewness, kurtosis  → 5×8 = 40
    Plus:
        TNFE = total number of flow entries in the snapshot   → 1
        PSE  = port Shannon entropy (src+dst ports combined)  → 1
    Total: 42

Feature names follow the paper's terminology exactly so SHAP ranking
is directly comparable to Fig. 9 in SFTO-Guard.
"""

import numpy as np
import pandas as pd
from scipy.stats import skew, kurtosis
from scipy.stats import entropy as scipy_entropy


# ------------------------------------------------------------------ #
# Per-rule features                                                    #
# ------------------------------------------------------------------ #

def compute_per_rule_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add APIT and APS columns to the per-row DataFrame."""
    df = df.copy()

    cp   = df["packets"].values.astype(float)
    cb   = df["bytes"].values.astype(float)
    time = df["duration"].values.astype(float)

    # APIT: if CP == 0, set APIT = Time (new-install with no matches yet)
    apit = np.where(cp > 0, time / cp, time)

    # APS: if CP == 0, set APS = 0
    aps  = np.where(cp > 0, cb / cp, 0.0)

    df["APIT"] = apit
    df["APS"]  = aps

    return df


# ------------------------------------------------------------------ #
# Aggregate 42 features per snapshot                                  #
# ------------------------------------------------------------------ #

_STAT_NAMES = ["mean", "median", "std", "CV", "IQR", "MAD", "skew", "kurt"]
_BASE_COLS  = ["bytes", "packets", "APIT", "APS", "duration"]

# Map to paper's nomenclature
_COL_ALIAS = {
    "bytes":    "CB",
    "packets":  "CP",
    "APIT":     "APIT",
    "APS":      "APS",
    "duration": "Time",
}


def _safe_cv(x: np.ndarray) -> float:
    """Coefficient of variation; 0 if mean is zero."""
    m = np.mean(x)
    return (np.std(x) / m) if m != 0 else 0.0


def _safe_mad(x: np.ndarray) -> float:
    """Median absolute deviation."""
    return np.median(np.abs(x - np.median(x)))


def _port_shannon_entropy(src_ports: np.ndarray, dst_ports: np.ndarray) -> float:
    """
    PSE — port Shannon entropy.
    Combine src and dst port values, compute entropy over their
    frequency distribution.  Concentrated (attacker) → low PSE.
    Scattered (normal)    → high PSE.
    """
    all_ports = np.concatenate([src_ports, dst_ports])
    if len(all_ports) == 0:
        return 0.0
    _, counts = np.unique(all_ports, return_counts=True)
    probs = counts / counts.sum()
    return float(scipy_entropy(probs, base=2))


def _aggregate_one_snapshot(group: pd.DataFrame) -> dict:
    """Compute all 42 features for a single (source, t) group."""
    row = {}

    for col in _BASE_COLS:
        alias = _COL_ALIAS[col]
        x = group[col].values.astype(float)
        if len(x) == 0:
            for s in _STAT_NAMES:
                row[f"{alias}_{s}"] = 0.0
            continue

        q75, q25 = np.percentile(x, [75, 25])
        row[f"{alias}_mean"]   = np.mean(x)
        row[f"{alias}_median"] = np.median(x)
        row[f"{alias}_std"]    = np.std(x)
        row[f"{alias}_CV"]     = _safe_cv(x)
        row[f"{alias}_IQR"]    = float(q75 - q25)
        row[f"{alias}_MAD"]    = _safe_mad(x)
        row[f"{alias}_skew"]   = float(skew(x))   if len(x) > 1 else 0.0
        row[f"{alias}_kurt"]   = float(kurtosis(x)) if len(x) > 1 else 0.0

    # TNFE: total number of flow entries
    row["TNFE"] = float(len(group))

    # PSE: port Shannon entropy
    row["PSE"] = _port_shannon_entropy(
        group["src_port"].values,
        group["dst_port"].values,
    )

    return row


def aggregate_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group by (source, t) — one snapshot per second per run —
    and compute 42 aggregate features + the snapshot label.

    Returns a DataFrame with one row per snapshot, ready for
    SHAP selection and LightGBM training.
    """
    records = []

    # Group by source file AND timestamp — this is one snapshot
    for (source, t), group in df.groupby(["source", "t"]):
        feat = _aggregate_one_snapshot(group)
        feat["t"]      = t
        feat["source"] = source
        # label is the same for all rows in a snapshot (verified by loader)
        feat["label"]  = int(group["label"].iloc[0])
        records.append(feat)

    feature_df = pd.DataFrame(records).reset_index(drop=True)

    # Column order: features first, then metadata
    meta_cols    = ["t", "source", "label"]
    feature_cols = [c for c in feature_df.columns if c not in meta_cols]
    feature_df   = feature_df[feature_cols + meta_cols]

    print(f"  Aggregated {len(feature_df)} snapshots × {len(feature_cols)} features")
    print(f"  Label distribution: {feature_df['label'].value_counts().to_dict()}")

    return feature_df


def get_feature_columns(feature_df: pd.DataFrame) -> list:
    """Return the 42 feature column names (excludes t, source, label)."""
    return [c for c in feature_df.columns if c not in ["t", "source", "label"]]
