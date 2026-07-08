"""
loader.py
---------
Loads and labels TCAM snapshot CSVs produced by your NS-3 simulation.

Schema expected (from your verified output):
    t, rsu_id, flow_id, src_ip, dst_ip, src_port, dst_port, proto,
    install_time, duration, packets, bytes, is_malicious

Per-SNAPSHOT label (for the SFTO-Guard detector):
    - Baseline CSV   → label = 0 for ALL t
    - Attack CSV     → label = 0 for t < attack_start_time
                       label = 1 for t >= attack_start_time

Per-ROW is_malicious is preserved for the mitigation model (future use).
"""

import pandas as pd
import numpy as np
import sys


REQUIRED_COLUMNS = [
    "t", "rsu_id", "flow_id",
    "src_ip", "dst_ip", "src_port", "dst_port", "proto",
    "install_time", "duration", "packets", "bytes", "is_malicious",
]


def _load_csv(path: str) -> pd.DataFrame:
    """Load a snapshot CSV with basic validation."""
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        print(f"ERROR: Missing columns in {path}: {missing}", file=sys.stderr)
        sys.exit(1)

    # Coerce numeric columns — IPs come as strings like "3.0.0.47"
    df["t"]           = pd.to_numeric(df["t"],       errors="coerce").astype(int)
    df["packets"]     = pd.to_numeric(df["packets"],  errors="coerce").fillna(0)
    df["bytes"]       = pd.to_numeric(df["bytes"],    errors="coerce").fillna(0)
    df["duration"]    = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
    df["src_port"]    = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)
    df["dst_port"]    = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    df["is_malicious"]= pd.to_numeric(df["is_malicious"], errors="coerce").fillna(0).astype(int)

    # Drop rows with NaN in critical columns
    before = len(df)
    df = df.dropna(subset=["t", "duration", "packets", "bytes"])
    dropped = before - len(df)
    if dropped > 0:
        print(f"  [loader] Dropped {dropped} malformed rows from {path}")

    return df


def load_and_label(
    baseline_path:     str,
    attack_path:       str,
    attack_start_time: float = 10.0,
) -> pd.DataFrame:
    """
    Load baseline + attack CSVs, assign per-snapshot labels, and
    return a single combined DataFrame with a 'label' column and
    a 'source' column ('baseline' | 'attack') for traceability.
    """
    print(f"  Loading baseline : {baseline_path}")
    baseline = _load_csv(baseline_path)
    baseline["label"]  = 0          # always benign
    baseline["source"] = "baseline"

    print(f"  Loading attack   : {attack_path}")
    attack = _load_csv(attack_path)
    # Per-snapshot label: 1 only after attack starts
    attack["label"]  = (attack["t"] >= attack_start_time).astype(int)
    attack["source"] = "attack"

    combined = pd.concat([baseline, attack], ignore_index=True)

    # Sanity report
    n_snap_baseline = baseline.groupby("t").ngroups
    n_snap_attack_0 = (attack[attack["label"] == 0]).groupby("t").ngroups
    n_snap_attack_1 = (attack[attack["label"] == 1]).groupby("t").ngroups

    print(f"  Baseline snapshots (label=0): {n_snap_baseline}")
    print(f"  Attack snapshots  (label=0): {n_snap_attack_0}  (pre-attack window)")
    print(f"  Attack snapshots  (label=1): {n_snap_attack_1}  (attack window)")
    print(f"  Total rows loaded          : {len(combined)}")

    return combined
