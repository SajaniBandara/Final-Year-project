"""
analyze_attacker_count.py
--------------------------
Evaluates SFTO-Guard detection performance as the NUMBER OF
ATTACKER NODES varies (1, 2, 3, ... N attackers).

Each attacker independently exhausts the TCAM of nearby RSUs.

Usage:
    python3 analyze_attacker_count.py \
        --attack_files  attack_n1.csv attack_n2.csv attack_n4.csv \
        --attacker_counts 1 2 4 \
        --n_vehicles 80 \
        --model    ~/sfto_results_v3/lgbm_detector.pkl \
        --features ~/sfto_results_v3/metrics.json \
        --output   ~/sfto_results_attacker_count/ \
        --attack_start_time 10

Produces:
    attacker_count_results.csv   — MCC/DR/FPR per attacker count
    attacker_count_summary.txt   — readable summary for supervisor

NOTE: Run one NS-3 sim per attacker count BEFORE using this script.
Each sim should use a different --num_attackers value.
"""

import argparse
import json
import os
import sys
import joblib
import numpy as np
import pandas as pd
from scipy.stats import skew, kurtosis, entropy as scipy_entropy
from sklearn.metrics import (
    matthews_corrcoef, confusion_matrix,
    precision_score, recall_score, f1_score, accuracy_score,
)


# ------------------------------------------------------------------ #
# Feature computation (self-contained, mirrors features.py)           #
# ------------------------------------------------------------------ #

def _safe_cv(x):
    m = np.mean(x)
    return float(np.std(x) / m) if m != 0 else 0.0

def _safe_mad(x):
    return float(np.median(np.abs(x - np.median(x))))

def _pse(src_ports, dst_ports):
    all_ports = np.concatenate([src_ports, dst_ports])
    if len(all_ports) == 0:
        return 0.0
    _, counts = np.unique(all_ports, return_counts=True)
    probs = counts / counts.sum()
    return float(scipy_entropy(probs, base=2))

def compute_snapshot_features(group: pd.DataFrame) -> dict:
    cp   = group["packets"].values.astype(float)
    cb   = group["bytes"].values.astype(float)
    time = group["duration"].values.astype(float)
    apit = np.where(cp > 0, time / cp, time)
    aps  = np.where(cp > 0, cb / cp, 0.0)

    feat = {}
    for alias, x in [("CB", cb), ("CP", cp), ("APIT", apit),
                      ("APS", aps), ("Time", time)]:
        if len(x) == 0:
            for s in ["mean","median","std","CV","IQR","MAD","skew","kurt"]:
                feat[f"{alias}_{s}"] = 0.0
            continue
        q75, q25 = np.percentile(x, [75, 25])
        feat[f"{alias}_mean"]   = float(np.mean(x))
        feat[f"{alias}_median"] = float(np.median(x))
        feat[f"{alias}_std"]    = float(np.std(x))
        feat[f"{alias}_CV"]     = _safe_cv(x)
        feat[f"{alias}_IQR"]    = float(q75 - q25)
        feat[f"{alias}_MAD"]    = _safe_mad(x)
        feat[f"{alias}_skew"]   = float(skew(x))    if len(x) > 1 else 0.0
        feat[f"{alias}_kurt"]   = float(kurtosis(x)) if len(x) > 1 else 0.0

    feat["TNFE"] = float(len(group))
    feat["PSE"]  = _pse(group["src_port"].values, group["dst_port"].values)
    return feat


def load_and_score(csv_path, model, selected, attack_start_time):
    """Load one attack CSV and score every snapshot."""
    df = pd.read_csv(csv_path)
    df["t"]            = pd.to_numeric(df["t"],           errors="coerce").astype(int)
    df["packets"]      = pd.to_numeric(df["packets"],     errors="coerce").fillna(0)
    df["bytes"]        = pd.to_numeric(df["bytes"],       errors="coerce").fillna(0)
    df["duration"]     = pd.to_numeric(df["duration"],    errors="coerce").fillna(0)
    df["src_port"]     = pd.to_numeric(df["src_port"],    errors="coerce").fillna(0)
    df["dst_port"]     = pd.to_numeric(df["dst_port"],    errors="coerce").fillna(0)
    df["is_malicious"] = pd.to_numeric(df["is_malicious"],errors="coerce").fillna(0).astype(int)
    df = df.dropna(subset=["t", "duration", "packets", "bytes"])

    y_true, y_pred = [], []

    for t, group in df.groupby("t"):
        true_label = 1 if t >= attack_start_time else 0
        feat = compute_snapshot_features(group)
        X    = np.array([[feat[f] for f in selected]])
        pred = int(model.predict(X)[0])
        y_true.append(true_label)
        y_pred.append(pred)

    return np.array(y_true), np.array(y_pred)


# ------------------------------------------------------------------ #
# Main                                                                 #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack_files",    nargs="+", required=True,
                        help="One CSV per attacker count, in order")
    parser.add_argument("--attacker_counts", nargs="+", type=int, required=True,
                        help="Number of attackers for each CSV (same order)")
    parser.add_argument("--n_vehicles",      type=int, default=80,
                        help="Total vehicles in sim (for % calculation)")
    parser.add_argument("--model",           required=True)
    parser.add_argument("--features",        required=True)
    parser.add_argument("--output",          default="sfto_results_attacker_count")
    parser.add_argument("--attack_start_time", type=float, default=10.0)
    args = parser.parse_args()

    if len(args.attack_files) != len(args.attacker_counts):
        print("ERROR: --attack_files and --attacker_counts must have same length")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    # Load model + selected features
    model = joblib.load(args.model)
    with open(args.features) as f:
        meta = json.load(f)
    selected = meta["selected_features"]
    print(f"Model loaded. Selected features: {selected}")
    print(f"Total vehicles: {args.n_vehicles}\n")

    # Score each attacker count
    records = []
    print(f"{'Attackers':>10} {'Atk%':>8} {'MCC':>8} "
          f"{'DR%':>8} {'FPR%':>8} {'F1%':>8} "
          f"{'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5}")
    print("-" * 75)

    for csv_path, n_atk in zip(args.attack_files, args.attacker_counts):
        atk_pct = round(n_atk / args.n_vehicles * 100, 1)

        y_true, y_pred = load_and_score(
            csv_path, model, selected, args.attack_start_time
        )

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        mcc  = float(matthews_corrcoef(y_true, y_pred))
        dr   = float(recall_score(y_true,    y_pred, zero_division=0))
        fpr  = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        f1   = float(f1_score(y_true,        y_pred, zero_division=0))
        acc  = float(accuracy_score(y_true,   y_pred))

        print(f"{n_atk:>10} {atk_pct:>7.1f}% {mcc:>8.4f} "
              f"{dr*100:>7.2f}% {fpr*100:>7.2f}% {f1*100:>7.2f}% "
              f"{tp:>5} {fp:>5} {tn:>5} {fn:>5}")

        records.append({
            "n_attackers":      n_atk,
            "attacker_pct":     atk_pct,
            "MCC_M1":           round(mcc,    4),
            "DR_M2_pct":        round(dr*100, 2),
            "FPR_M3_pct":       round(fpr*100, 2),
            "F1_pct":           round(f1*100,  2),
            "Accuracy_pct":     round(acc*100, 2),
            "TP": int(tp), "FP": int(fp),
            "TN": int(tn), "FN": int(fn),
            "csv_file":         os.path.basename(csv_path),
        })

    results_df = pd.DataFrame(records)

    # Save
    out_csv = os.path.join(args.output, "attacker_count_results.csv")
    results_df.to_csv(out_csv, index=False)

    # Summary text for supervisor
    out_txt = os.path.join(args.output, "attacker_count_summary.txt")
    with open(out_txt, "w") as f:
        f.write("SFTO-Guard: Detection vs Number of Attacker Nodes\n")
        f.write("=" * 55 + "\n\n")
        f.write(f"Total vehicles in network : {args.n_vehicles}\n")
        f.write(f"Attack type               : Attack 4 — Slow TCAM Exhaustion (Data Plane)\n")
        f.write(f"Model                     : LightGBM (SFTO-Guard reproduction)\n\n")
        f.write(f"{'Attackers':>10} {'Atk%':>8} {'MCC(M1)':>10} "
                f"{'DR%(M2)':>10} {'FPR%(M3)':>10} {'F1%':>8}\n")
        f.write("-" * 60 + "\n")
        for _, row in results_df.iterrows():
            f.write(f"{int(row['n_attackers']):>10} "
                    f"{row['attacker_pct']:>7.1f}% "
                    f"{row['MCC_M1']:>10.4f} "
                    f"{row['DR_M2_pct']:>9.2f}% "
                    f"{row['FPR_M3_pct']:>9.2f}% "
                    f"{row['F1_pct']:>7.2f}%\n")
        f.write("\nNote: SFTO-Guard covers Attack 4 (Data Plane TCAM) only.\n")
        f.write("Your system (MOBI-GUARD) covers all 8 attack variants.\n")

    print(f"\nResults saved to: {out_csv}")
    print(f"Summary saved to: {out_txt}")


if __name__ == "__main__":
    main()
