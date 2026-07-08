"""
analyze_heldout_rng.py
-----------------------
Tests a model trained on one simulation seed (RngRun=1) against
an independent simulation run with a different seed (RngRun=2),
WITHOUT retraining.

This is the "separate dataset for testing" validation requested
by the supervisor.

Usage:
    python3 analyze_heldout_rng.py \
        --baseline_test  ~/sfto_data_v2/tcam_snapshots_baseline_120s_rng2.csv \
        --attack_test    ~/sfto_data_v2/tcam_snapshots_attack4_120s_rng2.csv \
        --model    ~/sfto_results_v4/lgbm_detector.pkl \
        --features ~/sfto_results_v4/metrics.json \
        --output   ~/sfto_results_heldout_rng/ \
        --attack_start_time 10
"""

import argparse
import json
import os
import joblib
import numpy as np
import pandas as pd
from scipy.stats import skew, kurtosis, entropy as scipy_entropy
from sklearn.metrics import matthews_corrcoef, confusion_matrix, f1_score, accuracy_score


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


def load_csv(path):
    df = pd.read_csv(path)
    df["t"]            = pd.to_numeric(df["t"],           errors="coerce").astype(int)
    df["packets"]      = pd.to_numeric(df["packets"],     errors="coerce").fillna(0)
    df["bytes"]        = pd.to_numeric(df["bytes"],       errors="coerce").fillna(0)
    df["duration"]     = pd.to_numeric(df["duration"],    errors="coerce").fillna(0)
    df["src_port"]     = pd.to_numeric(df["src_port"],    errors="coerce").fillna(0)
    df["dst_port"]     = pd.to_numeric(df["dst_port"],    errors="coerce").fillna(0)
    df["is_malicious"] = pd.to_numeric(df["is_malicious"],errors="coerce").fillna(0).astype(int)
    return df.dropna(subset=["t", "duration", "packets", "bytes"])


def compute_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    mcc = float(matthews_corrcoef(y_true, y_pred)) if len(np.unique(y_true)) > 1 else 0.0
    dr  = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    f1  = float(f1_score(y_true, y_pred, zero_division=0))
    acc = float(accuracy_score(y_true, y_pred))
    return {
        "MCC_M1": round(mcc, 4), "DR_M2": round(dr*100, 2),
        "FPR_M3": round(fpr*100, 2), "F1": round(f1*100, 2),
        "Accuracy": round(acc*100, 2),
        "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
        "n_snapshots": len(y_true),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline_test", required=True)
    parser.add_argument("--attack_test",   required=True)
    parser.add_argument("--model",    required=True)
    parser.add_argument("--features", required=True)
    parser.add_argument("--output",   default="sfto_results_heldout_rng")
    parser.add_argument("--attack_start_time", type=float, default=10.0)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    model = joblib.load(args.model)
    with open(args.features) as f:
        meta = json.load(f)
    selected = meta["selected_features"]
    print(f"Model loaded. Features: {selected}\n")

    print("Loading held-out RNG2 data...")
    df_base_test = load_csv(args.baseline_test)
    df_atk_test  = load_csv(args.attack_test)

    X_test, y_test, records = [], [], []

    for t, group in df_base_test.groupby("t"):
        feat = compute_snapshot_features(group)
        X_test.append([feat[f] for f in selected])
        y_test.append(0)
        records.append({"source": "baseline_rng2", "t": int(t), "true_label": 0})

    for t, group in df_atk_test.groupby("t"):
        feat = compute_snapshot_features(group)
        X_test.append([feat[f] for f in selected])
        true_label = 1 if t >= args.attack_start_time else 0
        y_test.append(true_label)
        records.append({"source": "attack4_rng2", "t": int(t), "true_label": true_label})

    X_test = np.array(X_test)
    y_test = np.array(y_test)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    for i, rec in enumerate(records):
        rec["pred_label"] = int(y_pred[i])
        rec["pred_proba"] = round(float(y_proba[i]), 4)
        rec["correct"]    = int(y_pred[i] == y_test[i])

    m = compute_metrics(y_test, y_pred)

    print("\n" + "="*70)
    print("  Held-Out Seed Validation (Independent Simulation Run)")
    print("="*70)
    print(f"  Model trained on   : RngRun=1 (120s simulation)")
    print(f"  Evaluated on       : RngRun=2 (120s simulation, NEVER SEEN)")
    print(f"\n  {'Metric':<15} {'Value':>10}")
    print(f"  {'-'*27}")
    print(f"  {'MCC (M1)':<15} {m['MCC_M1']:>10.4f}")
    print(f"  {'DR (M2)':<15} {m['DR_M2']:>9.2f}%")
    print(f"  {'FPR (M3)':<15} {m['FPR_M3']:>9.2f}%")
    print(f"  {'F1':<15} {m['F1']:>9.2f}%")
    print(f"  {'Accuracy':<15} {m['Accuracy']:>9.2f}%")
    print(f"  {'n_snapshots':<15} {m['n_snapshots']:>10}")
    print(f"\n  Confusion Matrix:")
    print(f"              Pred Normal  Pred Attack")
    print(f"  True Normal    {m['TN']:<10}   {m['FP']}")
    print(f"  True Attack    {m['FN']:<10}   {m['TP']}")
    print("="*70)

    pd.DataFrame(records).to_csv(
        os.path.join(args.output, "heldout_results.csv"), index=False
    )

    with open(os.path.join(args.output, "heldout_summary.txt"), "w") as f:
        f.write("Held-Out Seed Validation\n")
        f.write("="*40 + "\n\n")
        f.write("Model trained on : RngRun=1 (120s simulation)\n")
        f.write("Evaluated on     : RngRun=2 (120s simulation, independent seed)\n\n")
        f.write(f"MCC (M1)   : {m['MCC_M1']:.4f}\n")
        f.write(f"DR  (M2)   : {m['DR_M2']:.2f}%\n")
        f.write(f"FPR (M3)   : {m['FPR_M3']:.2f}%\n")
        f.write(f"F1         : {m['F1']:.2f}%\n")
        f.write(f"Accuracy   : {m['Accuracy']:.2f}%\n")
        f.write(f"n_snapshots: {m['n_snapshots']}\n\n")
        f.write("Confusion Matrix:\n")
        f.write(f"              Pred Normal  Pred Attack\n")
        f.write(f"True Normal    {m['TN']:<10}   {m['FP']}\n")
        f.write(f"True Attack    {m['FN']:<10}   {m['TP']}\n\n")

        if m["MCC_M1"] >= 0.95:
            f.write("Interpretation: Model generalizes to an independent simulation\n")
            f.write("seed with no meaningful degradation. Detection remains near-perfect\n")
            f.write("under fixed-density conditions across multiple random instantiations.\n")
            f.write("SUMO-based density variation remains necessary to observe realistic\n")
            f.write("degradation, as fixed-density traffic patterns are structurally\n")
            f.write("similar across seeds.\n")
        else:
            f.write("Interpretation: Performance degrades on the independent seed,\n")
            f.write("indicating the model may have overfit to seed-specific patterns\n")
            f.write("in the RngRun=1 training data rather than learning a generalizable\n")
            f.write("attack signature.\n")

    print(f"\n  Saved: heldout_results.csv, heldout_summary.txt")
    print(f"  Output dir: {args.output}\n")


if __name__ == "__main__":
    main()
