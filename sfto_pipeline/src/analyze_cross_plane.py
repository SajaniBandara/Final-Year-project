"""
analyze_cross_plane.py
----------------------
Tests SFTO-Guard's trained detector (trained on Attack 4 Data-Plane)
against Attack 3 Control-Plane data — WITHOUT retraining.

This is a generalization test: does the statistical detector
transfer across attack planes?

For your paper:
  - If detection succeeds  → SFTO-Guard generalizes, note it.
  - If detection fails     → SFTO-Guard is plane-specific; your
                             system's multi-variant coverage (S1-S8)
                             is the necessary solution.

Usage:
    python3 analyze_cross_plane.py \
        --dp_attack   ~/sfto_data_v2/tcam_snapshots_attack4_120s.csv \
        --cp_attack   results_routing/tcam_snapshots_attack3_final.csv \
        --baseline    ~/sfto_data_v2/tcam_snapshots_baseline_120s.csv \
        --model       ~/sfto_results_v4/lgbm_detector.pkl \
        --features    ~/sfto_results_v4/metrics.json \
        --output      ~/sfto_results_cross_plane/ \
        --attack_start_time 10

Outputs:
    cross_plane_results.csv   — per-snapshot scores for both planes
    cross_plane_summary.txt   — clean summary for supervisor/paper
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
# Feature computation (self-contained)                                 #
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


def score_file(df, model, selected, attack_start_time, label_name):
    """Score every snapshot in a CSV. Returns records list."""
    records = []
    for t, group in df.groupby("t"):
        true_label = 1 if t >= attack_start_time else 0
        feat = compute_snapshot_features(group)
        X    = np.array([[feat[f] for f in selected]])
        pred = int(model.predict(X)[0])
        prob = float(model.predict_proba(X)[0][1])
        records.append({
            "source":      label_name,
            "t":           t,
            "true_label":  true_label,
            "pred_label":  pred,
            "pred_proba":  round(prob, 4),
            "correct":     int(pred == true_label),
        })
    return records


def compute_metrics(records):
    """Compute MCC, DR, FPR, F1 from a records list."""
    df   = pd.DataFrame(records)
    yt   = df["true_label"].values
    yp   = df["pred_label"].values
    cm   = confusion_matrix(yt, yp, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    mcc = float(matthews_corrcoef(yt, yp)) if len(np.unique(yt)) > 1 else 0.0
    dr  = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    f1  = float(f1_score(yt, yp, zero_division=0))
    acc = float(accuracy_score(yt, yp))

    return {
        "MCC_M1":   round(mcc,    4),
        "DR_M2":    round(dr*100, 2),
        "FPR_M3":   round(fpr*100, 2),
        "F1":       round(f1*100,  2),
        "Accuracy": round(acc*100, 2),
        "TP": int(tp), "FP": int(fp),
        "TN": int(tn), "FN": int(fn),
        "n_snapshots": len(df),
    }


# ------------------------------------------------------------------ #
# Main                                                                 #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dp_attack",  required=True,
                        help="Attack 4 DP CSV (what model was trained on)")
    parser.add_argument("--cp_attack",  required=True,
                        help="Attack 3 CP CSV (cross-plane generalization test)")
    parser.add_argument("--baseline",   required=True,
                        help="Baseline CSV (for FPR reference)")
    parser.add_argument("--model",      required=True)
    parser.add_argument("--features",   required=True,
                        help="metrics.json with selected_features")
    parser.add_argument("--output",     default="sfto_results_cross_plane")
    parser.add_argument("--attack_start_time", type=float, default=10.0)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # Load model
    model = joblib.load(args.model)
    with open(args.features) as f:
        meta = json.load(f)
    selected = meta["selected_features"]
    print(f"Model loaded. Features: {selected}\n")

    # Load CSVs
    print("Loading CSVs...")
    df_dp   = load_csv(args.dp_attack)
    df_cp   = load_csv(args.cp_attack)
    df_base = load_csv(args.baseline)
    print(f"  DP attack rows : {len(df_dp)}")
    print(f"  CP attack rows : {len(df_cp)}")
    print(f"  Baseline rows  : {len(df_base)}\n")

    # Score all three
    print("Scoring snapshots...")
    dp_records   = score_file(df_dp,   model, selected,
                               args.attack_start_time, "Attack4_DP")
    cp_records   = score_file(df_cp,   model, selected,
                               args.attack_start_time, "Attack3_CP")
    base_records = score_file(df_base, model, selected,
                               args.attack_start_time, "Baseline")

    # Compute metrics per plane
    dp_metrics   = compute_metrics(dp_records)
    cp_metrics   = compute_metrics(cp_records)
    base_metrics = compute_metrics(base_records)

    # Print comparison table
    print("\n" + "="*70)
    print("  SFTO-Guard Cross-Plane Generalization Results")
    print("  (Model trained on Attack 4 DP — tested on both planes)")
    print("="*70)
    header = f"  {'Condition':<25} {'MCC(M1)':>8} {'DR%(M2)':>9} {'FPR%(M3)':>9} {'F1%':>7} {'n':>5}"
    print(header)
    print("  " + "-"*62)

    rows = [
        ("Attack 4 DP (trained)",  dp_metrics),
        ("Attack 3 CP (unseen)",   cp_metrics),
        ("Baseline (no attack)",   base_metrics),
    ]
    for name, m in rows:
        print(f"  {name:<25} {m['MCC_M1']:>8.4f} "
              f"{m['DR_M2']:>8.2f}% {m['FPR_M3']:>8.2f}% "
              f"{m['F1']:>6.2f}% {m['n_snapshots']:>5}")

    print("="*70)

    # Interpret the CP result
    print("\n  Interpretation:")
    cp_dr = cp_metrics["DR_M2"]
    if cp_dr >= 90:
        verdict = ("GENERALIZES: SFTO-Guard detects CP attack "
                   f"({cp_dr:.1f}% DR). Statistical features transfer "
                   "across planes.")
        paper_note = ("SFTO-Guard's statistical detector generalizes to "
                      "the control-plane variant, suggesting the flow-table "
                      "occupancy signature is plane-agnostic. However, it "
                      "still covers only 2 of 8 attack variants and provides "
                      "no cryptographic mitigation (M4/M5/M6 unavailable).")
    elif cp_dr >= 50:
        verdict = (f"PARTIAL: SFTO-Guard detects CP attack partially "
                   f"({cp_dr:.1f}% DR). Some generalization, not reliable.")
        paper_note = ("SFTO-Guard partially detects the control-plane variant "
                      f"({cp_dr:.1f}% DR vs {dp_metrics['DR_M2']:.1f}% on its "
                      "trained DP variant), indicating that control-plane "
                      "exhaustion leaves a weaker statistical signature. "
                      "Your system's rule-based signatures S3/S4 detect both "
                      "variants by design with no generalization gap.")
    else:
        verdict = (f"FAILS: SFTO-Guard misses CP attack "
                   f"({cp_dr:.1f}% DR). Plane-specific — does not generalize.")
        paper_note = ("SFTO-Guard fails to detect the control-plane TCAM "
                      f"exhaustion variant ({cp_dr:.1f}% DR), confirming it "
                      "is structurally plane-specific. This directly motivates "
                      "your system's dual-plane coverage (Attacks 3 and 4 via "
                      "signatures S3/S4) and multi-variant architecture (S1-S8).")

    print(f"  {verdict}")

    # Save outputs
    all_records = dp_records + cp_records + base_records
    curve_df = pd.DataFrame(all_records)
    curve_df.to_csv(
        os.path.join(args.output, "cross_plane_results.csv"), index=False
    )

    summary_path = os.path.join(args.output, "cross_plane_summary.txt")
    with open(summary_path, "w") as f:
        f.write("SFTO-Guard Cross-Plane Generalization Test\n")
        f.write("="*55 + "\n\n")
        f.write("Model trained on: Attack 4 — Data Plane TCAM Exhaustion\n")
        f.write("Cross-plane test: Attack 3 — Control Plane TCAM Exhaustion\n\n")
        f.write(f"{'Condition':<28} {'MCC':>8} {'DR%':>8} "
                f"{'FPR%':>8} {'F1%':>7}\n")
        f.write("-"*60 + "\n")
        for name, m in rows:
            f.write(f"{name:<28} {m['MCC_M1']:>8.4f} "
                    f"{m['DR_M2']:>7.2f}% {m['FPR_M3']:>7.2f}% "
                    f"{m['F1']:>6.2f}%\n")
        f.write("\n\nPaper interpretation:\n")
        f.write(paper_note + "\n")

    print(f"\n  Saved: cross_plane_results.csv, cross_plane_summary.txt")
    print(f"  Output dir: {args.output}\n")


if __name__ == "__main__":
    main()
