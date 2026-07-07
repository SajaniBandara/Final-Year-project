"""
analyze_attack_curve.py
-----------------------
Evaluates the trained SFTO-Guard detector across varying attack
percentages — showing WHEN (at what malicious entry %) the model
can and cannot detect the attack.

This reproduces the spirit of SFTO-Guard Fig. 13/15 (detection
results over time as malicious % grows) on your SDVN data.

Usage:
    python3 analyze_attack_curve.py \
        --attack   ~/sfto_data_v2/tcam_snapshots_attack4_120s.csv \
        --model    ~/sfto_results_v3/lgbm_detector.pkl \
        --features ~/sfto_results_v3/metrics.json \
        --output   ~/sfto_results_v3/

Outputs:
    detection_curve.csv      — per-timestep: malicious%, model score, detected?
    bucket_analysis.csv      — grouped by malicious% bucket: precision/recall/F1
    early_detection_time.txt — timestep when model first correctly flags attack
"""

import argparse
import json
import os
import sys
import joblib
import numpy as np
import pandas as pd
from scipy.stats import skew, kurtosis, entropy as scipy_entropy


# ------------------------------------------------------------------ #
# Feature computation (mirrors features.py — kept self-contained)     #
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
    """Compute all 42 features for one snapshot group."""
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
        feat[f"{alias}_skew"]   = float(skew(x))   if len(x) > 1 else 0.0
        feat[f"{alias}_kurt"]   = float(kurtosis(x)) if len(x) > 1 else 0.0

    feat["TNFE"] = float(len(group))
    feat["PSE"]  = _pse(group["src_port"].values,
                        group["dst_port"].values)
    return feat


# ------------------------------------------------------------------ #
# Main                                                                 #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack",    required=True)
    parser.add_argument("--model",     required=True)
    parser.add_argument("--features",  required=True,
                        help="metrics.json — contains selected_features list")
    parser.add_argument("--output",    default="sfto_results_v3")
    parser.add_argument("--attack_start_time", type=float, default=10.0)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # ---- load model + selected features ----------------------------- #
    print(f"Loading model: {args.model}")
    model = joblib.load(args.model)

    with open(args.features) as f:
        meta = json.load(f)
    selected = meta["selected_features"]
    print(f"Selected features: {selected}")

    # ---- load attack CSV -------------------------------------------- #
    print(f"Loading attack data: {args.attack}")
    df = pd.read_csv(args.attack)
    df["t"]           = pd.to_numeric(df["t"],        errors="coerce").astype(int)
    df["packets"]     = pd.to_numeric(df["packets"],  errors="coerce").fillna(0)
    df["bytes"]       = pd.to_numeric(df["bytes"],    errors="coerce").fillna(0)
    df["duration"]    = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
    df["src_port"]    = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)
    df["dst_port"]    = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    df["is_malicious"]= pd.to_numeric(df["is_malicious"], errors="coerce").fillna(0).astype(int)
    df = df.dropna(subset=["t", "duration", "packets", "bytes"])

    # ---- per-timestep analysis -------------------------------------- #
    print("\nScoring each timestep...")
    records = []

    for t, group in df.groupby("t"):
        total_entries = len(group)
        mal_entries   = int(group["is_malicious"].sum())
        mal_pct       = mal_entries / total_entries * 100 if total_entries > 0 else 0.0

        # Ground-truth snapshot label
        true_label = 1 if t >= args.attack_start_time else 0

        # Compute features
        feat = compute_snapshot_features(group)
        X    = np.array([[feat[f] for f in selected]])

        # Model prediction
        pred_label = int(model.predict(X)[0])
        pred_proba = float(model.predict_proba(X)[0][1])

        records.append({
            "t":              t,
            "total_entries":  total_entries,
            "mal_entries":    mal_entries,
            "mal_pct":        round(mal_pct, 2),
            "true_label":     true_label,
            "pred_label":     pred_label,
            "pred_proba":     round(pred_proba, 4),
            "correct":        int(pred_label == true_label),
            "TP": int(true_label == 1 and pred_label == 1),
            "FP": int(true_label == 0 and pred_label == 1),
            "TN": int(true_label == 0 and pred_label == 0),
            "FN": int(true_label == 1 and pred_label == 0),
        })

    curve_df = pd.DataFrame(records).sort_values("t").reset_index(drop=True)

    # ---- early detection time --------------------------------------- #
    attack_rows = curve_df[curve_df["true_label"] == 1]
    first_tp    = attack_rows[attack_rows["TP"] == 1]

    if len(first_tp) > 0:
        first_detection_t   = int(first_tp.iloc[0]["t"])
        first_detection_pct = float(first_tp.iloc[0]["mal_pct"])
        detection_lag       = first_detection_t - int(args.attack_start_time)
        print(f"\n  First correct detection: t={first_detection_t}s "
              f"({detection_lag}s after attack start, "
              f"mal%={first_detection_pct:.1f}%)")
    else:
        first_detection_t   = None
        first_detection_pct = None
        detection_lag       = None
        print("\n  WARNING: Model never correctly detected the attack!")

    # ---- missed detections ------------------------------------------ #
    fn_rows = curve_df[curve_df["FN"] == 1]
    if len(fn_rows) > 0:
        print(f"  Missed detections (FN): {len(fn_rows)} timesteps")
        print(f"  Missed at mal%: "
              f"{fn_rows['mal_pct'].min():.1f}% – {fn_rows['mal_pct'].max():.1f}%")
    else:
        print("  No missed detections (FN=0 across all attack timesteps)")

    # ---- false alarms ----------------------------------------------- #
    fp_rows = curve_df[curve_df["FP"] == 1]
    if len(fp_rows) > 0:
        print(f"  False alarms (FP): {len(fp_rows)} pre-attack timesteps flagged")
    else:
        print("  No false alarms (FP=0 in pre-attack window)")

    # ---- bucket analysis -------------------------------------------- #
    print("\nBucket analysis by malicious %...")
    bins   = [0, 5, 15, 30, 50, 101]
    labels = ["0-5%", "5-15%", "15-30%", "30-50%", ">50%"]
    curve_df["mal_bucket"] = pd.cut(
        curve_df["mal_pct"], bins=bins, labels=labels, right=False
    )

    bucket_records = []
    for bucket in labels:
        sub = curve_df[curve_df["mal_bucket"] == bucket]
        if len(sub) == 0:
            continue
        tp = sub["TP"].sum()
        fp = sub["FP"].sum()
        tn = sub["TN"].sum()
        fn = sub["FN"].sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)

        bucket_records.append({
            "mal_pct_bucket": bucket,
            "n_snapshots":    len(sub),
            "TP": int(tp), "FP": int(fp),
            "TN": int(tn), "FN": int(fn),
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "f1":        round(f1,        4),
        })
        print(f"  {bucket:8s}  n={len(sub):3d}  "
              f"prec={precision:.3f}  rec={recall:.3f}  f1={f1:.3f}  "
              f"TP={tp} FP={fp} TN={tn} FN={fn}")

    bucket_df = pd.DataFrame(bucket_records)

    # ---- save outputs ----------------------------------------------- #
    curve_path  = os.path.join(args.output, "detection_curve.csv")
    bucket_path = os.path.join(args.output, "bucket_analysis.csv")
    early_path  = os.path.join(args.output, "early_detection.txt")

    curve_df.to_csv(curve_path,  index=False)
    bucket_df.to_csv(bucket_path, index=False)

    with open(early_path, "w") as f:
        f.write("SFTO-Guard Early Detection Analysis\n")
        f.write("====================================\n\n")
        f.write(f"Attack start time     : t={args.attack_start_time}s\n")
        f.write(f"First correct detection: t={first_detection_t}s\n")
        f.write(f"Detection lag         : {detection_lag}s\n")
        f.write(f"Malicious % at detection: {first_detection_pct:.1f}%\n")
        f.write(f"False alarms (pre-attack FP): {len(fp_rows)}\n")
        f.write(f"Missed detections (FN): {len(fn_rows)}\n\n")
        f.write("Interpretation for paper:\n")
        f.write(f"SFTO-Guard requires malicious entries to reach "
                f"~{first_detection_pct:.0f}% of the flow table\n")
        f.write(f"before triggering detection ({detection_lag}s lag).\n")
        f.write("Your proactive system detects at rule-installation time\n")
        f.write("with 0s lag, demonstrating the advantage of proactive\n")
        f.write("over reactive detection in SDVN environments.\n")

    # ---- print summary ---------------------------------------------- #
    print(f"\n{'='*60}")
    print("  Detection Curve Summary")
    print(f"{'='*60}")
    print(f"  Attack start        : t={args.attack_start_time}s")
    print(f"  First TP detection  : t={first_detection_t}s  "
          f"(lag={detection_lag}s, mal%={first_detection_pct:.1f}%)")
    print(f"  Total FP (pre-attack): {len(fp_rows)}")
    print(f"  Total FN (missed)    : {len(fn_rows)}")
    print(f"\n  Files saved:")
    print(f"    {curve_path}")
    print(f"    {bucket_path}")
    print(f"    {early_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
