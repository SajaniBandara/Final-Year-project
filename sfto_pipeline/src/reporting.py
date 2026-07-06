"""
reporting.py
------------
Save all results and print the comparison summary table.
Includes M1 (MCC), M3 (FPR), M2 (DR_attack4).
"""

import os
import json
import joblib
import numpy as np
import pandas as pd


def save_results(
    output_dir:   str,
    metrics:      dict,
    model,
    feature_df:   pd.DataFrame,
    selected:     list,
    shap_results: dict,
    X_test:       np.ndarray,
    y_test:       np.ndarray,
):
    os.makedirs(output_dir, exist_ok=True)

    # 1. Metrics JSON
    metrics_out = {}
    for k, v in metrics.items():
        if k in ("classification_report",):
            continue
        if isinstance(v, (float, np.floating)):
            metrics_out[k] = float(v)
        elif hasattr(v, "tolist"):
            metrics_out[k] = v.tolist()
        else:
            metrics_out[k] = v
    metrics_out["selected_features"] = selected

    with open(os.path.join(output_dir, "metrics.json"), "w") as f:
        json.dump(metrics_out, f, indent=2)

    # 2. Classification report
    with open(os.path.join(output_dir, "classification_report.txt"), "w") as f:
        f.write(metrics["classification_report"])

    # 3. Trained model
    joblib.dump(model, os.path.join(output_dir, "lgbm_detector.pkl"))

    # 4. Feature matrix
    feature_df.to_csv(
        os.path.join(output_dir, "feature_matrix.csv"), index=False
    )

    # 5. Benchmark comparison table
    _save_benchmark_table(output_dir, metrics, selected, shap_results)

    print(f"  Saved: metrics.json, classification_report.txt, "
          f"lgbm_detector.pkl, feature_matrix.csv, benchmark_table.csv")


def _save_benchmark_table(output_dir, metrics, selected, shap_results):
    row = {
        "Method":              "SFTO-Guard (reproduced)",
        "Data":                "SDVN NS-3 traces",
        "Attack_Variants":     "Attack 4 DP (TCAM Exhaustion, Data Plane)",
        # Core detection metrics
        "Accuracy (%)":        round(metrics["accuracy"]   * 100, 2),
        "Precision (%)":       round(metrics["precision"]  * 100, 2),
        "Recall (%)":          round(metrics["recall"]     * 100, 2),
        "F1 (%)":              round(metrics["f1"]         * 100, 2),
        "AUC":                 round(metrics["auc"],  4),
        # Your paper's metrics
        "MCC (M1)":            round(metrics["mcc"],  4),
        "DR_Attack4 (M2, %)":  round(metrics["dr_attack4"] * 100, 2),
        "FPR (M3, %)":         round(metrics["fpr"]  * 100, 2),
        # Confusion matrix
        "TP": metrics["TP"], "FP": metrics["FP"],
        "TN": metrics["TN"], "FN": metrics["FN"],
        # Feature info
        "N_features_selected": len(selected),
        "Selected_features":   "|".join(selected),
        # Coverage note
        "Attack_Coverage":     "1/8 variants (Attack 4 DP only)",
        "M4_Mitigation_Latency": "N/A (reactive eviction, no blockchain)",
        "M5_PDR":              "N/A (no PDR measurement in SFTO-Guard)",
        "M6_E2E_Latency":      "N/A (no latency measurement in SFTO-Guard)",
    }

    if shap_results is not None:
        row["Paper_feature_overlap"] = f"{len(shap_results['overlap'])}/8"

    df = pd.DataFrame([row])
    df.to_csv(os.path.join(output_dir, "benchmark_table.csv"), index=False)


def print_summary(metrics: dict, selected: list):
    cm = metrics["confusion_matrix"]
    print("\n" + "="*60)
    print("  SFTO-Guard Benchmark Results")
    print("="*60)
    print(f"  Accuracy   : {metrics['accuracy']   * 100:.2f}%")
    print(f"  Precision  : {metrics['precision']  * 100:.2f}%")
    print(f"  Recall     : {metrics['recall']     * 100:.2f}%")
    print(f"  F1 Score   : {metrics['f1']         * 100:.2f}%")
    print(f"  AUC-ROC    : {metrics['auc']:.4f}")
    print(f"\n  --- Your paper's metrics ---")
    print(f"  MCC  (M1)  : {metrics['mcc']:.4f}   (range -1 to +1; +1=perfect)")
    print(f"  DR   (M2)  : {metrics['dr_attack4'] * 100:.2f}%  (Attack 4 DP only)")
    print(f"  FPR  (M3)  : {metrics['fpr']  * 100:.2f}%  (false alarm rate)")
    print(f"  M4 Latency : N/A — SFTO-Guard uses reactive eviction")
    print(f"  M5 PDR     : N/A — not measured by SFTO-Guard")
    print(f"  M6 E2E Lat : N/A — not measured by SFTO-Guard")
    print(f"\n  Confusion Matrix:")
    print(f"              Pred Normal  Pred Attack")
    print(f"  True Normal    {cm[0,0]:<10}   {cm[0,1]}")
    print(f"  True Attack    {cm[1,0]:<10}   {cm[1,1]}")
    print(f"\n  Selected features ({len(selected)}):")
    for i, f in enumerate(selected, 1):
        print(f"    {i:2d}. {f}")
    print("\n" + "="*60)
    print(metrics["classification_report"])
