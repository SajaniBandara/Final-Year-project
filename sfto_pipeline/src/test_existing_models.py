import argparse
import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    matthews_corrcoef, confusion_matrix, classification_report
)

# Ensure pipeline modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from loader import load_and_label
from features import compute_per_rule_features, aggregate_features


def evaluate_model_on_data(model_path, features_path, baseline_path, attack_path, attack_start_time=10.0):
    # Load model
    model = joblib.load(model_path)
    
    # Load selected features
    with open(features_path, 'r') as f:
        meta = json.load(f)
    selected_features = meta["selected_features"]
    
    print(f"\nEvaluating Model: {os.path.basename(model_path)}")
    print(f"  Selected Features: {selected_features}")
    
    # 1. Load + Label data
    snapshots = load_and_label(
        baseline_path=baseline_path,
        attack_path=attack_path,
        attack_start_time=attack_start_time
    )
    
    # 2. Per-rule features
    snapshots = compute_per_rule_features(snapshots)
    
    # 3. Aggregate 42 features
    feature_df = aggregate_features(snapshots)
    
    # Extract features and targets
    X = feature_df[selected_features].values
    y_true = feature_df['label'].values
    
    # Predict
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else None
    
    # Calculate metrics
    accuracy = float(accuracy_score(y_true, y_pred))
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    mcc = float(matthews_corrcoef(y_true, y_pred))
    
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    # FPR (False Positive Rate)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    # DR (Detection Rate / Recall)
    dr = recall
    
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "mcc": mcc,
        "fpr": fpr,
        "dr": dr,
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn),
        "confusion_matrix": cm.tolist()
    }
    
    report = classification_report(y_true, y_pred, labels=[0, 1], zero_division=0)
    
    return metrics, report


def main():
    # ns-3 sim output lives outside this repo (regenerated per machine/run) --
    # override with --ns3-results-dir if your routing_results folder is elsewhere.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ns3-results-dir",
        default="/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/backup",
        help="Directory containing tcam_snapshots_{baseline,attack3,attack4}.csv",
    )
    args = parser.parse_args()

    base_dir = args.ns3_results_dir
    baseline = os.path.join(base_dir, "tcam_snapshots_baseline.csv")
    attack3 = os.path.join(base_dir, "tcam_snapshots_attack3.csv")
    attack4 = os.path.join(base_dir, "tcam_snapshots_attack4.csv")

    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
    models = {
        "v4_detector": {
            "model_path": os.path.join(results_dir, "v4", "lgbm_detector.pkl"),
            "features_path": os.path.join(results_dir, "v4", "metrics.json"),
        },
        "sumo_detector": {
            "model_path": os.path.join(results_dir, "sumo", "lgbm_detector.pkl"),
            "features_path": os.path.join(results_dir, "sumo", "metrics.json"),
        },
    }

    datasets = {
        "Attack_3_Control_Plane": attack3,
        "Attack_4_Data_Plane": attack4
    }

    output_dir = os.path.join(results_dir, "routing_eval")
    os.makedirs(output_dir, exist_ok=True)
    
    results = {}
    
    for model_name, model_info in models.items():
        results[model_name] = {}
        for dataset_name, attack_path in datasets.items():
            print("\n" + "="*80)
            print(f"Testing {model_name} on {dataset_name}")
            print("="*80)
            
            try:
                metrics, report = evaluate_model_on_data(
                    model_path=model_info["model_path"],
                    features_path=model_info["features_path"],
                    baseline_path=baseline,
                    attack_path=attack_path,
                    attack_start_time=10.0
                )
                
                results[model_name][dataset_name] = {
                    "metrics": metrics,
                    "report": report
                }
                
                # Print summary of metrics
                print("\nMetrics:")
                print(f"  Accuracy : {metrics['accuracy']*100:.2f}%")
                print(f"  Precision: {metrics['precision']*100:.2f}%")
                print(f"  Recall   : {metrics['recall']*100:.2f}%")
                print(f"  F1-Score : {metrics['f1']*100:.2f}%")
                print(f"  MCC      : {metrics['mcc']:.4f}")
                print(f"  FPR      : {metrics['fpr']*100:.2f}%")
                print(f"  TP: {metrics['TP']}, FP: {metrics['FP']}, TN: {metrics['TN']}, FN: {metrics['FN']}")
                print("\nClassification Report:")
                print(report)
                
                # Save report
                report_file = os.path.join(output_dir, f"{model_name}_{dataset_name}_report.txt")
                with open(report_file, 'w') as f:
                    f.write(f"Model: {model_name}\n")
                    f.write(f"Dataset: {dataset_name}\n")
                    f.write("="*40 + "\n\n")
                    f.write(report + "\n")
                    f.write(json.dumps(metrics, indent=2))
                
            except Exception as e:
                print(f"Error testing {model_name} on {dataset_name}: {e}")
                
    # Save combined results
    with open(os.path.join(output_dir, "combined_eval_results.json"), 'w') as f:
        json.dump(results, f, indent=2)
        
    print("\nAll evaluation results saved to sfto_results_routing_eval/\n")


if __name__ == "__main__":
    main()
