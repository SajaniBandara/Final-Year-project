"""
SFTO-Guard Benchmark Pipeline
==============================
Reproduces SFTO-Guard (Tang et al., 2023) as an offline benchmark
against your SDVN TCAM-exhaustion simulation data.

Usage:
    python run_pipeline.py --baseline results/tcam_snapshots_baseline.csv \
                           --attack   results/tcam_snapshots_attack3.csv \
                           --attack_start_time 10 \
                           --output   sfto_results/

Steps:
    1. Load + label snapshots
    2. Compute per-rule features (CB, CP, APIT, APS, Time)
    3. Aggregate 42 statistical features per snapshot
    4. SHAP feature selection (sweep 1-10, pick best)
    5. Train LightGBM detector (their exact params)
    6. Evaluate: accuracy / precision / recall / F1
    7. Save all results + plots
"""

import argparse
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="SFTO-Guard Benchmark Pipeline")
    parser.add_argument("--baseline",          required=True,
                        help="Path to tcam_snapshots_baseline.csv")
    parser.add_argument("--attack",            required=True,
                        help="Path to tcam_snapshots_attack3.csv (or attack4)")
    parser.add_argument("--attack_start_time", type=float, default=10.0,
                        help="Sim-time (s) when attack begins (default 10)")
    parser.add_argument("--output",            default="sfto_results",
                        help="Output directory for results (default: sfto_results/)")
    parser.add_argument("--train_ratio",       type=float, default=0.75,
                        help="Train/test split ratio (paper used 3:1 = 0.75)")
    parser.add_argument("--lgbm_lr",           type=float, default=0.12)
    parser.add_argument("--lgbm_estimators",   type=int,   default=300)
    parser.add_argument("--lgbm_leaves",       type=int,   default=30)
    parser.add_argument("--lgbm_depth",        type=int,   default=6)
    parser.add_argument("--skip_shap",         action="store_true",
                        help="Skip SHAP selection and use paper's 8 features directly")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Import pipeline modules                                              #
    # ------------------------------------------------------------------ #
    from loader      import load_and_label
    from features    import compute_per_rule_features, aggregate_features
    from selection   import run_shap_selection, PAPER_TOP8
    from detector    import train_detector, evaluate_detector
    from reporting   import save_results, print_summary

    print("\n" + "="*60)
    print("  SFTO-Guard Benchmark Pipeline")
    print("="*60)

    # ------------------------------------------------------------------ #
    # 1. Load + label                                                      #
    # ------------------------------------------------------------------ #
    print("\n[1/6] Loading data...")
    snapshots = load_and_label(
        baseline_path      = args.baseline,
        attack_path        = args.attack,
        attack_start_time  = args.attack_start_time,
    )
    print(f"      Baseline snapshots : {snapshots['label'].value_counts()[0]}")
    print(f"      Attack  snapshots  : {snapshots['label'].value_counts()[1]}")

    # ------------------------------------------------------------------ #
    # 2. Per-rule features                                                 #
    # ------------------------------------------------------------------ #
    print("\n[2/6] Computing per-rule features (CB, CP, APIT, APS, Time)...")
    snapshots = compute_per_rule_features(snapshots)

    # ------------------------------------------------------------------ #
    # 3. Aggregate 42 statistical features                                 #
    # ------------------------------------------------------------------ #
    print("\n[3/6] Aggregating 42 statistical features per snapshot...")
    feature_df = aggregate_features(snapshots)
    print(f"      Feature matrix: {feature_df.shape}")

    # ------------------------------------------------------------------ #
    # 4. SHAP feature selection                                            #
    # ------------------------------------------------------------------ #
    if args.skip_shap:
        print(f"\n[4/6] Skipping SHAP — using paper's 8 features: {PAPER_TOP8}")
        selected_features = PAPER_TOP8
        shap_results = None
    else:
        print("\n[4/6] Running SHAP feature selection (sweep 1-10)...")
        selected_features, shap_results = run_shap_selection(
            feature_df,
            output_dir = args.output,
        )
        print(f"      Selected {len(selected_features)} features: {selected_features}")

    # ------------------------------------------------------------------ #
    # 5. Train detector                                                    #
    # ------------------------------------------------------------------ #
    print("\n[5/6] Training LightGBM detector (paper params)...")
    model, X_test, y_test, X_train, y_train = train_detector(
        feature_df      = feature_df,
        selected_features = selected_features,
        train_ratio     = args.train_ratio,
        lgbm_lr         = args.lgbm_lr,
        lgbm_n          = args.lgbm_estimators,
        lgbm_leaves     = args.lgbm_leaves,
        lgbm_depth      = args.lgbm_depth,
    )

    # ------------------------------------------------------------------ #
    # 6. Evaluate                                                          #
    # ------------------------------------------------------------------ #
    print("\n[6/6] Evaluating...")
    metrics = evaluate_detector(model, X_test, y_test)

    # ------------------------------------------------------------------ #
    # Save + print                                                         #
    # ------------------------------------------------------------------ #
    save_results(
        output_dir      = args.output,
        metrics         = metrics,
        model           = model,
        feature_df      = feature_df,
        selected        = selected_features,
        shap_results    = shap_results,
        X_test          = X_test,
        y_test          = y_test,
    )
    print_summary(metrics, selected_features)
    print(f"\nAll results saved to: {args.output}/\n")


if __name__ == "__main__":
    main()
