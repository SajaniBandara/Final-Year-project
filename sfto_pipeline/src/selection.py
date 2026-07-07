"""
selection.py
------------
SHAP-based feature selection, reproducing Section 4.3.1 of SFTO-Guard.

Steps:
    1. Train a LightGBM on all 42 features.
    2. Compute SHAP values → rank features by mean |SHAP|.
    3. Sweep: add features one-by-one in descending SHAP order.
       At each step (1..10 features), train + evaluate and record
       accuracy, precision, F1.
    4. Pick the number of features with the highest F1.
    5. Return the selected feature list + the sweep DataFrame.

PAPER_TOP8 is the paper's reported selection on data-center traffic.
Re-running on your SDVN data will (correctly) produce a different list.
Both are saved so you can report the comparison.
"""

import numpy as np
import pandas as pd
import lightgbm as lgb
import shap
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, f1_score
from features import get_feature_columns


# Paper's top-8 on data-center traffic (Tang et al., 2023, Fig. 9)
PAPER_TOP8 = [
    "APIT_mean",
    "TNFE",
    "APIT_IQR",
    "APIT_std",
    "APIT_skew",
    "APIT_kurt",
    "CP_median",
    "PSE",
]


def run_shap_selection(
    feature_df:  pd.DataFrame,
    output_dir:  str  = "sfto_results",
    max_sweep:   int  = 10,
    test_size:   float = 0.25,
    random_seed: int  = 42,
) -> tuple:
    """
    Run SHAP selection.

    Returns
    -------
    selected_features : list[str]   — best feature subset for your data
    shap_results      : dict        — sweep DataFrame + SHAP rankings + paper comparison
    """
    all_features = get_feature_columns(feature_df)
    X = feature_df[all_features].values
    y = feature_df["label"].values

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=random_seed, stratify=y
    )

    # ---------------------------------------------------------------- #
    # 1. Train on all 42 features to get SHAP importances              #
    # ---------------------------------------------------------------- #
    print("  Training base model on all 42 features for SHAP ranking...")
    base_model = lgb.LGBMClassifier(
        learning_rate = 0.12,
        n_estimators  = 300,
        num_leaves    = 30,
        max_depth     = 6,
        random_state  = random_seed,
        class_weight  = "balanced",   # handles class imbalance
        verbose       = -1,
    )
    base_model.fit(X_tr, y_tr)

    explainer   = shap.TreeExplainer(base_model)
    shap_values = explainer.shap_values(X_tr)

    # For binary classification, shap_values may be list of 2 arrays
    if isinstance(shap_values, list):
        sv = shap_values[1]
    else:
        sv = shap_values

    mean_abs_shap = np.abs(sv).mean(axis=0)
    shap_ranking  = pd.DataFrame({
        "feature":    all_features,
        "mean_shap":  mean_abs_shap,
    }).sort_values("mean_shap", ascending=False).reset_index(drop=True)

    print(f"\n  SHAP ranking (top 10 on YOUR data):")
    print(shap_ranking.head(10).to_string(index=False))

    # Paper's top-8 comparison
    your_top8 = shap_ranking["feature"].head(8).tolist()
    overlap   = set(your_top8) & set(PAPER_TOP8)
    print(f"\n  Paper's top-8 : {PAPER_TOP8}")
    print(f"  Your top-8    : {your_top8}")
    print(f"  Overlap       : {len(overlap)}/8 features match")

    # ---------------------------------------------------------------- #
    # 2. Sweep 1..max_sweep features                                   #
    # ---------------------------------------------------------------- #
    print(f"\n  Sweeping feature count 1..{max_sweep}...")
    ranked_features = shap_ranking["feature"].tolist()
    sweep_records   = []

    for n in range(1, min(max_sweep, len(ranked_features)) + 1):
        feats   = ranked_features[:n]
        feat_idx = [all_features.index(f) for f in feats]

        m = lgb.LGBMClassifier(
            learning_rate = 0.12,
            n_estimators  = 300,
            num_leaves    = 30,
            max_depth     = 6,
            random_state  = random_seed,
            class_weight  = "balanced",
            verbose       = -1,
        )
        m.fit(X_tr[:, feat_idx], y_tr)
        y_pred = m.predict(X_te[:, feat_idx])

        acc  = accuracy_score(y_te,  y_pred)
        prec = precision_score(y_te, y_pred, zero_division=0)
        f1   = f1_score(y_te,        y_pred, zero_division=0)
        sweep_records.append({
            "n_features": n,
            "accuracy":   acc,
            "precision":  prec,
            "f1":         f1,
            "features":   feats,
        })
        print(f"    n={n:2d}  acc={acc:.4f}  prec={prec:.4f}  f1={f1:.4f}  [{feats[-1]}]")

    sweep_df = pd.DataFrame(sweep_records)

    # Pick best F1 (paper's criterion)
    best_idx  = sweep_df["f1"].idxmax()
    best_n    = int(sweep_df.loc[best_idx, "n_features"])
    selected  = ranked_features[:best_n]
    print(f"\n  Best: {best_n} features (F1={sweep_df.loc[best_idx,'f1']:.4f})")
    print(f"  Selected: {selected}")

    # ---------------------------------------------------------------- #
    # 3. Save artefacts                                                 #
    # ---------------------------------------------------------------- #
    os.makedirs(output_dir, exist_ok=True)

    shap_ranking.to_csv(
        os.path.join(output_dir, "shap_ranking.csv"), index=False
    )
    sweep_df.drop(columns=["features"]).to_csv(
        os.path.join(output_dir, "feature_sweep.csv"), index=False
    )

    # Paper comparison table
    comparison = pd.DataFrame({
        "rank":          range(1, 9),
        "paper_feature": PAPER_TOP8,
        "your_feature":  shap_ranking["feature"].head(8).tolist(),
        "your_shap":     shap_ranking["mean_shap"].head(8).tolist(),
    })
    comparison.to_csv(
        os.path.join(output_dir, "feature_comparison_vs_paper.csv"), index=False
    )

    shap_results = {
        "ranking":    shap_ranking,
        "sweep":      sweep_df,
        "comparison": comparison,
        "best_n":     best_n,
        "your_top8":  your_top8,
        "overlap":    overlap,
    }

    return selected, shap_results
