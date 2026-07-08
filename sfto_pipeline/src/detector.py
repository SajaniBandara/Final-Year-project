"""
detector.py
-----------
Train and evaluate the SFTO-Guard LightGBM attack detector.

Uses the exact hyperparameters from the paper (Section 4.3.2):
    learning_rate = 0.12
    n_estimators  = 300
    num_leaves    = 30
    max_depth     = 6

Metrics reported (mapped to your paper's M1-M3):
    MCC        = M1 (Matthews Correlation Coefficient)
    DR_attack4 = M2 (Detection Rate for Attack 4 DP variant)
    FPR        = M3 (False Positive Rate)
"""

import numpy as np
import pandas as pd
import lightgbm as lgb
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score, matthews_corrcoef,
)
from features import get_feature_columns


def train_detector(
    feature_df:        pd.DataFrame,
    selected_features: list,
    train_ratio:       float = 0.75,
    lgbm_lr:           float = 0.12,
    lgbm_n:            int   = 300,
    lgbm_leaves:       int   = 30,
    lgbm_depth:        int   = 6,
    random_seed:       int   = 42,
):
    """
    Train LightGBM on selected features with 3:1 train/test split.

    Returns
    -------
    model, X_test, y_test, X_train, y_train
    """
    X = feature_df[selected_features].values
    y = feature_df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size    = 1 - train_ratio,
        random_state = random_seed,
        stratify     = y,
    )

    print(f"  Train: {len(X_train)} snapshots  "
          f"(pos={y_train.sum()}, neg={(y_train==0).sum()})")
    print(f"  Test : {len(X_test)}  snapshots  "
          f"(pos={y_test.sum()},  neg={(y_test==0).sum()})")

    model = lgb.LGBMClassifier(
        learning_rate = lgbm_lr,
        n_estimators  = lgbm_n,
        num_leaves    = lgbm_leaves,
        max_depth     = lgbm_depth,
        class_weight  = "balanced",
        random_state  = random_seed,
        verbose       = -1,
    )
    model.fit(X_train, y_train)
    print("  Training complete.")

    return model, X_test, y_test, X_train, y_train


def evaluate_detector(
    model,
    X_test:  np.ndarray,
    y_test:  np.ndarray,
) -> dict:
    """
    Evaluate the trained detector.

    Metrics mapped to paper's framework:
        M1 = MCC
        M2 = DR for Attack 4 DP (= recall on attack class)
        M3 = FPR
    """
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc    = accuracy_score(y_test,   y_pred)
    prec   = precision_score(y_test,  y_pred, zero_division=0)
    rec    = recall_score(y_test,     y_pred, zero_division=0)
    f1     = f1_score(y_test,         y_pred, zero_division=0)
    auc    = roc_auc_score(y_test,    y_proba)
    mcc    = matthews_corrcoef(y_test, y_pred)
    cm     = confusion_matrix(y_test,  y_pred)
    report = classification_report(y_test, y_pred,
                                   target_names=["Normal", "Attack"],
                                   zero_division=0)

    tn, fp, fn, tp = cm.ravel()

    # M3: FPR = FP / (FP + TN)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # M2: DR for Attack 4 DP = recall = TP / (TP + FN)
    dr_attack4 = float(rec)

    metrics = {
        "accuracy":    float(acc),
        "precision":   float(prec),
        "recall":      float(rec),
        "f1":          float(f1),
        "auc":         float(auc),
        "mcc":         float(mcc),        # M1
        "fpr":         fpr,               # M3
        "dr_attack4":  dr_attack4,        # M2
        "TP": int(tp), "FP": int(fp),
        "TN": int(tn), "FN": int(fn),
        "confusion_matrix":      cm,
        "classification_report": report,
    }

    return metrics
