"""
evaluator.py — MOBIGUARD M1–M8 metrics (§Primary Performance Metrics)

M1  MCC      Matthews Correlation Coefficient
M2  DR       Detection Rate = TPR = TP/(TP+FN)
M3  FPR      False Positive Rate = FP/(FP+TN)
M4  L_mit    Mitigation latency — from simulation CSV avg_mit column
M5  PDR      Packet Delivery Ratio — from simulation CSV avg_PDR column
M6  L_e2e    End-to-End Latency — from simulation CSV avg_lat column
M7  TVR      Threshold Violation Rate — from simulation CSV avg_TVR% column
M8  UCR      Unauthorized Copy Rate — from simulation CSV avg_UCR% column

LSTM-based metrics (M1–M3) use the federated global model to predict on
the test split; rule-based metrics (M4–M8) are read from MOBIGUARD result CSVs.
"""

import os, json, argparse
import numpy as np
import torch
import pandas as pd
from pathlib import Path
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO      = Path(__file__).resolve().parents[2]
PRE       = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
RESULTS   = Path(os.environ.get("HOME", "/home/sdvn_hidden_attacks")) / \
            "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"

ATTACK_NAMES = {
    0: "Benign",
    1: "A1 CP-SelectiveDelay",
    2: "A2 DP-SelectiveDelay",
    3: "A3 CP-TCAM",
    4: "A4 DP-TCAM",
    5: "A5 HF-BasicReplay",
    6: "A6 HF-TimestampManip",
    7: "A7 HF-MultiPath",
    8: "A8 HF-CovertRelay",
}


# ── LSTM-based prediction ─────────────────────────────────────────────────────

def load_global_model() -> tuple:
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    return model, float(fed["global_theta"])


def predict_test(model: LSTMAutoencoder, theta: float) -> tuple:
    X    = np.load(PRE / "test_X.npy")
    y    = np.load(PRE / "test_y.npy")
    meta = np.load(PRE / "test_meta.npy")
    bs   = 512
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    y_pred = (scores > theta).astype(np.int8)
    return y, y_pred, scores, meta


# ── Metric computation ────────────────────────────────────────────────────────

def compute_clf_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    mcc = matthews_corrcoef(y_true, y_pred)
    dr  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
            "M1_MCC": round(mcc, 4),
            "M2_DR":  round(dr,  4),
            "M3_FPR": round(fpr, 4)}


def load_sim_csv(attack_v: int, pct: int) -> pd.DataFrame | None:
    """Load MOBIGUARD result CSV for a given attack variant and percentage."""
    pattern = RESULTS / f"MOBIGUARD_V{attack_v}_pct{pct}_*.csv"
    files   = sorted(RESULTS.glob(f"MOBIGUARD_V{attack_v}_pct{pct}_*.csv"))
    if not files:
        return None
    dfs = [pd.read_csv(f, comment="#") for f in files]
    return pd.concat(dfs, ignore_index=True)


def extract_sim_metrics(df: pd.DataFrame) -> dict:
    out = {}
    col_map = {
        "M4_L_mit_ms": "avg_mit",
        "M5_PDR":       "avg_PDR",
        "M6_L_e2e_ms":  "avg_lat",
        "M7_TVR_pct":   "avg_TVR%",
        "M8_UCR_pct":   "avg_UCR%",
    }
    for metric, col in col_map.items():
        if col in df.columns:
            out[metric] = round(float(df[col].mean()), 4)
        else:
            out[metric] = None
    return out


# ── Main ──────────────────────────────────────────────────────────────────────

def main(args):
    print(f"Loading global federated model …")
    model, theta = load_global_model()
    print(f"  Global θ = {theta:.6f}")

    print("Running inference on test split …")
    y_true, y_pred, scores, meta = predict_test(model, theta)

    all_results = {}

    # Per-attack-variant breakdown
    attack_variants = sorted(set(meta[:, 1]))
    for av in attack_variants:
        mask = meta[:, 1] == av
        if mask.sum() == 0:
            continue
        clf = compute_clf_metrics(y_true[mask], y_pred[mask])

        # Rule-based metrics from simulation CSV (use any pct available)
        sim_metrics = {}
        for pct in [20, 40, 60, 80]:
            df = load_sim_csv(av, pct)
            if df is not None:
                sim_metrics[f"pct{pct}"] = extract_sim_metrics(df)

        result = {**clf, "sim_metrics": sim_metrics}
        all_results[ATTACK_NAMES.get(av, f"A{av}")] = result

        print(f"\n  {ATTACK_NAMES.get(av, f'A{av}'):30s}"
              f"  MCC={clf['M1_MCC']:+.3f}"
              f"  DR={clf['M2_DR']:.3f}"
              f"  FPR={clf['M3_FPR']:.3f}"
              f"  n={int(mask.sum())}")

    # Overall (all variants combined, excluding benign)
    attack_mask = (meta[:, 1] > 0) & (y_true >= 0)
    if attack_mask.sum() > 0:
        overall = compute_clf_metrics(y_true[attack_mask], y_pred[attack_mask])
        all_results["Overall (attacks 1-8)"] = overall
        print(f"\n  {'Overall (attacks 1-8)':30s}"
              f"  MCC={overall['M1_MCC']:+.3f}"
              f"  DR={overall['M2_DR']:.3f}"
              f"  FPR={overall['M3_FPR']:.3f}")

    out_path = REPO / "lstm_pipeline" / "evaluation_results.json"
    with open(out_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"\nFull results → {out_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    main(ap.parse_args())
