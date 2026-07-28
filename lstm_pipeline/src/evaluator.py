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
            "ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing"
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"

# 5-8 match main.tex's own attack titles: Attack 5 "Active Hidden Forward
# Attack: Control Plane", Attack 6 "...: Data Plane", Attack 7 "Passive
# Hidden Forward Attack: Control Plane", Attack 8 "...: Data Plane"
# (main.tex sec:Overview of the four Hidden Forwarding Attacks, S5-S8).
ATTACK_NAMES = {
    0: "Benign",
    1: "A1 CP-SelectiveDelay",
    2: "A2 DP-SelectiveDelay",
    3: "A3 CP-TCAM",
    4: "A4 DP-TCAM",
    5: "A5 CP-ActiveHF",
    6: "A6 DP-ActiveHF",
    7: "A7 CP-PassiveHF",
    8: "A8 DP-PassiveHF",
}


# ── LSTM-based prediction ─────────────────────────────────────────────────────

def load_global_model() -> tuple:
    # weights_only=False: PyTorch >=2.6 safe loader rejects numpy scalars in
    # our own checkpoints.
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE,
                      weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    # eq:lstm_threshold/eq:lstm_detection: theta^(k) is explicitly PER-RSU
    # ("ensuring that each RSU applies a locally calibrated decision
    # boundary rather than a global threshold that would fail to account
    # for RSU-specific traffic distributions" — main.tex's own words).
    # This function used to return only the single scalar global_theta
    # (the mean across all 64 per-RSU thetas) and predict_test() applied
    # THAT ONE VALUE to every RSU's test windows — silently ignoring the
    # per-RSU calibration entirely. With per-RSU thetas ranging from ~0.7
    # to ~2200 (found 2026-07-18), that mean is dominated by whichever
    # RSUs happen to have inflated individual thetas, making the effective
    # cutoff far too conservative for every other RSU. Now returns the
    # full per-RSU dict; global_theta is kept only as the fallback for an
    # RSU id absent from fed_summary.json (e.g. skipped for <MIN_BENIGN
    # windows during training).
    per_rsu_theta = {int(k): float(v["theta"]) for k, v in fed["per_rsu"].items()}
    return model, per_rsu_theta, float(fed["global_theta"])


def predict_test(model: LSTMAutoencoder, per_rsu_theta: dict, global_theta: float) -> tuple:
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
    rsu_ids = meta[:, 0].astype(int)
    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids])
    y_pred = (scores > theta_arr).astype(np.int8)
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
    """
    Load MOBIGUARD result CSV(s) for a given attack variant and percentage.

    write_security_metrics_csv() (routing.cc) names files
    MOBIGUARD_Attack<N>_<pct>[_d<D>ms][_seed<S>].csv — never
    "MOBIGUARD_V<v>_pct<p>_*" (that pattern never matched anything, so this
    sim_metrics block was silently empty on every prior run). N here is the
    attack NUMBER (1-8), same as attack_v — ATTACK_NAMES below maps them
    1:1. glob picks up every delay/seed suffix variant.

    The file's own header is 4 lines, each prefixed with "#" (see
    write_security_metrics_csv()'s header write), so there is no valid
    single-line CSV header for pandas to parse — comment="#" strips all 4
    lines and pandas then silently promotes the first DATA row to column
    names instead. Read with header=None and pull columns by fixed
    position instead (see extract_sim_metrics()).
    """
    files = sorted(RESULTS.glob(f"MOBIGUARD_Attack{attack_v}_{pct}*.csv"))
    if not files:
        return None
    dfs = [pd.read_csv(f, comment="#", header=None) for f in files]
    return pd.concat(dfs, ignore_index=True)


# Fixed column positions in write_security_metrics_csv()'s row layout
# (routing.cc) — matches scripts/plot_fade_results.py's MOB_COL_* map.
# All 5 sit before the variant-conditional TCAM block (only present for
# A3/A4/benign, appended after avg_UCR), so these positions are stable
# across every attack variant.
SIM_COL_MAP = {
    "M4_L_mit_ms": 12,   # avg_mit_ms
    "M5_PDR":       2,   # avg_PDR
    "M6_L_e2e_ms":  4,   # avg_lat_ms
    "M7_TVR_pct":  18,   # avg_TVR
    "M8_UCR_pct":  20,   # avg_UCR
}


def extract_sim_metrics(df: pd.DataFrame) -> dict:
    out = {}
    for metric, col in SIM_COL_MAP.items():
        if col < df.shape[1]:
            out[metric] = round(float(df[col].mean()), 4)
        else:
            out[metric] = None
    return out


# ── Main ──────────────────────────────────────────────────────────────────────

def main(args):
    print(f"Loading global federated model …")
    model, per_rsu_theta, global_theta = load_global_model()
    theta_vals = list(per_rsu_theta.values())
    print(f"  Per-RSU θ: n={len(theta_vals)} min={min(theta_vals):.4f} "
          f"median={sorted(theta_vals)[len(theta_vals)//2]:.4f} max={max(theta_vals):.4f}")
    print(f"  Global θ (fallback only) = {global_theta:.6f}")

    print("Running inference on test split …")
    y_true, y_pred, scores, meta = predict_test(model, per_rsu_theta, global_theta)

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
