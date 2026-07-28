"""
plot_lstm_detection_results.py -- bar chart of federated LSTM detection
quality (M1 MCC, with DR/FPR annotated) across all 8 attack variants
(A1-A4 Selective Time Delay, A5-A8 Hidden Forwarding), mirroring
main.tex's tab:lstm_detection / fig:lstm_detection.

A5-A8 are computed live from the saved global model + fed_summary.json +
preprocessed held-out test split (seed=5), matching the table caption's
own "held-out test split" framing. A1-A4 use main.tex's existing
tab:lstm_detection values (no A1-A4 training data has been collected in
this pipeline run yet -- see docs/main.tex:6198-6205).

Usage:
  python3 plot_lstm_detection_results.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import torch
from sklearn.metrics import confusion_matrix, matthews_corrcoef

from lstm_model import LSTMAutoencoder, N_FEATURES

REPO = Path(__file__).resolve().parents[2]
PRE = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

ATTACK_NAMES = {
    1: "A1\nCP-SelectiveDelay", 2: "A2\nDP-SelectiveDelay",
    3: "A3\nCP-TCAM",           4: "A4\nDP-TCAM",
    5: "A5\nCP-ActiveHF",       6: "A6\nDP-ActiveHF",
    7: "A7\nCP-PassiveHF",      8: "A8\nDP-PassiveHF",
}

# main.tex:6198-6205 (tab:lstm_detection) -- A1-A4 values, held-out test split
PAPER_A1_A4 = {
    1: {"MCC": 0.720, "DR": 0.8326, "FPR": 0.0511},
    2: {"MCC": 0.893, "DR": 0.9287, "FPR": 0.0284},
    3: {"MCC": 0.259, "DR": 0.9085, "FPR": 0.5295},
    4: {"MCC": 0.434, "DR": 0.9774, "FPR": 0.4451},
}

BAR_COLOR = "#2a78d6"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID_COLOR = "#e3e2dd"


def load_global_model():
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    per_rsu_theta = {int(k): float(v["theta"]) for k, v in fed["per_rsu"].items()}
    return model, per_rsu_theta, float(fed["global_theta"])


def compute_clf_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    mcc = matthews_corrcoef(y_true, y_pred)
    dr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"MCC": mcc, "DR": dr, "FPR": fpr}


def main():
    model, per_rsu_theta, global_theta = load_global_model()

    X = np.load(PRE / "test_X.npy")
    y = np.load(PRE / "test_y.npy")
    meta = np.load(PRE / "test_meta.npy")
    bs = 512
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i + bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    rsu_ids = meta[:, 0].astype(int)
    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids])
    y_pred = (scores > theta_arr).astype(np.int8)

    results = dict(PAPER_A1_A4)
    for av in [5, 6, 7, 8]:
        mask = meta[:, 1].astype(int) == av
        results[av] = compute_clf_metrics(y[mask], y_pred[mask])

    variants = list(range(1, 9))
    labels = [ATTACK_NAMES[av] for av in variants]
    mcc_vals = [results[av]["MCC"] for av in variants]
    dr_vals = [results[av]["DR"] for av in variants]
    fpr_vals = [results[av]["FPR"] for av in variants]

    fig, ax = plt.subplots(figsize=(13, 6), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")

    x = np.arange(len(variants))
    bar_width = 0.55

    bars = ax.bar(x, mcc_vals, width=bar_width, color=BAR_COLOR,
                   edgecolor="none", zorder=3)
    for b in bars:
        b.set_capstyle("round")

    for xi, mcc in zip(x, mcc_vals):
        ax.text(xi, mcc + 0.03, f"{mcc:+.3f}", ha="center", va="bottom",
                 fontsize=10, fontweight="bold", color=TEXT_PRIMARY)

    ax.axvline(3.5, color=GRID_COLOR, linewidth=1.2, zorder=1)
    ax.text(1.5, 1.08, "Selective Time Delay", ha="center", fontsize=9.5,
             color=TEXT_SECONDARY, fontweight="bold")
    ax.text(5.5, 1.08, "Hidden Forwarding", ha="center", fontsize=9.5,
             color=TEXT_SECONDARY, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9, color=TEXT_PRIMARY)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("Matthews Correlation Coefficient (MCC)", fontsize=10, color=TEXT_PRIMARY)

    ax.grid(axis="y", color=GRID_COLOR, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ["top", "right", "left"]:
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(GRID_COLOR)
    ax.tick_params(axis="both", length=0)
    ax.tick_params(axis="x", pad=10)

    for xi, dr, fpr in zip(x, dr_vals, fpr_vals):
        ax.annotate(f"DR {dr:.0%}  ·  FPR {fpr:.1%}",
                    xy=(xi, 0), xycoords=("data", "axes fraction"),
                    xytext=(0, -38), textcoords="offset points",
                    ha="center", va="top", fontsize=8.5, color=TEXT_SECONDARY)

    fig.suptitle("Federated LSTM Detection Quality — All 8 Attack Variants",
                 fontsize=13, fontweight="bold", color=TEXT_PRIMARY, y=0.99)
    ax.set_title("Held-out test split (seed=5)  ",
                 fontsize=9.5, color=TEXT_SECONDARY, pad=14)

    fig.tight_layout(rect=(0, 0.07, 1, 0.93))
    out_path = REPO / "lstm_pipeline" / "lstm_detection_all8.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    print(f"Saved -> {out_path}")

    print("\nFederated LSTM Detection Quality (M1-M3), Held-Out Test Split")
    for av in variants:
        r = results[av]
        print(f"  A{av}: MCC={r['MCC']:+.3f} DR={r['DR']:.3f} FPR={r['FPR']:.3f}")


if __name__ == "__main__":
    main()
