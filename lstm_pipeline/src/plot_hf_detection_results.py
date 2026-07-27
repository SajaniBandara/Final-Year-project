"""
plot_hf_detection_results.py -- bar chart of per-variant HF detection
performance (M1 MCC, with DR/FPR annotated) for the 10-feature LSTM
(eq:lstm_input + d_div/a_tp/r_anom), read from the actual saved global
model + fed_summary.json + preprocessed split, so the figure always
reflects real evaluation output, not hardcoded numbers.

Usage:
  python3 plot_hf_detection_results.py --split val    # seed=4, complete
  python3 plot_hf_detection_results.py --split test   # seed=5, complete once collection finishes
"""
import argparse
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
    5: "A5\nCP-ActiveHF",
    6: "A6\nDP-ActiveHF",
    7: "A7\nCP-PassiveHF",
    8: "A8\nDP-PassiveHF",
}

# dataviz skill categorical slot 1 (blue) -- single-series chart, one
# consistent color for all bars; validated colorblind-safe pair set.
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


def predict(model, per_rsu_theta, global_theta, split):
    X = np.load(PRE / f"{split}_X.npy")
    y = np.load(PRE / f"{split}_y.npy")
    meta = np.load(PRE / f"{split}_meta.npy")
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
    return y, y_pred, meta


def compute_clf_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    mcc = matthews_corrcoef(y_true, y_pred)
    dr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"MCC": mcc, "DR": dr, "FPR": fpr, "n": len(y_true)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["val", "test"], default="val",
                     help="val=seed4 (complete now); test=seed5 (held-out, final number)")
    ap.add_argument("--out", default=None, help="output PNG path")
    args = ap.parse_args()

    model, per_rsu_theta, global_theta = load_global_model()
    y_true, y_pred, meta = predict(model, per_rsu_theta, global_theta, args.split)

    variants = sorted(v for v in set(meta[:, 1].astype(int)) if v in ATTACK_NAMES)
    results = {}
    for av in variants:
        mask = meta[:, 1].astype(int) == av
        results[av] = compute_clf_metrics(y_true[mask], y_pred[mask])

    labels = [ATTACK_NAMES[av] for av in variants]
    mcc_vals = [results[av]["MCC"] for av in variants]
    dr_vals = [results[av]["DR"] for av in variants]
    fpr_vals = [results[av]["FPR"] for av in variants]

    split_label = {"val": "Validation split (seed=4)", "test": "Test split (seed=5, held-out)"}[args.split]

    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")

    x = np.arange(len(variants))
    bar_width = 0.5  # capped thickness, leaves air in the slot

    bars = ax.bar(x, mcc_vals, width=bar_width, color=BAR_COLOR,
                   edgecolor="none", zorder=3)
    # 4px-equivalent rounded data-end at the tip only (square at baseline)
    for b in bars:
        b.set_capstyle("round")

    # value label at the tip, in text ink (never the bar's fill color)
    for xi, mcc in zip(x, mcc_vals):
        ax.text(xi, mcc + 0.03, f"MCC {mcc:+.3f}", ha="center", va="bottom",
                 fontsize=10.5, fontweight="bold", color=TEXT_PRIMARY)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9.5, color=TEXT_PRIMARY)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Matthews Correlation Coefficient (MCC)", fontsize=10, color=TEXT_PRIMARY)

    ax.grid(axis="y", color=GRID_COLOR, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ["top", "right", "left"]:
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(GRID_COLOR)
    ax.tick_params(axis="both", length=0)
    ax.tick_params(axis="x", pad=10)

    # DR/FPR annotations: y in axes-fraction (decoupled from the data scale
    # and from the tick-label transform), well below the tick labels --
    # avoids the collision a data-coordinate placement produced.
    for xi, dr, fpr in zip(x, dr_vals, fpr_vals):
        ax.annotate(f"DR {dr:.0%}  ·  FPR {fpr:.1%}",
                    xy=(xi, 0), xycoords=("data", "axes fraction"),
                    xytext=(0, -34), textcoords="offset points",
                    ha="center", va="top", fontsize=8.5, color=TEXT_SECONDARY)

    fig.suptitle("Hidden Forwarding Detection — Federated LSTM (10-feature input)",
                 fontsize=13, fontweight="bold", color=TEXT_PRIMARY, y=0.99)
    ax.set_title(f"{split_label}  ",
                 fontsize=9.5, color=TEXT_SECONDARY, pad=14)

    fig.tight_layout(rect=(0, 0.06, 1, 0.94))
    out_path = Path(args.out) if args.out else (REPO / "lstm_pipeline" / f"hf_detection_{args.split}.png")
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    print(f"Saved -> {out_path}")

    print(f"\n{split_label}")
    for av in variants:
        r = results[av]
        print(f"  A{av}: MCC={r['MCC']:+.3f} DR={r['DR']:.3f} FPR={r['FPR']:.3f} n={r['n']}")


if __name__ == "__main__":
    main()
