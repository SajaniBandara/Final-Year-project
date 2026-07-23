"""
plot_lstm_results.py
=====================
Automated plotting script for the federated LSTM anomaly detector's
training/evaluation pipeline (sec:fed_lstm). Modeled on plot_fade_results.py's
style (150 dpi, project output/ convention), but each panel here reads a
different lstm_pipeline/*.json artifact rather than NS-3 result CSVs:

  - Detection quality (M1 MCC, M2 DR, M3 FPR per attack)
      <- lstm_pipeline/evaluation_results.json (evaluator.py)
  - Federated convergence (global validation loss vs round, R selection)
      <- lstm_pipeline/fed_summary.json's round_log (fed_aggregator.py)
  - M8 poisoning resistance (Delta_poison vs rho_mal, BRFA-v2 vs FedAvg)
      <- lstm_pipeline/poison_sweep_results.json (poison_sweep.py)
  - Mobility-stratified MCC (eq:mcc_mobility, rho x v_bar bins per attack)
      <- lstm_pipeline/mobility_stratified_results.json (mobility_stratified_eval.py)

All four artifacts are produced by lstm_pipeline/src/pipeline.py (+ the
standalone mobility_stratified_eval.py) — run that first if any input file
is missing.

Usage:
    python3 scripts/plot_lstm_results.py            # all 4 figures
    python3 scripts/plot_lstm_results.py --figure detection convergence
"""

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PIPELINE_DIR = os.path.join(PROJECT_DIR, "lstm_pipeline")
OUTPUT_DIR  = os.path.join(PROJECT_DIR, "output", "lstm")

ATTACK_ORDER = ["A1 CP-SelectiveDelay", "A2 DP-SelectiveDelay", "A3 CP-TCAM", "A4 DP-TCAM",
                "A5 CP-ActiveHF", "A6 DP-ActiveHF", "A7 CP-PassiveHF", "A8 DP-PassiveHF"]
ATTACK_SHORT = ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"]

INK, MUTED, ACCENT, ACCENT_2, PASS, GRID, BG = (
    "#1C232C", "#6B7686", "#0E7C86", "#C25B2E", "#2E7D4F", "#E2E5EA", "#FFFFFF")

plt.rcParams.update({
    "text.color": INK, "axes.edgecolor": GRID, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.facecolor": BG,
    "figure.facecolor": BG, "savefig.facecolor": BG,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True, "font.size": 12,
})


def _strip_spines(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def _load(name):
    path = os.path.join(PIPELINE_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"{path} not found. Run lstm_pipeline/src/pipeline.py "
            f"(and mobility_stratified_eval.py for the mobility figure) first.")
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Figure 1 — Detection quality (M1 MCC / M2 DR / M3 FPR) per attack
# ---------------------------------------------------------------------------

def plot_detection_quality():
    ev = _load("evaluation_results.json")
    mcc = [ev[a]["M1_MCC"] for a in ATTACK_ORDER]
    dr  = [ev[a]["M2_DR"] * 100 for a in ATTACK_ORDER]
    fpr = [ev[a]["M3_FPR"] * 100 for a in ATTACK_ORDER]

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6))
    x = np.arange(len(ATTACK_SHORT))

    ax = axes[0]
    bars = ax.bar(x, mcc, color=ACCENT, width=0.6)
    ax.axhline(0, color=MUTED, linewidth=1)
    ax.set_ylim(-0.1, 1.0)
    ax.set_title("M1 — Matthews Correlation Coefficient", fontsize=12, color=INK, loc="left")
    ax.set_xticks(x); ax.set_xticklabels(ATTACK_SHORT)
    for b, v in zip(bars, mcc):
        ax.text(b.get_x() + b.get_width() / 2, v + (0.03 if v >= 0 else -0.06), f"{v:.2f}",
                ha="center", fontsize=9.5, color=INK)

    ax = axes[1]
    bars = ax.bar(x, dr, color=PASS, width=0.6)
    ax.set_ylim(0, 105)
    ax.set_title("M2 — Detection Rate (%)", fontsize=12, color=INK, loc="left")
    ax.set_xticks(x); ax.set_xticklabels(ATTACK_SHORT)
    for b, v in zip(bars, dr):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}", ha="center", fontsize=9.5, color=INK)

    ax = axes[2]
    bars = ax.bar(x, fpr, color=ACCENT_2, width=0.6)
    ax.set_ylim(0, max(fpr) * 1.25)
    ax.set_title("M3 — False Positive Rate (%)", fontsize=12, color=INK, loc="left")
    ax.set_xticks(x); ax.set_xticklabels(ATTACK_SHORT)
    for b, v in zip(bars, fpr):
        ax.text(b.get_x() + b.get_width() / 2, v + 1, f"{v:.0f}", ha="center", fontsize=9.5, color=INK)

    for ax in axes:
        _strip_spines(ax)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "Figure_LSTM_DetectionQuality.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


# ---------------------------------------------------------------------------
# Figure 2 — Federated training convergence (global loss vs round)
# ---------------------------------------------------------------------------

def plot_convergence():
    fed = _load("fed_summary.json")
    rounds = [r["round"] for r in fed["round_log"]]
    losses = [r["global_loss"] for r in fed["round_log"]]
    selected_r = fed["selected_R"]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(rounds, losses, color=ACCENT, linewidth=1.8)
    ax.axvline(selected_r, color=ACCENT_2, linestyle="--", linewidth=1.4)
    ax.text(selected_r + 2, max(losses) * 0.92, f"R selected = {selected_r}",
            color=ACCENT_2, fontsize=10.5, va="top")
    ax.set_xlabel("Federated aggregation round")
    ax.set_ylabel("Global validation loss\n(mean benign reconstruction error)")
    ax.set_title("Federated Training Convergence — BRFA-v2", fontsize=13, color=INK, loc="left")
    _strip_spines(ax)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "Figure_LSTM_Convergence.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


# ---------------------------------------------------------------------------
# Figure 3 — M8 poisoning resistance: Delta_poison vs rho_mal
# ---------------------------------------------------------------------------

def plot_poisoning_resistance():
    ps = _load("poison_sweep_results.json")

    def series(mode):
        rhos = sorted(float(k.split("_")[1]) for k in ps[mode].keys())
        dp = [ps[mode][f"rho_{r}"]["delta_poison"] or 0.0 for r in rhos]
        return rhos, dp

    rho_b, dp_b = series("brfa")
    rho_f, dp_f = series("fedavg")

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(rho_b, dp_b, marker="o", color=ACCENT, linewidth=2, markersize=6, label="BRFA-v2 (proposed)")
    ax.plot(rho_f, dp_f, marker="s", color=ACCENT_2, linewidth=2, markersize=6, label="Naive FedAvg (AB5-A)")
    ax.axvspan(0, 1 / 3, color=PASS, alpha=0.07)
    ax.axvline(1 / 3, color=MUTED, linestyle=":", linewidth=1.2)
    ax.text(1 / 3 + 0.01, ax.get_ylim()[1] * 0.05, "PBFT bound f<n/3", color=MUTED, fontsize=9.5)
    ax.set_xlabel(r"Malicious RSU fraction $\rho_{mal}$")
    ax.set_ylabel(r"$\Delta_{poison}$ = MCC$_{clean}$ − MCC($\rho_{mal}$)")
    ax.set_title("M8 — Federated Model Poisoning Resistance", fontsize=13, color=INK, loc="left")
    ax.legend(frameon=False, fontsize=10.5, loc="upper left")
    _strip_spines(ax)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "Figure_LSTM_M8_Poisoning.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


# ---------------------------------------------------------------------------
# Figure 4 — Mobility-stratified MCC heatmap (eq:mcc_mobility)
# ---------------------------------------------------------------------------

def plot_mobility_heatmap():
    mob = _load("mobility_stratified_results.json")

    cells = ["rho=low,v_bar=low", "rho=low,v_bar=high", "rho=medium,v_bar=low",
             "rho=medium,v_bar=high", "rho=high,v_bar=low", "rho=high,v_bar=high"]
    cell_labels = ["low ρ\nlow v̄", "low ρ\nhigh v̄", "med ρ\nlow v̄",
                   "med ρ\nhigh v̄", "high ρ\nlow v̄", "high ρ\nhigh v̄"]

    attacks_present = [a for a in ATTACK_ORDER if a in mob["per_variant"]]
    grid = np.full((len(attacks_present), len(cells)), np.nan)
    for i, a in enumerate(attacks_present):
        for j, c in enumerate(cells):
            v = mob["per_variant"][a].get(c)
            if v is not None:
                grid[i, j] = v["MCC"]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    masked = np.ma.masked_invalid(grid)
    cmap = plt.get_cmap("YlGnBu").copy()
    cmap.set_bad(color="#F0F1F3")
    im = ax.imshow(masked, cmap=cmap, vmin=0, vmax=0.9, aspect="auto")

    ax.set_xticks(range(len(cells))); ax.set_xticklabels(cell_labels, fontsize=9.5)
    ax.set_yticks(range(len(attacks_present)))
    ax.set_yticklabels([a.split(" ")[0] for a in attacks_present], fontsize=10.5)
    ax.set_title("Mobility-Stratified MCC — eq:mcc_mobility", fontsize=13, color=INK, loc="left")

    for i in range(len(attacks_present)):
        for j in range(len(cells)):
            v = grid[i, j]
            if not np.isnan(v):
                txt_color = "white" if v > 0.55 else INK
                ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=9.5, color=txt_color)
            else:
                ax.text(j, i, "n/a", ha="center", va="center", fontsize=8.5, color=MUTED)

    cbar = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02)
    cbar.set_label("MCC", color=INK)
    cbar.outline.set_visible(False)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks(np.arange(-.5, len(cells), 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(attacks_present), 1), minor=True)
    ax.grid(which="minor", color=BG, linewidth=2)
    ax.tick_params(which="minor", bottom=False, left=False)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "Figure_LSTM_MobilityStratifiedMCC.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


PLOTS = {
    "detection":   plot_detection_quality,
    "convergence": plot_convergence,
    "poisoning":   plot_poisoning_resistance,
    "mobility":    plot_mobility_heatmap,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--figure", nargs="+", choices=list(PLOTS.keys()), default=None,
                         help="Which figure(s) to generate (default: all four).")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    figures = args.figure or list(PLOTS.keys())
    print(f"Generating {len(figures)} figure(s) -> {OUTPUT_DIR}/")
    for name in figures:
        PLOTS[name]()
    print("Done.")


if __name__ == "__main__":
    main()
