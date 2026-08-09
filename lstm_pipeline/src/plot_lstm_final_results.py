"""
plot_lstm_final_results.py -- produces the three Federated LSTM Validation
Results figures (docs/main.tex sec:lstm_validation) directly from the
final, authoritative pipeline outputs:

  Figure_LSTM_MCC.png         <- evaluation_results.json (all 8 variants)
  Figure_LSTM_Convergence.png <- fed_summary.json's round_log
  Figure_LSTM_M8_Poisoning.png <- poison_sweep_results.json (BRFA-v2 vs FedAvg)

Replaces plot_lstm_detection_results.py, which hardcoded stale A1-A4
values (PAPER_A1_A4) instead of reading them from evaluation_results.json
like everything else now does.

Usage:
  python3 plot_lstm_final_results.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[2]
PIPE = REPO / "lstm_pipeline"
OUT  = REPO / "output" / "lstm"

ATTACK_NAMES = {
    1: "A1\nCP-SelectiveDelay", 2: "A2\nDP-SelectiveDelay",
    3: "A3\nCP-TCAM",           4: "A4\nDP-TCAM",
    5: "A5\nCP-ActiveHF",       6: "A6\nDP-ActiveHF",
    7: "A7\nCP-PassiveHF",      8: "A8\nDP-PassiveHF",
}
KEY_NAMES = {
    1: "A1 CP-SelectiveDelay", 2: "A2 DP-SelectiveDelay",
    3: "A3 CP-TCAM",           4: "A4 DP-TCAM",
    5: "A5 CP-ActiveHF",       6: "A6 DP-ActiveHF",
    7: "A7 CP-PassiveHF",      8: "A8 DP-PassiveHF",
}

BAR_COLOR = "#2a78d6"
BAR_COLOR2 = "#d6702a"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID_COLOR = "#e3e2dd"
FACE_COLOR = "#fcfcfb"


def style_axes(ax):
    ax.set_facecolor(FACE_COLOR)
    ax.grid(axis="y", color=GRID_COLOR, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ["top", "right", "left"]:
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(GRID_COLOR)
    ax.tick_params(axis="both", length=0)


def plot_mcc_bar():
    d = json.load(open(PIPE / "evaluation_results.json"))
    variants = list(range(1, 9))
    mcc_vals, dr_vals, fpr_vals = [], [], []
    for av in variants:
        r = d[KEY_NAMES[av]]
        mcc_vals.append(r["M1_MCC"])
        dr_vals.append(r["M2_DR"])
        fpr_vals.append(r["M3_FPR"])

    labels = [ATTACK_NAMES[av] for av in variants]
    fig, ax = plt.subplots(figsize=(13, 6), dpi=150)
    fig.patch.set_facecolor(FACE_COLOR)
    ax.set_facecolor(FACE_COLOR)

    x = np.arange(len(variants))
    bar_width = 0.55
    bars = ax.bar(x, mcc_vals, width=bar_width, color=BAR_COLOR, edgecolor="none", zorder=3)
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
    style_axes(ax)
    ax.tick_params(axis="x", pad=10)

    for xi, dr, fpr in zip(x, dr_vals, fpr_vals):
        ax.annotate(f"DR {dr:.0%}  ·  FPR {fpr:.1%}",
                    xy=(xi, 0), xycoords=("data", "axes fraction"),
                    xytext=(0, -38), textcoords="offset points",
                    ha="center", va="top", fontsize=8.5, color=TEXT_SECONDARY)

    fig.suptitle("Federated LSTM Detection Quality — All 8 Attack Variants",
                 fontsize=13, fontweight="bold", color=TEXT_PRIMARY, y=0.99)

    fig.tight_layout(rect=(0, 0.07, 1, 0.93))
    out_path = OUT / "Figure_LSTM_MCC.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved -> {out_path}")


def plot_convergence():
    d = json.load(open(PIPE / "fed_summary.json"))
    log = d["round_log"]
    rounds = [r["round"] for r in log]
    loss = [r["global_loss"] for r in log]

    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
    fig.patch.set_facecolor(FACE_COLOR)
    ax.set_facecolor(FACE_COLOR)

    ax.plot(rounds, loss, color=BAR_COLOR, linewidth=2.0, zorder=3)
    selected_R = d.get("selected_R")
    if selected_R is not None:
        idx = rounds.index(selected_R) if selected_R in rounds else None
        ax.axvline(selected_R, color=BAR_COLOR2, linewidth=1.2, linestyle="--", zorder=2)
        y_at_R = loss[idx] if idx is not None else min(loss)
        ax.annotate(f"Selected R={selected_R}\nloss={y_at_R:.3f}",
                    xy=(selected_R, y_at_R), xytext=(15, 15),
                    textcoords="offset points", fontsize=9, color=TEXT_SECONDARY,
                    arrowprops=dict(arrowstyle="-", color=TEXT_SECONDARY, lw=0.8))

    ax.set_xlabel("Global aggregation round", fontsize=10, color=TEXT_PRIMARY)
    ax.set_ylabel("Global validation loss (benign reconstruction error)",
                  fontsize=10, color=TEXT_PRIMARY)
    style_axes(ax)

    fig.suptitle("Federated LSTM Training Convergence (BRFA-v2)",
                 fontsize=13, fontweight="bold", color=TEXT_PRIMARY, y=0.98)
    ax.set_title(f"{rounds[0]}–{rounds[-1]} rounds, loss {loss[0]:.3f}→{loss[-1]:.3f}",
                 fontsize=9.5, color=TEXT_SECONDARY, pad=12)

    fig.tight_layout(rect=(0, 0, 1, 0.93))
    out_path = OUT / "Figure_LSTM_Convergence.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved -> {out_path}")


def plot_poisoning():
    d = json.load(open(PIPE / "poison_sweep_results.json"))
    rhos = sorted(d["brfa"].keys(), key=lambda k: float(k.split("_")[1]))
    rho_vals = [float(r.split("_")[1]) for r in rhos]
    brfa_delta = [d["brfa"][r]["delta_poison"] for r in rhos]
    fedavg_delta = [d["fedavg"][r]["delta_poison"] for r in rhos]

    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
    fig.patch.set_facecolor(FACE_COLOR)
    ax.set_facecolor(FACE_COLOR)

    x = np.arange(len(rhos))
    bar_width = 0.35
    b1 = ax.bar(x - bar_width/2, brfa_delta, width=bar_width, color=BAR_COLOR,
                edgecolor="none", zorder=3, label="BRFA-v2")
    b2 = ax.bar(x + bar_width/2, fedavg_delta, width=bar_width, color=BAR_COLOR2,
                edgecolor="none", zorder=3, label="Naive FedAvg")

    for bars in (b1, b2):
        for b in bars:
            h = b.get_height()
            ax.text(b.get_x() + b.get_width()/2, h + 0.001, f"{h:.4f}",
                    ha="center", va="bottom", fontsize=8, color=TEXT_PRIMARY)

    ax.set_xticks(x)
    ax.set_xticklabels([f"{rv:.0%}" for rv in rho_vals], fontsize=10, color=TEXT_PRIMARY)
    ax.set_xlabel("Malicious RSU fraction ($\\rho_{mal}$)", fontsize=10, color=TEXT_PRIMARY)
    ax.set_ylabel("$\\Delta_{poison}$ (MCC degradation vs. clean)", fontsize=10, color=TEXT_PRIMARY)
    style_axes(ax)
    ax.legend(frameon=False, fontsize=9.5, labelcolor=TEXT_PRIMARY, loc="upper left")

    fig.suptitle("BRFA-v2 vs. Naive FedAvg Under Sign-Flip Poisoning",
                 fontsize=13, fontweight="bold", color=TEXT_PRIMARY, y=0.98)
    ax.set_title("M8: $\\Delta_{poison}$ sweep across malicious-RSU fraction",
                 fontsize=9.5, color=TEXT_SECONDARY, pad=12)

    fig.tight_layout(rect=(0, 0, 1, 0.93))
    out_path = OUT / "Figure_LSTM_M8_Poisoning.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved -> {out_path}")

    print("\nPoisoning sweep (delta_poison, lower is better):")
    for r, rv in zip(rhos, rho_vals):
        print(f"  rho={rv:.0%}: BRFA-v2={d['brfa'][r]['delta_poison']:.4f}  "
              f"FedAvg={d['fedavg'][r]['delta_poison']:.4f}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    plot_mcc_bar()
    plot_convergence()
    plot_poisoning()


if __name__ == "__main__":
    main()
