#!/usr/bin/env python3
"""
plot_ablation_results.py — grouped bar charts for every ablation collected
2026-08-30 (AB1, AB2, AB3, AB4, AB5, AB6, AB7, AB8, AB9, AB11).

Reads directly from the same sources already reported in-session:
  - ns-3 ablations (AB1/AB4/AB6/AB7/AB8/AB9/AB11): MOBIGUARD_Attack*_AB*.csv
    in results_routing/, tagged via --run_tag (see run_ablation_sweep.py /
    run_ablation_sweep2.py's docstrings for why that mechanism exists).
  - LSTM ablations (AB2/AB3/AB5): the JSON result files each script already
    writes to lstm_pipeline/.

Palette: dataviz skill's reference categorical palette, slots 1-3
(#2a78d6 blue / #eb6834 orange / #1baf7a aqua) -- validated CVD-safe for
up to 3 series at once, which covers every ablation here (max 3 configs,
AB4).

Output: output/ablations_AB/<ablation>.png, one file per ablation.
"""

import json
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO        = Path(__file__).resolve().parent.parent
RESULTS_DIR = Path.home() / "G_13/ns-allinone-3.35/ns-3.35/results_routing"
OUT_DIR     = REPO / "output" / "ablations_AB"
OUT_DIR.mkdir(parents=True, exist_ok=True)

PALETTE = ["#2a78d6", "#eb6834", "#1baf7a"]  # blue / orange / aqua

plt.rcParams.update({
    "font.size": 13,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.axisbelow": True,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def fmt_value(v: float, pct_fmt: bool) -> str:
    """Adaptive precision -- a fixed '%.2f' overflows a narrow bar's width
    for large magnitudes (e.g. mitigation latency up to ~10688ms), and two
    adjacent bars with near-identical tall values then print labels that
    visually merge into one unreadable string. Large values don't need
    decimal precision anyway."""
    if pct_fmt:
        return f"{v:.0f}%"
    if abs(v) >= 100:
        return f"{v:.0f}"
    return f"{v:.2f}"


def grouped_bar(ax, attacks, series: dict, ylabel: str, title: str, pct_fmt=False):
    """series: {config_label: [value_per_attack]}"""
    n_series = len(series)
    x = np.arange(len(attacks))
    width = 0.8 / n_series
    bars_per_series = []
    for i, (label, vals) in enumerate(series.items()):
        offset = (i - (n_series - 1) / 2) * width
        bars = ax.bar(x + offset, vals, width, label=label, color=PALETTE[i % len(PALETTE)],
                       edgecolor="white", linewidth=0.5)
        bars_per_series.append((bars, vals))

    # Collision-aware label placement: within each x-group, two (or three)
    # bars can land at near-identical heights (e.g. AB7's A3/A4, where both
    # configs' mitigation latency round to the same value) -- a flat
    # xytext=(0,2) for every label then prints them on top of each other.
    # Stagger vertically whenever a group's values sit within 4% of the
    # axis range of one another, ordered tallest-label-nearest-its-bar.
    y_max = max((v for _, vals in bars_per_series for v in vals if v is not None), default=1)
    collision_gap = 0.04 * y_max
    for gi in range(len(attacks)):
        group = [(bars[gi], vals[gi]) for bars, vals in bars_per_series if vals[gi] is not None]
        group.sort(key=lambda bv: bv[1])
        placed_heights = []
        for b, v in group:
            level = 0
            for ph in placed_heights:
                if abs(v - ph) < collision_gap:
                    level += 1
            placed_heights.append(v)
            txt = fmt_value(v, pct_fmt)
            ax.annotate(txt, (b.get_x() + b.get_width() / 2, b.get_height()),
                        xytext=(0, 2 + level * 11), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8, color="#3a3a38")

    ax.set_xticks(x)
    ax.set_xticklabels([f"A{a}" for a in attacks])
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=14, fontweight="bold", pad=28)
    # Legend ALWAYS outside/above the axes, never a "best"-guessed corner --
    # AB11's bars fill ~90% of the y-range, so every in-plot corner
    # collides with something regardless of data shape. Placing it above
    # the data (matching AB6's two-panel fix) is collision-proof by
    # construction rather than by guessing.
    ax.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=n_series)
    ax.spines[["top", "right"]].set_visible(False)
    ax.margins(y=0.15)  # headroom for stacked labels above the tallest bar


def read_last_row(csv_path: Path) -> dict | None:
    """Returns {column_name: value} for the LAST data row, keyed by the
    file's own header. MUST be name-based, not positional: TCAM attacks
    (3, 4) insert 9 extra columns after avg_UCR
    (max_tcam_util..any_s4, write_security_metrics_csv()'s conditional
    block), shifting every later column's index for those two attacks
    only. A fixed positional index is silently wrong for attack 3/4 rows
    while looking fine for every other attack -- confirmed 2026-08-30:
    ctrl_failover_max_ms sits at column 34 for attack 1 but column 43 for
    attack 3."""
    if not csv_path.exists():
        return None
    raw = csv_path.read_text().splitlines()
    header_line = next((l for l in raw if l.startswith("#")), None)
    lines = [l for l in raw if l and not l.startswith("#")]
    if not header_line or not lines:
        return None
    names = [h.strip() for h in header_line.lstrip("#").split(",")]
    vals = [float(x) for x in lines[-1].split(",")]
    return dict(zip(names, vals))


def find_csv(attack, pct, tag, delay=False, seed=1):
    suffix = "_d80ms" if delay else ""
    pat = f"MOBIGUARD_Attack{attack}_{pct}{suffix}_seed{seed}_{tag}.csv"
    p = RESULTS_DIR / pat
    return p if p.exists() else None


# ── AB1: dual-mode (rule-only vs LSTM-only) ──────────────────────────────
def plot_ab1():
    attacks = list(range(1, 9))
    mcc = {"AB1-A (rule-only)": [], "AB1-B (LSTM-only)": []}
    for a in attacks:
        for label, tag in zip(mcc, ["AB1A", "AB1B"]):
            f = find_csv(a, 60, tag, delay=(a in (1, 2)))
            row = read_last_row(f) if f else None
            mcc[label].append(row["avg_MCC"] if row else None)
    fig, ax = plt.subplots(figsize=(10, 5))
    grouped_bar(ax, attacks, mcc, "avg MCC", "AB1 — Dual-Mode Detection Architecture (M1)")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB1_dual_mode_MCC.png", dpi=150)
    plt.close(fig)


# ── AB4: STARK proof components ──────────────────────────────────────────
def plot_ab4():
    attacks = [1, 2, 5, 6, 7, 8]
    mcc = {"AB4-A (no ZKP)": [], "AB4-B (delay only)": [], "AB4-C (hop only)": []}
    for a in attacks:
        for label, tag in zip(mcc, ["AB4A", "AB4B", "AB4C"]):
            f = find_csv(a, 60, tag, delay=(a in (1, 2)))
            row = read_last_row(f) if f else None
            mcc[label].append(row["avg_MCC"] if row else None)
    fig, ax = plt.subplots(figsize=(10, 5))
    grouped_bar(ax, attacks, mcc, "avg MCC", "AB4 — Individual STARK Proof Contributions (M1)")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB4_stark_proofs_MCC.png", dpi=150)
    plt.close(fig)


# ── AB6: witness mechanism (WAP-R is the real signal, not MCC) ──────────
def plot_ab6():
    attacks = [7, 8]
    prec = {"AB6-A (off)": [], "AB6-B (on)": []}
    rec  = {"AB6-A (off)": [], "AB6-B (on)": []}
    for a in attacks:
        for label, tag in zip(prec, ["AB6A", "AB6B"]):
            f = find_csv(a, 60, tag)
            row = read_last_row(f) if f else None
            prec[label].append(row["WAP_precision"] if row else None)
            rec[label].append(row["WAP_recall"] if row else None)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    grouped_bar(axes[0], attacks, prec, "WAP precision (%)", "WAP-R Precision", pct_fmt=True)
    grouped_bar(axes[1], attacks, rec, "WAP recall (%)", "WAP-R Recall", pct_fmt=True)
    for ax in axes:
        ax.get_legend().remove()
        ax.set_ylim(0, 110)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.02))
    fig.suptitle("AB6 — Witness-Based Forwarding Verification (M12)", fontsize=15, fontweight="bold", y=1.1)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB6_witness_WAP-R.png", dpi=150)
    plt.close(fig)


# ── AB7: quarantine (MCC + mitigation latency) ───────────────────────────
def plot_ab7():
    attacks = list(range(1, 9))
    mit = {"AB7-A (off)": [], "AB7-B (on)": []}
    for a in attacks:
        for label, tag in zip(mit, ["AB7A", "AB7B"]):
            f = find_csv(a, 60, tag, delay=(a in (1, 2)))
            row = read_last_row(f) if f else None
            mit[label].append(row["avg_mit_ms"] if row else None)
    fig, ax = plt.subplots(figsize=(10, 5))
    grouped_bar(ax, attacks, mit, "avg mitigation latency (ms)",
                "AB7 — Trust Scoring & Automated Quarantine (M4)")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB7_quarantine_latency.png", dpi=150)
    plt.close(fig)


# ── AB8: endorsement (UFCR) ───────────────────────────────────────────────
def plot_ab8():
    attacks = [1, 3, 5, 7]
    ufcr = {"AB8-A (no endorsement)": [], "AB8-B (f+1 endorsement)": []}
    for a in attacks:
        for label, tag in zip(ufcr, ["AB8A", "AB8B"]):
            f = find_csv(a, 60, tag, delay=(a == 1))
            row = read_last_row(f) if f else None
            ufcr[label].append(row["UFCR"] if row else None)
    fig, ax = plt.subplots(figsize=(9, 5))
    grouped_bar(ax, attacks, ufcr, "UFCR (%)",
                "AB8 — Multi-RSU FlowMod Endorsement (M11)", pct_fmt=True)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB8_endorsement_UFCR.png", dpi=150)
    plt.close(fig)


# ── AB9: controller failover (M5 latency + M11 UFCR), pct=20 ────────────
def plot_ab9():
    attacks = [1, 3]
    fail = {"AB9-A (single ctrl)": [], "AB9-B (multi-ctrl)": []}
    for a in attacks:
        for label, tag in zip(fail, ["AB9A", "AB9B"]):
            suffix = "_d80ms" if a == 1 else ""
            f = RESULTS_DIR / f"MOBIGUARD_Attack{a}_20{suffix}_seed1_{tag}.csv"
            row = read_last_row(f) if f.exists() else None
            fail[label].append(row["ctrl_failover_max_ms"] if row else None)
    fig, ax = plt.subplots(figsize=(8, 5))
    grouped_bar(ax, attacks, fail, "controller failover latency (ms)",
                "AB9 — Multi-Controller Zero-Trust, One Compromised\nController (M5), pct=20")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB9_controller_failover.png", dpi=150)
    plt.close(fig)


# ── AB11: key rotation (UCR) -- flagged flat/no-effect in-session; plotted
# honestly rather than omitted, with the scope-gap caveat in the caption.
def plot_ab11():
    attacks = [5, 6, 7, 8]
    ucr = {"AB11-A (no rotation)": [], "AB11-B (with rotation)": []}
    for a in attacks:
        for label, tag in zip(ucr, ["AB11A", "AB11B"]):
            f = find_csv(a, 60, tag)
            row = read_last_row(f) if f else None
            ucr[label].append(row["avg_UCR"] if row else None)
    fig, ax = plt.subplots(figsize=(9, 6))
    grouped_bar(ax, attacks, ucr, "avg UCR (%)",
                "AB11 — ZKP Proving Key Rotation on RSU Revocation (M3)", pct_fmt=True)
    fig.tight_layout(rect=(0, 0.14, 1, 1))  # reserve bottom 14% for the caption below
    fig.text(0.5, 0.02,
              "No revocation event is triggered mid-run in this sweep, so the flag has\n"
              "nothing to act on here — a real AB11 result needs a forced revocation at t=0\n"
              "and UCR sampled at t={1,2,3,4,5}s after it (main.tex's actual x-variable).",
              ha="center", fontsize=9, style="italic", color="#6a6a66")
    fig.savefig(OUT_DIR / "AB11_key_rotation_UCR.png", dpi=150)
    plt.close(fig)


# ── AB2: federated vs centralised LSTM (from JSON) ───────────────────────
def plot_ab2():
    path = REPO / "lstm_pipeline" / "ab2_centralized_vs_federated_results.json"
    if not path.exists():
        return
    data = json.loads(path.read_text())
    variants = [v for v in data["AB2_A_centralized"] if v != "Benign"]
    series = {"Centralised (A)": [data["AB2_A_centralized"][v]["MCC"] for v in variants],
              "Federated (B)":   [data["AB2_B_federated"][v]["MCC"] for v in variants]}
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(variants))
    grouped_bar(ax, [v.replace("A", "") for v in variants], series, "MCC",
                "AB2 — Federated vs Centralised LSTM (M1)")
    ax.set_xticklabels(variants)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB2_federated_vs_centralized.png", dpi=150)
    plt.close(fig)


# ── AB3: ZKP-failure features (from JSON) ────────────────────────────────
def plot_ab3():
    path = REPO / "lstm_pipeline" / "ab3_feature_ablation_results.json"
    if not path.exists():
        return
    data = json.loads(path.read_text())
    key_a = next(k for k in data if k.startswith("AB3_A"))
    key_b = next(k for k in data if k.startswith("AB3_B"))
    variants = [v for v in data[key_a] if v != "Benign"]
    series = {"5-feature (A)": [data[key_a][v]["MCC"] for v in variants],
              "7-feature (B)": [data[key_b][v]["MCC"] for v in variants]}
    fig, ax = plt.subplots(figsize=(10, 5))
    grouped_bar(ax, variants, series, "MCC", "AB3 — ZKP-Failure Indicators as LSTM Features (M1)")
    ax.set_xticklabels(variants)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB3_zkp_features.png", dpi=150)
    plt.close(fig)


# ── AB5: BRFA-v2 vs FedAvg poisoning sweep (from JSON) ───────────────────
def plot_ab5():
    # Real structure (verified 2026-08-30, NOT guessed): {"brfa": {"rho_0.0":
    # {"MCC":.., "delta_poison":..}, "rho_0.1": {...}, ...}, "fedavg": {...}}
    path = REPO / "lstm_pipeline" / "poison_sweep_results.json"
    if not path.exists():
        return
    data = json.loads(path.read_text())
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for label, color in [("brfa", PALETTE[0]), ("fedavg", PALETTE[1])]:
        block = data[label]
        rhos = sorted(block, key=lambda k: float(k.split("_")[1]))
        x     = [float(k.split("_")[1]) for k in rhos]
        mcc   = [block[k]["MCC"] for k in rhos]
        delta = [block[k]["delta_poison"] for k in rhos]
        axes[0].plot(x, mcc,   marker="o", label=label.upper(), color=color, linewidth=2, markersize=7)
        axes[1].plot(x, delta, marker="o", label=label.upper(), color=color, linewidth=2, markersize=7)
    axes[1].axhline(0, color="#8a8a86", linewidth=1, linestyle="--")
    for ax, ylabel, title in [(axes[0], "MCC", "Detection Quality"),
                               (axes[1], "Δ_poison", "Poisoning Degradation\n(target ≈0 for ρ<1/3)")]:
        ax.set_xlabel("ρ_mal (fraction of malicious RSUs)")
        ax.set_ylabel(ylabel)
        ax.set_title(title, fontsize=13)
        ax.legend(frameon=False)
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle("AB5 — Byzantine-Robust Aggregation vs FedAvg under Poisoning (M8)",
                  fontsize=15, fontweight="bold")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "AB5_poisoning_sweep.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    made = []
    for name, fn in [("AB1", plot_ab1), ("AB2", plot_ab2), ("AB3", plot_ab3),
                      ("AB4", plot_ab4), ("AB5", plot_ab5), ("AB6", plot_ab6),
                      ("AB7", plot_ab7), ("AB8", plot_ab8), ("AB9", plot_ab9),
                      ("AB11", plot_ab11)]:
        try:
            fn()
            made.append(name)
        except Exception as e:
            print(f"[{name}] FAILED: {e}")
    print(f"Generated plots for: {', '.join(made)} -> {OUT_DIR}")
