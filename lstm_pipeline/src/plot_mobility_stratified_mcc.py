"""
plot_mobility_stratified_mcc.py -- Mobility-stratified MCC (Eq. mcc_mobility)
per attack variant, across vehicle density (rho) and speed (v_bar) bins.

Scope: only A5-A8 (Hidden Forwarding) have live 10-feature predictions in
this pipeline run (see docs/main.tex sec:lstm_validation) -- A1-A4 are not
included since no per-window raw predictions exist for them yet.

Density/speed bins are NOT specified numerically anywhere in main.tex
(only "low/medium/high" density and "low/high" speed, "derived from the
SUMO mobility traces") -- this script derives them empirically as tertiles
(rho) / median split (v_bar) over the pooled window-mean values across all
evaluated A5-A8 test-split windows.

Usage:
  python3 plot_mobility_stratified_mcc.py
"""
import glob
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import matthews_corrcoef

from lstm_model import LSTMAutoencoder, N_FEATURES
import json

REPO = Path(__file__).resolve().parents[2]
PRE = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
BASE = Path(os.environ.get("HOME", "/home/nipuni")) / \
       "ns-allinone-3.35/ns-3.35/results_routing"
WINDOW = 10

ATTACK_NAMES = {5: "A5 CP-ActiveHF", 6: "A6 DP-ActiveHF",
                7: "A7 CP-PassiveHF", 8: "A8 DP-PassiveHF"}
MIN_CELL_N = 5   # cells with fewer windows than this are marked n/a


def load_global_model():
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    per_rsu_theta = {int(k): float(v["theta"]) for k, v in fed["per_rsu"].items()}
    return model, per_rsu_theta, float(fed["global_theta"])


def build_raw_lookup():
    """(rsu, attack_v, pct, seed, cycle) -> (rho, v_bar), read from the raw
    per-cycle CSVs (pre-Z-score), restricted to A5-A8 seed=5 (test split)."""
    lookup = {}
    pattern = str(BASE / "lstm_training" / "RSU_*" / "A[5-8]_pct*_seed5.csv")
    for path in glob.glob(pattern):
        p = Path(path)
        parts = p.stem.split("_")
        av = int(parts[0][1:]); pct = int(parts[1][3:]); seed = int(parts[2][4:])
        rsu = int(p.parent.name[4:])
        df = pd.read_csv(path)
        for row in df.itertuples():
            lookup[(rsu, av, pct, seed, int(row.cycle))] = (row.rho, row.v_bar)
    return lookup


def main():
    model, per_rsu_theta, global_theta = load_global_model()

    X = np.load(PRE / "test_X.npy")
    y = np.load(PRE / "test_y.npy")
    meta = np.load(PRE / "test_meta.npy")   # rsu, attack_v, pct, seed, start_cycle
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

    hf_mask = np.isin(meta[:, 1], [5, 6, 7, 8])
    meta_hf, y_hf, yp_hf = meta[hf_mask], y[hf_mask], y_pred[hf_mask]
    print(f"HF test windows: {len(meta_hf)}")

    lookup = build_raw_lookup()
    rho_win = np.full(len(meta_hf), np.nan)
    vbar_win = np.full(len(meta_hf), np.nan)
    for i, (rsu, av, pct, seed, start) in enumerate(meta_hf):
        vals = [lookup.get((rsu, av, pct, seed, c)) for c in range(start, start + WINDOW)]
        vals = [v for v in vals if v is not None]
        if vals:
            rho_win[i] = np.mean([v[0] for v in vals])
            vbar_win[i] = np.mean([v[1] for v in vals])

    valid = ~np.isnan(rho_win)
    print(f"Windows with matched raw mobility data: {valid.sum()}/{len(meta_hf)}")
    meta_hf, y_hf, yp_hf = meta_hf[valid], y_hf[valid], yp_hf[valid]
    rho_win, vbar_win = rho_win[valid], vbar_win[valid]

    rho_lo, rho_hi = np.percentile(rho_win, [33.33, 66.67])
    vbar_med = np.median(vbar_win)
    print(f"rho tertiles: <{rho_lo:.2f} low | {rho_lo:.2f}-{rho_hi:.2f} medium | >{rho_hi:.2f} high")
    print(f"v_bar median split: {vbar_med:.2f}")

    def rho_bin(r):
        return "low" if r < rho_lo else ("high" if r > rho_hi else "medium")

    def vbar_bin(v):
        return "low" if v <= vbar_med else "high"

    rho_bins = ["low", "medium", "high"]
    vbar_bins = ["low", "high"]
    variants = [5, 6, 7, 8]

    results = np.full((len(variants), len(rho_bins), len(vbar_bins)), np.nan)
    counts = np.zeros_like(results, dtype=int)
    for vi, av in enumerate(variants):
        vmask = meta_hf[:, 1] == av
        for ri, rb in enumerate(rho_bins):
            for si, sb in enumerate(vbar_bins):
                cmask = vmask & np.array([rho_bin(r) == rb for r in rho_win]) & \
                        np.array([vbar_bin(v) == sb for v in vbar_win])
                n = cmask.sum()
                counts[vi, ri, si] = n
                if n >= MIN_CELL_N and len(set(y_hf[cmask])) > 1:
                    results[vi, ri, si] = matthews_corrcoef(y_hf[cmask], yp_hf[cmask])

    # ---- plot: 4 small-multiple heatmaps (one per attack), rho x v_bar ----
    fig, axes = plt.subplots(1, 4, figsize=(15, 4.2), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    cmap = plt.get_cmap("Blues").copy()
    cmap.set_bad("#e3e2dd")   # n/a cells: neutral gray, distinct from any MCC value
    vmin, vmax = 0.0, 1.0

    for vi, av in enumerate(variants):
        ax = axes[vi]
        ax.set_facecolor("#fcfcfb")
        grid = np.ma.masked_invalid(results[vi].T)  # rows=v_bar(low,high), cols=rho(low,med,high)
        im = ax.imshow(grid, cmap=cmap, vmin=vmin, vmax=vmax, aspect="auto")
        for si in range(len(vbar_bins)):
            for ri in range(len(rho_bins)):
                val = results[vi, ri, si]
                n = counts[vi, ri, si]
                txt = f"{val:.2f}\n(n={n})" if not np.isnan(val) else f"n/a\n(n={n})"
                color = "white" if (not np.isnan(val) and val > 0.5) else "#333333"
                ax.text(ri, si, txt, ha="center", va="center", fontsize=8.5, color=color)
        ax.set_xticks(range(len(rho_bins))); ax.set_xticklabels(rho_bins, fontsize=9)
        ax.set_yticks(range(len(vbar_bins))); ax.set_yticklabels(vbar_bins, fontsize=9)
        ax.set_xlabel(r"density $\rho$", fontsize=9)
        if vi == 0:
            ax.set_ylabel(r"speed $\bar{v}$", fontsize=9)
        ax.set_title(ATTACK_NAMES[av], fontsize=10, fontweight="bold")
        for spine in ax.spines.values():
            spine.set_visible(False)

    fig.suptitle("Mobility-Stratified MCC — Hidden Forwarding Attacks (A5-A8)",
                 fontsize=13, fontweight="bold", y=1.04)
    fig.text(0.5, 0.98, "Held-out test split (seed=5); cells with n<5 windows marked n/a",
              ha="center", fontsize=9, color="#52514e")
    cbar = fig.colorbar(im, ax=axes, fraction=0.02, pad=0.02)
    cbar.set_label("MCC", fontsize=9)

    out_path = REPO / "lstm_pipeline" / "lstm_mobility_stratified_hf.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    print(f"Saved -> {out_path}")

    print("\nMobility-stratified MCC (rho x v_bar), HF variants:")
    for vi, av in enumerate(variants):
        for ri, rb in enumerate(rho_bins):
            for si, sb in enumerate(vbar_bins):
                val = results[vi, ri, si]
                n = counts[vi, ri, si]
                vs = f"{val:.3f}" if not np.isnan(val) else "n/a"
                print(f"  A{av} rho={rb:6s} v_bar={sb:4s}: MCC={vs}  (n={n})")


if __name__ == "__main__":
    main()
