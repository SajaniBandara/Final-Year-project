"""
MOBIGUARD TCAM Detection Plots
Reads MOBIGUARD_baseline.csv and MOBIGUARD_Attack3_*.csv
Produces 3 figures saved to the same directory as the CSVs.

Column map (0-indexed):
  0  cycle
  3  cur_lat_ms
  4  avg_lat_ms
  17 max_tcam_util
  18 avg_tcam_util
  19 total_lambda_fm
  20 total_lambda_pi
  21 total_malicious
  22 s3_fired_count
  23 s4_fired_count
  24 any_s3
  25 any_s4
"""

import os
import glob
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D

# ── configuration ────────────────────────────────────────────────────────────
RESULTS_DIR   = "results_routing"          # relative to ns-3 root
OUTPUT_DIR    = RESULTS_DIR                # save plots here
ATTACK_ID     = 3                          # Attack 3 = CP TCAM exhaustion
PERCENTAGES   = [20, 40, 60, 80]          # which sweep files to look for
ATTACK_START  = 10                         # seconds
TCAM_THRESH   = 0.80                       # S3 util threshold
FM_THRESH     = 10.0                       # S3 lambda_fm threshold

# colour palette (colourblind-friendly)
COL_BASE  = "#5F5E5A"   # gray   – baseline
COL_20    = "#B5D4F4"   # blue50 – 20%
COL_40    = "#378ADD"   # blue   – 40%
COL_60    = "#0C447C"   # blue80 – 60%
COL_80    = "#042C53"   # blue90 – 80%
COL_UTIL  = "#185FA5"   # blue
COL_FM    = "#BA7517"   # amber
COL_S3    = "#3B6D11"   # green
COL_TLINE = "#888780"   # gray mid

PCT_COLS  = {20: COL_20, 40: COL_40, 60: COL_60, 80: COL_80}

# ── helpers ───────────────────────────────────────────────────────────────────
def load_csv(path):
    """Load a MOBIGUARD CSV (skip # comment lines, no header)."""
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append([float(x.strip()) for x in line.split(",")])
    if not rows:
        raise ValueError(f"No data rows in {path}")
    return np.array(rows)

def col(arr, idx):
    return arr[:, idx]

def find_first(arr, condition):
    """Return first index where condition is true, or None."""
    idx = np.where(condition)[0]
    return idx[0] if len(idx) > 0 else None

def shade_s3(ax, cycles, any_s3, color=COL_S3, alpha=0.12):
    """Shade background where S3 is active."""
    in_region = False
    start = None
    for i, (c, v) in enumerate(zip(cycles, any_s3)):
        if v == 1 and not in_region:
            in_region = True
            start = c - 0.5
        elif v == 0 and in_region:
            ax.axvspan(start, c - 0.5, color=color, alpha=alpha, zorder=0)
            in_region = False
    if in_region:
        ax.axvspan(start, cycles[-1] + 0.5, color=color, alpha=alpha, zorder=0)

# ── load data ─────────────────────────────────────────────────────────────────
base_path = os.path.join(RESULTS_DIR, "MOBIGUARD_baseline.csv")
if not os.path.exists(base_path):
    raise FileNotFoundError(f"Baseline not found: {base_path}")
base = load_csv(base_path)

attacks = {}
for pct in PERCENTAGES:
    path = os.path.join(RESULTS_DIR, f"MOBIGUARD_Attack{ATTACK_ID}_{pct}.csv")
    if os.path.exists(path):
        attacks[pct] = load_csv(path)
    else:
        print(f"  [skip] {path} not found")

if not attacks:
    raise FileNotFoundError("No attack CSV files found. Run the sweep first.")

# ── figure 1: TCAM utilisation + S3 detection (one pct per sub-panel) ────────
n = len(attacks)
fig1, axes = plt.subplots(n, 1, figsize=(10, 3.2 * n), sharex=False)
if n == 1:
    axes = [axes]

for ax, (pct, atk) in zip(axes, sorted(attacks.items())):
    cycles = col(atk, 0).astype(int)
    util   = col(atk, 17) * 100          # max_tcam_util → %
    fm     = col(atk, 19)                # total_lambda_fm
    any_s3 = col(atk, 24)

    ax2 = ax.twinx()

    l1, = ax.plot(cycles, util, color=COL_UTIL, lw=2, label="TCAM util (%)")
    l2, = ax2.plot(cycles, fm,  color=COL_FM,   lw=1.5, ls="--",
                   label="FlowMod rate (FM/s)")

    ax.axhline(TCAM_THRESH * 100, color=COL_TLINE, lw=1, ls=":", zorder=1)
    ax.axvline(ATTACK_START, color="#A32D2D", lw=1, ls="--", alpha=0.6)

    shade_s3(ax, cycles, any_s3)

    det_cycle = find_first(atk, any_s3 == 1)
    sat_cycle = find_first(atk, util >= 99.9)
    if det_cycle is not None:
        ax.axvline(cycles[det_cycle], color=COL_S3, lw=1.5, ls="-.", alpha=0.9)
        ax.text(cycles[det_cycle] + 0.3, 85,
                f"S3 fires\n(cycle {cycles[det_cycle]})",
                fontsize=8, color=COL_S3, va="bottom")

    ax.set_ylabel("TCAM utilisation (%)", color=COL_UTIL, fontsize=10)
    ax2.set_ylabel("FlowMod rate (FM/s)", color=COL_FM,   fontsize=10)
    ax.set_xlabel("Simulation cycle (s)", fontsize=10)
    ax.set_title(f"Attack 3 (CP TCAM) — {pct}% attacker ratio", fontsize=11)
    ax.set_ylim(0, 115)
    ax.set_xlim(cycles[0] - 0.5, cycles[-1] + 0.5)
    ax.tick_params(axis="y", labelcolor=COL_UTIL)
    ax2.tick_params(axis="y", labelcolor=COL_FM)
    ax.grid(axis="y", alpha=0.25, lw=0.5)

    legend_elems = [
        l1, l2,
        Line2D([0],[0], color=COL_TLINE, lw=1, ls=":", label="80% threshold"),
        Line2D([0],[0], color="#A32D2D",  lw=1, ls="--", alpha=0.6,
               label=f"Attack start (t={ATTACK_START}s)"),
        mpatches.Patch(color=COL_S3, alpha=0.25, label="S3 active"),
    ]
    ax.legend(handles=legend_elems, fontsize=8, loc="upper left",
              framealpha=0.85)

    info = []
    if det_cycle is not None and sat_cycle is not None:
        early = int(cycles[sat_cycle]) - int(cycles[det_cycle])
        info.append(f"Early warning: {early} cycle(s) before saturation")
    info.append(f"S3 fired RSUs: {int(col(atk,22).max())} of 64")
    ax.text(0.99, 0.04, "\n".join(info),
            transform=ax.transAxes, fontsize=8,
            ha="right", va="bottom",
            bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.8, ec="#D3D1C7"))

fig1.suptitle("S3 detection — TCAM utilisation and FlowMod rate", fontsize=12, y=1.01)
fig1.tight_layout()
out1 = os.path.join(OUTPUT_DIR, "plot_s3_tcam_util.png")
fig1.savefig(out1, dpi=150, bbox_inches="tight")
print(f"Saved: {out1}")

# ── figure 2: latency comparison — baseline vs all attack percentages ─────────
fig2, ax = plt.subplots(figsize=(10, 4.5))

base_cycles = col(base, 0).astype(int)
base_lat    = col(base, 3)
ax.plot(base_cycles, base_lat, color=COL_BASE, lw=1.5, ls="--",
        label="Baseline", zorder=5)

for pct, atk in sorted(attacks.items()):
    cycles = col(atk, 0).astype(int)
    lat    = col(atk, 3)
    ax.plot(cycles, lat, color=PCT_COLS[pct], lw=2,
            label=f"Attack 3 — {pct}%", zorder=4)

ax.axvline(ATTACK_START, color="#A32D2D", lw=1, ls="--", alpha=0.5,
           label=f"Attack start (t={ATTACK_START}s)")
ax.axhline(100, color="#993C1D", lw=1, ls=":", alpha=0.7,
           label="100 ms safety limit")

ax.set_xlabel("Simulation cycle (s)", fontsize=10)
ax.set_ylabel("Current latency (ms)", fontsize=10)
ax.set_title("End-to-end latency: baseline vs Attack 3 (CP TCAM exhaustion)", fontsize=11)
ax.legend(fontsize=9, framealpha=0.85)
ax.grid(alpha=0.25, lw=0.5)
ax.set_ylim(bottom=0)

fig2.tight_layout()
out2 = os.path.join(OUTPUT_DIR, "plot_latency_comparison.png")
fig2.savefig(out2, dpi=150, bbox_inches="tight")
print(f"Saved: {out2}")

# ── figure 3: detection summary bar chart ─────────────────────────────────────
fig3, axes3 = plt.subplots(1, 3, figsize=(12, 4))

pcts_avail   = sorted(attacks.keys())
det_cycles   = []
early_warns  = []
max_rsus     = []
peak_utils   = []

for pct in pcts_avail:
    atk    = attacks[pct]
    cycles = col(atk, 0).astype(int)
    util   = col(atk, 17) * 100
    any_s3 = col(atk, 24)
    s3_cnt = col(atk, 22)

    dc = find_first(atk, any_s3 == 1)
    sc = find_first(atk, util >= 99.9)

    det_cycles.append(cycles[dc] if dc is not None else None)
    early_warns.append(
        (cycles[sc] - cycles[dc]) if (dc is not None and sc is not None) else 0
    )
    max_rsus.append(int(s3_cnt.max()))
    peak_utils.append(float(util.max()))

pct_labels = [str(p) + "%" for p in pcts_avail]
x = np.arange(len(pcts_avail))
bar_kw = dict(width=0.55, zorder=3)

# panel A — detection cycle
ax_a = axes3[0]
bars_a = ax_a.bar(x, [d if d is not None else 0 for d in det_cycles],
                  color=[PCT_COLS[p] for p in pcts_avail], **bar_kw)
ax_a.set_xticks(x); ax_a.set_xticklabels(pct_labels)
ax_a.set_ylabel("Cycle", fontsize=10)
ax_a.set_title("Detection cycle", fontsize=10)
ax_a.grid(axis="y", alpha=0.3, lw=0.5)
for bar, val in zip(bars_a, det_cycles):
    if val is not None:
        ax_a.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                  str(val), ha="center", va="bottom", fontsize=9)

# panel B — early warning (cycles before saturation)
ax_b = axes3[1]
bars_b = ax_b.bar(x, early_warns,
                  color=[PCT_COLS[p] for p in pcts_avail], **bar_kw)
ax_b.set_xticks(x); ax_b.set_xticklabels(pct_labels)
ax_b.set_ylabel("Cycles", fontsize=10)
ax_b.set_title("Early warning\n(cycles before saturation)", fontsize=10)
ax_b.grid(axis="y", alpha=0.3, lw=0.5)
for bar, val in zip(bars_b, early_warns):
    ax_b.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
              str(val), ha="center", va="bottom", fontsize=9)

# panel C — RSUs flagged
ax_c = axes3[2]
bars_c = ax_c.bar(x, max_rsus,
                  color=[PCT_COLS[p] for p in pcts_avail], **bar_kw)
ax_c.set_xticks(x); ax_c.set_xticklabels(pct_labels)
ax_c.set_ylabel("RSU count", fontsize=10)
ax_c.set_title("Peak RSUs flagged by S3\n(of 64 total)", fontsize=10)
ax_c.grid(axis="y", alpha=0.3, lw=0.5)
ax_c.set_ylim(0, 70)
for bar, val in zip(bars_c, max_rsus):
    ax_c.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
              str(val), ha="center", va="bottom", fontsize=9)

fig3.suptitle("S3 detection summary across attack intensities — Attack 3 (CP TCAM)",
              fontsize=12)
fig3.tight_layout()
out3 = os.path.join(OUTPUT_DIR, "plot_s3_summary.png")
fig3.savefig(out3, dpi=150, bbox_inches="tight")
print(f"Saved: {out3}")

plt.show()
print("\nDone. Run from your ns-3 root directory:")
print("  python3 plot_tcam_detection.py")
