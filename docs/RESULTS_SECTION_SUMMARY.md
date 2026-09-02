# Results-section data summary — 2026-09-02

What has been produced toward the thesis Results section, the numbers, and the
CSV → figure mapping. Follows `HPC_PLAN_2026-09-01.md`.

**Status at a glance**

| Item | State |
|---|---|
| S2 ground-truth latch fix (validity of every TAP/FADE A2 comparison) | **done, verified, committed** (`c994bf6` / `d4652fa`) |
| P1 graph 1 — TAP baseline (A1, A2) | **done** — 60 s, seed 1, pct {20,60,100}, fixed binary |
| P1 graph 2 — FADE baseline (A5–A8) | **done** — 60 s, seed 1, pct {20,60,100} (unchanged by the fix) |
| P1 graph 3 — SFTO-Guard baseline (A3, A4) | **done** — offline, pct {20,40,80,100} |
| Matched MOBIGUARD @ 60 s (baseline comparison column) | **in progress** — 3/18 (`_cmp60` tag) |
| P2 — ablations AB7 / AB1 / AB4 | not produced — host thermals (96–100 °C at ≥4 sims); needs a cooler box |
| P3 — fill 40 % / 80 % (MOBIGUARD) | not started |
| P4 — seeds 2–5 | dropped (per instruction) |
| Enforcement OFF-vs-ON re-collection | not started (`SWEEP180_summary_e0/e1.csv` absent) |

Deviations to declare: baselines at **60 s** (spec `main.tex:5240` = 300 s; local
MOBIGUARD enforcement-arm data = 180 s). **Seed 1 only.**

---

## 1. Methodology fix — S2 event-gated ground truth

**Finding.** TAP/FADE baselines run with MOBIGUARD's detectors off
(`--enable_lrad_obu=0 --enable_lrad_rsu=0`). For **Attack 2** this invalidated
the baseline's own scoring: `calculate_tap_security_metrics()` gates A2 ground
truth on `g_s2_gt_delay_exceeded[n]`, written only inside `s2_detect_packet()`,
whose sole caller `lrad_rsu()` early-returns when `enable_lrad_rsu=0`. Result:
every node scored benign → **TP = FN = 0 every cycle**, every alert booked FP.
A1 was unaffected (reads `is_malicious_node[0][]` directly).

**Fix** (`scratch/s2_detection.h`, `scratch/lrad.h`, committed): new
`s2_latch_ground_truth()` (measurement only, no STARK proof / no detection
record) called from `lrad_rsu()` **before** the `enable_lrad_rsu` gate — so A2
ground truth is populated in every config (baseline isolation, AB1-A, Q2–Q4).

**Before / after** (A2 TAP, 60 s, seed 1, `d100ms`):

| pct | ΣTP before → after | ΣFN | avg_MCC after |
|---|---|---|---|
| 20  | 0 → 1 890 | 0 | 0.097 |
| 60  | 0 → 6 036 | 0 | 0.194 |
| 100 | 0 → 9 944 | 0 | 0.346 |

ΣFN stays 0 by construction (once latched malicious, TAP's permanent blacklist
catches the node). The baseline weakness shows as **precision** (FPR 90 → 80 %)
and low MCC, not recall.

---

## 2. P1 — state-of-the-art baseline results

Seed 1, 200 veh / 64 RSU / 4 ctrl, SUMO LA trace, `sim_run=1`.
TAP/FADE: 60 s, final-cycle cumulative (`avg_*`) columns.
Files: `results_routing/TAP_Attack{1,2}_<pct>_d100ms_seed1.csv`,
`results_routing/FADE_Attack{5,6,7,8}_<pct>_seed1.csv`.

### 2.1 TAP (Arsalan & Rehman, FIT 2018) — Selective Time Delay, A1 / A2

All six re-run 2026-09-02 on the fixed binary (`d4652fa`); A1 numbers identical
to the pre-fix run (deterministic), A2 now valid.

| variant | pct | avg_PDR % | avg_lat ms | avg_MCC | avg_DR % | avg_FPR % | TP | FP | TN | FN | avg_TVR |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| A1 (CP) | 20  | 64.32 | 35.8  | **−0.075** | 85.67 | 91.64 | 14 | 245 | 7 | 2 | 2.46 |
| A1 (CP) | 60  | 65.62 | 42.4  | **−0.169** | 80.71 | 92.50 | 27 | 230 | 6 | 5 | 4.05 |
| A1 (CP) | 100 | 65.62 | 43.7  | **−0.207** | 81.79 | 93.64 | 55 | 200 | 4 | 9 | 9.09 |
| A2 (DP) | 20  | 64.90 | 78.2  | 0.097 | 100 | 89.53 | 46 | 214 | 8 | 0 | 6.37 |
| A2 (DP) | 60  | 62.45 | 219.2 | 0.194 | 100 | 88.16 | 136 | 125 | 7 | 0 | 25.15 |
| A2 (DP) | 100 | 56.24 | 311.3 | 0.346 | 100 | 79.91 | 228 | 34 | 6 | 0 | 43.21 |

- **A1: negative MCC** — TAP performs worse than chance on the control-plane
  delay variant (FP 200–245 vs TP 14–55). Headline baseline-weakness result.
- **A2: recall 100 %, poor precision** — MCC rises 0.10 → 0.35 with intensity
  only because FP falls as more of the fleet is genuinely malicious.
- A2 latency 78 → 219 → 311 ms is raw attack impact.

### 2.2 FADE (eFADE) — Hidden Forwarding, A5–A8

From the 2026-09-01 P1 run (binary-independent for A5–A8; a re-run reproduces
these byte-for-byte and was skipped).

| variant | pct | avg_PDR % | avg_lat ms | avg_DR % | avg_FPR % | TP | FP | TN | FN | avg_UCR* |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| A5 (HF CP)   | 20  | 64.22 | 28.1 | 0.00  | 1.15 | 0 | 0 | 0 | 2 | 52.8 |
| A5           | 60  | 61.19 | 28.2 | 32.76 | 1.15 | 1 | 0 | 0 | 1 | 72.8 |
| A5           | 100 | 63.64 | 28.1 | 59.48 | 1.15 | 2 | 0 | 0 | 0 | 74.5 |
| A6 (HF DP)   | 20  | 62.85 | 29.3 | 30.17 | 1.15 | 2 | 0 | 0 | 0 | 75.4 |
| A6           | 60  | 60.74 | 30.2 | 29.31 | 1.15 | 1 | 0 | 0 | 1 | 81.0 |
| A6           | 100 | 60.23 | 33.2 | 59.48 | 1.15 | 2 | 0 | 0 | 0 | 80.5 |
| A7 (HF CP v2)| 20  | 63.73 | 27.4 | 0.00  | 1.15 | 0 | 0 | 0 | 2 | 53.5 |
| A7           | 60  | 63.20 | 29.0 | 25.00 | 1.15 | 1 | 0 | 0 | 1 | 73.1 |
| A7           | 100 | 63.81 | 28.3 | 29.31 | 1.15 | 1 | 0 | 0 | 1 | 73.0 |
| A8 (HF DP v2)| 20  | 63.28 | 27.7 | 10.34 | 1.15 | 1 | 0 | 0 | 1 | 76.4 |
| A8           | 60  | 29.52 | 26.6 | 61.21 | 1.15 | 2 | 0 | 0 | 0 | 81.7 |
| A8           | 100 | 13.87 |  8.4 | 36.21 | 1.15 | 2 | 0 | 0 | 0 | 83.2 |

`* avg_UCR` = column 23 of the FADE CSV — **confirm against
`write_security_metrics_csv()`** (no `#` header in these files). avg_MCC = 0 in
every row (TP/FN of 1–2 collapse the denominator). FADE **barely fires** on
Hidden Forwarding: DR 0–61 %, single-digit TP, fixed ~1.15 % FPR. A8 PDR
collapse at 60/100 % is attack delivery impact, not a detector artefact.

### 2.3 SFTO-Guard (Tang et al., 2023) — TCAM exhaustion, A3 / A4

Offline LightGBM benchmark (`sfto_pipeline/`), paper's 8 features
(`--skip_shap`), 3:1 split, run over the ON-arm `tcam_snapshots_*.csv.gz`
time-series. 149 window-samples per point (77 normal / 72 attack).
Results in `sfto_pipeline/results/hpc_p1_a{3,4}[_p<pct>]/`.

| attack | pct | MCC | DR % | FPR % | acc | AUC | TP | FP | TN | FN |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **A3** (TCAM CP) | 20  | **−0.410** | 27.8 | 68.8 | 0.295 | 0.321 | 20 | 53 | 24 | 52 |
| A3               | 40  | 0.974 | 100 | 2.6 | 0.987 | 1.000 | 72 | 2 | 75 | 0 |
| A3               | 80  | 0.961 | 100 | 3.9 | 0.980 | 1.000 | 72 | 3 | 74 | 0 |
| A3               | 100 | 0.974 | 100 | 2.6 | 0.987 | 1.000 | 72 | 2 | 75 | 0 |
| **A4** (TCAM DP) | 20  | 0.974 | 100 | 2.6 | 0.987 | 1.000 | 72 | 2 | 75 | 0 |
| A4               | 40  | 0.974 | 100 | 2.6 | 0.987 | 1.000 | 72 | 2 | 75 | 0 |
| A4               | 80  | **1.000** | 100 | 0.0 | 1.000 | 1.000 | 72 | 0 | 77 | 0 |
| A4               | 100 | **1.000** | 100 | 0.0 | 1.000 | 1.000 | 72 | 0 | 77 | 0 |

- **SFTO-Guard is near-perfect on TCAM exhaustion** (MCC ≥ 0.96) **except it
  collapses on the control-plane variant A3 at low intensity (20 %): MCC −0.41,
  DR 27.8 %, FPR 68.8 %** — worse than chance. Recovers completely at ≥ 40 %.
  This asymmetry (CP low-rate blind spot) is the headline SFTO result.
- Tool caveat: metric labels in its output are hard-coded to "Attack 4 DP";
  the confusion matrices are correct regardless of which attack was fed.

### 2.4 MOBIGUARD comparison column — in progress

`run_tag=cmp60` runs (A1, A2, A5–A8 × {20,60,100}, 60 s, full S1–S8 stack) →
`MOBIGUARD_Attack<N>_<pct>[_d100ms]_seed1_cmp60.csv`, so canonical 180 s data is
untouched. 3/18 complete at time of writing; table to be filled on completion,
giving each baseline row a same-length MOBIGUARD counterpart.

---

## 3. CSV → figure mapping (HPC_PLAN §0)

| Fig | Metric / column | Source files |
|---|---|---|
| PDR vs attack % (8 variants) | `avg_PDR` | `MOBIGUARD_Attack<N>_<pct>*_seed1.csv` |
| Latency vs attack % | `avg_lat_ms` | same |
| UCR vs attack %, A5–A8 | `avg_UCR` | `MOBIGUARD_Attack{5..8}_*` (+ `FADE_*` baseline) |
| MCC / DR / FPR vs attack % | `TP,FP,TN,FN` + `avg_DR`,`avg_FPR` | same |
| Enforcement OFF vs ON | both summary CSVs | `SWEEP180_summary_e0.csv`, `_e1.csv` — **missing on this host** |
| TVR vs attack %, A1/A2 | `avg_TVR` | `MOBIGUARD_Attack{1,2}_*`, `TAP_Attack{1,2}_*` |
| SOTA baseline vs MOBIGUARD | above columns | `TAP_*` (§2.1), `FADE_*` (§2.2), `sfto_pipeline/results/hpc_p1_*` (§2.3), `*_cmp60` (§2.4) |
| P2 ablation deltas (AB7, AB1, AB4) | per-variant MCC/DR/FPR, arm A vs B | `MOBIGUARD_Attack*_seed1_AB{7A,7B,1A,1B,4A,4B,4C}.csv` — **not yet produced** |

---

## 4. Reporting rules to honour

- **M1 / MCC**: window-level only (`scripts/results_table.py` / `m1_local.py`,
  `eq:eval_dedup` — RSU rows, primary-detector column, non-overlapping 10 s
  blocks, warm-up dropped). The per-node whole-run confusion matrix is a
  sticky-latch statistic (precision decays with run length) — debugging tool,
  not a results number.
- CSV `avg_MCC` (time-avg of per-cycle MCC) ≠ MCC from the cumulative
  `TP/FP/TN/FN` (latter higher in 41/49, mean +0.0485). Pick one, state it;
  `main.tex:5079` reads as MCC *of the matrix*.
- **Recall both ways** where supported: `recall_declared` vs `recall_acted`.
- Monotonicity per variant along its own ladder, not one global grid.
- A6@100 MCC drop under enforcement (0.719 → 0.426) is not a regression —
  early-quarantined nodes stop emitting signal while ground truth still marks
  them malicious (latch reset-boundary). Do not "fix" in code.

---

## 5. Outstanding before the Results section is complete

1. **MOBIGUARD `_cmp60`** — finish 18 runs, fill §2.4.
2. **P2 ablations** (AB7, AB1, AB4) — blocked by host thermals; needs a cooler
   box. Launchers ready (`scripts/run_plan_p2.sh` + `scripts/temp_governor.sh`).
3. **P3** — add 40 % / 80 % (2 pct × 8 variants × 2 arms), 180 s.
4. **`SWEEP180_summary_e0/e1.csv`** absent — needed for enforcement OFF-vs-ON.
5. **Baseline sim-time** 60 s vs 300 s spec — declare in
   `SIMULATION_SETTINGS_DEVIATIONS.md` or re-run for final figures.
6. **Seeds** — all seed 1; `main.tex:5240` specifies 5.
7. Confirm the FADE CSV column map (`avg_UCR` index) against
   `write_security_metrics_csv()`.
