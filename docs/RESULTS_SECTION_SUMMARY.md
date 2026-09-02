# Results-section data summary — 2026-09-02

What has actually been produced so far toward the thesis Results section, the
numbers themselves, and the CSV → figure mapping. Follows `HPC_PLAN_2026-09-01.md`.

**Status at a glance**

| Item | State |
|---|---|
| S2 ground-truth latch fix (affects every TAP/FADE baseline comparison for A2) | **done, verified** |
| P1 — TAP baseline (A1, A2) | **done** — 60 s, seed 1, pct {20,60,100} |
| P1 — FADE baseline (A5–A8) | **done** — 60 s, seed 1, pct {20,60,100} |
| P1 — SFTO-Guard baseline (A3, A4) | not run (offline, 0 sims) |
| P2 — ablations AB7 / AB1 / AB4 | **not produced** — box overheats (96–100 °C) at ≥4 concurrent sims |
| P3 — fill 40 % / 80 % | not started |
| P4 — seeds 2–5 | dropped (per instruction) |
| Enforcement OFF-vs-ON re-collection | not started |

Deviation to declare in the write-up: baselines were run at **60 s**, not the
`main.tex:5240` spec of 300 s (or the 180 s used for the local MOBIGUARD
enforcement-arm data). Seed 1 only.

---

## 1. Methodology fix — S2 event-gated ground truth

**Finding.** The TAP and FADE baselines are run with MOBIGUARD's own detectors
disabled (`--enable_lrad_obu=0 --enable_lrad_rsu=0`) so the baseline is measured
in isolation. For **Attack 2** this silently invalidated the baseline's scoring:

- `calculate_tap_security_metrics()` gates A2's ground truth on
  `g_s2_gt_delay_exceeded[n]` (the Issue-5 event-gate: a node counts as malicious
  only once its injected delay has actually exceeded Δ_max = 50 ms).
- `g_s2_gt_delay_exceeded[]` was written **only** inside `s2_detect_packet()`,
  whose sole caller is `lrad_rsu()`, which early-returns when `enable_lrad_rsu=0`.
- Result: with the RSU engine off, the latch never fired → every node scored
  benign → **TP = FN = 0 for all cycles**, every TAP alert booked as FP.

Confirmed: pre-fix `TAP_Attack2_{20,60,100}` all had ΣTP = ΣFN = 0
(ΣFP ≈ 14 000). `TAP_Attack1_*` was unaffected (A1 ground truth reads
`is_malicious_node[0][]` directly, set before `Simulator::Run()`).

**Fix.** `s2_latch_ground_truth()` (new, `scratch/s2_detection.h`) does the
anchored `hop_delay > S2_DELTA_MAX` check as a pure measurement (no STARK proof,
no detection record). `lrad_rsu()` (`scratch/lrad.h`) calls it **before** the
`enable_lrad_rsu` gate, so A2's ground truth is populated in every config
(baseline isolation runs, AB1-A, Q2–Q4).

**Before / after** (A2 TAP, 60 s, seed 1, `d100ms`):

| pct | ΣTP before → after | ΣFN before → after | avg_MCC after (final cycle) |
|---|---|---|---|
| 20  | 0 → 1 890 | 0 → 0 | 0.097 |
| 60  | 0 → 6 036 | 0 → 0 | 0.194 |
| 100 | 0 → 9 944 | 0 → 0 | 0.346 |

ΣFN stays 0 by construction: once a node's delay exceeds Δ_max it is latched
malicious for the run, and TAP permanently blacklists on first detection, so it
catches every latched node. The baseline's weakness shows as **precision**
(ΣFP still 12 157 / 8 202 / 4 144; FPR 89 → 80 %) and low MCC, not recall.

---

## 2. P1 — state-of-the-art baseline results

Seed 1, 60 s, `sim_run=1`, 200 veh / 64 RSU / 4 ctrl, SUMO LA trace.
All values are the **final-cycle cumulative** (`avg_*`) columns.
Files: `results_routing/TAP_Attack{1,2}_<pct>_d100ms_seed1.csv`,
`results_routing/FADE_Attack{5,6,7,8}_<pct>_seed1.csv`.

### 2.1 TAP (Arsalan & Rehman, FIT 2018) — Selective Time Delay, A1 / A2

| variant | pct | avg_PDR % | avg_lat ms | avg_MCC | avg_DR % | avg_FPR % | TP | FP | TN | FN | avg_TVR |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| A1 (CP) | 20  | 64.32 | 35.8  | **−0.075** | 85.67 | 91.64 | 14 | 245 | 7 | 2 | 2.46 |
| A1 (CP) | 60  | 65.62 | 42.4  | **−0.169** | 80.71 | 92.50 | 27 | 230 | 6 | 5 | 4.05 |
| A1 (CP) | 100 | 65.62 | 43.7  | **−0.207** | 81.79 | 93.64 | 55 | 200 | 4 | 9 | 9.09 |
| A2 (DP) | 20  | 64.90 | 78.2  | 0.097 | 100 | 89.53 | 46 | 214 | 8 | 0 | 6.37 |
| A2 (DP) | 60  | 62.45 | 219.2 | 0.194 | 100 | 88.16 | 136 | 125 | 7 | 0 | 25.15 |
| A2 (DP) | 100 | 56.24 | 311.3 | 0.346 | 100 | 79.91 | 228 | 34 | 6 | 0 | 43.21 |

- **A1: negative MCC** — TAP performs *worse than chance* on the control-plane
  delay variant (near-total FP saturation, 200–245 FP vs 14–55 TP). Headline
  baseline-weakness result.
- **A2: recall 100 %, precision poor** — MCC rises 0.10 → 0.35 with attack
  intensity only because FP falls as more of the fleet is genuinely malicious.
- A2 latency 78 → 219 → 311 ms is the raw attack impact (matches the plan's
  "A2: 71 → 156 → 238 ms" family; higher here at 60 s / d100ms).

### 2.2 FADE (eFADE) — Hidden Forwarding, A5–A8

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

`* avg_UCR` is taken as column 23 of the FADE CSV — **confirm against
`write_security_metrics_csv()` before quoting**; the FADE files carry no `#`
header. avg_MCC is 0 in every FADE row (TP/FN counts are 1–2, denominators
collapse). FADE's story is **very low detection** on Hidden Forwarding
(DR 0–61 %, single-digit TP) at a fixed ~1.15 % FPR — i.e. it barely fires.
- A8 PDR collapse at 60 %/100 % (29 %, 14 %) is the attack's delivery impact,
  not a detector artefact.

### 2.3 MOBIGUARD comparison column — TODO

Not included here: the paired MOBIGUARD 60 s halves were restored to the
canonical 180 s data after the P1 run (to protect the enforcement-arm results),
so there is no matched-length MOBIGUARD row to sit beside these baselines.
Fill from either (a) the canonical `MOBIGUARD_Attack*_seed1.csv` (180 s — note
the length mismatch) or (b) a matched 60 s MOBIGUARD re-run.

---

## 3. CSV → figure mapping (HPC_PLAN §0)

| Fig | Metric / column | Source files |
|---|---|---|
| PDR vs attack % (8 variants) | `avg_PDR` | `MOBIGUARD_Attack<N>_<pct>*_seed1.csv` |
| Latency vs attack % | `avg_lat_ms` | same |
| UCR vs attack %, A5–A8 | `avg_UCR` | `MOBIGUARD_Attack{5..8}_*` (+ `FADE_*` for baseline) |
| MCC / DR / FPR vs attack % | `TP,FP,TN,FN` + `avg_DR`,`avg_FPR` | same |
| Enforcement OFF vs ON | both summary CSVs | `SWEEP180_summary_e0.csv`, `_e1.csv` — **missing on this host** |
| TVR vs attack %, A1/A2 | `avg_TVR` | `MOBIGUARD_Attack{1,2}_*`, `TAP_Attack{1,2}_*` |
| SOTA baseline vs MOBIGUARD | above columns | `TAP_*`, `FADE_*`, `SFTO` (offline) |
| P2 ablation deltas (AB7, AB1, AB4) | per-variant MCC/DR/FPR, arm A vs arm B | `MOBIGUARD_Attack*_seed1_AB{7A,7B,1A,1B,4A,4B,4C}.csv` — **not yet produced** |

---

## 4. Reporting rules to honour (do not drift)

- **M1 / MCC**: report the **window-level** metric only (`scripts/results_table.py`
  / `scripts/m1_local.py`, `eq:eval_dedup`: RSU rows, primary-detector column,
  non-overlapping 10 s blocks, warm-up dropped). The per-node whole-run
  confusion matrix is a sticky-latch statistic (precision decays with run length)
  and is a debugging tool, **not** a results number.
- `avg_MCC` in the CSV (time-average of per-cycle MCC) ≠ MCC recomputed from the
  cumulative `TP/FP/TN/FN`; the latter is higher in 41/49 runs (mean +0.0485).
  Pick one convention and state it; `main.tex:5079` reads as MCC *of the matrix*.
- **Recall both ways** where the data supports it: `recall_declared` (vs all
  declared attackers) and `recall_acted` (vs attackers that acted).
- **Monotonicity** checked per variant along its own ladder, not one global grid.
- A6@100 MCC drop under enforcement (0.719 → 0.426) is **not** a regression —
  early-quarantined nodes stop emitting signal while ground truth still marks
  them malicious (latch reset-boundary). Do not "fix" in code.

---

## 5. Outstanding before the Results section is complete

1. **P2 ablations** (AB7, AB1, AB4) — blocked by machine thermals; needs a
   cooler host or a fixed cooler. Launchers ready: `scripts/run_plan_p2.sh`
   (180 s, seed 1, both arms), with `scripts/temp_governor.sh` as backstop.
2. **P3** — add 40 % / 80 % (2 pct × 8 variants × 2 arms), 180 s.
3. **SFTO-Guard** (A3/A4) — offline, run `sfto_pipeline/` over the existing
   `tcam_snapshots_Attack{3,4}_*_seed1_*_final.csv`.
4. **MOBIGUARD comparison rows** at matched length for §2.1 / §2.2.
5. **`SWEEP180_summary_e0/e1.csv`** and `sweep180_e0_bundle.tar.gz` are absent —
   needed for the enforcement OFF-vs-ON figure.
6. **Baseline sim-time**: 60 s vs the 300 s spec — declare in
   `SIMULATION_SETTINGS_DEVIATIONS.md` or re-run for final figures.
7. **Seeds** — everything is seed 1; `main.tex:5240` specifies 5.
