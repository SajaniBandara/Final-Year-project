# Detection Pipeline Implementation Plan

> **Reference:** `main (10).tex`
> Sections covered: §Lightweight Rule-Based Detection Engine, §Federated LSTM Anomaly
> Detection, §Data Collection, §Performance Evaluation and Benchmarking.
>
> **Scope:** This document covers everything NOT covered by `CRYPTO_IMPLMENTATION.md`.
> That document handles: §Hybrid Cryptographic Integrity Layer, §Blockchain Architecture,
> §Multi-Controller Zero-Trust Architecture, §Distributed Trusted Time Reference.
>
> **Implementation note:** The rule-based signatures (S1–S8) are already deployed as
> individual detection headers. What is missing is (a) threshold calibration via
> regression, (b) the composite LRAD-OBU / LRAD-RSU wiring, (c) the full Python
> Federated LSTM pipeline, and (d) the performance evaluation harness.

---

## 1. Overview

| Component | Proposal Reference | Files | Status |
|---|---|---|---|
| Mobility-adjusted baseline (`eq:mobility_baseline`) | §Lightweight Rule-Based | `s1_detection.h` | Implemented — parameters **uncalibrated** |
| EWMA variance estimator (`eq:ewma_variance`) | §Lightweight Rule-Based | `s1_detection.h` | Implemented — β **uncalibrated** |
| S1 detection rule (`eq:rule_s1`) | §Lightweight Rule-Based | `s1_detection.h` | Implemented — k **uncalibrated** |
| S2 partial (threshold only, no ZKP) | §Lightweight Rule-Based | `s2_detection.h` | Implemented |
| S2 full (with STARK proof) | LRAD-RSU, `alg:lrad_rsu` | `s2_detection.h` | Implemented |
| S3 / S4 TCAM rules (`eq:rule_s34`) | §Lightweight Rule-Based | `tcam_detection.h` | Implemented |
| S5–S8 RSU full-mode signatures | LRAD-RSU, `alg:lrad_rsu` | `s5–s8_detection.h` | Implemented |
| Composite OBU decision (`eq:composite_light`) | `alg:lrad_obu` | — | **Not implemented** |
| Escalation signal OBU → RSU | `alg:lrad_obu` | — | **Not implemented** |
| Threshold calibration (δ₀, αρ, αv via regression) | §Simulation settings | — | **Not implemented** |
| β grid search `{0.7, 0.8, 0.9, 0.95}` | §Simulation settings | — | **Not implemented** |
| k grid search `{1, 2, 3}` | §Simulation settings | — | **Not implemented** |
| Robustness perturbation ±{10%, 20%, 30%} | §Simulation settings | — | **Not implemented** |
| LSTM training data logger | `eq:lstm_input` | `lstm_logger.h` | Implemented |
| LSTM preprocessing (Z-score, windowing) | §Federated LSTM | `lstm_pipeline/src/preprocessor.py` | **Not implemented** |
| LSTM model (2-layer, autoencoder) | `eq:lstm_hidden`, `eq:anomaly_score` | `lstm_pipeline/src/lstm_model.py` | **Not implemented** |
| Local trainer + threshold calibration | `eq:lstm_detection`, `eq:lstm_threshold` | `lstm_pipeline/src/local_trainer.py` | **Not implemented** |
| BRFA-v2 federated aggregation | `alg:brfa_v2`, `eq:fed_robust` | `lstm_pipeline/src/fed_aggregator.py` | **Not implemented** |
| Evaluator (MCC, DR, FPR, latency) | §Primary Performance Metrics | `lstm_pipeline/src/evaluator.py` | **Not implemented** |
| Ablation baselines A1–A5 | §Internal Ablation Baselines | — | **Not implemented** |
| Benign simulation runs (5 seeds) | §Data Collection | — | **Not run** |
| Attack simulation runs (240 total) | §Data Collection | — | Partial (Attacks 2, 5–8 only) |

---

## 2. Lightweight Rule-Based Detection Engine

### 2.1 Equations from Proposal

#### `eq:mobility_baseline` — Mobility-Adjusted Baseline Delay

```
δ̄_r(t) = δ₀ + α_ρ · ρ(t) + α_v · v̄(t)⁻¹
```

| Symbol | Meaning | Current value in `s1_detection.h` |
|---|---|---|
| `δ₀` | Static propagation baseline (s) | `0.002` — **uncalibrated** |
| `α_ρ` | Density sensitivity coefficient (s/vehicle) | `0.0001` — **uncalibrated** |
| `α_v` | Speed sensitivity coefficient (s²/m) | `0.05` — **uncalibrated** |
| `ρ(t)` | Vehicle density in RSU zone | From `linklifetimeMatrix_dsrc` |
| `v̄(t)` | Mean vehicle speed in RSU zone (m/s) | From `velocity` field |

All three coefficients must be fitted via least-squares regression over benign (0% attack)
SUMO traces, as stated in the proposal (§Simulation settings). Current values are initial
estimates only.

#### `eq:ewma_variance` — EWMA Variance Estimator

```
σ²_r(t) = β · σ²_r(t-1) + (1 − β) · (δ_r(t) − δ̄_r(t))²
```

| Symbol | Meaning | Current value |
|---|---|---|
| `β` | EWMA forgetting factor ∈ (0, 1) | `0.9` — **uncalibrated** |

Proposal (§Simulation settings): β ∈ {0.7, 0.8, 0.9, 0.95}, selected for fastest stable
σ²(t) convergence within the 9 s minimum RSU zone residence window.

#### `eq:rule_s1` — Signature S1 Flag

```
f_S1(p, r, t) = 1  if  δ_p > δ̄_r(t) + k · σ_r(t)  ∧  Priority(p) = HIGH
              = 0  otherwise
```

| Symbol | Meaning | Current value |
|---|---|---|
| `k` | Standard-deviation multiplier | `3.0` — **uncalibrated** |

Proposal (§Simulation settings): k ∈ {1, 2, 3}, selected for best MCC at ≤ 1% FPR;
k = 3 (three-sigma rule) is the initial candidate.

#### `eq:rule_s34` — Signatures S3 / S4 Flag

```
f_S3,S4(r, t) = 1  if  λ̂_a(r,t) > λ_thresh  ∧  U_TCAM(r,t) > U_thresh
              = 0  otherwise
```

Implemented in `tcam_detection.h` via `ComputeTcamDetection()`.

#### `eq:composite_light` — Composite OBU Detection Decision

```
D_OBU(v, t) = f_S1(v,t) ∨ f_S2p(v,t) ∨ f_S3(v,t) ∨ f_S4(v,t)
```

**Not implemented.** Individual signatures fire independently and call
`record_detection_event()` directly. The composite OR across all four OBU-side
signatures into a single `D_OBU` boolean that triggers escalation to the RSU
(as defined in `alg:lrad_obu`) does not exist in the code.

### 2.2 Algorithms from Proposal

#### `alg:lrad_obu` — LRAD-OBU (OBU Lightweight Detection)

The proposal defines a unified procedure `LRAD-OBU(p, v, r, t, ρ, v̄, τ)` that:
1. Computes the mobility-adjusted baseline δ̄
2. Evaluates all four OBU-side flags (S1, S2-partial, S3, S4)
3. Computes `D_OBU = f_S1 ∨ f_S2p ∨ f_S3 ∨ f_S4`
4. If `D_OBU = 1`, calls `ESCALATE(p, v, r, {flags})`

**Implementation status:** Steps 1–2 are implemented across separate headers.
Steps 3–4 (composite OR and escalation call) are **not implemented**.

#### `alg:lrad_rsu` — LRAD-RSU (RSU Full Detection)

The proposal defines `LRAD-RSU(p, v, r, π_delay, π_hop, σ, {pk_i}, {m_i})` that:
1. Evaluates S2-full (`stark_verify_timing`)
2. Computes batch challenge and runs `BatchVerify`
3. Evaluates S5: `¬b_batch ∧ FlowMod ∉ BC.Query(C_P)`
4. Evaluates S6: `¬b_batch ∧ DUP(msg_id, W)`
5. Evaluates S7: `Vol_rate > ε_vol ∧ b_hop = 0`
6. Evaluates S8: `b_batch ∧ b_hop = 0`
7. If `D_RSU = 1`: calls `BC.Write()` and `BTMM()`

**Implementation status:** Each individual flag is implemented in a separate header
(S2-full in `s2_detection.h`, S5–S8 in respective headers). The unified LRAD-RSU
procedure that receives an escalated event and evaluates all flags in one call is
**not implemented** as a single function. Detection events are recorded individually.

### 2.3 Threshold Calibration (Pending)

The proposal (§Simulation settings) requires:

1. **Least-squares regression** — fit δ₀, α_ρ, α_v from benign SUMO traces:
   ```
   δ̄(t) = δ₀ + α_ρ · ρ(t) + α_v · v̄(t)⁻¹
   ```
   Data source: benign LSTM CSVs (`lstm_training/RSU_*/A0_pct0_seed*.csv`) — columns
   `delta_t`, `rho`, `v_bar` are already in the output of `lstm_log_rsu_cycle()`.

2. **β sweep** — run benign simulations at each β ∈ {0.7, 0.8, 0.9, 0.95}; select
   the value that produces fastest stable σ²(t) convergence within 9 s.

3. **k sweep** — run validation split at each k ∈ {1, 2, 3}; select the value that
   maximises MCC subject to FPR ≤ 1%.

4. **Robustness check** — rerun with δ₀, α_ρ, α_v each perturbed by ±{10%, 20%, 30%}
   and record the change in FPR.

**File to create:** `lstm_pipeline/src/rule_calibrator.py`

---

## 3. Federated LSTM Anomaly Detection

### 3.1 Equations from Proposal

#### `eq:lstm_input` — LSTM Input Feature Vector

```
x_t^(f) = [δ_t, λ_PI,t, U_TCAM,t, 𝟙[π_delay=⊥], 𝟙[π_hop=⊥], ρ_t, v̄_t]ᵀ
```

| Feature | Source in simulation | Logged by |
|---|---|---|
| `δ_t` | `obs_delay` from S1 EWMA accumulator | `lstm_logger.h` → `delta_t` column |
| `λ_PI,t` | Δ(`g_slowpath_hit_count`) per cycle | `lstm_logger.h` → `lambda_PI` column |
| `U_TCAM,t` | `g_tcam_rule_count / 256` | `lstm_logger.h` → `U_TCAM` column |
| `𝟙[π_delay=⊥]` | `g_lstm_stark_counts[node].first > 0` | `lstm_logger.h` → `zkp_delay_fail` column |
| `𝟙[π_hop=⊥]` | `g_lstm_stark_counts[node].second > 0` | `lstm_logger.h` → `zkp_hop_fail` column |
| `ρ_t` | Vehicles in RSU zone from `linklifetimeMatrix_dsrc` | `lstm_logger.h` → `rho` column |
| `v̄_t` | Mean speed of vehicles in RSU zone | `lstm_logger.h` → `v_bar` column |

All 7 features are captured by `lstm_log_rsu_cycle()` in `lstm_logger.h`.

#### `eq:lstm_hidden` — LSTM Hidden State Update

```
h_t = LSTM(x_t, h_{t-1}; W_local^(k))
```

Architecture (from §Simulation settings):
- 2 stacked LSTM layers (64 units, then 32 units)
- Followed by a fully connected sigmoid output layer
- Autoencoder reconstruction head for anomaly score

**Not implemented** — Python model only.

#### `eq:anomaly_score` — Anomaly Score

```
A_t^(k) = ||x_t − x̂_t||²₂
```

Squared L2 reconstruction error between observed feature vector and autoencoder output.
**Not implemented.**

#### `eq:lstm_detection` — Detection Decision

```
D_LSTM^(k)(t) = 1  if  A_t^(k) > θ^(k)
              = 0  otherwise
```

**Not implemented.**

#### `eq:lstm_threshold` — RSU-Specific Detection Threshold

```
θ^(k) = μ_A^(k) + z_α · σ_A^(k)
```

μ and σ are computed from the benign training distribution at RSU k.
z_α is the z-score corresponding to the target FPR α.
**Not implemented.**

### 3.2 Federated Aggregation

#### `eq:fed_robust` — Krum-Filtered Weighted Aggregation

```
W_global^(t+1) = Σ_k [ n_k · W_local^(k) · 𝟙[d(W_local^(k), W̃) < γ] ]
               / Σ_k [ n_k · 𝟙[d(W_local^(k), W̃) < γ] ]
```

W̃ is the coordinate-wise median; d is Euclidean distance; γ is the outlier threshold.

#### `eq:bc_model_verify` — Blockchain Model Hash Verification

```
𝟙_BC^(k) = SC.VerifyModelHash(H(W_local^(k)), CommittedHash^(k))
```

Stubs `bc_commit_model_hash()` and `bc_verify_model_hash()` are **implemented** in
`blockchain_sim.h`. These are the integration points for the Python FL pipeline.

#### `alg:brfa_v2` — BRFA-v2 Procedure

Four steps in sequence:

1. **Trust gate**: `K_e = {k : T_{r_k} ≥ T_min}`. Abort if `|K_e| < 2f+1`.
2. **Hash verification**: `𝟙_BC^(k) = SC.VerifyModelHash(W^(k))` for each k ∈ K_e.
3. **Krum geometric filter**: compute W̃, compute ω_k = n_k · 𝟙_BC^(k) · 𝟙[d < γ].
4. **Weighted aggregation**: `W_global = Σ ω_k W^(k) / Σ ω_k`; commit `H(W_global)` to blockchain.

**Not implemented** — Python pipeline only.

### 3.3 Hyperparameter Grid Search Space (from Proposal)

| Parameter | Search space | Selection criterion |
|---|---|---|
| Learning rate η (Adam) | {10⁻⁴, 10⁻³, 10⁻²} | Max MCC at ≤ 1% FPR |
| Batch size B | {32, 64, 128} | Max MCC at ≤ 1% FPR |
| Local epochs per round E | {1, 3, 5} | Balance local fit vs weight drift |
| Global aggregation rounds R | {50, 100, 150} | Global loss convergence |

Detection threshold base: anomaly score ≥ 0.5, fine-tuned for ≥ 95% precision, ≤ 1% FPR.

### 3.4 Preprocessing Requirements (from Proposal)

- **Z-score normalisation** per RSU using benign-only (0% attack) statistics
- **Sliding window**: 10 s window, 5 s stride (50% overlap)
- **Train / val / test split**: 70% / 15% / 15%, partitioned by seed, stratified by
  attack variant and percentage
- **Data source**: `lstm_training/RSU_{id}/{run_tag}.csv` (written by `lstm_logger.h`)

---

## 4. Data Collection

### 4.1 Required Simulation Runs

The proposal (§Simulation settings) specifies:

```
6 attack percentages × 8 variants × 5 seeds = 240 labeled run-instances
+ 1 variant (benign, 0%) × 5 seeds = 5 benign runs
Total: 245 runs
```

Each run: 300 s simulation, 1 Hz data collection, `--training=1` flag.

Attack percentage allocation:
- 0%, 20%, 40%, 60%, 80%, 100%
- Attacker count: `⌊0.01 × p × 264⌋` nodes
- Control-plane variants (1, 3, 5, 7): attackers allocated among RSUs
- Data-plane variants (2, 4, 6, 8): attackers allocated among vehicles and RSUs
- Controller attackers: p < 33% → 1; 33–66% → 2; ≥ 66% → 3; 100% → 4

### 4.2 Run Status

| Attack Variant | Simulation results exist | LSTM training data |
|---|---|---|
| Benign (0% attack) | No | Not yet collected |
| Attack 1 (STD CP) | No | Not yet collected |
| Attack 2 (STD DP) | Yes (`MOBIGUARD_Attack2_*.csv`) | Not yet collected |
| Attack 3 (TCAM CP) | No | Not yet collected |
| Attack 4 (TCAM DP) | No | Not yet collected |
| Attack 5 (HF Active CP) | Yes | Not yet collected |
| Attack 6 (HF Active DP) | Yes | Not yet collected |
| Attack 7 (HF Passive CP) | Yes | Not yet collected |
| Attack 8 (HF Passive DP) | Yes | Not yet collected |

LSTM training data (`--training=1`) has not been collected for any variant yet —
`lstm_logger.h` was just added. All 245 runs need to be re-executed with `--training=1`.

---

## 5. Performance Evaluation

### 5.1 External Baselines (from Proposal §External Baselines)

| ID | System | Attacks covered | What the comparison shows |
|---|---|---|---|
| B1 — FSDM | Centralized entropy-based (Huang 2020) | Variants 1–3 | Failure under vehicular mobility and compromised controller |
| B2 — SFTO-Guard | Static ML thresholds (Tang 2023) | Variants 3–4 | Degradation under vehicular topology dynamics |
| B3 — FADE | Flow-conservation forwarding anomaly (Zhang 2021) | Variants 5–8 | Short observation-window limitation under vehicular mobility |

**Not implemented.** Requires replicating or simulating each baseline's decision logic.

### 5.2 Internal Ablation Baselines (from Proposal §Internal Ablation Baselines)

| ID | Configuration | Purpose |
|---|---|---|
| A1 — Rule-only | `alg:lrad_obu` alone; no LSTM, no crypto | Isolates rule engine contribution |
| A2 — LSTM-only | `alg:brfa_v2` alone; no rule pre-filter, no ZKP in input | Isolates LSTM contribution |
| A3 — No-ZKP | Full system without ZKP proofs; ML-DSA-87 + aggregate sigs retained | Isolates ZKP contribution |
| A4 — No-BC | Full system without blockchain; detection retained, quarantine + model validation disabled | Isolates blockchain contribution |
| A5 — Full MOBIGUARD | Complete proposed framework | Primary result |

**Not implemented.** Each ablation requires a separate simulation run configuration.

### 5.3 Primary Performance Metrics (from Proposal §Primary Performance Metrics)

| ID | Metric | Formula / Definition | Target |
|---|---|---|---|
| M1 — MCC | Matthews Correlation Coefficient | `(TP·TN − FP·FN) / √((TP+FP)(TP+FN)(TN+FP)(TN+FN))` | Primary detection quality metric |
| M2 — DR | Per-variant Detection Rate | TP / (TP + FN) per attack variant | Independent per variant (8 values) |
| M3 — FPR | False Positive Rate | FP / (FP + TN) | ≤ 1% (both lightweight and full mode) |
| M4 — L_mit | Mitigation latency | Attack onset → smart contract quarantine (`eq:quarantine`) | ≤ 100 ms |
| M5 — PDR | Packet Delivery Ratio | Delivered / sent, safety-critical packets | Evaluated under attack with/without MOBIGUARD |
| M6 — L_e2e | End-to-End Latency | Mean per-packet latency across all hops | ≤ 100 ms safety-critical bound |

MCC, DR, FPR are already computed by the existing simulation output (columns in
`MOBIGUARD_Attack{N}_{pct}.csv`). M4 (mitigation latency) and M5, M6 (PDR, E2E latency)
are also in the existing CSV output.

---

## 6. Files to Create

### 6.1 `lstm_pipeline/src/rule_calibrator.py` (Step 2.5)

Reads benign LSTM CSVs and calibrates the three rule-based parameters:

```python
# Inputs: lstm_training/RSU_*/A0_pct0_seed*.csv
# Outputs: calibrated_params.json  { "delta0": ..., "alpha_rho": ..., "alpha_v": ...,
#                                     "beta": ..., "k": ... }

# Step 1: Fit least-squares δ̄(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
#         using columns: delta_t (y), rho (x1), 1/v_bar (x2)

# Step 2: Sweep β ∈ {0.7, 0.8, 0.9, 0.95}
#         Recompute EWMA σ² per RSU; select β for fastest convergence in 9 s window

# Step 3: Sweep k ∈ {1, 2, 3}
#         Compute FPR and MCC on benign validation split; select best k at FPR ≤ 1%

# Step 4: Robustness check
#         Perturb δ₀, α_ρ, α_v by ±{10%, 20%, 30%}; record ΔFPR per perturbation
```

After running, update `s1_detection.h` constants:
```cpp
double s1_delta0    = <fitted_value>;
double s1_alpha_rho = <fitted_value>;
double s1_alpha_v   = <fitted_value>;
double s1_k         = <selected_k>;
double s1_beta      = <selected_beta>;
```

### 6.2 `lstm_pipeline/src/preprocessor.py` (Step 4)

```python
# Inputs:  lstm_training/RSU_*/A{v}_pct{p}_seed{s}.csv
# Outputs: lstm_pipeline/data/processed/RSU_{id}/{train,val,test}.npz

# 1. Load all CSVs per RSU
# 2. Z-score normalise using benign (label==0) statistics per RSU per feature
# 3. Sliding window: 10 s window, 5 s stride → sequences of shape (10, 7)
# 4. Split: 70% train / 15% val / 15% test — partitioned by seed,
#            stratified by attack_variant and label
# 5. Save as .npz per RSU
```

### 6.3 `lstm_pipeline/src/lstm_model.py` (Step 5)

Architecture from proposal (`eq:lstm_hidden`, `eq:anomaly_score`):
- 2 stacked LSTM layers: 64 units then 32 units
- Autoencoder reconstruction head: FC layer back to input dim (7)
- Sigmoid FC output layer for binary classification

```python
class MobiGuardLSTM(nn.Module):
    # Encoder: LSTM(64) → LSTM(32) → h_t
    # Reconstruction head: Linear(32 → 7)  → x̂_t   [for eq:anomaly_score]
    # Output head: Linear(32 → 1) + Sigmoid           [for eq:lstm_detection]
    # Anomaly score: A_t = ||x_t − x̂_t||²
```

### 6.4 `lstm_pipeline/src/local_trainer.py` (Step 6)

```python
# Per-RSU local training
# Grid search: η ∈ {1e-4, 1e-3, 1e-2}, B ∈ {32, 64, 128}, E ∈ {1, 3, 5}
# Optimiser: Adam
# Loss: BCE (output head) + MSE (reconstruction head)
# After training: compute θ^(k) = μ_A + z_α · σ_A on benign validation set
# Save: local model weights, θ^(k), SHA3-512 hash of weights (for bc_commit_model_hash)
```

### 6.5 `lstm_pipeline/src/fed_aggregator.py` (Step 7)

Implements `alg:brfa_v2` exactly:
```python
# BRFA-v2(weights, sample_counts, trust_scores, gamma, T_min)
# Step 1: Trust gate   — exclude RSUs with T_r < T_min; abort if < 2f+1 remain
# Step 2: Hash verify  — call bc_verify_model_hash() stub (or Python equivalent)
# Step 3: Krum filter  — compute coordinate-wise median W̃;
#                        keep only RSUs with d(W_local, W̃) < γ
# Step 4: Weighted avg — W_global = Σ ω_k W^(k) / Σ ω_k
#         Loop R rounds (R ∈ {50, 100, 150})
```

### 6.6 `lstm_pipeline/src/evaluator.py` (Step 8)

Computes all six metrics (M1–M6) per attack variant and ablation:
```python
# M1: MCC per variant and overall
# M2: DR per variant
# M3: FPR (lightweight mode and full mode separately)
# M4: Mitigation latency from simulation CSV (avg_mit column)
# M5: PDR from simulation CSV (cur_PDR / avg_PDR columns)
# M6: E2E latency from simulation CSV (cur_lat / avg_lat columns)
# Output: results/metrics/{variant}_{ablation}.json
```

---

## 7. Implementation Order

```
Step 1  (done)  — lstm_logger.h: LSTM training data logger
Step 2          — Run 5 benign simulations (--training=1, 5 seeds, 0% attack)
Step 2.5        — rule_calibrator.py: fit δ₀, α_ρ, α_v; select β, k
Step 2.6        — Update s1_detection.h with calibrated values
Step 3          — Run 240 attack simulations (--training=1, all 8 variants × 6 pct × 5 seeds)
Step 4          — preprocessor.py: Z-score, windowing, train/val/test split
Step 5          — lstm_model.py: 2-layer LSTM + autoencoder + sigmoid head
Step 6          — local_trainer.py: grid search η, B, E; calibrate θ^(k)
Step 7          — fed_aggregator.py: BRFA-v2
Step 8          — evaluator.py: M1–M6 per variant and ablation
Step 9          — pipeline.py: end-to-end orchestration
Step 10         — Ablation runs A1–A5 (requires disabling components per config)
```
