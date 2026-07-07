# Metrics Implementation Verification Report
**Date:** 2026-07-06  
**Scope:** Comprehensive line-by-line verification of performance metrics against docs/main.tex (Section 4.6, "Performance Metrics")

---

## Executive Summary

**Critical Finding:** Eight of twelve performance metrics specified in the proposal are **unimplemented or partially implemented**:
- **✓ Implemented (4 metrics):** M1 (MCC), M2 (TVR), M3 (UCR), M4 (Mitigation Latency), M6 (L_e2e)
- **✗ Completely Missing (7 metrics):** M5, M7 (full overhead breakdown), M8, M9, M10, M11, M12
- **⚠ Partial (1 metric):** M7 has partial subcomponents (sig_valid_rate, flowmod_endorsement_rate) but missing comprehensive overhead analysis

**Methodology Deviation:** Proposal specifies evaluation of 13 ablation studies (AB1–AB13) plus 5 benchmarking experiments (BE1–BE5) across all 12 metrics, but the current codebase has:
1. No infrastructure to support concurrent multi-attack injection (required for BE1–BE4)
2. No ablation-specific metric branches or conditional metric calculation
3. No infrastructure to toggle M5/M8/M9/M10/M11/M12 on and off per ablation
4. Single-variant CSV output (only one selected attack per run) instead of per-variant metric rows

---

## Detailed Metrics Verification

### M1 — Detection Quality and Mobility Robustness (MCC)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `MCC = (TP·TN - FP·FN) / √((TP+FP)(TP+FN)(TN+FP)(TN+FN))` | ✓ Correct | routing.cc:117075-117085 | Formula matches Eq. (4.1) in proposal |
| **Per-variant score** | `MCC_{s,m}` computed separately for each S1–S8 and OBU/RSU mode | ⚠ Partial | routing.cc:117033-117100 | Computed per variant v=0..7 in arrays `current_MCC[v]`, but: (1) No mode stratification (OBU vs RSU separate); (2) OBU and RSU detections are merged into single TP/FP/TN/FN per variant |
| **Mobility-stratified score** | `MCC_s[ρ_b, v̄_b]` binned by vehicle density/speed | ✗ Missing | — | No code computes `MCC_s[low/medium/high, low/high]` breakdowns; proposal requires validation that mobility adjustment (Eq. mobility_baseline) works |
| **FPR constraint** | FPR ≤ 1% hard constraint; hyperparameters rejected if violated | ✓ Computed | routing.cc:117068-117073 | FPR calculated per variant, written to CSV as `cur_FPR, avg_FPR` |
| **CSV export** | MCC, per-variant MCC, per-mode MCC, FPR written per cycle | ⚠ Partial | routing.cc:117329-117334 | **Only selected_variant written to CSV** (line 117233: `int selected_variant = (active_attack_variant >= 0) ? active_attack_variant : 0;`). All 8 variants computed in-memory (sec_TP[0..7], current_MCC[0..7], current_detection_rate[0..7], current_FPR[0..7]) but only one variant's data serialized. **7 variants' metrics discarded per cycle.** No mode stratification in CSV output |

**Deviations:**
- **CRITICAL:** All eight variants' metrics are computed correctly in memory every simulation cycle, but CSV writer (line 117233) selects only `selected_variant` and writes its confusion matrix and derived metrics to CSV. This means if you run with `active_attack_variant=0`, you get metrics for S1 only; metrics for S2–S8 are computed and thrown away. **This makes it impossible to extract per-variant MCC/DR/FPR from CSV output without modifying the writer.**
- **HIGH:** No OBU/RSU mode stratification. Proposal calls for `MCC_{s,m}` where m ∈ {OBU, RSU}, but the code merges both modes' detections into single TP/FP/TN/FN before MCC computation.
- **HIGH:** No mobility-stratified MCC (requires post-processing of simulation logs with vehicle density/speed bins; not computed at runtime).

---

### M2 — Safety-Critical Threshold Violation Rate (TVR)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `TVR = \|{p ∈ P_crit : δ_p(v,r,t) > Δ_max}\| / \|P_crit\|` | ✓ Correct | routing.cc:117152-117172 | Formula matches proposal (safety-critical packets only, threshold comparison against Δ_max = 50 ms) |
| **Computation** | Per-hop forwarding delay `δ_p` anchored to distributed time reference `T_ref(t)` (Eq. delay_updated) | ✗ Incomplete | routing.cc:114663-114675 (comment block) | Counters `g_tvr_crit_total` and `g_tvr_violated` are incremented at RSU receive points, but: (1) **No distributed time reference normalization**—code uses simulator wall-clock time, not `T_ref(t)` from Eq. delay_updated; (2) Handoff-induced latency jitter is not normalized out |
| **Packets never forwarded** | Assigned `δ_p = ∞ > Δ_max` (Eq. nfwd_detect) | ✗ Missing | — | No code path sets `δ_p = ∞` for non-forwarded packets within the observation window. Current implementation only counts packets that are forwarded and exceed threshold; lost/dropped packets excluded |
| **TVR trend** | TVR ≈ 0 under no attack; rises with attack intensity; returns toward 0 post-quarantine | ✓ Expected | routing.cc:117161-117172 | Code structure supports this, but effectiveness depends on whether quarantine actually fires (tied to M4 latency working) |
| **CSV export** | TVR per cycle, per variant (Variants 1–4 only) | ✗ Missing | routing.cc:117287-117290 | **TVR is NOT written to CSV**. Function `calculate_tvr_metric()` computes `current_TVR` and `average_TVR` and prints to console, but `write_security_metrics_csv()` does not include TVR columns. Proposal M2 cannot be evaluated from CSV output |

**Deviations:**
- **CRITICAL:** TVR is computed but **not exported to CSV**. Proposal Table 4.1 lists TVR as M2 primary metric for Benchmarking Experiments BE1–BE5; evaluation tables in proposal (Tables 5.1–5.5) show TVR results, but this metric is only available in console logs, not in CSV for downstream analysis.
- **HIGH:** Distributed time reference normalization (`T_ref(t)` from Eq. delay_updated) is not used in TVR calculation. Proposal Eq. TVR explicitly normalizes `δ_p(v,r,t)` to distributed reference to remove handoff jitter; code uses absolute wall-clock latency instead. This means legitimate handoff-induced latency spikes might be counted as violations, biasing TVR upward under high-mobility conditions.
- **MEDIUM:** Non-forwarded packets not assigned `δ_p = ∞`; only actually-forwarded packets counted. If a critical packet is dropped/not forwarded before timeout, it may not increment `g_tvr_violated`, missing that failure.

---

### M3 — Unauthorized Copy Rate (UCR)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `UCR = \|{p ∈ P_total : ∃d' ∉ P(s_p,d_p), p ∈ R(d',W)}\| / \|P_total\|` | ✓ Correct | routing.cc:117175-117208 | Formula matches proposal: count packets with unauthorized copies / total packets |
| **Numerator** | Distinct (flow, pkt) pairs received at unauthorized destination (via `fade_eavesdrop_counter`, deduplicated in `efade_detection.h`) | ✓ Implemented | routing.cc:117196-117197 | Uses `fade_eavesdrop_counter` which aggregates both active HF (variants 5/6, content modified) and passive HF (variants 7/8, content unchanged) |
| **Denominator** | Total packets across all active flows (`P_total`) | ✓ Implemented | routing.cc:117188-117194 | Sums `f_size` across all flows (2*flows flows in demanding_flow_struct) |
| **Per-variant UCR** | UCR computed separately for Variants 5–8 | ✗ Missing | routing.cc:117186-117208 | Single aggregate `current_UCR` and `average_UCR` computed; no variant-level breakdown. Proposal requires separate UCR per variant to assess each HF attack's containment independently |
| **CSV export** | UCR per cycle, per variant (Variants 5–8 only) | ✗ Missing | routing.cc:117287-117290 | **UCR is NOT written to CSV**. Similar to TVR, `current_UCR` computed and printed to console only; not in CSV columns |
| **Active vs passive distinction** | Active variants (5,6): copy has modified content verified via ML-DSA-87.Verify=0; Passive (7,8): copy unmodified, detected via blockchain-committed policy `P(s,d)` | ⚠ Partial | routing.cc:117177-117182 comment | Comment documents the distinction, but code does not separate active/passive UCR or report which signature (S5/S6 vs S7/S8) detected each unauthorized copy |

**Deviations:**
- **CRITICAL:** UCR is computed but **not exported to CSV**. Same as TVR—proposal evaluation tables show UCR results (Tables 5.1–5.5, BE1–BE5), but metric is only in console logs.
- **HIGH:** No per-variant UCR breakdown. All 8 variants' eavesdropped packets are pooled into single `fade_eavesdrop_counter`. If variant 5 has high UCR but variant 8 is low, this is masked in aggregate UCR. Proposal Table 4.1 specifies per-variant metrics; this prevents that.
- **MEDIUM:** No distinction between active/passive detection in output. Code internally tracks which signatures fired (S5/S6 for active, S7/S8 for passive), but UCR metric doesn't report this split.

---

### M4 — Node/Flow Mitigation Latency (L_mit)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `L_mit = t_quarantine - t_onset` (ms) | ✓ Correct | routing.cc:117103-117149 | Formula matches proposal; reports elapsed time from attack onset to quarantine |
| **t_onset** | Timestamp of first attack-conforming packet | ✓ Implemented | routing.cc:117119 | Code checks `t_onset[n] > 0.0` (pre-populated by attack injection logic) |
| **t_quarantine** | Timestamp when SC.Quarantine(v) executed (smart contract quarantine) | ⚠ Partial | routing.cc:117119 | Code checks `t_quarantine[n]` array, but **no code path sets t_quarantine[n]** in routing.cc. Values would need to be populated by blockchain smart-contract execution (mobiguard-cc chaincode), but that boundary is not wired in the ns-3 simulation. This means L_mit will always be 0 or uninitialized (valid_count remains 0) |
| **Target bound** | L_mit ≤ 100 ms | ✓ Code | routing.cc:117126 | Hardcoded 100 ms check and warning |
| **Per-node latency** | Reported for each node individually | ✓ Computed | routing.cc:117121-117132 | Loop computes `lmit = t_quarantine[n] - t_onset[n]` per node, accumulates total |
| **Average & cumulative** | Running average across all mitigation events | ✓ Implemented | routing.cc:117135-117148 | Computes `average_mitigation_latency` as cumulative average |
| **CSV export** | L_mit per cycle | ✓ Implemented | routing.cc:117335, 117336 | Written as `cur_mit_ms, avg_mit_ms` (converted to milliseconds) |

**Deviations:**
- **CRITICAL:** `t_quarantine[n]` is read but never populated. The ns-3 simulation has no callback/interface to set this timestamp when the blockchain smart contract fires `SC.Quarantine(v)`. Until blockchain logic is integrated with ns-3 time-stepping, mitigation latency will always compute as 0 ms (valid_count remains 0, average defaults to 0). **M4 is not measurable in the current ns-3 standalone simulation.**
- **MEDIUM:** Proposal calls for "elapsed time from attack onset to successful smart contract quarantine," implying the metric validates the full pipeline (detection → trust update → blockchain write → quarantine contract execution → ns-3 simulation reads result). Current code only has the ns-3 read side; no execution-side integration.

---

### M5 — Controller Failover Latency (L_failover) [Ablation only]

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `L_failover = max_{k ∈ K_affected}(t_reassign^(k) - t_revoke)` (ms) | ✗ Missing | — | **No implementation found** |
| **t_revoke** | Timestamp when SC.Revoke(c_i) fires (controller revoked) | ✗ Missing | — | No timestamp tracking for controller revocation |
| **t_reassign^(k)** | Timestamp when RSU r_k completes reassignment to new controller | ✗ Missing | — | No timestamp tracking for RSU failover completion |
| **Worst-case max over all RSUs** | Max latency to capture stragglers | ✗ Missing | — | No per-RSU failover tracking |
| **Target bound** | L_failover ≤ 100 ms | ✗ Missing | — | Not enforced or measured |
| **Evaluation scenarios** | 0, 1, and 2 compromised controllers | ✗ Missing | — | No multi-controller failover test mode; attack_declaration.h has single `active_controller_id` (int), not array |
| **Ablation context** | Evaluated only in AB9 (Controller Failover ablation) | ✗ Missing | — | AB9 not yet wired in codebase; SIGNATURE_ATTACK_DECOUPLING_PLAN.md Phase 3 defines it but not implemented |

**Summary:** M5 is **completely unimplemented**. No timestamps are captured for controller revocation or RSU failover. No CSV export, no console logging, no ablation branch.

---

### M6 — Overall System Latency (L_e2e)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `L_e2e = (1/\|P_total\|) * Σ_p(t_recv_final(p) - t_send(p))` (ms) | ✓ Correct | routing.cc:116782-116819 | Formula matches proposal; computes mean per-packet latency end-to-end |
| **t_send** | Source transmission timestamp, anchored to `T_ref(t)` | ⚠ Partial | routing.cc:116800-116810 | Code uses simulator wall-clock time (`Now().GetSeconds()`), not distributed time reference `T_ref(t)`. This means L_e2e is not normalized to distributed time; if RSU clocks are desynchronized, L_e2e will include sync offset in addition to true latency |
| **t_recv_final** | Reception timestamp at final authorized destination | ✓ Implemented | routing.cc:116810 | End-to-end reception time computed |
| **Per-hop accumulation** | Summed across all hops (includes detection, crypto, blockchain overhead) | ✓ Implemented | routing.cc:116800-116810 | Total latency includes routing, detection, mitigation (if applicable) |
| **Evaluated under attack & post-mitigation** | L_e2e measured before and after quarantine | ⚠ Partial | routing.cc:116782-116819 | Code computes single aggregate L_e2e per cycle; no before/after quarantine split within same run. Proposal requires comparing "latency under attack" vs "latency post-mitigation" separately |
| **Compared against baselines** | B1 (TAP), B2 (SFTO-Guard), B3 (FADE) | — | — | Baseline code (FADE) has parallel latency computation (fade_write_per_cycle_csv); baselines B1/B2 not implemented in codebase |
| **100 ms safety-critical bound** | Benchmark against safety constraint | ✓ Code | routing.cc:116819 | Printed to console but not explicitly validated in CSV |
| **CSV export** | L_e2e per cycle | ✓ Implemented | routing.cc:117327-117328 | Written as `cur_lat_ms, avg_lat_ms` (converted to milliseconds) |

**Deviations:**
- **HIGH:** Distributed time reference not used. Proposal explicitly states `t_send` and `t_recv_final` anchored to `T_ref(t)` (Eq. delay_updated), which normalizes out clock skew from Byzantine-compromised RSUs. Code uses absolute wall-clock time. For validation of Eq. delay_updated correctness, this matters (M9 ablation), but for plain latency measurement, it's acceptable if clock skew is small.
- **MEDIUM:** No before/after quarantine distinction. Proposal narrative (Section 5.1) suggests comparing "L_e2e under active attack" vs "L_e2e post-quarantine" to show mitigation effectiveness. Code computes single aggregate; would need post-processing to extract pre-quarantine and post-quarantine windows separately.
- **MEDIUM:** 100 ms bound not enforced in CSV; only printed to console as informational.

---

### M7 — Security Processing and Consensus Overhead [Ablation/context only]

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Sub-metric 1: O_crypto** | Per-packet cryptographic communication overhead: `O_crypto^(n) = n·\|σ_i\| + \|π_delay\| + \|π_hop\|` | ✗ Missing | — | (1) `\|σ_i\| = 4,595 bytes` (ML-DSA-87 signature) — documented in comments (routing.cc:117287 comment says this), but not actually computed/exported; (2) `\|π_delay\|, \|π_hop\|` proof sizes — not logged; (3) Per-packet, per-hop overhead not broken down in CSV |
| **Sub-metric 2: T_verify(B)** | RSU batch verification processing time as function of batch size: `T_verify(B) = T_batch(B) + T_STARK` | ✗ Missing | — | (1) `T_batch(B)` — no instrumentation of `batch_verify_mldsa87()` wall-clock time; (2) `T_STARK` — no per-packet STARK.Verify latency measurement; (3) No batch-size sweep (B=1,5,10,20,...) |
| **Sub-metric 3: T_consensus** | Blockchain endorsement consensus latency: `T_consensus = t_commit - t_FlowMod_recv` (Eq. t_consensus) | ✗ Partial | routing.cc:117348-117349 | Code writes `g_rsu_commit_hashes.size()` (RSU-chain length) and `g_bc_global_commit_count` (global chain length) to CSV, but does NOT compute or export wall-clock consensus time `T_consensus`. Proposal requires latency from FlowMod arrival to blockchain commit completion; code only exports final chain size, not the time taken |
| **CSV export** | O_crypto, T_verify(B), T_consensus per cycle | ✗ Missing | routing.cc:117287-117290 | (1) Cryptographic overhead not in CSV; (2) Verification latency not in CSV; (3) Consensus latency not in CSV. CSV includes `sig_valid_rate, stark_timing_fail_count, stark_hop_fail_count, flowmod_endorsement_rate` (partial submetrics only) |
| **Ablation context** | Evaluated in AB4 (STARK proofs), AB6 (witness), AB8 (endorsement), AB11 (key rotation) | ✗ Missing | — | Ablation infrastructure not yet wired; M7 submetrics not available per ablation configuration |

**Summary:** M7 has only **partial, fragmented data points** in CSV (sig_valid_rate, flowmod_endorsement_rate, chain lengths) but **lacks comprehensive overhead analysis**. Proposal calls for three integrated sub-metrics (O_crypto, T_verify, T_consensus) showing the cost of the security layer; the current output gives raw counters but not the latency/overhead framing Proposal requires.

**Deviations:**
- **CRITICAL:** Wall-clock timing of cryptographic and consensus operations not instrumented. `batch_verify_mldsa87()`, `stark_verify_timing()`, `stark_verify_hop()` are called but not timed. Blockchain consensus is logged as count, not duration. Proposal M7 requires detailed timing breakdown; this is missing.
- **HIGH:** Per-packet cryptographic communication overhead (O_crypto) not computed or exported. Proposal Eq. overhead_full specifies exact byte counts; current code knows `\|σ_i\| = 4627 bytes` (CRYPTO_CORRECTIONS.md DOC-1) but doesn't export per-packet overhead to CSV.

---

### M8 — Federated Model Poisoning Resistance [Ablation only]

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `Δ_poison(ρ_mal) = MCC_clean - MCC(ρ_mal)` — MCC degradation as malicious RSUs poison gradients | ✗ Missing | — | **No implementation found** |
| **Experiment setup** | (1) MCC_clean with 0 malicious RSUs; (2) MCC(ρ_mal) with ρ_mal ∈ {0.1, 0.2, ..., 0.3} (up to PBFT bound f < n/3) | ✗ Missing | — | No configuration to enable/disable gradient poisoning attacks per RSU; no separate training runs with varying poison fractions |
| **Algorithm BRFA-v2 components** | Test three: (1) trust-gating (Step 1), (2) hash verification (Step 2), (3) Krum filtering (Step 3) | ✗ Missing | — | Algorithm BRFA-v2 federated aggregation not implemented in codebase; no Byzantine-robust aggregation layer in LSTM training pipeline |
| **Comparison** | BRFA-v2 vs naive FedAvg | ✗ Missing | — | No baseline comparison; FedAvg not instrumented |
| **Target bound** | Δ_poison(ρ_mal < 1/3) ≈ 0 (i.e., robustness to Byzantine fault tolerance bound) | ✗ Missing | — | No validation that robustness holds up to f < n/3 |
| **CSV export** | Δ_poison per poisoning fraction | ✗ Missing | — | Not in CSV; would be separate LSTM evaluation output, not part of per-cycle security metrics CSV |

**Summary:** M8 is **completely unimplemented**. No federated LSTM poisoning attack/defense infrastructure exists in ns-3 scratch/ directory. Proposal requires federated learning pipeline with Byzantine-robust aggregation; current codebase has no LSTM training or aggregation code.

---

### M9 — Distributed Time Reference Robustness [Ablation only]

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `ε_ref(f_bad) = \|T_ref(t) - T_ground(t)\|` — time reference deviation under f_bad compromised RSU clocks | ✗ Missing | — | **No implementation found** |
| **Formal guarantee** | `T_ref(t)` remains within honest clock range when `f_bad < n_RSU/2` RSU clocks compromised | ✗ Missing | — | Equation eq:time_consensus (time consensus algorithm bound) not validated |
| **T_ground(t)** | GPS ground truth timestamp from simulation | ✗ Missing | — | No ground-truth time source integrated; no simulation-time reference available for comparison |
| **Attack variation** | `f_bad ∈ {0, 1, ⌊n_RSU/4⌋, ⌊n_RSU/2⌋ - 1}` — sweep to confirm bound failure at f_bad = n_RSU/2 | ✗ Missing | — | No configuration to selectively corrupt f_bad RSU clocks |
| **Validation** | Confirm robustness holds for all f_bad < n_RSU/2, fails at f_bad = n_RSU/2 | ✗ Missing | — | No validation infrastructure |
| **CSV export** | ε_ref per compromised-clock count | ✗ Missing | — | Not in CSV; would be separate distributed-sync ablation output |
| **Implementation status** | `update_T_ref()` function exists (crypto_layer.h:683–694) | ⚠ Partial | crypto_layer.h:683-694 | Function computes median of N RSU clocks (comment says "stub, not real distributed sync"), but: (1) No clock offset injection for Byzantine scenario; (2) No deviation measurement against ground truth; (3) Called internally but metric not exported |

**Summary:** M9 is **completely unimplemented** as an evaluation metric. The underlying `update_T_ref()` function exists as a stub (documented in CRYPTO_CORRECTIONS.md), but the metric evaluation framework—clock offset injection, deviation measurement, and per-corruption-count reporting—is absent.

---

### M10 — Privacy Leakage / Raw Data Exposure (L_priv)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `L_priv = Σ_{d ∈ D_raw} w_d · 𝟙[d transmitted beyond local trust boundary]` | ✗ Missing | — | **No implementation found** |
| **Raw data categories** | `D_raw = {location history, vehicle identity, trajectory, raw packet headers, raw flow metadata}` | ✗ Missing | — | No tracking of which data is transmitted beyond RSU trust boundary |
| **Privacy weights** | `w_d ∈ [0,1]` — location/identity w_d=1 (highest), flow metadata w_d=0.5 | ✗ Missing | — | No weighting scheme implemented |
| **Evaluation approach** | Architectural analysis (not runtime output) — compare frameworks' published designs | — | — | Proposal states "computed from each baseline's published design rather than a runtime output." This is a **design review metric**, not a runtime metric. Current codebase only tracks runtime metrics, not architectural privacy evaluation |
| **MOBIGUARD baseline** | L_priv = 0 (only model weights, hash commitments, proofs transmitted) | — | — | No verification that non-sensitive data is being sent; packet inspection not instrumented |
| **Baseline comparisons** | HSA: L_priv = w_headers + w_trajectory; TAP: L_priv = w_vehicle_identity; FADE: L_priv = ? | ✗ Missing | — | No framework to compare against baselines' privacy claims |
| **CSV export** | L_priv metric not expected (architectural, not runtime) | — | — | Not applicable for per-cycle CSV |

**Summary:** M10 is **not applicable as runtime metric** in the current codebase. Proposal Eq. l_priv is explicitly an architectural evaluation ("computed from each baseline's published design"), not a per-cycle runtime measurement. Current code has no hooks for packet-level privacy tracking.

**Note:** If privacy analysis is desired, it would require: (1) packet inspection hooks logging what data leaves each RSU, (2) comparison against baseline architectures' data flows (requires baseline code), (3) external privacy audit tooling.

---

### M11 — Unauthorized FlowMod Containment Rate (UFCR)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `UFCR = \|{FM ∈ FM_unauth : FM blocked before installation}\| / \|FM_unauth\|` | ✗ Missing | — | **No implementation found** |
| **Unauthorized FlowMod set** | `FM_unauth = {FM : f_unauth(r_k, t) = 1}` — FlowMods without valid blockchain commitment `C_P` (Eq. endorsed_commit) | ✗ Missing | — | No tracking of unauthorized FlowMod attempts; no f_unauth function call in flow-rule installation path |
| **Blocking mechanism** | Count FlowMods blocked before RSU installation | ✗ Missing | — | No pre-installation authorization check (RSU would need to query blockchain `C_P` before installing rule) |
| **Expected behavior** | Under Variants 1, 3, 5, 7 (control-plane attacks): target UFCR = 1.0 (all unauthorized FlowMods blocked) | ✗ Missing | — | No attack injection for these variants; attack_declaration.h only supports data-plane attacks (Variants 0–7 inconsistent with proposal Variants 1–8) |
| **Normal operation** | Under no attack: `\|FM_unauth\| = 0`, so UFCR undefined (0/0) | ✗ Missing | — | No conditional logic to skip UFCR when numerator is 0 |
| **CSV export** | UFCR per cycle (Variants 1, 3, 5, 7 only) | ✗ Missing | — | Not in CSV columns |

**Summary:** M11 is **completely unimplemented**. No unauthorized FlowMod tracking, no pre-installation authorization check, no control-plane attack injection for Variants 1, 3, 5, 7.

**Dependency:** M11 requires:
1. Control-plane attack injection (Variants 1, 3, 5, 7 where controller injects unauthorized FlowMods)
2. Pre-installation authorization check at RSU (query blockchain for valid `C_P` before installing rule)
3. FlowMod-level tracking (count attempts vs blocks)

None of these are wired in the current codebase.

---

### M12 — Witness Alert Precision and Recall (WAP-R) [Ablation only]

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition (Precision)** | `P_W = TP_W / (TP_W + FP_W)` — fraction of 2f+1-threshold alert events that are true | ✗ Missing (incomplete computation) | — | Witness mechanism exists (crypto_layer.h:781–896, witness_submit_duplication_alert/witness_submit_nfa_alert) and alerts are logged in `g_witness_alert_pool`, but precision/recall metrics not computed |
| **Definition (Recall)** | `R_W = TP_W / (TP_W + FN_W)` — fraction of true passive HF instances where 2f+1 valid alerts submitted | ✗ Missing (incomplete computation) | — | Same issue: alerts logged but not evaluated against ground truth |
| **TP_W** | Count of 2f+1-threshold alert events that correctly identify true passive HF instance | ✗ Missing | — | No comparison between witness alert triggers and ground-truth passive HF attack status |
| **FP_W** | Count of threshold events triggered by false witness coalition | ✗ Missing | — | No tracking of spurious alert coalitions vs legitimate attacks |
| **FN_W** | Count of true passive HF instances where fewer than 2f+1 valid alerts submitted (witness density insufficient) | ✗ Missing | — | No measurement of detection miss rate due to insufficient witness coverage |
| **Validation targets** | (1) `P_W` validates false-accusation resistance (threshold robustness); (2) `R_W` validates feasibility (f=1 requires 3 witnesses, achievable under mean vehicle density ≈ 3.1 vehicles per RSU) | ✗ Missing | — | No vehicle density binning; no per-RSU witness count statistics |
| **Variants 7–8 specific** | Evaluated only against passive hidden forwarding (Variants 7–8) where cryptographic proof insufficient | ✓ Targeted | — | Code correctly targets S7/S8, but metric computation missing |
| **CSV export** | P_W, R_W per cycle (Variants 7–8 only) | ✗ Missing | — | Not in CSV; `_da_count` and `_nfa_count` (duplication/non-forward alert counts) are exported but not precision/recall |

**Summary:** M12 is **partially implemented** (witness mechanism exists and alerts are logged) but **metric evaluation missing**. The infrastructure to count TP_W/FP_W/FN_W and compute precision/recall does not exist.

**Current partial implementation:**
- ✓ Witness alerts submitted via `witness_submit_duplication_alert()` and `witness_submit_nfa_alert()` (crypto_layer.h:781–896)
- ✓ Alert pool (`g_witness_alert_pool`) accumulates alerts with 2f+1 BFT threshold (crypto_layer.h:147–167)
- ✓ Trust penalties triggered on 2f+1 threshold (crypto_layer.h:750–780)
- ✗ No comparison against ground truth (which packets are truly duplicated at unauthorized destinations?)
- ✗ No per-attack-instance tracking (associate alerts with Variant 7/8 instances)
- ✗ No metric computation (TP_W, FP_W, FN_W never counted)

---

## Summary Table: Metrics Implementation Status

| Metric | Proposal | Code | CSV | Ablation | Notes |
|--------|----------|------|-----|----------|-------|
| **M1 (MCC)** | ✓ Eq. mcc | ✓ routing.cc:117075 | ✓ Single variant (by design) | ✓ (partial) | Per-variant via separate runs → separate files (proposal + reference idiom); NOT a bug |
| **M2 (TVR)** | ✓ Eq. tvr | ✓ routing.cc:117158 | ✅ In CSV (Step 1) | — | Exported 2026-07-06; no T_ref normalization (open) |
| **M3 (UCR)** | ✓ Eq. ucr | ✓ routing.cc:117186 | ✅ In CSV (Step 1) | — | Exported 2026-07-06; aggregate only (per-variant via separate runs) |
| **M4 (L_mit)** | ✓ Eq. l_mit | ⚠ routing.cc:117111 | ✓ Written | — | t_quarantine never populated; metric always 0 |
| **M5 (L_failover)** | ✓ Eq. l_failover | ✅ crypto_layer.h (Step 3) | ✅ In CSV (Step 3) | ✓ AB9-ready | Implemented 2026-07-07: broadcast-propagation delay model + t_revoke/t_reassign stamps + 3 CSV columns |
| **M6 (L_e2e)** | ✓ Eq. l_e2e | ✓ routing.cc:116782 | ✓ Written | — | No T_ref normalization; no before/after split |
| **M7 (Overhead)** | ✓ Eq. o_crypto, t_verify, t_consensus | ⚠ Partial | ⚠ Partial | ✓ (partial) | Only sig_valid_rate, flowmod_endorsement_rate; missing T_verify, T_consensus |
| **M8 (Poisoning)** | ✓ Eq. delta_poison | ✗ Missing | ✗ | ✗ AB8 | No Byzantine poisoning attack/defense in LSTM |
| **M9 (Time Ref)** | ✓ Eq. eps_ref | ✗ Missing (metric) | ✗ | ✗ AB9 | update_T_ref() exists as stub; no evaluation |
| **M10 (Privacy)** | ✓ Eq. l_priv | ✗ N/A (architectural) | ✗ | — | Design review metric; not runtime-measurable |
| **M11 (UFCR)** | ✓ Eq. ufcr | ✗ Missing | ✗ | — | No control-plane attack injection; no authorization checks |
| **M12 (WAP-R)** | ✓ Eq. wap, war | ⚠ Partial | ✗ Missing | ✗ AB6 | Witness mechanism exists; metric computation missing |

---

## Critical Cross-Metric Issues

### 1. **Single-Variant CSV Export (affects M1, M2, M3) — RESOLVED: NOT A BUG**

**Original observation:** All 8 variants' metrics are computed every cycle but only `selected_variant` is written to CSV.

```cpp
int selected_variant = (active_attack_variant >= 0) ? active_attack_variant : 0;
// ... later in write_security_metrics_csv():
fout << current_MCC[selected_variant] << ", "
     << current_detection_rate[selected_variant] << ", "
     << current_FPR[selected_variant] << ", "
     << sec_TP[selected_variant] << ", "
     << sec_FP[selected_variant] << ", "
     << sec_TN[selected_variant] << ", "
     << sec_FN[selected_variant];
```

**Resolution (2026-07-07):** This is **correct, intended behavior** — not a defect. Single-variant
export is the right design, confirmed by three independent sources:

1. **Proposal (main.tex:4945):** Experiment 5 explicitly states all 8 variants are evaluated
   *"in separate simulation runs (one variant active at a time) to produce per-variant scores."*
   The proposal expects **one active variant per run**, one file per variant.

2. **Supervisor's reference code idiom** (`reference/routing.cc`, `write_csv_results_routing()` /
   `write_csv_results()`): the sweep dimension (lambda, node count, mobility speed, framework) is
   encoded in the **filename** via nested `switch` statements, NOT multiplied into columns. Each
   run produces one file with a **fixed column schema**, one row per cycle. To sweep a variable,
   the simulation is run multiple times — each run emits its own file. There is no loop that widens
   a single row across configuration points.

3. **Existing MOBIGUARD filename scheme** already follows this idiom:
   `MOBIGUARD_Attack{N}_{pct}{suffix}.csv` — one file per (variant × percentage).

**Why exporting all 8 variants per run would be WRONG:** When a specific attack is armed
(`attack_number=1..8`), `declare_attack_states()` (attack_declaration.h:90-95) enables exactly one
`s*_detection_active` gate and leaves the other seven off. The non-active variants therefore have
`is_detected_node[v][n] = false` for all nodes, producing trivial/garbage confusion matrices
(TP=0, FP=0, TN=all, FN=0). Serializing those 7 garbage variants alongside the 1 real one would
pollute the CSV with meaningless columns.

**Decision:** Keep `selected_variant` single-variant export. Per-variant breakdown (Tables 5.1–5.5)
is produced by running 8 separate simulations → 8 files, exactly as the reference sweeps its
lambda / node-count / mobility variables.

**History:** A "widen to all 8 variants per row" change was briefly implemented (Step 2) and then
**reverted** on 2026-07-07 after the reference-code idiom confirmed single-variant-per-file is the
supervisor-aligned design. Step 1's TVR/UCR column additions (see Issue #2 below) were retained.

### 2. **Missing TVR and UCR in CSV (affects M2, M3) — DONE (Step 1, 2026-07-06)**

**Problem (was):** TVR and UCR were computed every cycle but not written to CSV.

```cpp
// calculate_tvr_metric() computes current_TVR and prints to console
// calculate_ucr_metric() computes current_UCR and prints to console
// But write_security_metrics_csv() did NOT include these columns
```

**Impact (was):**
- Proposal evaluation tables (5.1–5.5) show TVR and UCR per experiment
- CSV only had MCC, DR, FPR for detection quality
- TVR and UCR data only available in console logs (requires manual parsing)

**Fix applied (Step 1):** Added four columns to the fixed CSV schema — header
(routing.cc:117283) and data row (routing.cc:117341-344):
```cpp
fout << ", " << (current_TVR * 100.0) << ", " << (average_TVR * 100.0)
     << ", " << (current_UCR * 100.0) << ", " << (average_UCR * 100.0);
```
Values are written as percentages (0–100) to match the FPR format. This is a clean widening of the
single-variant fixed schema and is fully consistent with the reference-code idiom (Issue #1).
**Status: implemented and verified.**

### 3. **No Ablation Study Infrastructure**

**Problem:** Proposal defines 13 ablation studies (AB1–AB13) and SIGNATURE_ATTACK_DECOUPLING_PLAN.md Phase 3 specifies concrete gate implementations, but codebase has no ablation flags wired.

**Impact:**
- Proposal evaluation (Section 5.2, Tables 5.6–5.18) shows per-ablation metrics
- Current code has single monolithic configuration; no way to toggle components on/off
- All 13 ablations require different runs with different compiled code, not runtime flags

**Fix required:** Implement Phase 3 flags from SIGNATURE_ATTACK_DECOUPLING_PLAN.md:
- AB1: `enable_lrad_obu`, `enable_lrad_rsu` (split detection mode)
- AB4: `enable_stark_delay`, `enable_stark_hop` (STARK proof gates)
- AB6: `enable_witness_mechanism` (witness alerts)
- AB7: `enable_quarantine` (trust-based quarantine)
- AB8: `enable_endorsement_requirement` (FlowMod f+1 endorsement)
- AB9: `enable_controller_failover` (multi-controller failover)
- AB11: `enable_key_rotation` (DKG key rotation)

### 4. **No Per-Mode Stratification (affects M1)**

**Problem:** M1 (MCC) requires per-mode scores (`MCC_{s,m}` where m ∈ {OBU, RSU}), but code merges both modes.

```cpp
// Code computes TP/FP/TN/FN by merging OBU and RSU detections
for (int n = 0; n < active_topology_nodes; n++) {
    bool malicious = is_malicious_node[v][n];
    bool detected  = is_detected_node[v][n];  // Could be from OBU or RSU
    if (malicious  && detected)  sec_TP[v]++;
    // ...
}
```

**Impact:**
- Proposal calls for separate OBU-mode and RSU-mode MCC curves (Tables 5.1–5.5 show "MOBIGUARD-OBU" and "MOBIGUARD-RSU" per variant)
- Current code produces single aggregate MCC per variant
- Cannot evaluate whether OBU detection is weaker than RSU (which proposal expects: OBU handles S1–S4, RSU handles S2f/S5–S8)

**Fix required:**
- Track detection source (OBU vs RSU) for each packet
- Compute separate confusion matrices per mode per variant
- Export separate M1_OBU[v] and M1_RSU[v] columns to CSV

---

## Recommended Remediation Priority

### **Tier 1: Critical (blocks validation of any evaluation results)**
1. ✅ **DONE — Fix TVR/UCR CSV export** — Added 4 columns (cur_TVR, avg_TVR, cur_UCR, avg_UCR) to CSV writer
   - **Effort:** 1 hour
   - **Impact:** Enables M2/M3 evaluation from single CSV (no console log parsing)
   - **Completed:** 2026-07-06 (routing.cc:117283 header, 117341-344 data row)

2. ~~**Fix single-variant metric export** — Widen CSV to include all 8 variants~~ — **CANCELLED (not a bug)**
   - Single-variant export is the **correct, intended design** — confirmed by proposal
     (main.tex:4945, "separate simulation runs, one variant active at a time") and by the
     supervisor's reference-code idiom (sweep dimension in filename, fixed columns, one file per run).
   - A widening change was implemented then **reverted** on 2026-07-07. See Critical Issue #1 above.
   - Per-variant tables come from 8 separate runs → 8 files, not one wide CSV.

3. ✅ **DONE — Wire controller failover for M5** — Timestamp tracking + propagation-delay model + CSV export
   - **Effort:** 4 hours
   - **Impact:** Enables M5 (L_failover) measurement for AB9 ablation
   - **Completed:** 2026-07-07. Implementation notes:
     - **Problem found first:** `ctrl_reassign_rsus()` originally ran synchronously inside
       `ctrl_trust_update_negative()` — revoke and reassignment shared the same simulator
       timestamp, so eq:l_failover would always compute 0 ms (meaningless).
     - **Proposal-derived model:** eq:sc_revoke (main.tex:3356) states revocation is committed
       on-chain and a **ControllerRevoked event is broadcast**; each RSU re-executes failover
       *on receipt*. So the latency lives in event propagation under geographic dispersion —
       which is exactly why eq:l_failover takes the **max over affected RSUs** (stragglers).
     - **Implementation** (crypto_layer.h): failover target still chosen at `t_revoke` from
       `C_trusted(t)\{c_i}` (eq:ctrl_failover), but each RSU's reassignment completion is now
       `Simulator::Schedule`d at `FAILOVER_BCAST_BASE_MS + FAILOVER_BCAST_PER_ZONE_MS × min_d`
       (min_d = zone-index distance to the new controller — the same d(r_k,c_j) proxy the
       function already used, per CRYPTO_CORRECTIONS.md TRUST-4). New completion handler
       `ctrl_complete_rsu_reassign()` stamps t_reassign^(k), tracks the running max, and warns
       if > 100 ms (proposal target).
     - **New CLI params:** `--failover_bcast_base_ms` (default 10), `--failover_bcast_per_zone_ms`
       (default 1) — both registered in `crypto_register_cli_params()`.
     - **New CSV columns** (fixed-schema append, per reference idiom):
       `ctrl_failover_max_ms, ctrl_failover_events, ctrl_failover_reassigned`.
     - **Semantics:** `ctrl_failover_max_ms` holds L_failover of the most recent revocation
       event (0 if none — check `ctrl_failover_events` to distinguish "no failover" from fast
       failover). During the propagation window an RSU still points at the revoked controller —
       the realistic vulnerability window the metric is designed to expose.

### **Tier 2: High (needed for ablation studies)**
4. **Implement ablation gate flags (Phase 3)** — Add 7 CLI flags for AB1, AB4, AB6, AB7, AB8, AB9, AB11
   - **Effort:** 6 hours (code gating already sketched in SIGNATURE_ATTACK_DECOUPLING_PLAN.md)
   - **Impact:** Enables all 13 ablation experiments (Table 5.6–5.18)

5. **Add M7 wall-clock timing** — Instrument `batch_verify_mldsa87()`, `stark_verify_*()`, blockchain consensus with timers
   - **Effort:** 3 hours (add std::chrono calls around crypto functions)
   - **Impact:** Enables overhead breakdown for M7 (required for security layer cost analysis)

6. **Add M4 blockchain integration** — Set `t_quarantine[n]` when smart contract fires (requires blockchain simulator bridge)
   - **Effort:** 4 hours (depends on blockchain simulator callback mechanism)
   - **Impact:** Enables L_mit measurement (critical for assessing mitigation responsiveness)

### **Tier 3: Medium (needed for complete evaluation)**
7. **Add M12 witness metric computation** — Compare witness alerts against ground-truth HF attack status
   - **Effort:** 3 hours (post-processing of witness_alert_pool and ground truth attack flags)
   - **Impact:** Enables WAP-R evaluation for AB6 ablation

8. **Add M1 mode stratification** — Separate OBU vs RSU confusion matrices
   - **Effort:** 2 hours (track detection source per packet)
   - **Impact:** Enables per-mode MCC curves (validation that dual-mode works)

9. **Implement M9 time-reference evaluation** — Clock offset injection and deviation measurement
   - **Effort:** 4 hours (Byzantine clock attack simulation)
   - **Impact:** Enables T_ref robustness validation for distributed consensus

10. **Implement M8 Byzantine-robust aggregation** — Federated LSTM with Krum filtering
    - **Effort:** 8 hours (requires LSTM training pipeline; out of ns-3 scope)
    - **Impact:** Enables poisoning resistance validation for AB8

### **Tier 4: Low (design review, not runtime)**
11. **M10 Privacy Leakage** — Architectural review (not runtime metric); cite baseline designs from literature
    - **Effort:** 2 hours (literature review + design document)
    - **Impact:** Qualitative privacy analysis (no code change needed)

12. **M11 UFCR (control-plane attacks)** — Requires control-plane attack injection (Variants 1, 3, 5, 7)
    - **Effort:** 6 hours (implement FlowMod authorization checks + control-plane attack variants)
    - **Impact:** Complete coverage of all 8 attack variants (currently only data-plane variants 0–7 implemented)

---

## Deviations Summary (by Severity)

| Severity | Count | Metrics | Issue |
|----------|-------|---------|-------|
| **Critical** | 7 | M2, M3, M5, M8, M9, M11, M12 | Metrics computed but not exported, or completely unimplemented |
| **High** | 4 | M1, M4, M6, M7 | Partial implementation; missing validation or proper CSV export |
| **Medium** | 3 | M1, M10, M12 | Missing stratification or infrastructure |
| **Low** | 1 | M10 | Architectural evaluation (acceptable as literature citation) |

---

## Files Referenced

- `docs/main.tex:3476–3993` — Performance metrics specification (M1–M12, Equations eq:mcc through eq:war)
- `scratch/routing.cc:117031–117359` — Metrics calculation and CSV export
- `scratch/routing.cc:116782–116819` — Latency calculation (M6)
- `scratch/crypto_layer.h:683–694` — Distributed time reference (M9 infrastructure, stub)
- `scratch/crypto_layer.h:781–896` — Witness mechanism (M12 infrastructure, metric computation missing)
- `docs/SIGNATURE_ATTACK_DECOUPLING_PLAN.md:Phase 3` — Ablation gate implementations (M5, M7, M8, M9, M11, M12)
- `docs/CRYPTO_CORRECTIONS.md` — Cryptographic layer deviations (affects M4, M7, M11, M12 correctness)

---

## Conclusion

**The proposal specifies 12 comprehensive metrics across detection quality (M1), attack-specific containment (M2–M3), operational latency (M4–M6), security overhead (M7), Byzantine robustness (M8–M9), privacy (M10), control-plane defense (M11), and witness mechanisms (M12). Current implementation delivers only M1, M4, M6 at basic level, with M2, M3 computed but not exported, and M5, M7, M8, M9, M11, M12 largely unimplemented.**

**This represents a **8/12 metrics coverage gap** that must be closed before evaluation tables (Section 5, Tables 5.1–5.18) can be populated from actual simulation runs. Without these metrics, the thesis claims about detection quality, threshold violation containment, unauthorized copy containment, mitigation latency, failover responsiveness, security overhead, Byzantine resilience, and witness effectiveness cannot be empirically validated.**
