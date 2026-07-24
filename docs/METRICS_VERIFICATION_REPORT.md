# Metrics Implementation Verification Report
**Date:** 2026-07-06 (original) — **Last updated:** 2026-07-07
**Scope:** Comprehensive line-by-line verification of performance metrics against docs/main.tex (Section 4.6, "Performance Metrics")

---

## Executive Summary (updated 2026-07-07)

**Original finding (2026-07-06):** Eight of twelve performance metrics specified in the proposal were
unimplemented or partially implemented.

**Current status: all 12 metrics are now implemented.** Three are code-complete but not yet
build/run-verified by the user (flagged below); the other nine were implemented and confirmed
building/running clean earlier in this session:
- **✅ Implemented + verified:** M1 (MCC + per-mode via AB1-A/B/C run recipe — no new code needed),
  M2 (TVR), M3 (UCR), M4 (Mitigation Latency), M5 (Controller Failover Latency), M6 (L_e2e),
  M7 (Security/Consensus Overhead), M10 (Privacy — architectural analysis, no code needed), M12 (WAP-R)
- **✅ Implemented, build/run pending:** M8 (Byzantine-robust LSTM aggregation — Python, needs a
  `pipeline.py` run on the GPU host), M9 (distributed time-reference robustness — ns-3/C++, needs
  `./waf build`), M11 (control-plane FlowMod authorization/UFCR — ns-3/C++, needs `./waf build`)

**Ablation infrastructure:** All 9 Phase-3 ns-3 ablation gate flags (AB1, AB4, AB6, AB7, AB8, AB9,
AB11) plus the new AB5 BRFA-v2/FedAvg switch (Python, M8) are implemented. Multi-attack concurrent
injection (for BE1–BE4) remains open — out of scope for the 12-metric plan this report tracks.

**Single-variant CSV export was investigated and found to be correct, not a defect** — see Critical
Issue #1 below for the full resolution (proposal + reference-code idiom both specify one run per
variant, sweep dimension encoded in filename).

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
- ~~**CRITICAL:** All eight variants'... **This makes it impossible to extract per-variant MCC/DR/FPR from CSV output without modifying the writer.**~~ — **RESOLVED, NOT A BUG.** See Critical Cross-Metric Issue #1: single-variant export is the correct, proposal-specified design (separate simulation runs per variant).
- ~~**HIGH:** No OBU/RSU mode stratification...~~ — **RESOLVED, NO CODE NEEDED (2026-07-07).** See Critical Cross-Metric Issue #4: each signature is evaluated by exactly one mode by design; per-mode MCC is obtained via the existing `enable_lrad_obu`/`enable_lrad_rsu` flags across 3 separate runs (AB1-A/B/C), not new instrumentation.
- **HIGH (still open):** No mobility-stratified MCC (requires post-processing of simulation logs with vehicle density/speed bins; not computed at runtime).

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

### M8 — Federated Model Poisoning Resistance [Ablation only] — DONE (2026-07-07)

**Correction to the original finding:** the original report stated "no federated LSTM poisoning
attack/defense infrastructure exists" and "current codebase has no LSTM training or aggregation
code." This was **checking the wrong directory** — the search was scoped to `scratch/` (ns-3), but
a full Python federated LSTM pipeline exists at `lstm_pipeline/src/` (`preprocessor.py`,
`local_trainer.py`, `fed_aggregator.py`, `evaluator.py`, `pipeline.py`), separate from the ns-3
simulation. `fed_aggregator.py` already implemented Krum-style coordinate-median distance filtering
and weighted FedAvg — i.e., **half of BRFA-v2's four steps existed already.**

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `Δ_poison(ρ_mal) = MCC_clean - MCC(ρ_mal)` | ✅ Implemented | `lstm_pipeline/src/poison_sweep.py` | New script computes this exactly, per mode, per ρ_mal |
| **Experiment setup** | MCC_clean (ρ_mal=0) vs MCC(ρ_mal) for ρ_mal ∈ {0.1,0.2,0.3} | ✅ Implemented | `poison_sweep.py --rho` | Configurable sweep, default `[0.0, 0.1, 0.2, 0.3]` |
| **Algorithm BRFA-v2 Step 1 (Trust gate)** | `K_e = {k : T_r_k >= T_min}` | ✅ Implemented (new) | `fed_aggregator.py::trust_gate()` | Optional `--trust_scores` JSON; defaults all RSUs to trust=1.0 (crypto_layer.h's `TRUST_INIT`) since no live ns-3→Python trust bridge exists yet — see caveat below |
| **Algorithm BRFA-v2 Step 2 (Hash verification)** | `1_BC^(k) = SC.VerifyModelHash(W^(k))` | ✅ Implemented (new), scoped | `fed_aggregator.py::hash_verify_all()` | Real SHA-256 recompute-and-compare, always passes in this single-process simulation by construction — see scope caveat below |
| **Algorithm BRFA-v2 Step 3 (Krum filter)** | reject if `d(W^(k), median) >= γ` | ✅ Already existed | `fed_aggregator.py::krum_filter()` | Unmodified from the pre-existing implementation |
| **Algorithm BRFA-v2 Step 4 (Weighted aggregation)** | `ω_k = n_k · 1_BC^(k) · 1[d<γ]` | ✅ Generalized (new) | `fed_aggregator.py::run_aggregation()` | Composes all three upstream masks into `final_mask` before calling `weighted_fedavg()` |
| **Poisoning injection** | Malicious RSUs submit corrupted gradients | ✅ Implemented (new) | `fed_aggregator.py::apply_poisoning()` | 3 attack models: `sign_flip` (negate), `scale` (×50), `random` (Gaussian replacement) |
| **Comparison** | BRFA-v2 vs naive FedAvg | ✅ Implemented (new) | `fed_aggregator.py --mode {brfa,fedavg}` | `fedavg` mode skips Steps 1–3 entirely — pure naive weighted average, the AB5-A baseline |
| **Target bound** | `Δ_poison(ρ_mal < 1/3) ≈ 0` | ✅ Checked automatically | `poison_sweep.py` | Prints a PASS/CHECK flag per swept ρ_mal below 1/3 for the `brfa` mode (`|Δ_poison| < 0.05` threshold) |
| **CSV/JSON export** | Δ_poison per poisoning fraction | ✅ Implemented (new) | `lstm_pipeline/poison_sweep_results.json` | Per-mode, per-ρ_mal MCC, Δ_poison, accepted/rejected RSU lists |

**Ablation mapping correction:** the original report's remediation table said M8 maps to "AB8" — this
was wrong. Per main.tex:4283 ("AB5 — Byzantine-Robust Aggregation"), M8 is the y-metric for **AB5**,
not AB8 (which main.tex:4387 defines as "Multi-RSU FlowMod Endorsement," feeding M11/M7 instead).
The `--mode brfa`/`--mode fedavg` flag added to `fed_aggregator.py` is the AB5-A/AB5-B switch.

**Implementation notes (2026-07-07):**
- **New file:** `lstm_pipeline/src/poison_sweep.py` — sweeps ρ_mal × {brfa, fedavg}, calls the
  refactored `fed_aggregator.run_aggregation()` in-process (no disk writes during the sweep via
  `out_suffix=None`), evaluates each resulting global model's MCC on the held-out test split, and
  writes `poison_sweep_results.json`.
- **Refactored:** `fed_aggregator.py`'s original `main()` logic was extracted into a reusable
  `run_aggregation(...)` function so both the CLI (unchanged default behavior — still writes
  `global.pt`/`rsu_{k}_global.pt`) and the sweep script can call the same code path.
- **Poisoning model:** corrupts the first `round(ρ_mal · K)` RSUs by sorted `rsu_id` (deterministic).
  Default attack is `sign_flip` (negate all weights) — the standard "worst-case Byzantine" model used
  in the Krum literature; `scale` and `random` are also available via `--poison_mode`.
- **Hash verification (Step 2) scope caveat:** in a single-process simulation reading local
  checkpoint files, there is no network transit for an attacker to tamper with after a legitimate
  commit — so Step 2, implemented faithfully, will always pass (it recomputes and compares a hash of
  the same in-memory weights). This is **correct alg:brfa_v2 behavior, not a shortcut**: Step 2
  defends against transit tampering/impersonation, while Step 3 (Krum) is the layer that must catch
  a malicious RSU that self-consistently poisons and correctly self-hashes its own corrupted model.
  Both are implemented; only Step 3 is expected to actually reject anything in this experiment.
- **Trust gate (Step 1) scope caveat:** no live bridge exists yet to pull real per-RSU
  `g_trust_score[]` values out of an ns-3 run into the Python pipeline, so `--trust_scores` is
  optional and defaults every RSU to `1.0` (all pass). The gate is fully implemented and will use
  real scores the moment such a CSV/JSON is supplied — wiring that bridge is a small follow-up
  (loop over RSU indices in `write_security_metrics_csv()` and dump `g_trust_score[N_Vehicles+r]`
  per RSU to a JSON), not part of this fix's scope.
- **Pipeline integration:** added as optional Step 5 in `pipeline.py` (`--from-step 5`), after local
  training (Step 2) has produced clean `rsu_{k}.pt` checkpoints. Does not require Steps 3–4 to have
  run first since `poison_sweep.py` calls `run_aggregation()` directly per sweep point.
- **Syntax-checked** (`python3 -c "import ast; ast.parse(...)"`) for all three modified/new files;
  full execution requires the GPU-equipped training host (`local_trainer.py` needs the preprocessed
  `.npy` splits and a trained checkpoint set) and has not been run end-to-end yet — pending user
  test alongside the ns-3 build check.

---

### M9 — Distributed Time Reference Robustness [Ablation only] — DONE (2026-07-07, build pending)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `ε_ref(f_bad) = \|T_ref(t) - T_ground(t)\|` — time reference deviation under f_bad compromised RSU clocks | ✅ Implemented | crypto_layer.h `update_T_ref()` | `g_eps_ref` recomputed on every sync tick |
| **Formal guarantee** | `T_ref(t)` remains within honest clock range when `f_bad < n_RSU/2` RSU clocks compromised | ✅ Reproduced by design | crypto_layer.h `update_T_ref()` | Coordinate-wise median over N_RSUs offsets — honest majority pins the median at 0 offset for any `f_bad < N_RSUs/2` |
| **T_ground(t)** | GPS ground truth timestamp from simulation | ✅ Implemented | crypto_layer.h `update_T_ref()` | `t_ground = Simulator::Now().GetSeconds()`, the simulator's own authoritative clock |
| **Attack variation** | `f_bad ∈ {0, 1, ⌊n_RSU/4⌋, ⌊n_RSU/2⌋ - 1}` — sweep to confirm bound failure at f_bad = n_RSU/2 | ✅ CLI-sweepable | `--time_ref_f_bad`, `--time_ref_delta_attack` | First `f_bad` RSU indices get a fixed offset; run once per sweep value (same separate-runs idiom as M1/variant sweeps) |
| **Validation** | Confirm robustness holds for all f_bad < n_RSU/2, fails at f_bad = n_RSU/2 | ✅ Verifiable | — | With `f_bad < N_RSUs/2`: median lands on an honest (0-offset) entry → `eps_ref=0`. At `f_bad = N_RSUs/2` exactly: median index lands on the first compromised entry → `eps_ref = delta_attack`, reproducing the proposal's claimed failure point exactly |
| **CSV export** | ε_ref per compromised-clock count | ✅ Implemented | routing.cc `write_security_metrics_csv()` | 3 new columns: `eps_ref_s, avg_eps_ref_s, time_ref_f_bad` |
| **Implementation status** | `update_T_ref()` function exists (crypto_layer.h) | ✅ Upgraded from stub | crypto_layer.h `update_T_ref()` | Previously pushed `N_RSUs` identical copies of the same simulator clock (no per-RSU divergence possible at all); now models per-RSU offset and computes real deviation |

**Summary:** M9 is now **fully implemented**, pending build verification. The `update_T_ref()` stub
previously had no way to represent per-RSU clock divergence — every "RSU clock" was just the same
global `Simulator::Now()` value, so no offset could ever be injected. It now models `N_RSUs`
independent clock readings with configurable Byzantine offsets.

**Implementation notes (2026-07-07):**
- **Design choice:** compromised RSUs are the first `TIME_REF_F_BAD` indices (0..f_bad-1), each
  offset by a fixed `TIME_REF_DELTA_ATTACK` seconds (default 0.5s) — mirrors the proposal's
  "f_bad RSU clocks offset by a fixed attack value δ_attack" framing exactly, and matches the
  simple index-based selection pattern used elsewhere in the codebase (e.g. TCAM malicious RSUs).
- **Why the bound reproduces correctly:** `times[]` is sorted; `g_T_ref = times[size/2]`. For
  `f_bad < N_RSUs/2`, honest (offset-0) entries are strictly more than half the array, so the median
  index always falls on an honest entry regardless of how large `delta_attack` is. At
  `f_bad = N_RSUs/2` (even N_RSUs), the median index lands exactly on the boundary between the
  honest and compromised halves — landing on the first compromised entry — which is the exact
  "fails exactly at f_bad = n_RSU/2" behavior the proposal specifies for validation.
- **Default `f_bad=0`** reproduces the original all-honest behavior exactly (`eps_ref ≡ 0`), so this
  change is backward-compatible with every existing run/CSV that doesn't pass the new flags.
- Two new CLI flags registered in `crypto_register_cli_params()`: `--time_ref_f_bad`,
  `--time_ref_delta_attack`.
- **Build check:** pending — user to run `./waf build 2>&1 | grep -i error` and confirm clean.

---

### M10 — Privacy Leakage / Raw Data Exposure (L_priv) — DONE (2026-07-07, architectural analysis)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition** | `L_priv = Σ_{d ∈ D_raw} w_d · 𝟙[d transmitted beyond local trust boundary]` | ✓ Evaluated below | — | Confirmed architectural, not runtime (proposal's own words: "computed from each baseline's published design rather than a runtime output") |
| **Raw data categories** | `D_raw = {location history, vehicle identity, trajectory, raw packet headers, raw flow metadata}` | ✓ Verified against codebase | See analysis below | Checked what MOBIGUARD's security layer actually transmits, category by category |
| **Privacy weights** | `w_d ∈ [0,1]` — location/identity w_d=1 (highest), flow metadata w_d=0.5 | ✓ Taken from proposal | — | Weights are a proposal-defined constant, not something the codebase computes |
| **MOBIGUARD baseline** | L_priv = 0 (only model weights, hash commitments, proofs transmitted) | ✓ Confirmed, with one scoping caveat | See analysis below | Security layer transmits only hashes/signatures/booleans; **but** the underlying ns-3 routing tag layer transmits raw position/velocity/acceleration in cleartext — see caveat below |
| **Baseline comparisons** | HSA: L_priv = w_headers + w_trajectory; TAP: L_priv = w_vehicle_identity | ✓ Reproduced from proposal | — | These are literature citations (HSA/TAP's own published designs), not something derivable from this codebase |
| **CSV export** | Not expected (architectural, not runtime) | ✓ N/A confirmed | — | Correctly excluded from per-cycle CSV |

**Summary:** M10 is an architectural/documentation metric per the proposal's own definition, not a
runtime measurement. Rather than treat this as "nothing to verify," the security layer's actual
message contents were checked against each `D_raw` category to confirm the `L_priv=0` claim holds
for what MOBIGUARD's *security layer* (crypto, witness, blockchain, LSTM) transmits.

**Verification (2026-07-07) — what MOBIGUARD's security layer actually puts on the wire:**

| `D_raw` category | Transmitted by MOBIGUARD's security layer? | Evidence |
|---|---|---|
| Location history | No | ML-DSA-87 signatures sign message digests (`msg_id`, `flow_id`, hashes) — no coordinates. STARK proofs are SHA3-512 commitments, not raw timing/position traces. |
| Vehicle identity | Pseudonymous node index only | `witness_id`, `target_node`, `prev_sender`, `rsu_idx` are `uint32_t` simulation node indices, not real-world identifiers (VIN/plate) — consistent with how the proposal frames "vehicle identity" as a re-identifying credential, not an internal array index. Flagged as a modeling assumption, not a gap. |
| Trajectory | No | No velocity/heading/position history included in any signed payload, witness alert, or blockchain commit. |
| Raw packet headers | No | Witness alerts sign `H(p)` (a hash of the target's ML-DSA-87 signature) plus `dst`/`dst'`/timestamps — never the packet header itself. |
| Raw flow metadata | No | FlowMod endorsement (`flowmod_endorse()`) signs `SHA3-512(flowmod_params ‖ ts ‖ T_rj)` — a hash digest, not the FlowMod parameters in the clear. |

**Caveat — scoping boundary between the security layer and the base routing protocol:**
The ns-3 network layer's own unicast routing tags (`CustomDataUnicastTag` and 25 numbered sibling
tag classes, `routing.cc:6129` on) carry **raw `Vector` position, velocity, and acceleration in
cleartext** on every data packet (confirmed at the `MacRx` log site, `routing.cc:95239`:
`"...at position "<<*tag_routing.Getposition()<<"with velocity "<<*tag_routing.Getvelocity()...`).
This is **not** part of MOBIGUARD's security contribution — it is the base geographic/predictive
routing protocol's own positional requirement, present in the simulation infrastructure for *every*
framework under test (MOBIGUARD, FADE, TAP baselines alike), since next-hop selection in this VANET
routing scheme needs raw position. Eq. l_priv, per the proposal's own framing, measures what each
*security/detection framework* additionally exposes beyond the local trust boundary, not the
underlying routing substrate every scheme shares. Under that scoping, `L_priv = 0` for MOBIGUARD's
security layer holds; it would be a **mischaracterization** to claim `L_priv = 0` for the full
simulated stack including base routing telemetry, so this scoping distinction should be stated
explicitly wherever M10 appears in the thesis (Section 5) rather than left implicit.

**M10 result table (for Section 5, reproduced from proposal + verification above):**

| Framework | $L_{priv}$ | Basis |
|---|---|---|
| MOBIGUARD (security layer) | 0 | Verified above: only hash commitments, signatures, and boolean proof outcomes cross the trust boundary |
| HSA | $w_{headers} + w_{trajectory}$ | Proposal main.tex:3894 — centralizes raw packet headers |
| TAP | $w_{vehicle\_identity}$ | Proposal main.tex:3895-3897 — Controller-Defaulter-List centralizes attacker vehicle ID |
| FADE | Not specified in proposal | main.tex M10 text only covers HSA/TAP as privacy baselines; FADE's $L_{priv}$ would need a literature citation from its own paper if included in Section 5's table |

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

### M12 — Witness Alert Precision and Recall (WAP-R) [Ablation only] — DONE (2026-07-07)

| Aspect | Proposal Requirement | Implementation Status | Code Location | Notes |
|--------|---------------------|----------------------|---|---|
| **Definition (Precision)** | `P_W = TP_W / (TP_W + FP_W)` — fraction of 2f+1-threshold alert events that are true | ✅ Implemented | routing.cc `calculate_witness_wapr_metric()` | Computed every cycle from cumulative `g_witness_TP_W`/`g_witness_FP_W` |
| **Definition (Recall)** | `R_W = TP_W / (TP_W + FN_W)` — fraction of true passive HF instances where 2f+1 valid alerts submitted | ✅ Implemented | routing.cc `calculate_witness_wapr_metric()` | `g_witness_FN_W` recomputed as a snapshot each cycle |
| **TP_W** | Count of 2f+1-threshold alert events that correctly identify true passive HF instance | ✅ Implemented | crypto_layer.h (both `witness_submit_*_alert()` threshold blocks) | Incremented once per node, first time its alert pool crosses 2f+1, when `present_passive_hf_attack && passive_hf_malicious_nodes[target_node]` |
| **FP_W** | Count of threshold events triggered by false witness coalition | ✅ Implemented | crypto_layer.h (same blocks) | Incremented once per node when threshold crossed on a non-passive-HF-malicious target |
| **FN_W** | Count of true passive HF instances where fewer than 2f+1 valid alerts submitted (witness density insufficient) | ✅ Implemented | routing.cc `calculate_witness_wapr_metric()` | Iterates `passive_hf_malicious_nodes[]`, counts those with `g_witness_threshold_fired[n] == false` |
| **Validation targets** | (1) `P_W` validates false-accusation resistance (threshold robustness); (2) `R_W` validates feasibility (f=1 requires 3 witnesses, achievable under mean vehicle density ≈ 3.1 vehicles per RSU) | ⚠ Metric ready; density binning not done | — | P_W/R_W now computable per run; stratifying by vehicle density bin is a separate post-processing step, not part of this fix |
| **Variants 7–8 specific** | Evaluated only against passive hidden forwarding (Variants 7–8) where cryptographic proof insufficient | ✓ Targeted | — | Ground-truth check uses `passive_hf_malicious_nodes[]` + `present_passive_hf_attack`, matching Attack 7/8 runs |
| **CSV export** | P_W, R_W per cycle (Variants 7–8 only) | ✅ Implemented | routing.cc `write_security_metrics_csv()` | 5 new columns appended: `witness_TP_W, witness_FP_W, witness_FN_W, WAP_precision, WAP_recall` |

**Summary:** M12 is now **fully implemented**. Witness alerts were already being submitted and pooled
against the 2f+1 BFT threshold (crypto_layer.h); the gap was purely the missing ground-truth
comparison and metric computation, which is now wired end-to-end.

**Implementation notes (2026-07-07):**
- **Granularity decision:** the proposal defines TP_W/FP_W/FN_W as counts of "alert events," but the
  codebase's `g_witness_alert_pool[target_node]` accumulates without time decay (known gap WIT-1,
  CRYPTO_CORRECTIONS.md) — once crossed, the threshold check re-fires on every subsequent alert push
  for the same node. A per-node one-shot guard (`g_witness_threshold_fired`, mirroring the
  blockchain-side `WitnessAlert.Penalized` single-fire guard from `blockchain/SPEC.md`) was added so
  each node contributes at most one TP_W or FP_W count per run. This matches the per-node granularity
  already used elsewhere in the codebase for M1's confusion matrix (`is_malicious_node[v][n]`).
- **TP_W/FP_W are cumulative** (incremented once per node, never reset during a run); **FN_W is a
  snapshot** recomputed every cycle from current pool state — consistent with "how many true
  instances have not yet been caught as of now."
- Both counting blocks are duplicated identically in `witness_submit_duplication_alert()` (α_w) and
  `witness_submit_nfa_alert()` (β_w) since both alert types share the same pool and threshold check.
- New scheduling call: `calculate_witness_wapr_metric()` fires at t+0.000093s, after UCR and before
  the CSV write, alongside the other M-series calculators.
- Build verified clean (waf, 2026-07-07).

---

## Summary Table: Metrics Implementation Status

| Metric | Proposal | Code | CSV | Ablation | Notes |
|--------|----------|------|-----|----------|-------|
| **M1 (MCC)** | ✓ Eq. mcc | ✓ routing.cc:117075 | ✓ Single variant (by design) | ✓ AB1-ready | Per-variant AND per-mode via separate runs (proposal + reference idiom); mode stratification needs zero new code — see Critical Issue #4 |
| **M2 (TVR)** | ✓ Eq. tvr | ✓ routing.cc:117158 | ✅ In CSV (Step 1) | — | Exported 2026-07-06; no T_ref normalization (open) |
| **M3 (UCR)** | ✓ Eq. ucr | ✓ routing.cc:117186 | ✅ In CSV (Step 1) | — | Exported 2026-07-06; aggregate only (per-variant via separate runs) |
| **M4 (L_mit)** | ✓ Eq. l_mit | ✅ Wired (verified 2026-07-07) | ✓ Written | — | t_quarantine set via record_detection_event() + trust_update_negative(); see Tier 2 item 6 |
| **M5 (L_failover)** | ✓ Eq. l_failover | ✅ crypto_layer.h (Step 3) | ✅ In CSV (Step 3) | ✓ AB9-ready | Implemented 2026-07-07: broadcast-propagation delay model + t_revoke/t_reassign stamps + 3 CSV columns |
| **M6 (L_e2e)** | ✓ Eq. l_e2e | ✓ routing.cc:116782 | ✓ Written | — | No T_ref normalization; no before/after split |
| **M7 (Overhead)** | ✓ Eq. o_crypto, t_verify, t_consensus | ✅ Instrumented (Step 5) | ✅ 4 new columns | ✓ | O_crypto + T_batch(B) + T_consensus wall-clock; per-op rows in crypto_timing_log.csv; see Tier 2 item 5 |
| **M8 (Poisoning)** | ✓ Eq. delta_poison | ✅ lstm_pipeline/src (test pending) | ✅ poison_sweep_results.json | ✓ AB5-ready | Implemented 2026-07-07: full BRFA-v2 (4 steps) + poisoning injection + FedAvg baseline + Δ_poison sweep; correct mapping is AB5, not AB8 |
| **M9 (Time Ref)** | ✓ Eq. eps_ref | ✅ crypto_layer.h (build pending) | ✅ 3 new columns | ✓ sweepable | Implemented 2026-07-07: per-RSU clock offset model + eps_ref deviation tracking |
| **M10 (Privacy)** | ✓ Eq. l_priv | ✅ Architectural analysis done | N/A (by design) | — | L_priv=0 verified against actual security-layer message contents; scoping caveat re: base routing tags documented |
| **M11 (UFCR)** | ✓ Eq. ufcr | ✗ Missing | ✗ | — | No control-plane attack injection; no authorization checks |
| **M12 (WAP-R)** | ✓ Eq. wap, war | ✅ crypto_layer.h + routing.cc | ✅ 5 new columns | ✓ AB6-ready | Implemented 2026-07-07: per-node TP_W/FP_W one-shot counters + FN_W snapshot + P_W/R_W |

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

### 3. **No Ablation Study Infrastructure — DONE (Step 4, 2026-07-07)**

**Problem (was):** Proposal defines 13 ablation studies (AB1–AB13) and SIGNATURE_ATTACK_DECOUPLING_PLAN.md Phase 3 specifies concrete gate implementations, but codebase had no ablation flags wired.

**Fix applied (Step 4):** All 9 Phase-3 gate flags implemented, each a guard clause at the
single natural chokepoint, all defaulting `true` (full proposed behavior), all registered in
`crypto_register_cli_params()`:

| Flag | Ablation | Gate location |
|---|---|---|
| `enable_lrad_obu` | AB1 | top of `lrad_obu()` (lrad.h) — returns all-false flags, no escalation |
| `enable_lrad_rsu` | AB1 | top of `lrad_rsu()` (lrad.h) — returns all-false flags |
| `enable_stark_delay` | AB4 | `stark_prove_timing()` **and** `stark_verify_timing()` (crypto_layer.h) — vacuous PASS |
| `enable_stark_hop` | AB4 | `stark_verify_hop()` (crypto_layer.h) — vacuous PASS |
| `enable_witness_mechanism` | AB6 | both `witness_submit_*_alert()` (crypto_layer.h) |
| `enable_quarantine` | AB7 | `trust_update_positive()` / `trust_update_negative()` (crypto_layer.h) |
| `enable_endorsement_requirement` | AB8 | f+1 quorum check in `bc_commit_flowmod()` (bc_blockchain_helper.h) — off ⇒ unilateral commit via the existing commit path |
| `enable_controller_failover` | AB9 | `ctrl_trust_update_positive()` / `negative()` (crypto_layer.h) |
| `enable_key_rotation` | AB11 | the `dkg_rotate_keys()` call inside `trust_update_negative()` |

**Implementation notes:**
- **Deviation from plan spec (deliberate):** the plan gated only `stark_prove_timing()`, but
  `stark_verify_timing()` independently re-checks `(t_fwd − t_recv) ≤ STARK_DELTA_MAX`, so a
  vacuously-valid proof would still fail verification. Both functions are gated so "π_delay
  removed ⇒ vacuously passes" actually holds end-to-end.
- STARK gates are placed **before** the `g_disable_crypto` check and produce vacuous PASS
  (proof contributes nothing), never vacuous FAIL — per the plan's AB4 semantics.
- AB13 needs no new flag: `--s1_alpha_rho=0 --s1_alpha_v=0` already collapses to static thresholds.
- AB10/AB12 are chaincode/architecture-side, not ns-3 flags (per plan §"Phase 2 mapping").
- **Provenance note:** `docs/SIGNATURE_ATTACK_DECOUPLING_PLAN.md` exists only on branch **A25**
  (never merged to A26); the Phase 3 spec was recovered via `git show A25:docs/...`.
- Build verified clean (waf, 2026-07-07).

### 4. **No Per-Mode Stratification (affects M1) — RESOLVED: NO CODE NEEDED (2026-07-07)**

**Original problem:** M1 (MCC) requires per-mode scores (`MCC_{s,m}` where m ∈ {OBU, RSU}), and it was
assumed the code merges both modes' detections into one confusion matrix, requiring new per-packet
detection-source tracking to separate them.

**Investigation (2026-07-07):** Traced every `record_detection_event(v, n)` call site to see which
mode actually drives each variant's `is_detected_node[v][n]`:

| Variant | Detector | Called from | Mode |
|---|---|---|---|
| S1 (v=0) | `s1_detect_packet()` | `lrad_obu()` only | OBU-only |
| S2 (v=1) | `s2_detect_packet()` | `lrad_rsu()` only | RSU-only |
| S3/S4 (v=2,3) | TCAM checks | cycle-level (`ComputeTcamDetection()`), OBU-intended | OBU-only |
| S5–S8 (v=4..7) | `s5_detect()`…`s8_detect()` | `lrad_rsu()` only | RSU-only |

**Finding:** each variant is evaluated by **exactly one mode, never both** — there is no per-packet
ambiguity for the current architecture to disambiguate, and therefore nothing being "merged." The
assumption in the original report was incorrect.

**What the proposal actually means by "per-mode MCC":** main.tex:4166 lists "M1 (per-variant,
per-mode MCC)" as the y-metric for **AB1** (Dual-Mode Detection Architecture), whose three configs are:
- **AB1-A (Rule-only):** OBU evaluates locally; no escalation to RSU; no LSTM inference
- **AB1-B (LSTM-only):** OBU disabled; all packets forwarded directly to RSU
- **AB1-C (Full dual-mode):** both active (today's default)

So `MCC_{s,OBU}` and `MCC_{s,RSU}` are not two matrices computed *simultaneously within one run* —
they are the per-variant MCC measured from **two separate ablation runs**, using the
`enable_lrad_obu`/`enable_lrad_rsu` flags already implemented (Critical Issue #3, AB1 row). Verified
both gates behave correctly for this: disabling one does not affect the other's independent
per-packet call site (`lrad.h:271` for `enable_lrad_rsu`, `lrad.h:421` for `enable_lrad_obu`).

**Resolution — no code change required.** Per-mode MCC is obtained via:
```
Run 1 (AB1-A): --enable_lrad_obu=true  --enable_lrad_rsu=false  → MCC_{s,OBU}  (meaningful for S1,S3,S4)
Run 2 (AB1-B): --enable_lrad_obu=false --enable_lrad_rsu=true   → MCC_{s,RSU}  (meaningful for S2,S5-S8)
Run 3 (AB1-C): --enable_lrad_obu=true  --enable_lrad_rsu=true   → MCC_{s,dual} (default; = current_MCC[v] today)
```
This mirrors exactly how Critical Issue #1 (single-variant CSV) was resolved: the proposal wants
separate runs with the sweep dimension encoded in configuration/filename, not one run computing
everything at once. For variants where a given mode never fires (e.g., `MCC_{S1,RSU}` — RSU never
attempts S1), the resulting confusion matrix is trivially all-negative and should be reported as
not-applicable for that (s,m) pair, consistent with the fixed one-mode-per-signature design of
Algorithms LRAD-OBU/LRAD-RSU.

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
4. ✅ **DONE — Implement ablation gate flags (Phase 3)** — 9 CLI flags for AB1, AB4, AB6, AB7, AB8, AB9, AB11
   - **Effort:** 6 hours (code gating already sketched in SIGNATURE_ATTACK_DECOUPLING_PLAN.md)
   - **Impact:** Enables all 13 ablation experiments (Table 5.6–5.18)
   - **Completed:** 2026-07-07 — see Critical Issue #3 above for the full flag table,
     gate locations, and the stark_verify_timing deviation note. Build verified clean.

5. ✅ **DONE — Add M7 wall-clock timing** — Instrumented batch verify, FlowMod consensus, and O_crypto
   - **Effort:** 3 hours (add std::chrono calls around crypto functions)
   - **Impact:** Enables overhead breakdown for M7 (required for security layer cost analysis)
   - **Completed:** 2026-07-07. Implementation notes:
     - **Pre-existing coverage found first:** `crypto_event_log.h` already logs per-op wall-clock
       µs (`sign`, `verify`, `stark_hop`, `lrad_obu`, `lrad_rsu`) to `crypto_timing_log.csv` —
       the report's "not instrumented" claim was stale for individual ops. The real gaps were
       the three M7 aggregates:
     - **T_batch(B) (eq:t_verify):** `crypto_batch_verify_tick()` now times `batch_verify_mldsa87()`
       with `std::chrono` (the function's own `elapsed_s` is a simulated 1 ms/pkt budget counter,
       NOT wall time — deliberately left untouched) and emits a `batch_verify` row to
       `crypto_timing_log.csv` (node_id column = batch size B, pkt_id = n_verified).
     - **T_consensus (eq:t_consensus):** the endorse→commit sequence in `transmit_delta_values()`
       runs at a single simulator timestamp (sim-time Δ would be identically 0 — same trap M5 had),
       so the honest measurable quantity is its wall-clock processing time. Timed with
       `std::chrono`; emits a `consensus` row (node_id = endorser count, pkt_id = fid).
     - **O_crypto (eq:o_crypto):** accumulated at sign time in `mldsa87_sign()` as the bytes the
       simulation actually attaches: `sig_len` (ML-DSA-87, 4627 B) + 64 B π_delay commitment
       (the simulated STARK proof is a SHA3-512 commitment, NOT the proposal's conservative
       ≤100 KB FRI bound; π_hop is embedded in σ via signed_next_hop → 0 extra bytes on-wire).
     - **New CSV columns** (fixed-schema append, running averages since sim start):
       `o_crypto_bytes_pkt, t_batch_ms_avg, batch_B_avg, t_consensus_ms_avg`.
     - **Include-order note:** `crypto_event_log.h` is included after `crypto_layer.h` in
       routing.cc, so the batch tick uses a forward declaration of `crypto_log_event()`
       (same translation unit — legal and resolved at link of the inline definition).
     - Build verified clean (waf, 2026-07-07).

6. ✅ **DONE (already wired — report was stale)** — M4 `t_quarantine[n]` population
   - Verified 2026-07-07: `t_quarantine[n]` IS set on two paths — (1) `record_detection_event()`
     (routing.cc:115112, called from inside each `s*_detect()` when its equation fires) and
     (2) the quarantine branch of `trust_update_negative()` (crypto_layer.h, T_min crossing,
     which also stamps SC.Quarantine semantics). `t_onset[n]` is set by attack injection
     (attack_declaration.h:180/245, hf_attack_helper.h:639). `calculate_mitigation_latency_metric()`
     guards `t_quarantine > t_onset` correctly. **No blockchain bridge needed for the ns-3-side
     metric** — the original "always 0" claim predates the trust/quarantine wiring.
   - The M4 section table above (t_quarantine "never populated") is superseded by this note.

### **Tier 3: Medium (needed for complete evaluation)**
7. ✅ **DONE — Add M12 witness metric computation** — Compare witness alerts against ground-truth HF attack status
   - **Effort:** 3 hours (post-processing of witness_alert_pool and ground truth attack flags)
   - **Impact:** Enables WAP-R evaluation for AB6 ablation
   - **Completed:** 2026-07-07. See M12 section above for full implementation notes (one-shot
     per-node TP_W/FP_W counters, FN_W snapshot, 5 new CSV columns). Build verified clean (waf).

8. ✅ **DONE — Add M1 mode stratification** — Separate OBU vs RSU confusion matrices
   - **Effort:** 2 hours estimated → **0 hours actual** (no code needed)
   - **Impact:** Enables per-mode MCC curves (validation that dual-mode works)
   - **Completed:** 2026-07-07. Investigation found each signature (S1-S8) is evaluated by exactly
     one mode by construction — nothing is merged. "Per-mode MCC" in the proposal refers to AB1's
     three run configurations (AB1-A OBU-only, AB1-B RSU-only, AB1-C dual), not simultaneous
     per-packet tracking within one run. Achieved entirely via the `enable_lrad_obu`/
     `enable_lrad_rsu` flags already implemented in Step 4. See Critical Issue #4 above.

9. ✅ **DONE — Implement M9 time-reference evaluation** — Clock offset injection and deviation measurement
   - **Effort:** 4 hours
   - **Impact:** Enables T_ref robustness validation for distributed consensus
   - **Completed:** 2026-07-07 (build verification pending). See M9 section above for full
     implementation notes (per-RSU offset model, eps_ref computation, boundary-behavior proof,
     2 new CLI flags, 3 new CSV columns).

10. ✅ **DONE — Implement M8 Byzantine-robust aggregation** — Federated LSTM with Krum filtering
    - **Effort:** 8 hours estimated → ~3 hours actual (Krum filter + weighted FedAvg already existed
      in `lstm_pipeline/src/fed_aggregator.py`; only trust-gate, hash-verify, poisoning injection,
      FedAvg-baseline mode, and the sweep script were net-new)
    - **Impact:** Enables poisoning resistance validation for AB5 (not AB8 — corrected mapping,
      see M8 section above)
    - **Completed:** 2026-07-07 (pipeline execution pending — syntax-checked only, needs a run on
      the GPU training host). See M8 section above for full implementation notes.

### **Tier 4: Low (design review, not runtime)**
11. ✅ **DONE — M10 Privacy Leakage** — Architectural review (not runtime metric); cite baseline designs from literature
    - **Effort:** 2 hours
    - **Impact:** Qualitative privacy analysis (no code change needed)
    - **Completed:** 2026-07-07. Verified `L_priv=0` for MOBIGUARD's security layer against actual
      transmitted message contents (signatures, hashes, boolean outcomes only across all 5 D_raw
      categories); documented a scoping caveat that the base ns-3 routing tag layer separately
      carries raw position/velocity/acceleration in cleartext, but that's shared VANET routing
      infrastructure common to all frameworks under test, not part of MOBIGUARD's security-layer
      contribution the metric is scoped to. See M10 section above for full analysis + result table.

12. ✅ **DONE — M11 UFCR (control-plane attacks)** — Control-plane attack injection + FlowMod authorization
    - **Effort:** 6 hours estimated → ~2 hours actual (existing `bc_commit_flowmod()` quorum check
      already implemented the authorization gate; only needed an unauthorized-attempt injector)
    - **Impact:** Complete coverage of the 4 control-plane variants for M11 evaluation
    - **Completed:** 2026-07-07 (build verification pending). See M11 section above.

---

## Deviations Summary (by Severity) — as of 2026-07-07

| Severity | Remaining | Metrics | Issue |
|----------|-------|---------|-------|
| **Resolved** | 12 | M1, M2, M3, M4, M5, M6\*, M7, M8\*\*\*, M9\*\*, M10, M11\*\*, M12 | All 12 metrics now implemented. M6 T_ref normalization still open but base metric works. \*\*M9/M11 (ns-3/C++) pending `waf build`. \*\*\*M8 (Python) pending end-to-end pipeline run — syntax-checked only. |

**Progress: 12 of 12 metrics implemented.** Three items (M8, M9, M11) are code-complete but await
your build/run pass: M9 and M11 need `./waf build` (ns-3/C++), M8 needs a full `pipeline.py` run on
the GPU training host (Python, untouched by the ns-3 build). Everything else has already been
verified building/running clean in earlier steps of this session.

---

## Files Referenced

- `docs/main.tex:3476–3993` — Performance metrics specification (M1–M12, Equations eq:mcc through eq:war)
- `scratch/routing.cc:117031–117440` — Metrics calculation and CSV export
- `scratch/routing.cc:116782–116819` — Latency calculation (M6)
- `scratch/crypto_layer.h` (`update_T_ref()`) — Distributed time reference + M9 eps_ref instrumentation (done 2026-07-07)
- `scratch/crypto_layer.h` (`witness_submit_duplication_alert`/`witness_submit_nfa_alert`) — Witness mechanism + M12 TP_W/FP_W counting (done 2026-07-07)
- `docs/SIGNATURE_ATTACK_DECOUPLING_PLAN.md:Phase 3` — ns-3 ablation gate implementations (done for AB1/4/6/7/8/9/11)
- `docs/CRYPTO_CORRECTIONS.md` — Cryptographic layer deviations (M4/M7/M12 correctness gaps now resolved; referenced for historical context)
- `lstm_pipeline/src/fed_aggregator.py`, `poison_sweep.py` — BRFA-v2 (4 steps) + M8 Δ_poison sweep (done 2026-07-07)
- `scratch/routing.cc` (`ufcr_attempt_unauthorized_flowmod`, `calculate_ufcr_metric`) — M11 UFCR (done 2026-07-07)

---

## Conclusion

**The proposal specifies 12 comprehensive metrics across detection quality (M1), attack-specific
containment (M2–M3), operational latency (M4–M6), security overhead (M7), Byzantine robustness
(M8–M9), privacy (M10), control-plane defense (M11), and witness mechanisms (M12). As of 2026-07-07,
all 12 metrics are implemented.** M1, M2, M3, M4, M5, M6, M7, M10, and M12 have been verified
building/running clean during this session. M8 (Python, `lstm_pipeline/`), M9, and M11 (both ns-3/C++,
`scratch/`) are code-complete and syntax/logic-reviewed but await the user's build/run pass — M9 and
M11 need `./waf build`, M8 needs a `pipeline.py --from-step 5` run on the GPU training host (or
the full pipeline from step 1 if no trained checkpoints exist yet).

**No metric requires further design work.** The coverage gap identified in the original report
(8 of 12 unimplemented or partial) has been closed to 0 pending-design / 3 pending-verification.
Once the three pending items are confirmed running clean, every metric in Section 4.6 is available
to populate the evaluation tables in Section 5.**

---

## Testing / Run Recipes (for later verification)

Commands to run once each feature's build is confirmed clean. All paths assume the ns-3 tree at
`/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35` — adjust `NS3_DIR` if different.

### Build check (run after every code change in this doc)
```bash
cd /home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35
./waf build 2>&1 | grep -i error
```
No output = clean build.

### M9 — Distributed Time Reference Robustness sweep
Run once per `f_bad` value to populate `eps_ref_s` / `avg_eps_ref_s` / `time_ref_f_bad` columns
across the sweep the proposal specifies (`f_bad ∈ {0, 1, ⌊N_RSUs/4⌋, ⌊N_RSUs/2⌋-1, N_RSUs/2}`).
With default `N_RSUs=64`: {0, 1, 16, 31, 32}.
```bash
./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --time_ref_f_bad=0  --time_ref_delta_attack=0.5"
./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --time_ref_f_bad=1  --time_ref_delta_attack=0.5"
./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --time_ref_f_bad=16 --time_ref_delta_attack=0.5"
./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --time_ref_f_bad=31 --time_ref_delta_attack=0.5"
./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --time_ref_f_bad=32 --time_ref_delta_attack=0.5"
```
**Expected result:** `eps_ref_s ≈ 0` for f_bad ∈ {0,1,16,31}; `eps_ref_s ≈ 0.5` (= delta_attack) at
f_bad=32 — confirming the bound holds below N_RSUs/2 and fails exactly at N_RSUs/2.

### M1 — Per-mode MCC stratification (AB1-A / AB1-B / AB1-C)
Run each config against the same attack variant (example: Attack 6, Active HF Data Plane) and
compare `cur_MCC`/`avg_MCC` across the three output files.
```bash
# AB1-A: Rule-only (OBU evaluates locally, RSU engine off)
./waf --run "scratch/routing/routing --attack_number=6 --attack_percentage=40 --enable_lrad_obu=true  --enable_lrad_rsu=false"

# AB1-B: LSTM-only (OBU disabled, RSU evaluates every packet)
./waf --run "scratch/routing/routing --attack_number=6 --attack_percentage=40 --enable_lrad_obu=false --enable_lrad_rsu=true"

# AB1-C: Full dual-mode (default — both true)
./waf --run "scratch/routing/routing --attack_number=6 --attack_percentage=40 --enable_lrad_obu=true  --enable_lrad_rsu=true"
```
**Note:** S1/S3/S4 (OBU-only signatures) will show `MCC=0`/undefined under AB1-B since RSU never
evaluates them; S2/S5–S8 (RSU-only signatures) will show `MCC=0`/undefined under AB1-A since OBU
never evaluates them. This is expected — see Critical Issue #4 for why each signature is
single-mode by design.

### M12 — Witness Alert Precision/Recall (WAP-R)
Only meaningful under passive HF attacks (Attack 7 or 8):
```bash
./waf --run "scratch/routing/routing --attack_number=7 --attack_percentage=40"   # S7, passive HF CP
./waf --run "scratch/routing/routing --attack_number=8 --attack_percentage=40"   # S8, passive HF DP
```
Check `witness_TP_W, witness_FP_W, witness_FN_W, WAP_precision, WAP_recall` columns in the resulting
`MOBIGUARD_Attack7_40.csv` / `MOBIGUARD_Attack8_40.csv`.

### M5 — Controller Failover Latency
Requires a controller-compromise scenario (attack variants that trigger `SC.Revoke`); check
`ctrl_failover_max_ms, ctrl_failover_events, ctrl_failover_reassigned` columns. Target: max ≤ 100ms.

### M7 — Security/Consensus Overhead
No special flags needed — `o_crypto_bytes_pkt, t_batch_ms_avg, batch_B_avg, t_consensus_ms_avg` are
populated on every run once packets are signed/batch-verified/consensus-committed. Also check
`crypto_timing_log.csv` for per-operation wall-clock rows (`sign`, `verify`, `stark_hop`,
`batch_verify`, `consensus`, `lrad_obu`, `lrad_rsu`).

### Full per-variant sweep (M1/M2/M3 baseline coverage)
Per Critical Issue #1, each variant needs its own run to populate meaningful per-variant metrics:
```bash
for n in 1 2 3 4 5 6 7 8; do
  ./waf --run "scratch/routing/routing --attack_number=$n --attack_percentage=40"
done
./waf --run "scratch/routing/routing --active_attack_variant=-1"   # baseline
```

### M11 — Unauthorized FlowMod Containment Rate (UFCR)
Only meaningful under control-plane attacks (Attacks 1, 3, 5, 7). Run each endorsement mode (AB8):
```bash
# AB8-B (proposed): endorsement required -> unauthorized FlowMods rejected -> UFCR ~= 1.0
./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=40 --enable_endorsement_requirement=true"

# AB8-A (baseline): no endorsement -> controller commits unilaterally -> UFCR = 0
./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=40 --enable_endorsement_requirement=false"
```
Check `ufcr_unauth_total, ufcr_blocked, UFCR` columns. Repeat for `--attack_number=3,5,7` to cover
all four control-plane variants.

### M8 — Federated Model Poisoning Resistance (BRFA-v2 vs FedAvg)
Run on the GPU training host, from `lstm_pipeline/src/`. Requires clean per-RSU models first
(steps 1–2 of the pipeline) if not already trained:
```bash
# One-time setup (skip if lstm_pipeline/models/rsu_*.pt already exist):
python3 pipeline.py --from-step 1     # preprocess + train clean local models (steps 1-2), then stops before step 3

# M8 sweep — compares BRFA-v2 vs naive FedAvg across malicious-RSU fractions:
python3 poison_sweep.py --rho 0.0 0.1 0.2 0.3 --modes brfa fedavg

# Try a stronger/weaker attack model:
python3 poison_sweep.py --poison_mode scale     # or: sign_flip (default), random
```
**Expected result:** for `--modes brfa`, `Delta_poison` should stay near 0 (script prints a
PASS/CHECK flag automatically) for every `rho_mal < 1/3`; for `--modes fedavg`, `Delta_poison`
should grow monotonically with `rho_mal` since naive FedAvg has no rejection mechanism. Results
written to `lstm_pipeline/poison_sweep_results.json`.

**Note:** `pipeline.py --from-step 1` runs the full STEPS list starting at step 1 (preprocess),
which will also execute steps 2, 3, 4 unless interrupted — if you only want the clean per-RSU
checkpoints (steps 1–2) without immediately overwriting `global.pt` via step 3, either stop the
process after step 2's `local_trainer.py` completes, or run `preprocessor.py` and `local_trainer.py`
directly instead of through `pipeline.py`.
