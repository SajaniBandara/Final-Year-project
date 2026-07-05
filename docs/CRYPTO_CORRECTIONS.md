# Crypto Layer Deviations from Proposal (Scope: Signing, Proofs, Witness,
# Trust, DKG Key Material, Detection-Signature Linkage)

This list excludes everything that is purely blockchain ledger/commit/write/
query/anchor/log mechanics (`bc_write_event`, `bc_log_flowmod`,
`bc_commit_flowmod`, `bc_query_flowmod`, `bc_anchor_to_global`,
`bc_commit_dkg`'s payload construction, `bc_commit_model_hash`/
`bc_verify_model_hash`, `BlockchainCommit`/`FlowModEndorsement` chain
fields) — that's tracked separately and owned by the teammate working on
the blockchain layer. One item below (DKG-1) sits right at that boundary
and needs a quick sync with them; it's flagged accordingly.

Severity key: **Critical** = undermines a core thesis claim or detection
result · **High** = real correctness/security gap · **Medium** = integration
gap or dead/duplicated code · **Low** = robustness/maintainability, not a
correctness bug.

---

## 1. ML-DSA-87 Signing Scheme

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| SIGN-1 | η_i is specified as "a fresh nonce preventing replay." The only live `mldsa87_sign()` call site passes the **flow ID** into the nonce-slot parameter — a constant reused across every packet of that flow at that hop, not a fresh per-signature value. Replay protection ends up resting entirely on `msg_id`+`timestamp` instead of a real nonce. | eq:mldsa_sign | `routing.cc:120422` | High |
| SIGN-2 | Witness alert signing (eq:da_sign/eq:nfa_sign) is specified as a distinct message structure: `H_SHA3-512(H(p)‖dst‖dst'‖ts_w)` for α_w and `H_SHA3-512(H(p)‖v_i‖ts_w‖T_fwd)` for β_w. The implementation reuses the generic per-packet `mldsa87_sign()` (built for eq:mldsa_sign's structure) and repurposes its fields to approximate this — `next_hop` is overloaded to mean `dup_dst`, and the "msg_id" is `pkt_id*1000+dst` rather than the actual packet hash `H(p)`. Functionally it still produces a valid, attributable ML-DSA-87 signature, but it isn't signing the literal message structure the equations define. | eq:da_sign, eq:nfa_sign | `witness_submit_duplication_alert()` / `witness_submit_nfa_alert()`, `crypto_layer.h:669–735` | Medium |
| SIGN-3 | `mldsa87_verify()` has exactly **one** call site in the entire codebase (the generic per-packet block). Real ML-DSA-87 signature verification essentially never drives any of the S5–S8 detection decisions (see DETECT-2 through DETECT-5 below) — it's computed once per packet for metrics purposes but not consumed by the signatures whose formal definitions require it. | §sec:crypto_layer, eq:sig_s5–s8 | `routing.cc:120912` | High |

---

## 2. STARK Proof Simulation

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| STARK-1 | A second, independent Δ_max threshold check is computed inline (`routing.cc:120915–120918`) purely to feed `stark_update_meta()`/LSTM counters, duplicating the same comparison `s2_detect_packet()` already performs properly via `stark_prove_timing()`/`stark_verify_timing()`. Two code paths, two separately-maintained constants (`S2_DELTA_MAX` vs. `STARK_DELTA_MAX`) that happen to both be 0.050 today but aren't tied together. | eq:stark_delay, eq:stark_delay_verify | `routing.cc:120915–120918` vs. `s2_detection.h` | Low |
| STARK-2 | `stark_update_meta()` — which feeds the two ZKP-failure indicators into the LSTM feature pipeline — is only called when `sig_ok == true`. Whenever the ML-DSA-87 signature itself fails, the timing/hop failure signal for that packet is silently dropped instead of recorded, so the LSTM input vector under-counts failures that co-occur with a bad signature. | eq:lstm_input | `routing.cc:120923–120930` | Medium |
| STARK-3 | `stark_verify_hop()` is called once (same generic per-packet block as SIGN-3) but, like ML-DSA-87 verify, is never consulted by S5/S6/S7's own `b_hop` checks — those use the ground-truth `*_malicious_nodes[]` arrays instead (see DETECT-2/3/4). | eq:stark_hop_verify, eq:sig_s5/s6/s7 | `routing.cc:120913` | High |

---

## 3. Aggregate / Batch Verification

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| BATCH-1 | `batch_verify_mldsa87()`'s 50 ms budget is simulated as a fixed `+0.001s` per packet rather than measured time, capping each tick at ~50 verifications. Packets beyond that cap in a given tick are simply skipped — there's no backlog/carry-over, and since the next tick's window is `now − 0.050s`, a skipped packet falls permanently outside the window and is **never verified** under high traffic load. This silently undercounts `sig_valid_rate` and weakens S8's `BatchVerify` evidence precisely when it matters most (high duplication/flood scenarios). | eq:batch_verify, eq:overhead_batch | `batch_verify_mldsa87()`, `crypto_layer.h:388–427` | Medium |
| BATCH-2 | On `crypto_batch_verify_tick()` failure, only an aggregate warning is logged (`NS_LOG_WARN`) — no specific offending node is identified or penalized. The per-node `BatchVerify ∧ b_π → trust update` loop in Algorithm BTMM is not implemented here. (Cross-referenced under TRUST-3 below, since it's really one gap viewed from two angles.) | Algorithm BTMM | `crypto_batch_verify_tick()`, `crypto_layer.h:615–633` | Critical |
| BATCH-3 | S8's first conjunct is literally `BatchVerify(...) = 1`. `s8_detect()` never calls `batch_verify_mldsa87()` — it substitutes the `0xDEAD0000` marker-absence check instead (see DETECT-5). | eq:sig_s8 | `s8_detection.h` | Critical |

---

## 4. Witness-Based Forwarding Verification

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| WIT-1 | `witness_check_duplication()` correctly applies the `WITNESS_WINDOW` cutoff (the formal `W` in `L_w(dst,W)`), but `g_witness_alert_pool` — the structure the `2f+1` BFT threshold is counted against — has **no time decay/expiry** at all. Alerts from arbitrarily early in the simulation can combine with new ones to cross the threshold, which doesn't match the windowed semantics implied by the rest of the witness model. Only `trust_init_all()` clears it, on a full reset. | eq:dup_alert_cond, eq:bft_penalty | `g_witness_alert_pool`, `crypto_layer.h:147–167, 669–735` | Medium |
| WIT-2 | The proposal states the *primary* detector for S7/S8 is witness-based monitoring (eq:dup_alert_cond + eq:bft_penalty), with `b_hop` only corroborating. In code, the witness path (drives `trust_update_negative`/quarantine) and `s7_detect()`/`s8_detect()` (drive `record_detection_event` independently) are two disconnected signals rather than the single combined indicator the narrative describes. | §sec:witness narrative for S7/S8 | `routing.cc` ~120825–120952 | Medium |
| WIT-3 | `check_msg_duplication()` is called but its boolean return value is discarded (`check_msg_duplication(pkt_hash, destination);` as a bare statement) — it mutates `g_msg_id_seen` with no resulting detection action anywhere. | eq:sig_s6 (msg-id duplication) | `routing.cc:120950` | Medium |

---

## 5. Trust Score Management

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| TRUST-1 | `trust_update_positive()` has **zero call sites anywhere** in the codebase, including inside `crypto_layer.h` itself. Node trust scores can only ever decrease, never recover — contradicts the reward branch of the update rule. | eq:trust_update | `crypto_layer.h:475` (defined, unused) | Critical |
| TRUST-2 | `ctrl_trust_update_positive()` likewise has zero call sites — controller trust also only ever decreases. | eq:ctrl_trust_update | `crypto_layer.h:514` (defined, unused) | High |
| TRUST-3 | The per-packet `BatchVerify ∧ b_π → reward/penalty` loop from Algorithm BTMM isn't implemented for any node. The only thing that currently moves a trust score is the witness BFT-threshold path (`trust_update_negative` called from `witness_submit_duplication_alert`/`witness_submit_nfa_alert`). Routine signature/STARK verification outcomes never touch trust at all. | Algorithm BTMM | `crypto_layer.h` (no caller wires `mldsa87_verify`/`stark_verify_*` results to `trust_update_*`) | Critical |
| TRUST-4 | `ctrl_reassign_rsus()`'s failover target selection (eq:ctrl_failover) uses a 1‑D zone-index difference as a proxy for `d(r_k, c_i)` (geographic distance), rather than an actual distance metric. Reasonable simulation simplification, but worth a comment/flag since the equation specifies a real distance function. | eq:rsu_ctrl_assign, eq:ctrl_failover | `ctrl_reassign_rsus()`, `crypto_layer.h:538–567` | Low |

---

## 6. S1–S8 Detection Signature ↔ Crypto-Layer Linkage

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| DETECT-1 | S2 is the one signature genuinely, correctly linked end-to-end — `s2_detect_packet()` calls real `stark_prove_timing()`/`stark_verify_timing()`. No fix needed; noted here only for contrast with the rest. | eq:sig_s2 | `s2_detection.h` | — (reference, not a bug) |
| DETECT-2 | S5 requires `ML-DSA-87.Verify(σ_copy,...)=0` and `b_hop(u)=0`. Implementation substitutes a `0xDEAD0000` marker bit in `recv_flow_id` for the verify failure, and `active_hf_malicious_nodes[prev_sender]` (ground truth) for `b_hop`. Neither `mldsa87_verify()` nor `stark_verify_hop()` is called from `s5_detect()`. | eq:sig_s5 | `s5_detection.h` | Critical |
| DETECT-3 | S6: identical marker-bit + ground-truth-array substitution for the ML-DSA-87/`b_hop` conjuncts. The duplication check (`s6_msg_recv_log`) is real but is a second, independent tracker parallel to `check_msg_duplication()`/`g_witness_log` rather than reusing them. | eq:sig_s6 | `s6_detection.h` | Critical |
| DETECT-4 | S7: same marker-bit proxy for `ML-DSA-87.Verify=1`; `b_hop_fails` is hardcoded `true` once the ground-truth flag passes. The volume-rate check is real but reimplemented locally (`s7_vol_count`/`s7_window_start`) instead of calling `crypto_layer.h`'s own `volume_check_anomaly()` — which is fed live data via `volume_record_delivery()` but is **never called anywhere**, so that mechanism's output is computed and discarded. | eq:sig_s7 | `s7_detection.h` | Critical |
| DETECT-5 | S8's `BatchVerify(...)=1` conjunct is replaced by the same `0xDEAD0000` marker-absence check; `batch_verify_mldsa87()` is never consulted by `s8_detect()` (cross-ref BATCH-3). | eq:sig_s8 | `s8_detection.h` | Critical |

---

## 7. DKG / Key Management (non-blockchain-write parts)

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| DKG-1 ⚠ | `dkg_rotate_keys()` correctly excludes the revoked RSU's commitment when computing the **new** `vk_zkp` — that part is correct, pure key-management logic. But it then hands the full `N_RSUs` count and the full (stale) `com[]` array to `bc_commit_dkg()` for the on-chain write, which is the boundary with the blockchain teammate's code. **Needs a quick sync**: either the crypto side should pass a filtered array/count of just the rotated set, or the blockchain side needs to accept and honor an explicit "active set" parameter instead of assuming `N_RSUs` entries are all current. | eq:vk_commit_rotated | `dkg_rotate_keys()`, `dkg_setup.h:74–107` (crypto side) ↔ `bc_commit_dkg()` (blockchain side) | High (coordination needed) |
| DKG-2 | `DKGState::com[64][64]` is hardcoded; default `N_RSUs = 64` sits exactly at that bound. Any CLI run configured with `N_RSUs > 64` will silently overflow `g_dkg.com[]` during the ceremony — pure key-storage sizing issue, no blockchain involvement. | — (robustness) | `crypto_layer.h:123`, `routing.cc:111` | Low |

---

## 8. Lightweight Authentication (HMAC-SHA3-512 / OBU mode)

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| HMAC-1 | DKG Phase 4 derives `hmac_key` for every vehicle, but `hmac_sha3_512()` is **never called** anywhere in `routing.cc`. The lightweight authentication tag τ_i is never actually produced or verified for any packet — the dual-mode (full/lightweight) architecture described in the proposal only ever exercises full mode in this simulation. | eq:hmac_light | `crypto_layer.h:64–69` (defined, unused) | Medium |

---

## 9. Federated LSTM Bridge (crypto-side only)

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| LSTM-1 | `crypto_get_lstm_features()` — the function that exports the two novel ZKP-failure indicators `𝟙[π_delay=⊥]`/`𝟙[π_hop=⊥]` into the LSTM input vector — is **never called**. The counters it would read (`g_lstm_stark_counts`/`g_lstm_pkt_counts`) are accumulated (subject to the STARK-2 gating gap above) but never exported to whatever LSTM training/inference code exists elsewhere. | eq:lstm_input | `crypto_layer.h:431` (defined, unused) | High |

---

## 10. Logging / Documentation

| # | Deviation | Proposal ref | Code location | Severity |
|---|---|---|---|---|
| LOG-1 | `CRYPTO_DEBUG_LOG` defaults to `true` and is never set anywhere in `routing.cc`; `crypto_register_cli_params()` doesn't expose it as a CLI flag despite an inline comment implying "normal runs" should have it off. Every run currently emits full per-packet `[CRYPTO-SIGN]/[CRYPTO-VERIFY]/[STARK]/[WITNESS-*]` logging. | — (hygiene) | `crypto_layer.h:42` | Low |
| DOC-1 | eq:overhead_full states the ML-DSA-87 signature is "4,595 bytes." The real NIST ML-DSA-87 size — and the value the code's own debug comments expect (`// expected 4627`) — is 4,627 bytes. Almost certainly a stale number in `main.tex`, not a code bug; confirmable by grepping a run's `sig_len=` output. | eq:overhead_full | `main__10_.tex` | Low (doc fix) |

---

## Suggested fix order (crypto-side scope only)

1. **DETECT-2 through DETECT-5** (S5–S8 not actually consuming `mldsa87_verify`/`stark_verify_hop`/`batch_verify_mldsa87`) — this is the single biggest gap between what the thesis claims drives detection and what actually does. Fixing this is what makes the "cryptographically-grounded" framing of Attacks 5–8 true rather than coincidentally-correct.
2. **TRUST-1, TRUST-3** (trust never recovers; BatchVerify/STARK results never drive trust at all) — affects any experiment measuring trust-score trajectories or long-run rehabilitation behavior.
3. **SIGN-1** (nonce/replay fix) — small, contained, and worth doing before any of the above since it touches the core `mldsa87_sign()` call signature.
4. **BATCH-1, STARK-2** — coverage gaps that quietly bias `sig_valid_rate` / LSTM feature accuracy under load; worth fixing before trusting any high-traffic-scenario numbers.
5. **DKG-1** — flag to your teammate now even though it's not yours to fix alone, since it's a shared function signature/contract issue.
6. **WIT-1, SIGN-2, LSTM-1, HMAC-1, TRUST-2, TRUST-4, DKG-2, LOG-1, DOC-1** — lower-severity / scope-dependent; fix opportunistically or explicitly note as out-of-scope limitations if lightweight-OBU mode and federated LSTM aren't part of this round's evaluation.