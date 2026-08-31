# Cryptographic Layer Implementation Plan (Corrected)

> **Reference:** `main.tex`
> Sections: §2.4 Hybrid Cryptographic Integrity Layer, §2.5 Blockchain Architecture Under
> Zero-Trust Controller Assumption, §2.6 Multi-Controller Zero-Trust Architecture, §1.7
> Distributed Trusted Time Reference.
>
> **Blockchain status:** `blockchain_sim.h` functions are in-memory stubs throughout this
> plan. They compile, run, and log to `g_rsu_chain`/`g_global_chain` vectors. No external
> chain linkage is required at this stage. Swap the stub implementations for real chain
> transactions later without changing any crypto layer code.
>
> **Corrections vs. previous plan:**
> - Gap 1: `eq:nfa_sign` non-forwarding alert (`β_w`) added — was entirely missing
> - Gap 1: `g_witness_alert_pool` now merges `α_w ∪ β_w` per `eq:bft_penalty`
> - Gap 3: `bc_commit_flowmod()` payload now explicitly includes `H(FlowMod)` binding
> - Gap 4: FlowMod log order corrected — receipt → log → endorsement check
> - Gap 5: `bc_query_flowmod()` key noted as simulation simplification
> - Gap 6: LSTM feature export bridge added (`crypto_get_lstm_features()`)
> - Gap 7: `bc_commit_model_hash()` / `bc_verify_model_hash()` stubs added for FL integration
> - Signature size: 4,627 bytes (liboqs) noted vs. 4,595 bytes (proposal citation); no
>   functional impact
> - Controller write-path guard confirmed: no BC write calls from controller code paths

---

## 1. Overview

The `routing.cc` simulation currently has no cryptography — all packet tags are plaintext,
timestamps and routing decisions are unprotected. This plan implements the full post-quantum
cryptographic integrity layer from the proposal so that:

- Every forwarded packet carries a verifiable ML-DSA-87 signature or HMAC-SHA3-512 tag
- Malicious nodes produce proofs that fail verification, driving existing attack detection
- Trust scores `T_v` rise or fall on cryptographic evidence, triggering smart-contract
  quarantine at `T_min`
- Attack signatures S1, S2, S5–S8 are grounded in cryptographic failures
- LSTM input vector receives `𝟙[π_delay=⊥]` and `𝟙[π_hop=⊥]` indicators via export bridge

### 1.1 Simulation-Realism Tradeoffs

| Component | Proposal Specification | Simulation Implementation | Reason |
|---|---|---|---|
| ML-DSA-87 keys | 2,592-byte pk / 4,896-byte sk | Real `OQS_SIG_keypair()` via liboqs | liboqs provides FIPS 204 ML-DSA-87 |
| ML-DSA-87 signing | 4,595 B/pkt (proposal) / 4,627 B (liboqs) | Real `OQS_SIG_sign()` via liboqs; sig stored in `g_packet_crypto`; 1.5 ms delay modelled | Size discrepancy is a parameter-set citation difference; no functional impact |
| ML-DSA-87 signing inputs | `H(msg_id ‖ ts_i ‖ η_i ‖ nh_i ‖ z_i)` per `eq:mldsa_sign` | All five fields present including `z_i` via `crypto_zone_id()` | `SigningInput` struct carries `zone_id` field |
| SHA3-512 | Full NIST FIPS 202 hash | Real `EVP_sha3_512()` via OpenSSL | Available after `sudo apt-get install libssl-dev` |
| HMAC-SHA3-512 | 64-byte MAC | Tag **generation** real via OpenSSL `HMAC(EVP_sha3_512(), ...)`; tag **verification** modelled (see §2.5) | Generation and its CPU cost are genuine and measured (`crypto_timing_log`). Verification is modelled: the threat model contains no impersonation attack, and HMAC authenticates origin, not truthfulness — a malicious forwarder signs its own false timestamp validly, which is why `alg:lrad_obu` specifies S2-partial as *"threshold only, no ZKP"* |
| Batch verification | Combined lattice equation `∑ r_i A_i z_i = ∑ r_i(t_i c_i + w'_i) mod q` | SHA3-512 Fiat-Shamir challenge (`eq:batch_challenge` faithful over full sigs + messages) + real `OQS_SIG_verify()` per sig | Internal lattice vectors not exposed by liboqs API; per-sig OQS verify provides equivalent correctness; 50 ms budget enforced via modelled 1 ms/sig delay |
| STARK proofs | 100 KB FRI proof, 10 ms verify | SHA3-512 commitment + logical validity flag + 10 ms delay | No open-source STARK library exists; `stark_timing_ok` and `stark_hop_ok` flags are exported to LSTM input vector |
| Two-tier blockchain | RSU-chain (PBFT) + global anchor | In-memory `vector<BlockchainCommit>` with two tiers | Preserves audit-trail semantics; swap to real chain without changing crypto code |
| DKG ceremony | Multi-round VSS among RSUs | Real ML-DSA-87 keypairs per RSU via liboqs + SHA3-512 `vk_ZKP` combination at `t = 0` | Outcome-faithful: each RSU holds genuine post-quantum keypair; result committed via `bc_commit_dkg()` |
| `T_ref` | GPS-synchronised RSU clocks | `Simulator::Now()` median across RSU nodes | Ideal clock acceptable in NS3; committed to blockchain every `T_sync` |
| Controller write access | Read-only per zero-trust model | No BC write functions called from controller code paths | Enforced by code structure |

---

## 2. Cryptographic Procedures (from Proposal)

Locate any equation with: `grep -n "label{eq:..." main.tex`

### 2.1 Per-Packet ML-DSA-87 Signing — `eq:mldsa_sign`

```
σ_i = ML-DSA-87.Sign(sk_i, H_SHA3-512(msg_id ‖ ts_i ‖ η_i ‖ nh_i ‖ z_i))
```

| Symbol | Meaning |
|---|---|
| `sk_i` | Signing node's ML-DSA-87 private key (4,896 bytes) |
| `ts_i` | Forwarding timestamp anchored to `T_ref` |
| `η_i` | Fresh per-packet nonce (replay prevention) — mapped to `seq` in simulation |
| `nh_i` | Chosen next-hop identity |
| `z_i` | Current RSU zone identifier (cross-zone replay prevention); 0 for vehicles |

Overhead: 4,627 bytes per packet (liboqs) · ~1.5 ms sign time (scheduled delay).

### 2.2 Aggregate Signature — Randomised Batch Verification — `eq:batch_challenge`, `eq:batch_verify`

Challenge over full signatures and messages (not truncated to 64 bytes):
```
r = H_SHA3-512(σ_1 ‖ ... ‖ σ_n ‖ m_1 ‖ ... ‖ m_n)
```

Verification: real `OQS_SIG_verify()` per sig within 50 ms budget.
Combined lattice equation not implementable via liboqs — per-sig verify provides equivalent
correctness guarantee. Note this tradeoff explicitly in thesis §2.4.

### 2.3 STARK Proof — Timing Compliance — `eq:stark_delay`, `eq:stark_delay_verify`

`b_delay,i = 0` when `t_fwd - t_recv > Δ_max (50 ms)`.
Contributes to S1 and S2 detection. `stark_timing_ok` flag exported to LSTM feature vector.

### 2.4 STARK Proof — Next-Hop Legitimacy — `eq:stark_hop`, `eq:stark_hop_verify`

`b_hop,i = 0` when `next_hop ∉ P(s,d)` (authorised policy set).
Contributes to S5–S8 detection. `stark_hop_ok` flag exported to LSTM feature vector.

### 2.5 Lightweight HMAC-SHA3-512 (OBU Mode) — `eq:hmac_light`

```
τ_i = HMAC-SHA3-512(k_i, msg_id ‖ ts_i ‖ η_i)
```

Three fields only (no `nh_i`, no `z_i` — matches proposal exactly). Tag: 64 bytes.
Pre-shared symmetric key established at RSU association. No non-repudiation.

**Implementation note — verification is modelled (2026-08-31).**

Tag generation is real: `lrad_hmac_tag_packet()` (`lrad_hmac.h`) computes a genuine
HMAC-SHA3-512 over the message with the node's pre-shared key, and its cost is
measured in `crypto_timing_log`.

Verification is not. `lrad_s2_partial_check()` (`lrad.h`) rebuilds the message from
the stored entry's **own** `ts` and `flow_id` — the same values that produced the
tag — and compares against that entry's tag, so the comparison is
`HMAC(k,m) == HMAC(k,m)` and cannot fail. `flag_S2p` is therefore the threshold
test `(t_now - ts_recv) > Δ_max` alone.

This is a deliberate modelling choice, not an oversight, for two reasons:

1. **HMAC authenticates origin, not truthfulness.** In S2 the malicious node is the
   *forwarder*; holding its own key `k_i`, it can sign a false timestamp validly, and
   a correct `HMAC.Verify` returns true. This is exactly why full S2 pairs the check
   with a ZKP (`eq:sig_s2`: `... ∧ π_delay(u) = ⊥`) and why `alg:lrad_obu`
   (`main.tex:2342`) annotates S2-partial *"threshold only, no ZKP"*.
2. **No forgery vector is modelled.** None of the eight attack variants is an
   impersonation or spoofing attack, so the third-party forgery that HMAC verification
   defends against never occurs in these simulations.

Implementing it faithfully would mean carrying `τ` in the packet tag per
`alg:lrad_obu`'s `HMAC.Verify(τ,p)`. That is cheap (ns-3 packet tags are simulation
metadata — they do not change packet size, airtime, PDR, latency, or any LSTM
feature) but would still produce a check that never fails, for reason 1.

**Message composition (corrected 2026-08-31).** Now matches `eq:hmac_light` exactly:

```
tau_i = HMAC-SHA3-512(k_i, msg_id || ts_i || eta_i)     16-byte buffer
        msg_id(4) | ts(8) | eta(4)
```

This is the full-mode 24-byte sign buffer (`eq:mldsa_sign`) minus `nh_i` and `z_i`,
which `eq:hmac_light` omits by design, so both modes now derive their inputs the
same way:

- `msg_id = crypto_msg_key(pkt_id, flow_id)`, the same convention full mode uses.
  `pkt_id` alone is a per-cycle slot index and does not identify a packet (see
  `docs/BUGS_MISMATCHES_AND_OPEN_DOUBTS_2026-08-31.md` section 1).
- `eta_i <- RAND()` via `OQS_randombytes()`, the same primitive the full-mode signer
  uses. Previously every caller passed `pkt_id` as the nonce, so the field duplicated
  `msg_id` and carried no entropy.

Verified behaviour-neutral: A2 @40%, 40 s, seed 1 - `d_obu_count`,
`escalation_count`, TP/FP/TN/FN and `avg_PDR` all bit-identical before and after.
Expected, since the nonce is stored and re-read by the same code path.

**Replay detection remains unmodelled.** `eta_i` is now a genuine fresh nonce, so
tags are unique per stamping, but nothing tracks nonce freshness on the receive
side, and given the verification above a freshness check would have nothing to
reject. The nonce makes the *construction* spec-faithful; it does not make replay
protection real.

### 2.6 Distributed Key Generation — `eq:vk_commit`, `eq:key_rotation_trigger`

Real ML-DSA-87 keypairs per RSU. `vk_ZKP = SHA3-512(Com_0 ‖ ... ‖ Com_{N-1})`.
Result committed via `bc_commit_dkg()`. Key rotation triggered when
`T_{r_j} < T_min ∧ r_j ∈ P_DKG_current`.

### 2.7 Multi-RSU FlowMod Endorsement — `eq:rsu_endorsement`, `eq:endorsed_commit`, `eq:flowmod_log`, `eq:unauth_flowmod`, `eq:policy_commit`

Per-RSU endorsement (ML-DSA-87, not HMAC — must be blockchain-attributable):
```
ε_j = ML-DSA-87.Sign(sk_{r_j}, H_SHA3-512(FlowMod ‖ ts ‖ T_{r_j}))
```

where `T_{r_j}` = SHA3-512(zone_id ‖ rsu_local_idx) — topology view proxy.

**Corrected commitment payload** (Gap 3 fix — now explicitly includes H(FlowMod)):
```
C_P = BC.Commit(H(FlowMod) ‖ {ε_j}^{f+1} ‖ ts_commit)
```

**Corrected FlowMod log order** (Gap 4 fix):
On FlowMod receipt: log immediately → then collect endorsements → then commit or reject.
`BC.LogFlowMod(r_k, H(FlowMod_recv) ‖ ts_recv ‖ ε_endorsement)` before rule installation.

Requires `f+1 = ⌊N_RSU/3⌋ + 1 = 22` endorsements.

### 2.8 RSU-Initiated Blockchain Writes — `eq:rsu_write`

```
BC.Write(r_k, v_s ‖ S_i ‖ ts ‖ ML-DSA-87.Sign(sk_{r_k}, H_SHA3-512(v_s ‖ S_i ‖ ts)))
```

RSUs are the **sole** blockchain writers. Controller has read-only access — no BC write
functions are called from any controller code path.

### 2.9 Trust Score Management — `eq:trust_update`, `eq:quarantine`

```
T_v^{t+1} = min(1, T_v^t + Δ_r)   if BatchVerify=1 AND b_π=1
           = max(0, T_v^t - Δ_p)   if BatchVerify=0 OR  b_π=0
```

Both conditions must hold for reward. Either failure causes penalty. `b_π` combines both
STARK proofs: `b_π = stark_timing_ok AND stark_hop_ok`.

Quarantine: `SC.Quarantine(v) ← T_v < T_min`

### 2.10 Controller Trust Management — `eq:trusted_ctrl_set`, `eq:ctrl_trust_update`, `eq:sc_revoke`, `eq:ctrl_failover`

```
T_{c_i}^{t+1} = min(1, T_{c_i}^t + Δ_r_ctrl)  if conflict_evidence < f+1
              = max(0, T_{c_i}^t - Δ_p_ctrl)  if conflict_evidence >= f+1
```

Revocation: `SC.Revoke(c_i) ← T_{c_i} < T_min_ctrl`
Failover: RSU re-assigned to `arg min d(r_k, c_j)` among remaining trusted controllers.

### 2.11 Distributed Trusted Time Reference — `eq:time_consensus`, `eq:delay_updated`

```
T_ref(t) = median_j τ_j(t),   j = 1,...,n_RSU
```

Committed to blockchain every `T_sync` seconds via `bc_write_event()`.
Robust to up to `f < n_RSU/2` faulty clocks.

### 2.12 Witness Alert Signing — `eq:dup_alert_cond`, `eq:nfwd_detect`, `eq:da_sign`, `eq:nfa_sign`, `eq:bft_penalty`

**Two distinct signed alert types (both required for `eq:bft_penalty`):**

Duplication alert `α_w` (`eq:da_sign`) — same packet hash seen at two destinations:
```
α_w = ML-DSA-87.Sign(sk_w, H_SHA3-512(H(p) ‖ dst ‖ dst' ‖ ts_w))
```

Non-forwarding alert `β_w` (`eq:nfa_sign`) — packet received by node but not forwarded
within deadline `T_fwd` (covers Attacks 1–4 delay variants):
```
β_w = ML-DSA-87.Sign(sk_w, H_SHA3-512(H(p) ‖ v_i ‖ ts_w ‖ T_fwd))
```

BFT penalty threshold uses the **union** of both alert types:
```
SC.PenalizeTrust(v_i) ← |{α_w ∪ β_w : ML-DSA-87.Verify(·) = 1}| >= 2f+1
```

Both alert types are written to blockchain via `bc_write_event()` immediately on submission.
`g_witness_alert_pool[target_node]` aggregates both types.

### 2.13 Two-Tier Blockchain Structure — `eq:anchor_hash`

```
H_anchor^{(r)} = H(H_root_RSU ‖ ts_anchor ‖ H_prev_global)
```

| Tier | Scope | Consensus | Block interval |
|---|---|---|---|
| RSU-chain | Per RSU cluster | PBFT (`f < n/3`) | 1 s |
| Global anchor | All 64 RSUs | Periodic Merkle root commit | `T_sync` |

### 2.14 LSTM Feature Export Bridge (Gap 6 — new)

`eq:lstm_input` requires `𝟙[π_delay=⊥]` and `𝟙[π_hop=⊥]` as binary features per timestep.
`crypto_get_lstm_features()` reads `g_packet_crypto` and exports these flags per node per
time window. Called by the LSTM data collection path at each 1s cycle.

### 2.15 Federated LSTM Blockchain Model Verification (Gap 7 — new stubs)

`eq:bc_model_verify` requires `SC.VerifyModelHash(H(W_local^k), CommittedHash^k)`.
Stubs `bc_commit_model_hash()` and `bc_verify_model_hash()` are provided in
`blockchain_sim.h` for the FL integration. Required for A4 ablation baseline ("No-BC").

---

## 3. Attack-to-Crypto Mapping

| Attack | Primary detection signal | Confirmatory crypto signal | Labels |
|---|---|---|---|
| S1 (CP Selective Delay) | EWMA delay anomaly | `bc_commit_flowmod()` → false (f+1 endorsements not met) + `stark_verify_timing()` → false | `eq:sig_s1`, `eq:rsu_endorsement`, `eq:stark_delay_verify` |
| S2 (DP Selective Delay) | Hop-delay > Δ_max | `stark_verify_timing()` → false | `eq:sig_s2`, `eq:stark_delay_verify` |
| S3 (CP TCAM Exhaustion) | FlowMod rate excess | `bc_query_flowmod()` → no committed policy endorsement | `eq:sig_s3`, `eq:unauth_flowmod` |
| S4 (DP TCAM Exhaustion) | PACKET_IN rate + TCAM util | No additional crypto signal | `eq:sig_s4` |
| S5 (CP Active HF) | Fabrication marker + malicious flag | All four conditions: `d'∉P(s,d)` + `bc_query_flowmod()→false` + `mldsa87_verify()→false` + `stark_verify_hop()→false` | `eq:sig_s5`, `eq:mldsa_sign`, `eq:stark_hop_verify`, `eq:unauth_flowmod` |
| S6 (DP Active HF) | Same msg_id at two destinations | `mldsa87_verify()→false` + `stark_verify_hop()→false` | `eq:sig_s6`, `eq:mldsa_sign`, `eq:stark_hop_verify` |
| S7 (CP Passive HF) | Volume rate anomaly | `stark_verify_hop()→false` + `bc_query_flowmod()→no policy` + witness BFT (`α_w ∪ β_w`) | `eq:sig_s7`, `eq:stark_hop_verify`, `eq:unauth_flowmod`, `eq:bft_penalty` |
| S8 (DP Passive HF) | Absent marker + malicious flag | `batch_verify_mldsa87()→true` + `stark_verify_hop()→false` + witness BFT (`α_w ∪ β_w`) | `eq:sig_s8`, `eq:bft_penalty` |

### 3.1 Pre-Blockchain Fixable Gaps

**Gap A — S3 second condition wrong (CRITICAL)**
Current `tcam_detection.h` uses `tcam_util > tcam_util_thresh` as S3 second condition.
`eq:sig_s3` requires `∄v : flow(r) ∈ F_active(v)`.
Fix: replace with `malicious_count > 0` as proxy until `BC.Query(C_P)` is live.

**Gap B — S3/S4 never call `record_detection_event` (CRITICAL)**
`ComputeTcamDetection()` computes `flag_s3`/`flag_s4` but never calls
`record_detection_event()`. TP/FP/TN/FN metrics for Attacks 3/4 are permanently wrong.
Fix: wire `record_detection_event(2, node_id)` / `record_detection_event(3, node_id)`
inside `ComputeTcamDetection()`.

**Gap C — S6 key alignment needed at crypto integration**
`s6_detection.h` uses `(base_flow_id, packet_id)` key; `g_msg_id_seen` uses SHA3-512
packet hash. Reconcile at integration time.

---

## 4. Prerequisites

### 4.1 Install libssl-dev

```bash
sudo apt-get install libssl-dev
```

Installs OpenSSL headers to `/usr/include/openssl/`. Enables `EVP_sha3_512()` and `HMAC()`.

### 4.2 Build and install liboqs

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git ~/liboqs
cd ~/liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

Verify:
```bash
ls /usr/local/include/oqs/oqs.h && ls /usr/local/lib/liboqs.so
```

Key liboqs constants for ML-DSA-87:
- `OQS_SIG_ml_dsa_87_length_public_key  = 2592`
- `OQS_SIG_ml_dsa_87_length_secret_key  = 4896`
- `OQS_SIG_ml_dsa_87_length_signature   = 4627`

---

## 5. Files to Create

### 5.1 `scratch/crypto_layer.h`

Included in `routing.cc` after all existing detection headers. All functions are
`static`/`inline` — single-translation-unit pattern, no separate `.cc` needed.

#### 5.1.1 Includes and Forward Declarations

```cpp
#ifndef CRYPTO_LAYER_H
#define CRYPTO_LAYER_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <map>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <oqs/oqs.h>
#include "ns3/simulator.h"
#include "ns3/log.h"

// Forward declarations — defined in blockchain_sim.h (included after this header).
// Valid in a single translation unit: compiler sees the decl here; the inline
// definition in blockchain_sim.h satisfies the linker.
void bc_write_event(uint32_t rsu_idx, uint32_t event_type, uint32_t node, double ts);
void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][64],
                   uint32_t n_rsus, double ts_setup);
```

#### 5.1.2 SHA3-512 and HMAC-SHA3-512 via OpenSSL

```cpp
static bool sha3_512_hash(const uint8_t* data, size_t len, uint8_t* out_64) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    unsigned int out_len = 64;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out_64, &out_len) == 1 && out_len == 64);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool hmac_sha3_512(const uint8_t* key, size_t klen,
                           const uint8_t* data, size_t dlen, uint8_t* out_64) {
    unsigned int out_len = 64;
    return HMAC(EVP_sha3_512(), key, (int)klen, data, dlen, out_64, &out_len) != nullptr
           && out_len == 64;
}
```

#### 5.1.3 Tunable Parameters (all CLI-exposed)

```cpp
double   TRUST_DELTA_R      = 0.05;   // CLI: --trust_delta_r
double   TRUST_DELTA_P      = 0.10;   // CLI: --trust_delta_p  (must satisfy Δ_p > Δ_r)
double   TRUST_T_MIN        = 0.50;   // CLI: --trust_t_min  (sweep {0.3,0.5,0.7})
double   TRUST_T_MIN_CTRL   = 0.50;   // CLI: --trust_t_min_ctrl (sweep {0.3,0.5,0.7})
double   TRUST_DELTA_R_CTRL = 0.05;   // CLI: --trust_delta_r_ctrl
double   TRUST_DELTA_P_CTRL = 0.10;   // CLI: --trust_delta_p_ctrl
double   STARK_DELTA_MAX    = 0.050;  // Δ_max = 50 ms (eq:stark_delay)
double   ML_DSA_SIGN_DELAY  = 0.0015; // 1.5 ms sign overhead (scheduled delay)
double   T_SYNC_INTERVAL    = 1.0;    // CLI: --t_sync  (sweep {0.5,1.0,2.0})
uint32_t BATCH_SIZE         = 15;     // CLI: --batch_size  (sweep {10,15,20})
double   WITNESS_WINDOW     = 10.0;   // CLI: --witness_window  (sweep {5,10,15})
uint32_t WITNESS_F          = 1;      // CLI: --witness_f  (sweep {1,2,3})
double   VOL_RATE_THRESH    = 5.0;    // CLI: --vol_rate_thresh (ε_vol)
```

#### 5.1.4 Data Structures

```cpp
// Real ML-DSA-87 key sizes from liboqs:
//   pk = 2592 bytes, sk = 4896 bytes
// 268 nodes × ~7.5 KB ≈ 2 MB total — acceptable.
struct NodeKeyMaterial {
    uint8_t  pk[OQS_SIG_ml_dsa_87_length_public_key];
    uint8_t  sk[OQS_SIG_ml_dsa_87_length_secret_key];
    uint8_t  hmac_key[64];       // HMAC-SHA3-512 pre-shared key (OBU/vehicle mode)
    bool     keys_generated = false;
    uint32_t node_id        = UINT32_MAX;
};
NodeKeyMaterial g_node_keys[total_size];

// Full ML-DSA-87 signature (4627 bytes) stored in memory.
// CryptoAnchorTag carries only sha3_512(sig) as a 64-byte reference.
// Active entries: ~275 × 4.7 KB ≈ 1.3 MB — evicted every 5 s.
//
// stark_timing_ok and stark_hop_ok are the 𝟙[π_delay=⊥] and 𝟙[π_hop=⊥] indicators
// exported to the LSTM input vector via crypto_get_lstm_features().
struct PacketCryptoMeta {
    uint8_t  sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t   sig_len          = 0;
    uint8_t  msg_digest[64]   = {};  // SHA3-512(SigningInput) — stored for eq:batch_challenge m_i
    uint8_t  hmac_tag[64]     = {};
    double   sign_timestamp   = 0.0;
    bool     sig_valid        = false;
    bool     stark_timing_ok  = false;  // b_delay,i — 𝟙[π_delay=⊥] for LSTM
    bool     stark_hop_ok     = false;  // b_hop,i   — 𝟙[π_hop=⊥]   for LSTM
};
// std::pair key eliminates any collision risk between (node_id, pkt_id) tuples.
std::map<std::pair<uint32_t,uint32_t>, PacketCryptoMeta> g_packet_crypto;

// All five fields from eq:mldsa_sign.
// zone_id (z_i) prevents cross-zone replay attacks.
// eta_nonce maps to seq in simulation (fresh per-packet nonce role).
struct SigningInput {
    uint32_t msg_id;
    uint32_t node_id;
    uint32_t next_hop;
    uint32_t seq;       // η_i — fresh per-packet nonce (replay prevention)
    uint32_t zone_id;   // z_i: rsu_controller_assignment[r] for RSU nodes; 0 for vehicles
    double   timestamp;
};

struct DKGState {
    uint8_t  vk_zkp[64]  = {};   // SHA3-512(Com_0 ‖ ... ‖ Com_{N_RSUs-1})
    uint8_t  com[64][64] = {};   // per-RSU commitment: Com_j = SHA3-512(pk_j)
    bool     ceremony_done = false;
    double   last_rotation = 0.0;
};
DKGState g_dkg;

// CORRECTED (Gap 3): endorsement_hash now computed over H(FlowMod) ‖ {ε_j} ‖ ts_commit
// so that stark_verify_hop() can reference this commitment as immutable ground truth.
struct FlowModEndorsement {
    uint8_t               flowmod_hash[64]     = {};  // SHA3-512(FlowMod params) — new
    uint8_t               endorsement_hash[64] = {};  // SHA3-512(flowmod_hash ‖ {ε_j} ‖ ts)
    std::vector<uint32_t> endorsing_rsus;
    bool   committed   = false;
    bool   logged      = false;           // true after pre-installation BC.Log (Gap 4)
    double log_time    = 0.0;             // timestamp of BC.LogFlowMod (before install)
    double commit_time = 0.0;
};
std::map<uint32_t, FlowModEndorsement> g_flowmod_endorsements;

struct StarkTimingProof { uint8_t commitment[64] = {}; bool valid = false; };
struct BatchVerifyResult { bool passed; uint32_t n_verified; double elapsed_s; };

// Unified witness log entry — used for both duplication (DA) and non-forwarding (NFA) alerts.
struct WitnessLogEntry {
    uint8_t  pkt_hash[64] = {};
    uint32_t dst;
    double   ts;
};

// Witness alert pool entry — covers both α_w (duplication) and β_w (non-forwarding).
// alert_type: 0 = α_w (DA), 1 = β_w (NFA). Both types count toward 2f+1 per eq:bft_penalty.
struct WitnessAlert {
    std::array<uint8_t,64> sig_hash = {};
    uint8_t alert_type = 0;  // 0 = α_w, 1 = β_w
};

// Trust score arrays
double g_trust_score[total_size]       = {};
double g_trust_last_update[total_size] = {};
bool   g_quarantined[total_size]       = {};
double g_ctrl_trust_score[total_size]  = {};
bool   g_ctrl_revoked[total_size]      = {};

double g_T_ref = 0.0, g_T_ref_last_sync = 0.0;

std::map<uint32_t, std::vector<WitnessLogEntry>> g_witness_log;
std::map<uint32_t, std::vector<WitnessAlert>>    g_witness_alert_pool;  // α_w ∪ β_w
std::map<uint64_t, std::pair<uint32_t,double>>   g_msg_id_seen;
std::map<uint32_t, double> g_dst_volume_prev, g_dst_volume_curr;

// LSTM feature export: per-node crypto indicators for the current 1s cycle.
// crypto_get_lstm_features(node) returns {stark_timing_fail_count, stark_hop_fail_count}
// to be inserted as 𝟙[π_delay=⊥] and 𝟙[π_hop=⊥] in eq:lstm_input.
struct CryptoLstmFeatures {
    float stark_timing_fail;  // fraction of packets this cycle with stark_timing_ok=false
    float stark_hop_fail;     // fraction of packets this cycle with stark_hop_ok=false
};
// Accumulator reset each LSTM cycle by crypto_reset_lstm_accumulators()
std::map<uint32_t, std::pair<uint32_t,uint32_t>> g_lstm_stark_counts; // node→{timing_fail,hop_fail}
std::map<uint32_t, uint32_t>                      g_lstm_pkt_counts;   // node→total_pkts
```

#### 5.1.5 liboqs Singleton and Zone Helper

```cpp
static OQS_SIG* g_oqs_sig = nullptr;
static OQS_SIG* get_oqs_ctx() {
    if (!g_oqs_sig) g_oqs_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    return g_oqs_sig;
}

// z_i per eq:mldsa_sign: RSU r → zone = rsu_controller_assignment[r]; vehicles → 0
static inline uint32_t crypto_zone_id(uint32_t node_index) {
    if (node_index >= N_Vehicles && node_index < N_Vehicles + N_RSUs)
        return (uint32_t)rsu_controller_assignment[node_index - N_Vehicles];
    return 0;
}
```

#### 5.1.6 ML-DSA-87 Key Generation — `eq:vk_commit`

```cpp
inline bool mldsa87_keygen(uint32_t node_index) {
    if (node_index >= (uint32_t)total_size) return false;
    NodeKeyMaterial& km = g_node_keys[node_index];
    if (km.keys_generated) return true;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;
    if (OQS_SIG_keypair(sig, km.pk, km.sk) != OQS_SUCCESS) return false;
    km.keys_generated = true;
    km.node_id = node_index;
    return true;
}
```

#### 5.1.7 ML-DSA-87 Signing — `eq:mldsa_sign`

```cpp
inline bool mldsa87_sign(uint32_t signer, uint32_t pkt_id,
                          uint32_t next_hop, uint32_t seq) {
    if (signer >= (uint32_t)total_size) return false;
    if (!g_node_keys[signer].keys_generated && !mldsa87_keygen(signer)) return false;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // Build message per eq:mldsa_sign: H(msg_id ‖ ts_i ‖ η_i ‖ nh_i ‖ z_i)
    SigningInput inp;
    inp.msg_id    = pkt_id;
    inp.node_id   = signer;
    inp.next_hop  = next_hop;
    inp.seq       = seq;                         // η_i
    inp.zone_id   = crypto_zone_id(signer);      // z_i
    inp.timestamp = Simulator::Now().GetSeconds();

    uint8_t digest[64];
    if (!sha3_512_hash(reinterpret_cast<const uint8_t*>(&inp), sizeof(inp), digest))
        return false;

    PacketCryptoMeta& meta = g_packet_crypto[{signer, pkt_id}];
    memcpy(meta.msg_digest, digest, 64);  // stored for eq:batch_challenge m_i
    meta.sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(sig, meta.sig, &meta.sig_len,
                     digest, 64, g_node_keys[signer].sk) != OQS_SUCCESS) {
        meta.sig_len = 0;
        return false;
    }
    meta.sign_timestamp = inp.timestamp;
    meta.sig_valid = true;
    return true;
}
```

#### 5.1.8 ML-DSA-87 Verification

```cpp
inline bool mldsa87_verify(uint32_t claimed_signer, uint32_t pkt_id,
                            uint32_t next_hop, uint32_t seq) {
    if (claimed_signer >= (uint32_t)total_size) return false;
    auto it = g_packet_crypto.find({claimed_signer, pkt_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return false;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // Reconstruct same SigningInput — any field tampered by attacker → OQS_ERROR
    SigningInput inp;
    inp.msg_id    = pkt_id;
    inp.node_id   = claimed_signer;
    inp.next_hop  = next_hop;
    inp.seq       = seq;
    inp.zone_id   = crypto_zone_id(claimed_signer);
    inp.timestamp = it->second.sign_timestamp;

    uint8_t digest[64];
    if (!sha3_512_hash(reinterpret_cast<const uint8_t*>(&inp), sizeof(inp), digest))
        return false;

    bool ok = OQS_SIG_verify(sig, digest, 64,
                              it->second.sig, it->second.sig_len,
                              g_node_keys[claimed_signer].pk) == OQS_SUCCESS;
    it->second.sig_valid = ok;
    return ok;
}
```

#### 5.1.9 STARK Proof Simulation — `eq:stark_delay` / `eq:stark_hop`

```cpp
inline StarkTimingProof stark_prove_timing(double t_recv, double t_fwd, uint32_t nonce) {
    StarkTimingProof proof;
    proof.valid = (t_fwd - t_recv) <= STARK_DELTA_MAX;
    uint8_t buf[20];
    memcpy(buf, &t_recv, 8); memcpy(buf+8, &t_fwd, 8); memcpy(buf+16, &nonce, 4);
    sha3_512_hash(buf, 20, proof.commitment);
    return proof;
}

inline bool stark_verify_timing(const StarkTimingProof& proof,
                                 double t_recv, double t_fwd) {
    return proof.valid && (t_fwd - t_recv) <= STARK_DELTA_MAX;
}

// Returns false when next_hop is not the authorised hop for src→dst (v_{i+1} ∉ P_i).
inline bool stark_verify_hop(uint32_t next_hop, uint32_t src, uint32_t dst) {
    uint32_t expected = find_next_hop(src, dst, next_hop);
    return (expected != (uint32_t)-1)
        && (expected < (uint32_t)total_size)
        && (next_hop == expected);
}

// Update PacketCryptoMeta STARK flags and LSTM accumulators in one call.
// Called immediately after verifying a packet so LSTM export is always current.
inline void stark_update_meta(uint32_t signer, uint32_t pkt_id,
                               bool timing_ok, bool hop_ok) {
    auto it = g_packet_crypto.find({signer, pkt_id});
    if (it == g_packet_crypto.end()) return;
    it->second.stark_timing_ok = timing_ok;
    it->second.stark_hop_ok    = hop_ok;
    // Accumulate for LSTM export
    g_lstm_pkt_counts[signer]++;
    if (!timing_ok) g_lstm_stark_counts[signer].first++;
    if (!hop_ok)    g_lstm_stark_counts[signer].second++;
}
```

#### 5.1.10 Randomised Batch Verification — `eq:batch_challenge` / `eq:batch_verify`

```cpp
inline BatchVerifyResult batch_verify_mldsa87(
    const std::vector<std::pair<uint32_t,uint32_t>>& node_pkt_pairs,
    double budget_s = 0.050)
{
    BatchVerifyResult res{true, 0, 0.0};

    // eq:batch_challenge: r = SHA3-512(σ_1‖...‖σ_n‖m_1‖...‖m_n)
    // Full signatures first (complete 4627-byte sigs, not truncated), then all message
    // digests. This is the faithful Fiat-Shamir transcript per eq:batch_challenge.
    std::vector<uint8_t> combined;
    combined.reserve(node_pkt_pairs.size() *
                     (OQS_SIG_ml_dsa_87_length_signature + 64));
    for (auto& [node, pkt] : node_pkt_pairs) {
        auto it = g_packet_crypto.find({node, pkt});
        if (it != g_packet_crypto.end() && it->second.sig_len > 0)
            combined.insert(combined.end(),
                            it->second.sig,
                            it->second.sig + it->second.sig_len);
    }
    for (auto& [node, pkt] : node_pkt_pairs) {
        auto it = g_packet_crypto.find({node, pkt});
        if (it != g_packet_crypto.end() && it->second.sig_len > 0)
            combined.insert(combined.end(),
                            it->second.msg_digest, it->second.msg_digest + 64);
    }
    uint8_t challenge[64];
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), challenge);

    // eq:batch_verify — per-sig real OQS_SIG_verify within 50 ms budget.
    // Note: combined lattice equation (∑ r_i A_i z_i = ∑ r_i(t_i c_i + w'_i) mod q)
    // is not implementable via the liboqs high-level API (internal Dilithium vectors
    // A_i, z_i, t_i, c_i, w'_i are not exposed). Per-sig OQS_SIG_verify provides
    // equivalent security: any individual forgery is caught. Declare this limitation
    // in thesis §2.4.
    for (auto& [node, pkt] : node_pkt_pairs) {
        if (res.elapsed_s >= budget_s) break;
        if (!mldsa87_verify(node, pkt, 0, 0)) res.passed = false;
        ++res.n_verified;
        res.elapsed_s += 0.001; // ~1 ms per ML-DSA-87 verify (modelled)
    }
    return res;
}
```

#### 5.1.11 LSTM Feature Export Bridge — `eq:lstm_input` (Gap 6 fix)

```cpp
// Returns the binary STARK failure indicators for a given node over the last cycle.
// Call this from the LSTM data collection path at each 1s routing cycle.
// Output: stark_timing_fail = fraction of packets with timing proof failure (→ 𝟙[π_delay=⊥])
//         stark_hop_fail    = fraction of packets with hop proof failure    (→ 𝟙[π_hop=⊥])
inline CryptoLstmFeatures crypto_get_lstm_features(uint32_t node) {
    CryptoLstmFeatures f{0.0f, 0.0f};
    auto pc = g_lstm_pkt_counts.find(node);
    if (pc == g_lstm_pkt_counts.end() || pc->second == 0) return f;
    auto sc = g_lstm_stark_counts.find(node);
    if (sc == g_lstm_stark_counts.end()) return f;
    float total = (float)pc->second;
    f.stark_timing_fail = (float)sc->second.first  / total;
    f.stark_hop_fail    = (float)sc->second.second / total;
    return f;
}

// Call at the start of each LSTM collection cycle (every 1s) to reset accumulators.
inline void crypto_reset_lstm_accumulators() {
    g_lstm_pkt_counts.clear();
    g_lstm_stark_counts.clear();
}
```

#### 5.1.12 Trust Management — `eq:trust_update` / `eq:quarantine`

```cpp
inline void trust_init_all() {
    for (uint32_t i = 0; i < (uint32_t)total_size; ++i) {
        g_trust_score[i] = g_ctrl_trust_score[i] = 1.0;
        g_quarantined[i] = g_ctrl_revoked[i]      = false;
        g_trust_last_update[i] = 0.0;
        g_node_keys[i] = NodeKeyMaterial{};
    }
    memset(&g_dkg, 0, sizeof(DKGState));
    g_T_ref = g_T_ref_last_sync = 0.0;
    g_packet_crypto.clear(); g_flowmod_endorsements.clear();
    g_witness_log.clear(); g_witness_alert_pool.clear();
    g_msg_id_seen.clear(); g_dst_volume_prev.clear(); g_dst_volume_curr.clear();
    g_lstm_pkt_counts.clear(); g_lstm_stark_counts.clear();
    if (g_oqs_sig) { OQS_SIG_free(g_oqs_sig); g_oqs_sig = nullptr; }
}

inline void trust_update_positive(uint32_t node) {
    if (node >= (uint32_t)total_size) return;
    g_trust_score[node] = std::min(1.0, g_trust_score[node] + TRUST_DELTA_R);
    g_trust_last_update[node] = Simulator::Now().GetSeconds();
}

inline void trust_update_negative(uint32_t node) {
    if (node >= (uint32_t)total_size) return;
    g_trust_score[node] = std::max(0.0, g_trust_score[node] - TRUST_DELTA_P);
    g_trust_last_update[node] = Simulator::Now().GetSeconds();
    if (g_trust_score[node] < TRUST_T_MIN && !g_quarantined[node]) {
        g_quarantined[node] = true;
        t_quarantine[node]  = Simulator::Now().GetSeconds();
        if (active_attack_variant >= 0 && active_attack_variant < NUM_ATTACK_VARIANTS)
            record_detection_event(active_attack_variant, (int)node);
        NS_LOG_WARN("[TRUST] Quarantine: node=" << node
            << " trust=" << g_trust_score[node]
            << " t=" << Simulator::Now().GetSeconds());
    }
}

inline void ctrl_trust_update_positive(uint32_t ctrl) {
    if (ctrl >= N_Controllers || g_ctrl_revoked[ctrl]) return;
    g_ctrl_trust_score[ctrl] = std::min(1.0,
        g_ctrl_trust_score[ctrl] + TRUST_DELTA_R_CTRL);
}

inline void ctrl_trust_update_negative(uint32_t ctrl) {
    if (ctrl >= N_Controllers) return;
    g_ctrl_trust_score[ctrl] = std::max(0.0,
        g_ctrl_trust_score[ctrl] - TRUST_DELTA_P_CTRL);
    if (g_ctrl_trust_score[ctrl] < TRUST_T_MIN_CTRL && !g_ctrl_revoked[ctrl]) {
        g_ctrl_revoked[ctrl] = true;
        ctrl_reassign_rsus(ctrl);
        NS_LOG_WARN("[CTRL-TRUST] Controller revoked: idx=" << ctrl
            << " t=" << Simulator::Now().GetSeconds());
    }
}

// eq:rsu_ctrl_assign + eq:ctrl_failover
// Re-assigns every RSU that was under revoked_ctrl to the nearest remaining
// trusted controller. "Nearest" approximated by controller-zone distance.
inline void ctrl_reassign_rsus(uint32_t revoked_ctrl) {
    std::vector<uint32_t> trusted;
    for (uint32_t c = 0; c < N_Controllers; ++c)
        if (!g_ctrl_revoked[c]) trusted.push_back(c);
    if (trusted.empty()) {
        NS_LOG_ERROR("[CTRL] All controllers revoked — no failover possible");
        return;
    }
    uint32_t zone_size = N_RSUs / N_Controllers;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        if ((uint32_t)rsu_controller_assignment[r] != revoked_ctrl) continue;
        uint32_t rsu_zone = r / (zone_size > 0 ? zone_size : 1);
        uint32_t best = trusted[0], min_d = UINT32_MAX;
        for (uint32_t c : trusted) {
            uint32_t d = (rsu_zone > c) ? rsu_zone - c : c - rsu_zone;
            if (d < min_d) { min_d = d; best = c; }
        }
        rsu_controller_assignment[r] = (int)best;
        NS_LOG_WARN("[CTRL-FAILOVER] RSU " << r << " ctrl " << revoked_ctrl
            << " → " << best);
    }
}
```

#### 5.1.13 Distributed Time Reference — `eq:time_consensus`

```cpp
inline void update_T_ref() {
    std::vector<double> times;
    times.reserve(N_RSUs);
    for (uint32_t r = 0; r < N_RSUs; ++r)
        times.push_back(Simulator::Now().GetSeconds());
    std::sort(times.begin(), times.end());
    g_T_ref           = times[times.size() / 2];
    g_T_ref_last_sync = Simulator::Now().GetSeconds();
}

inline void update_T_ref_recurring() {
    update_T_ref();
    // Commit T_ref to blockchain every T_sync per eq:time_consensus
    bc_write_event(N_Vehicles /*RSU 0*/, 3 /*event_type=T_ref_sync*/,
                   0, g_T_ref);
    Simulator::Schedule(Seconds(T_SYNC_INTERVAL), &update_T_ref_recurring);
}
```

#### 5.1.14 Map Eviction

```cpp
inline void crypto_evict_old_entries() {
    double cutoff = Simulator::Now().GetSeconds() - 5.0;
    for (auto it = g_packet_crypto.begin(); it != g_packet_crypto.end(); )
        it = (it->second.sign_timestamp < cutoff)
             ? g_packet_crypto.erase(it) : std::next(it);
    double wcut = Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    for (auto& [w, entries] : g_witness_log)
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [wcut](const WitnessLogEntry& e){ return e.ts < wcut; }),
            entries.end());
}

inline void crypto_evict_old_entries_recurring() {
    crypto_evict_old_entries();
    Simulator::Schedule(Seconds(5.0), &crypto_evict_old_entries_recurring);
}
```

#### 5.1.15 Batch Verify Tick (recurring, 50 ms)

```cpp
inline void crypto_batch_verify_tick() {
    std::vector<std::pair<uint32_t,uint32_t>> pending;
    double window = Simulator::Now().GetSeconds() - 0.050;
    for (auto& [key, meta] : g_packet_crypto)
        if (meta.sign_timestamp >= window) pending.push_back(key);
    if (!pending.empty()) {
        auto result = batch_verify_mldsa87(pending);
        if (!result.passed)
            NS_LOG_WARN("[BATCH] Verify failed: " << pending.size() << " pkts");
    }
    Simulator::Schedule(Seconds(0.050), &crypto_batch_verify_tick);
}
```

#### 5.1.16 Witness Mechanism — `eq:da_sign`, `eq:nfa_sign`, `eq:bft_penalty` (Corrected)

Both `α_w` (duplication alert) and `β_w` (non-forwarding alert) are now implemented.
Both types contribute to the unified `g_witness_alert_pool` per `eq:bft_penalty`.

```cpp
inline void witness_log_packet(uint32_t witness, const uint8_t* pkt_hash,
                                uint32_t dst, double ts) {
    WitnessLogEntry e;
    memcpy(e.pkt_hash, pkt_hash, 64); e.dst = dst; e.ts = ts;
    g_witness_log[witness].push_back(e);
}

inline bool witness_check_duplication(uint32_t witness, const uint8_t* pkt_hash,
                                       uint32_t dst_seen_now) {
    auto it = g_witness_log.find(witness);
    if (it == g_witness_log.end()) return false;
    double cutoff = Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    for (auto& e : it->second)
        if (memcmp(e.pkt_hash, pkt_hash, 64) == 0 &&
            e.dst != dst_seen_now && e.ts >= cutoff)
            return true;
    return false;
}

// α_w: duplication alert — same packet at two destinations (eq:da_sign).
// Signs H_SHA3-512(H(p) ‖ dst ‖ dst' ‖ ts_w) with witness ML-DSA-87 key.
inline void witness_submit_duplication_alert(uint32_t witness, uint32_t target_node,
                                              uint32_t pkt_id, uint32_t dst,
                                              uint32_t dup_dst) {
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    uint32_t sign_id = pkt_id * 1000 + dst;
    if (!mldsa87_sign(witness, sign_id, dup_dst,
                      (uint32_t)Simulator::Now().GetSeconds())) return;
    auto it = g_packet_crypto.find({witness, sign_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return;
    WitnessAlert alert;
    memcpy(alert.sig_hash.data(), it->second.sig, 64);
    alert.alert_type = 0;  // α_w
    g_witness_alert_pool[target_node].push_back(alert);
    // α_w written directly to blockchain per eq:da_sign
    bc_write_event(N_Vehicles, 2 /*witness_alert*/, target_node,
                   Simulator::Now().GetSeconds());
    // Check BFT threshold: |{α_w ∪ β_w : Verify=1}| >= 2f+1  (eq:bft_penalty)
    if ((uint32_t)g_witness_alert_pool[target_node].size() >= 2 * WITNESS_F + 1) {
        NS_LOG_WARN("[WITNESS-DA] BFT threshold reached for node " << target_node);
        trust_update_negative(target_node);
    }
}

// β_w: non-forwarding alert — packet received by v_i but not forwarded within T_fwd (eq:nfa_sign).
// Signs H_SHA3-512(H(p) ‖ v_i ‖ ts_w ‖ T_fwd) with witness ML-DSA-87 key.
// Covers Attacks 1–4 (delay variants) from the witness perspective.
inline void witness_submit_nfa_alert(uint32_t witness, uint32_t target_node,
                                      uint32_t pkt_id, double T_fwd) {
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    // Unique sign_id for NFA alerts: offset from DA range to avoid collision
    uint32_t sign_id = pkt_id * 1000 + (uint32_t)(T_fwd * 1000) + 500000;
    uint32_t ts_u    = (uint32_t)Simulator::Now().GetSeconds();
    if (!mldsa87_sign(witness, sign_id, target_node, ts_u)) return;
    auto it = g_packet_crypto.find({witness, sign_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return;
    WitnessAlert alert;
    memcpy(alert.sig_hash.data(), it->second.sig, 64);
    alert.alert_type = 1;  // β_w
    g_witness_alert_pool[target_node].push_back(alert);
    // β_w written directly to blockchain per eq:nfa_sign
    bc_write_event(N_Vehicles, 4 /*nfa_alert*/, target_node,
                   Simulator::Now().GetSeconds());
    // Check BFT threshold: unified pool includes both α_w and β_w (eq:bft_penalty)
    if ((uint32_t)g_witness_alert_pool[target_node].size() >= 2 * WITNESS_F + 1) {
        NS_LOG_WARN("[WITNESS-NFA] BFT threshold reached for node " << target_node);
        trust_update_negative(target_node);
    }
}
```

#### 5.1.17 Volume Rate Tracking — S7, `eq:sig_s7`

```cpp
inline void volume_record_delivery(uint32_t dst) { g_dst_volume_curr[dst]++; }

inline bool volume_check_anomaly(uint32_t dst) {
    double prev = g_dst_volume_prev.count(dst) ? g_dst_volume_prev[dst] : 0.0;
    double curr = g_dst_volume_curr.count(dst) ? g_dst_volume_curr[dst] : 0.0;
    return (curr - prev) / (T_SYNC_INTERVAL > 0 ? T_SYNC_INTERVAL : 1.0)
           > VOL_RATE_THRESH;
}

inline void volume_tick() {
    for (auto& [dst, cnt] : g_dst_volume_curr) g_dst_volume_prev[dst] = cnt;
    g_dst_volume_curr.clear();
}
```

#### 5.1.18 Msg-ID Duplication Cache — S6

```cpp
inline bool check_msg_duplication(const uint8_t* pkt_hash, uint32_t dst_now) {
    uint64_t key; memcpy(&key, pkt_hash, 8);
    auto it = g_msg_id_seen.find(key);
    if (it == g_msg_id_seen.end()) {
        g_msg_id_seen[key] = {dst_now, Simulator::Now().GetSeconds()};
        return false;
    }
    return (it->second.first != dst_now);
}
```

#### 5.1.19 FlowMod RSU Endorsement — `eq:rsu_endorsement` (Corrected)

Now computes `H(FlowMod)` explicitly and stores it in `FlowModEndorsement.flowmod_hash`
so that `bc_commit_flowmod()` can include it in the commitment payload per `eq:endorsed_commit`.

```cpp
inline bool flowmod_endorse(uint32_t rsu_idx, uint32_t flow_id,
                             const uint8_t* flowmod_params, size_t params_len) {
    if (rsu_idx >= (uint32_t)total_size) return false;
    if (!g_node_keys[rsu_idx].keys_generated && !mldsa87_keygen(rsu_idx)) return false;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return false;

    double   ts            = Simulator::Now().GetSeconds();
    uint32_t rsu_local_idx = rsu_idx - N_Vehicles;
    uint32_t zone          = crypto_zone_id(rsu_idx);

    // T_{r_j} = SHA3-512(zone_id ‖ rsu_local_idx) — topology view proxy
    uint8_t topo_in[8];
    memcpy(topo_in,   &zone,          4);
    memcpy(topo_in+4, &rsu_local_idx, 4);
    uint8_t T_rj[64];
    sha3_512_hash(topo_in, 8, T_rj);

    // Compute H(FlowMod) first — stored in endorsement for Gap 3 fix
    uint8_t flowmod_hash[64] = {};
    if (params_len > 0 && flowmod_params)
        sha3_512_hash(flowmod_params, params_len, flowmod_hash);
    else {
        // No params: hash the flow_id as proxy
        sha3_512_hash(reinterpret_cast<const uint8_t*>(&flow_id), 4, flowmod_hash);
    }

    // Build endorsement message: FlowMod ‖ ts ‖ T_{r_j}
    std::vector<uint8_t> msg(params_len + 8 + 64);
    size_t off = 0;
    if (params_len && flowmod_params) { memcpy(msg.data(), flowmod_params, params_len); off += params_len; }
    memcpy(msg.data() + off, &ts,  8);  off += 8;
    memcpy(msg.data() + off, T_rj, 64);

    uint8_t msg_digest[64];
    sha3_512_hash(msg.data(), msg.size(), msg_digest);

    // Real ML-DSA-87.Sign(sk_{r_j}, msg_digest) — blockchain-attributable
    uint8_t endorsement_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  endorsement_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, endorsement_sig, &endorsement_sig_len,
                     msg_digest, 64, g_node_keys[rsu_idx].sk) != OQS_SUCCESS)
        return false;

    FlowModEndorsement& e = g_flowmod_endorsements[flow_id];
    // Store H(FlowMod) on first endorser (Gap 3 fix)
    if (e.endorsing_rsus.empty()) {
        memcpy(e.flowmod_hash, flowmod_hash, 64);
        sha3_512_hash(endorsement_sig, endorsement_sig_len, e.endorsement_hash);
    }
    e.endorsing_rsus.push_back(rsu_idx);
    return true;
}
```

#### 5.1.20 CLI Parameter Registration

```cpp
inline void crypto_register_cli_params(ns3::CommandLine& cmd) {
    cmd.AddValue("trust_delta_r",      "Trust reward Δ_r",                   TRUST_DELTA_R);
    cmd.AddValue("trust_delta_p",      "Trust penalty Δ_p (must be > Δ_r)",  TRUST_DELTA_P);
    cmd.AddValue("trust_t_min",        "Quarantine threshold T_min",          TRUST_T_MIN);
    cmd.AddValue("trust_t_min_ctrl",   "Controller revocation threshold",     TRUST_T_MIN_CTRL);
    cmd.AddValue("trust_delta_r_ctrl", "Controller reward Δ_r^ctrl",          TRUST_DELTA_R_CTRL);
    cmd.AddValue("trust_delta_p_ctrl", "Controller penalty Δ_p^ctrl",         TRUST_DELTA_P_CTRL);
    cmd.AddValue("t_sync",             "T_ref sync interval (s)",             T_SYNC_INTERVAL);
    cmd.AddValue("batch_size",         "Packets per batch verify cycle B",    BATCH_SIZE);
    cmd.AddValue("witness_window",     "Witness observation window W (s)",    WITNESS_WINDOW);
    cmd.AddValue("witness_f",          "Witness BFT parameter f",             WITNESS_F);
    cmd.AddValue("vol_rate_thresh",    "Volume rate threshold ε_vol (pkt/s)", VOL_RATE_THRESH);
}

#endif // CRYPTO_LAYER_H
```

---

### 5.2 `scratch/dkg_setup.h`

Included after `crypto_layer.h`.

```cpp
#ifndef DKG_SETUP_H
#define DKG_SETUP_H

inline void dkg_run_ceremony() {
    if (g_dkg.ceremony_done) return;

    // Phase 1: Real ML-DSA-87 keypairs for all RSUs
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t idx = N_Vehicles + r;
        if (!mldsa87_keygen(idx)) {
            NS_LOG_ERROR("[DKG] Key gen failed for RSU " << r);
            continue;
        }
        // Com_j = SHA3-512(pk_j) — 64-byte commitment to each RSU public key
        sha3_512_hash(g_node_keys[idx].pk,
                      OQS_SIG_ml_dsa_87_length_public_key,
                      g_dkg.com[r]);
    }

    // Phase 2: vk_ZKP = SHA3-512(Com_0 ‖ Com_1 ‖ ... ‖ Com_{N_RSUs-1})
    std::vector<uint8_t> combined(N_RSUs * 64);
    for (uint32_t r = 0; r < N_RSUs; ++r)
        memcpy(combined.data() + r * 64, g_dkg.com[r], 64);
    if (!sha3_512_hash(combined.data(), combined.size(), g_dkg.vk_zkp)) {
        NS_LOG_ERROR("[DKG] vk_ZKP computation failed");
        return;
    }

    // Phase 3: Real ML-DSA-87 keypairs for all vehicles
    for (uint32_t v = 0; v < N_Vehicles; ++v)
        mldsa87_keygen(v);

    // Phase 4: HMAC pre-shared keys for OBU (vehicle) mode
    // hmac_key_v = SHA3-512(v ‖ vk_ZKP)
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        uint8_t seed[68];
        memcpy(seed,   &v,            4);
        memcpy(seed+4, g_dkg.vk_zkp, 64);
        sha3_512_hash(seed, 68, g_node_keys[v].hmac_key);
    }

    g_dkg.ceremony_done = true;
    g_dkg.last_rotation = Simulator::Now().GetSeconds();
    // BC.Commit(vk_ZKP, {Com_j}, ts_setup) per eq:vk_commit
    bc_commit_dkg(g_dkg.vk_zkp, g_dkg.com, N_RSUs, g_dkg.last_rotation);
    NS_LOG_INFO("[DKG] Ceremony complete: " << N_RSUs << " RSUs + "
        << N_Vehicles << " vehicles keyed  vk_zkp[0]=" << (int)g_dkg.vk_zkp[0]);
}

// Triggered by eq:key_rotation_trigger when T_{r_j} < T_min ∧ r_j ∈ P_DKG_current
inline void dkg_rotate_keys(uint32_t revoked_rsu_node_index) {
    std::vector<uint8_t> combined;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t idx = N_Vehicles + r;
        if (idx == revoked_rsu_node_index) continue;
        g_node_keys[idx].keys_generated = false;
        mldsa87_keygen(idx);
        sha3_512_hash(g_node_keys[idx].pk,
                      OQS_SIG_ml_dsa_87_length_public_key,
                      g_dkg.com[r]);
        combined.insert(combined.end(), g_dkg.com[r], g_dkg.com[r] + 64);
    }
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), g_dkg.vk_zkp);
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        g_node_keys[v].keys_generated = false;
        mldsa87_keygen(v);
    }
    g_dkg.last_rotation = Simulator::Now().GetSeconds();
    // BC.Commit(vk_ZKP^new, {Com_j}, ts_rotation) per eq:vk_commit_rotated
    bc_commit_dkg(g_dkg.vk_zkp, g_dkg.com, N_RSUs, g_dkg.last_rotation);
    NS_LOG_INFO("[DKG] Key rotation after RSU " << revoked_rsu_node_index
        << " revocation at t=" << g_dkg.last_rotation);
}

#endif // DKG_SETUP_H
```

---

### 5.3 `scratch/blockchain_sim.h`

Included after `dkg_setup.h`. In-memory stubs — no external chain required.

```cpp
#ifndef BLOCKCHAIN_SIM_H
#define BLOCKCHAIN_SIM_H

struct BlockchainCommit {
    uint8_t  commit_hash[64];
    double   timestamp;
    uint32_t num_endorsements;
    uint32_t tier;   // 0 = RSU-chain, 1 = global anchor
};

std::vector<BlockchainCommit> g_rsu_chain;
std::vector<BlockchainCommit> g_global_chain;

// CORRECTED (Gap 4): Pre-installation audit log.
// Called IMMEDIATELY on FlowMod receipt, BEFORE endorsement collection and installation.
// Returns false if SHA3 fails.
inline bool bc_log_flowmod(const FlowModEndorsement& e, uint32_t /*rsu_idx*/) {
    BlockchainCommit entry;
    entry.timestamp        = Simulator::Now().GetSeconds();
    entry.num_endorsements = (uint32_t)e.endorsing_rsus.size();
    entry.tier             = 0;
    // Payload: H(FlowMod) ‖ ts — logs the FlowMod hash before endorsement
    uint8_t buf[72];
    memcpy(buf,    e.flowmod_hash, 64);   // H(FlowMod) — explicit binding (Gap 3)
    memcpy(buf+64, &entry.timestamp, 8);
    if (!sha3_512_hash(buf, 72, entry.commit_hash)) return false;
    g_rsu_chain.push_back(entry);
    return true;
}

// CORRECTED (Gap 3): Commitment payload now explicitly includes H(FlowMod).
// C_P = BC.Commit(H(FlowMod) ‖ {ε_j}^{f+1} ‖ ts_commit) per eq:endorsed_commit.
// Returns false → S1 detection signal: f+1 endorsements not met.
inline bool bc_commit_flowmod(FlowModEndorsement& e) {
    uint32_t f_plus_1 = (N_RSUs / 3) + 1;  // f+1 = 22 for 64 RSUs
    if ((uint32_t)e.endorsing_rsus.size() < f_plus_1) {
        NS_LOG_WARN("[BC] FlowMod rejected: " << e.endorsing_rsus.size()
            << " < required " << f_plus_1 << " — S1 signal");
        return false;
    }
    BlockchainCommit commit;
    commit.timestamp        = Simulator::Now().GetSeconds();
    commit.num_endorsements = (uint32_t)e.endorsing_rsus.size();
    commit.tier             = 0;
    // Payload: H(FlowMod) ‖ endorsement_hash ‖ ts_commit
    uint8_t buf[136];
    memcpy(buf,     e.flowmod_hash,     64);   // H(FlowMod) explicit
    memcpy(buf+64,  e.endorsement_hash, 64);   // SHA3-512(ε_j signatures)
    memcpy(buf+128, &commit.timestamp,   8);
    if (!sha3_512_hash(buf, 136, commit.commit_hash)) return false;
    g_rsu_chain.push_back(commit);
    e.committed   = true;
    e.commit_time = commit.timestamp;
    return true;
}

// RSU-initiated write with real ML-DSA-87 signature per eq:rsu_write.
// Controller MUST NOT call this function — enforced by call sites.
inline void bc_write_event(uint32_t rsu_idx, uint32_t event_type,
                            uint32_t node, double ts) {
    if (rsu_idx >= (uint32_t)total_size) return;
    if (!g_node_keys[rsu_idx].keys_generated) mldsa87_keygen(rsu_idx);
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    uint8_t buf[16];
    memcpy(buf,   &node,       4);
    memcpy(buf+4, &event_type, 4);
    memcpy(buf+8, &ts,         8);
    uint8_t content_hash[64];
    sha3_512_hash(buf, 16, content_hash);

    // Real ML-DSA-87.Sign(sk_{r_k}, content_hash) — non-repudiable RSU attribution
    uint8_t rsu_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  rsu_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, rsu_sig, &rsu_sig_len,
                     content_hash, 64,
                     g_node_keys[rsu_idx].sk) != OQS_SUCCESS) return;

    BlockchainCommit entry;
    entry.timestamp = ts; entry.num_endorsements = 1; entry.tier = 0;
    sha3_512_hash(rsu_sig, rsu_sig_len, entry.commit_hash);
    g_rsu_chain.push_back(entry);
}

// DKG ceremony/rotation commit per eq:vk_commit / eq:vk_commit_rotated.
// BC.Commit(vk_ZKP, {Com_j}, ts_setup) → global chain (tier=1).
inline void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][64],
                           uint32_t n_rsus, double ts_setup) {
    std::vector<uint8_t> payload(64 + n_rsus * 64 + 8);
    memcpy(payload.data(), vk_zkp, 64);
    for (uint32_t r = 0; r < n_rsus; ++r)
        memcpy(payload.data() + 64 + r * 64, com[r], 64);
    memcpy(payload.data() + 64 + n_rsus * 64, &ts_setup, 8);
    BlockchainCommit entry;
    entry.timestamp        = ts_setup;
    entry.num_endorsements = n_rsus;
    entry.tier             = 1;
    sha3_512_hash(payload.data(), payload.size(), entry.commit_hash);
    g_global_chain.push_back(entry);
    NS_LOG_INFO("[DKG-BC] vk_ZKP committed to global chain at t=" << ts_setup);
}

// Query whether a committed (f+1 endorsed) FlowMod exists for flow_key.
// Used for S3/S5 detection (eq:unauth_flowmod).
// Note: uses src*total_size+dst integer key — simulation simplification.
// Collision possible if two FlowMods share (src,dst) pair; declare in thesis §2.5.
inline bool bc_query_flowmod(uint32_t flow_key) {
    auto it = g_flowmod_endorsements.find(flow_key);
    return (it != g_flowmod_endorsements.end()) && it->second.committed;
}

// Periodic global anchor commit per eq:anchor_hash.
// H_anchor^{(r)} = H(H_root_RSU ‖ ts_anchor ‖ H_prev_global)
inline void bc_anchor_to_global() {
    if (g_rsu_chain.empty()) return;
    BlockchainCommit anchor;
    anchor.timestamp = Simulator::Now().GetSeconds();
    anchor.num_endorsements = (uint32_t)g_rsu_chain.size();
    anchor.tier = 1;
    uint8_t buf[72];
    memcpy(buf, g_rsu_chain.back().commit_hash, 64);
    memcpy(buf+64, &anchor.timestamp, 8);
    if (!g_global_chain.empty())
        for (int i = 0; i < 64; ++i)
            buf[i] ^= g_global_chain.back().commit_hash[i];
    sha3_512_hash(buf, 72, anchor.commit_hash);
    g_global_chain.push_back(anchor);
}

inline void bc_anchor_recurring() {
    bc_anchor_to_global();
    Simulator::Schedule(Seconds(T_SYNC_INTERVAL), &bc_anchor_recurring);
}

// --- Federated LSTM model hash verification stubs (Gap 7 fix) ---
// eq:bc_model_verify: SC.VerifyModelHash(H(W_local^k), CommittedHash^k)
// Required for A4 ablation baseline ("No-BC") and BRFA-v2 algorithm.
// Replace with real chain queries when FL blockchain linkage is implemented.

std::map<uint32_t, std::array<uint8_t,64>> g_committed_model_hashes; // rsu_idx → hash

inline void bc_commit_model_hash(uint32_t rsu_idx, const uint8_t* model_hash_64) {
    std::array<uint8_t,64> arr;
    memcpy(arr.data(), model_hash_64, 64);
    g_committed_model_hashes[rsu_idx] = arr;
    bc_write_event(N_Vehicles + (rsu_idx < N_RSUs ? rsu_idx : 0),
                   5 /*event_type=model_hash_commit*/, rsu_idx,
                   Simulator::Now().GetSeconds());
}

// Returns true if submitted hash matches the pre-committed hash (eq:bc_model_verify).
inline bool bc_verify_model_hash(uint32_t rsu_idx, const uint8_t* submitted_hash_64) {
    auto it = g_committed_model_hashes.find(rsu_idx);
    if (it == g_committed_model_hashes.end()) return false;
    return memcmp(it->second.data(), submitted_hash_64, 64) == 0;
}

#endif // BLOCKCHAIN_SIM_H
```

---

### 5.4 `CryptoAnchorTag` — add to `routing.cc` (~line 6545)

```cpp
class CryptoAnchorTag : public Tag {
public:
    static TypeId GetTypeId(void) {
        static TypeId tid = TypeId("CryptoAnchorTag")
            .SetParent<Tag>().AddConstructor<CryptoAnchorTag>();
        return tid;
    }
    TypeId GetInstanceTypeId(void) const override { return GetTypeId(); }
    uint32_t GetSerializedSize(void) const override { return 129; }  // 64+64+1
    void Serialize(TagBuffer i) const override {
        i.Write(m_sig_hash, 64); i.Write(m_hmac_tag, 64); i.WriteU8(m_flags);
    }
    void Deserialize(TagBuffer i) override {
        i.Read(m_sig_hash, 64); i.Read(m_hmac_tag, 64); m_flags = i.ReadU8();
    }
    void Print(std::ostream& os) const override { os << "CryptoAnchorTag"; }
    void SetSigHash(const uint8_t* h)  { memcpy(m_sig_hash, h, 64); }
    void SetHmacTag(const uint8_t* h)  { memcpy(m_hmac_tag, h, 64); }
    void SetFlags(uint8_t f)           { m_flags = f; }
    const uint8_t* GetSigHash() const  { return m_sig_hash; }
    uint8_t GetFlags() const           { return m_flags; }
    CryptoAnchorTag() : m_flags(0) {
        memset(m_sig_hash, 0, 64); memset(m_hmac_tag, 0, 64);
    }
private:
    uint8_t m_sig_hash[64];  // SHA3-512(full ML-DSA-87 sig) — reference only
    uint8_t m_hmac_tag[64];  // HMAC-SHA3-512 tag (OBU/vehicle mode)
    uint8_t m_flags;         // bit0=sig_valid, bit1=stark_timing_ok, bit2=stark_hop_ok
};
// Tag overhead: 129 bytes. If approaching DSRC MTU, reduce m_sig_hash to 32 bytes.
```

---

### 5.5 `scratch/wscript`

```python
import os

def build(bld):
    obj = bld.create_ns3_program('routing', bld.env['NS3_ENABLED_MODULES'])
    obj.source  = ['routing.cc']
    obj.lib     = ['oqs', 'ssl', 'crypto']
    obj.libpath = ['/usr/local/lib']
    obj.rpath   = ['/usr/local/lib']
```

---

## 6. Modified Files

### 6.1 `routing.cc`

Add includes after all existing detection headers:

```cpp
#include "crypto_layer.h"
#include "dkg_setup.h"
#include "blockchain_sim.h"
```

Add `CryptoAnchorTag` class at ~line 6545 (after `CustomDataUnicastTag_Routing`).

Add in `main()` before `Simulator::Run()`:

```cpp
#include <openssl/crypto.h>
// ...
OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
```

Add to `CommandLine` block:

```cpp
crypto_register_cli_params(cmd);
```

### 6.2 `s2_detection.h` (~line 88)

```cpp
// BEFORE:
bool zkp_proof_fails = delay_exceeds;

// AFTER:
StarkTimingProof proof = stark_prove_timing(t_fwd_by_sender, t_recv_now, pkt_id);
bool zkp_proof_fails   = !stark_verify_timing(proof, t_fwd_by_sender, t_recv_now);
```

---

## 7. Integration Points in `routing.cc`

### 7.1 Initialization — `initialise_stub_attack_state()` (~line 115304)

```cpp
trust_init_all();
Simulator::Schedule(Seconds(0.0),             &dkg_run_ceremony);
Simulator::Schedule(Seconds(T_SYNC_INTERVAL), &update_T_ref_recurring);
Simulator::Schedule(Seconds(T_SYNC_INTERVAL), &bc_anchor_recurring);
Simulator::Schedule(Seconds(0.050),           &crypto_batch_verify_tick);
Simulator::Schedule(Seconds(5.0),             &crypto_evict_old_entries_recurring);
```

### 7.2 Packet Signing — `HandleReadOne()` forwarding paths (~line 95062)

```cpp
if (!mldsa87_sign(current_hop_idx, pkt_seq, final_next_hop, pkt_seq)) {
    NS_LOG_ERROR("[CRYPTO] Sign failed node=" << current_hop_idx);
    return;  // do not forward unsigned packet
}
CryptoAnchorTag ct;
auto& meta = g_packet_crypto[{current_hop_idx, pkt_seq}];
uint8_t sig_ref[64];
sha3_512_hash(meta.sig, meta.sig_len, sig_ref);
ct.SetSigHash(sig_ref);
if (current_hop_idx < N_Vehicles) {  // OBU mode: also attach HMAC
    uint8_t hmac_in[20], hmac_out[64];
    memcpy(hmac_in, &pkt_seq, 4);
    double ts = meta.sign_timestamp;
    memcpy(hmac_in+4, &ts, 8);
    memcpy(hmac_in+12, &current_hop_idx, 4);
    if (hmac_sha3_512(g_node_keys[current_hop_idx].hmac_key, 64,
                      hmac_in, 20, hmac_out))
        ct.SetHmacTag(hmac_out);
}
packet_i->AddPacketTag(ct);
Simulator::Schedule(Seconds(ML_DSA_SIGN_DELAY), /* original Send call */);
```

### 7.3 Packet Verification — `HandleReadOne()` receive paths (~line 95077)

```cpp
CryptoAnchorTag crypto_tag;
if (packet->PeekPacketTag(crypto_tag)) {
    bool sig_ok  = mldsa87_verify(sender_idx, pkt_id, next_hop, seq);
    auto proof   = stark_prove_timing(t_claimed, t_recv_now, pkt_id);
    bool stark_t = stark_verify_timing(proof, t_claimed, t_recv_now);
    bool stark_h = stark_verify_hop(next_hop, src, dst);
    // Update PacketCryptoMeta flags and LSTM accumulators
    stark_update_meta(sender_idx, pkt_id, stark_t, stark_h);
    // Trust update per eq:trust_update: both conditions for reward, either for penalty
    bool b_pi = stark_t && stark_h;
    if (sig_ok && b_pi)
        trust_update_positive(sender_idx);
    else
        trust_update_negative(sender_idx);
    if (!sig_ok || !b_pi)
        bc_write_event(rsu_idx, 1 /*crypto_fail*/, sender_idx, t_recv_now);
}
```

### 7.4 FlowMod Endorsement — `transmit_delta_values()` (~line 118197)

Corrected order: log immediately on receipt, then collect endorsements, then commit.
Controller MUST NOT call any `bc_*` write function here.

```cpp
uint32_t fm_key = (uint32_t)src * total_size + (uint32_t)dst;
FlowModEndorsement& e = g_flowmod_endorsements[fm_key];
e.endorsing_rsus.clear();

// CORRECTED (Gap 4): Log immediately on FlowMod receipt, BEFORE endorsement collection.
// Hash the FlowMod params first so bc_log_flowmod has flowmod_hash to write.
uint8_t fm_params[8];
memcpy(fm_params, &src, 4); memcpy(fm_params+4, &dst, 4);
sha3_512_hash(fm_params, 8, e.flowmod_hash);
bc_log_flowmod(e, rsu_idx);   // pre-installation audit — Gap 4 fix
e.logged   = true;
e.log_time = Simulator::Now().GetSeconds();

// Collect endorsements from RSUs in this controller's zone
for (uint32_t r = 0; r < N_RSUs; ++r) {
    if (rsu_controller_assignment[r] != controller_id) continue;
    uint32_t rsu_node_idx = N_Vehicles + r;
    if (!flowmod_endorse(rsu_node_idx, fm_key, fm_params, 8)) continue;
    e.endorsing_rsus.push_back(rsu_node_idx);
}
// Commit or signal S1
if (!bc_commit_flowmod(e))
    ctrl_trust_update_negative(controller_node_idx);  // S1 signal
```

### 7.5 LSTM Feature Collection — per 1s routing cycle

Add at the start of each 1s data collection cycle:

```cpp
// Export 𝟙[π_delay=⊥] and 𝟙[π_hop=⊥] per node for LSTM input vector (eq:lstm_input)
for (uint32_t n = 0; n < (uint32_t)total_size; ++n) {
    CryptoLstmFeatures f = crypto_get_lstm_features(n);
    lstm_feature_stark_timing_fail[n] = f.stark_timing_fail;  // → 𝟙[π_delay=⊥]
    lstm_feature_stark_hop_fail[n]    = f.stark_hop_fail;     // → 𝟙[π_hop=⊥]
}
crypto_reset_lstm_accumulators();  // reset for next cycle
volume_tick();                     // reset volume counters for S7
```

### 7.6 Witness Integration — promiscuous path

```cpp
// Log overheard packet (every promiscuous receive)
witness_log_packet(witness_idx, pkt_hash_64, observed_dst, t_now);

// Check duplication condition (eq:dup_alert_cond)
if (witness_check_duplication(witness_idx, pkt_hash_64, observed_dst))
    witness_submit_duplication_alert(witness_idx, suspected_node,
                                     pkt_id, observed_dst, prior_dst);

// Check non-forwarding condition (eq:nfwd_detect) — packet received but not forwarded
// within T_fwd = STARK_DELTA_MAX
if (witnessed_recv && !witnessed_fwd_within_deadline)
    witness_submit_nfa_alert(witness_idx, suspected_node, pkt_id, STARK_DELTA_MAX);
```

---

## 8. Key Constants Reference

| Constant | Value | Source |
|---|---|---|
| `STARK_DELTA_MAX` | 50 ms | Proposal `eq:stark_delay` |
| `ML_DSA_SIGN_DELAY` | 1.5 ms | Simulated overhead |
| `OQS_SIG_ml_dsa_87_length_public_key` | 2,592 bytes | liboqs / FIPS 204 |
| `OQS_SIG_ml_dsa_87_length_secret_key` | 4,896 bytes | liboqs / FIPS 204 |
| `OQS_SIG_ml_dsa_87_length_signature` | 4,627 bytes | liboqs (proposal cites 4,595 — no functional impact) |
| `HMAC_TAG_BYTES` | 64 | Proposal `eq:hmac_light` |
| `TRUST_DELTA_R` | CLI `--trust_delta_r`, default 0.05 | Proposal `[tbd]`, constraint Δ_p > Δ_r |
| `TRUST_DELTA_P` | CLI `--trust_delta_p`, default 0.10 | Proposal `[tbd]` |
| `TRUST_T_MIN` | CLI `--trust_t_min`, default 0.50 | Proposal sweep `{0.3, 0.5, 0.7}` |
| `TRUST_T_MIN_CTRL` | CLI `--trust_t_min_ctrl`, default 0.50 | Proposal sweep `{0.3, 0.5, 0.7}` |
| `T_SYNC_INTERVAL` | CLI `--t_sync`, default 1.0 s | Proposal sweep `{0.5, 1.0, 2.0}` |
| `BATCH_SIZE` | CLI `--batch_size`, default 15 | Proposal sweep `{10, 15, 20}` |
| `WITNESS_WINDOW` | CLI `--witness_window`, default 10.0 s | Proposal sweep `{5, 10, 15}` |
| `WITNESS_F` | CLI `--witness_f`, default 1 | Proposal sweep `{1, 2, 3}` |
| `VOL_RATE_THRESH` | CLI `--vol_rate_thresh`, default 5.0 pkt/s | Proposal `ε_vol` |
| `f+1` (endorsements) | 22 RSUs | `⌊64/3⌋ + 1` |
| `2f+1` (witness BFT) | `2×WITNESS_F+1` = 3 | Proposal `eq:bft_penalty` |

---

## 9. Implementation Order

```
Phase 0 — Prerequisites
  [0.1]  sudo apt-get install libssl-dev
  [0.2]  Build and install liboqs (§4.2)
  [0.3]  Verify: ls /usr/local/include/oqs/oqs.h && ls /usr/local/lib/liboqs.so

Phase 0.5 — Pre-Blockchain Fixes (no crypto dependency)
  [0.5.1]  Fix S3 second condition in tcam_detection.h → malicious_count > 0
  [0.5.2]  Wire record_detection_event(2/3, node_id) into ComputeTcamDetection()

Phase 1 — Core Crypto Library
  [1.1]  Create scratch/crypto_layer.h (§5.1) — includes β_w, LSTM bridge

Phase 2 — Support Modules
  [2.1]  Create scratch/dkg_setup.h (§5.2)
  [2.2]  Create scratch/blockchain_sim.h (§5.3) — includes model hash stubs

Phase 3 — NS3 Integration (do atomically)
  [3.1]  Add CryptoAnchorTag class to routing.cc (~line 6545) — §5.4
  [3.2]  Add #include lines to routing.cc after detection headers
  [3.3]  Add OPENSSL_init_crypto() in main()
  [3.4]  Add crypto_register_cli_params(cmd) to CommandLine block
  [3.5]  Create scratch/wscript — §5.5

Phase 4 — Hook Integration
  [4.1]  Initialization block in initialise_stub_attack_state() — §7.1
  [4.2]  Packet signing in HandleReadOne() forwarding paths — §7.2
  [4.3]  Packet verification + stark_update_meta() in receive paths — §7.3
  [4.4]  FlowMod endorsement (corrected order: log→endorse→commit) — §7.4
  [4.5]  Replace S2 ZKP proxy in s2_detection.h — §6.2
  [4.6]  LSTM feature export at each 1s cycle — §7.5
  [4.7]  Witness log on every promiscuous receive — §7.6
  [4.8]  Duplication alert (α_w) via witness_submit_duplication_alert()
  [4.9]  Non-forwarding alert (β_w) via witness_submit_nfa_alert() — NEW
  [4.10] Unauthorized destination check for S5 (find_next_hop guard)
  [4.11] msg_id duplication cache check for S6
  [4.12] Volume rate tracking for S7
  [4.13] Controller trust update on unauthorized FlowMod (S1/S3/S5/S7)

Phase 5 — Metrics
  [5.1]  Add CSV columns: sig_valid_rate, avg_trust_score,
         batch_verify_pass_rate, stark_timing_fail_count, stark_hop_fail_count,
         flowmod_endorsement_rate, rsu_chain_len, global_chain_len,
         witness_da_count, witness_nfa_count

Phase 6 — Testing
  [6.1]  Baseline run (0% attack): all trust=1.0, zero quarantine, sig_ok=true,
         stark flags true, LSTM features = 0.0
  [6.2]  Per-variant runs: quarantine events must align with ground truth
  [6.3]  False-positive check: honest nodes must never appear in quarantine
  [6.4]  Timing check: end-to-end latency < 100 ms for honest flows
  [6.5]  Parameter sweep: T_min ∈ {0.3, 0.5, 0.7}, t_sync ∈ {0.5,1.0,2.0},
         batch_size ∈ {10,15,20}, witness_window ∈ {5,10,15}, witness_f ∈ {1,2,3}
  [6.6]  LSTM feature check: stark_timing_fail > 0 for Attack 1/2 nodes,
         stark_hop_fail > 0 for Attack 5/6/7/8 nodes
  [6.7]  Witness alert check: β_w alerts fire for Attack 1/2 delay scenarios;
         α_w alerts fire for Attack 5/6/7/8 forwarding scenarios
```

---

## 10. Known Risks and Mitigations

| Risk | Mitigation |
|---|---|
| `g_packet_crypto` grows (4.6 KB × many entries) | Eviction tick every 5 s prunes entries > 5 s old |
| `g_witness_log` grows across 200 vehicles | Prune entries older than `WITNESS_WINDOW` inside eviction |
| `g_witness_alert_pool` unbounded | Prune after BFT threshold is reached per target node |
| Map key collision in `g_packet_crypto` | `std::pair<uint32_t,uint32_t>` key — no collision possible |
| `bc_query_flowmod()` key collision on same (src,dst) | Simulation simplification; declare in thesis §2.5 |
| Error-silent crypto failures | Every crypto call return checked; unsigned packets not forwarded |
| Trust params hardcoded | All 11 params exposed via `CommandLine` |
| OpenSSL SHA3-512 not initialised | `OPENSSL_init_crypto()` called in `main()` before simulation |
| CryptoAnchorTag (129 bytes) near DSRC MTU | Measure per test; reduce to 32-byte sig reference if needed |
| liboqs not found at link time | Verify `ldconfig` was run after `sudo make install` |
| DKG at t=0 takes time (268 real keypairs) | Profile; if > 1 s, schedule at t=0 with Simulator::Schedule |
| Batch verify combined lattice eq not implementable via liboqs | Accepted: per-sig OQS_SIG_verify + faithful batch challenge; declare in thesis |
| S2 timestamp and STARK proof from same NS3 clock | Accepted simulation limitation: NS3 ideal clock |
| LSTM feature accumulators not thread-safe | NS3 is single-threaded; no issue |
| β_w sign_id collision with α_w range | Offset by +500000 — adequate for simulation pkt_id range |
| Controller write-path | Enforced structurally: no bc_* write calls from controller code paths |
| Signature size 4,627 vs. proposal 4,595 bytes | Parameter-set citation difference; no functional impact; note in thesis |

---

## 11. Coverage Summary vs. Proposal

| Category | Equations | Implementation | Status |
|---|---|---|---|
| Per-packet ML-DSA-87 signing | `eq:mldsa_sign` | Real liboqs `OQS_SIG_sign()` | ✅ |
| Batch verification | `eq:batch_challenge`, `eq:batch_verify` | Faithful challenge + real per-sig verify | ✅ |
| STARK proofs | `eq:stark_delay_verify`, `eq:stark_hop_verify` | Simulated; flags exported to LSTM | ✅ |
| HMAC-SHA3-512 | `eq:hmac_light` | Real OpenSSL `HMAC()`, three fields only | ✅ |
| DKG + key rotation | `eq:vk_commit`, `eq:vk_commit_rotated`, `eq:key_rotation_trigger` | Real liboqs keypairs; result on blockchain | ✅ |
| FlowMod endorsement | `eq:rsu_endorsement`, `eq:endorsed_commit`, `eq:policy_commit` | ML-DSA-87.Sign; H(FlowMod) explicit in commit | ✅ |
| FlowMod pre-install log | `eq:flowmod_log` | Receipt → log → endorse → commit order | ✅ |
| RSU blockchain writes | `eq:rsu_write` | Real ML-DSA-87.Sign — non-repudiable | ✅ |
| Controller read-only | Table 3 (trust roles) | No bc_* write calls from controller paths | ✅ |
| Controller re-assignment | `eq:rsu_ctrl_assign`, `eq:ctrl_failover` | `ctrl_reassign_rsus()` on revocation | ✅ |
| Two-tier blockchain | `eq:anchor_hash` | In-memory two tiers; DKG on global chain | ✅ |
| Vehicle/RSU trust | `eq:trust_update`, `eq:quarantine` | Both conditions for reward; either for penalty | ✅ |
| Controller trust | `eq:ctrl_trust_update`, `eq:sc_revoke` | Complete with RSU re-assignment | ✅ |
| Duplication alert α_w | `eq:da_sign`, `eq:dup_alert_cond` | Real ML-DSA-87 signed; on blockchain | ✅ |
| Non-forwarding alert β_w | `eq:nfa_sign`, `eq:nfwd_detect` | Real ML-DSA-87 signed; on blockchain | ✅ (new) |
| BFT penalty α_w ∪ β_w | `eq:bft_penalty` | Unified pool; both types counted | ✅ (new) |
| Time reference | `eq:time_consensus` | `Simulator::Now()` median; on blockchain | ✅ |
| LSTM feature bridge | `eq:lstm_input` | `crypto_get_lstm_features()` export | ✅ (new) |
| FL model hash verification | `eq:bc_model_verify` | `bc_commit_model_hash()` / `bc_verify_model_hash()` stubs | ✅ (new) |