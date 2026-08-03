#ifndef CRYPTO_LAYER_H
#define CRYPTO_LAYER_H

// routing.cc defines 'max' and 'min' as object-like macros (#define max 40).
// Save and remove them for all header includes below so that openssl/oqs headers
// that use max/min as function calls compile correctly. Restored at end of header.
#pragma push_macro("max")
#pragma push_macro("min")
#undef max
#undef min

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <algorithm>
#include <chrono>   // M7: wall-clock timing of batch verification (eq:t_verify)
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <oqs/oqs.h>
// ns3/simulator.h and ns3/log.h are already included earlier in routing.cc.

#pragma pop_macro("min")
#pragma pop_macro("max")

// Forward declarations — bc_commit_dkg defined in bc_blockchain_helper.h (included after this).
void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][64],
                   uint32_t n_rsus, double ts_setup);
// bc_commit_tref_to_chain defined in bc_blockchain_helper.h (included after this) —
// called from update_T_ref() below so every T_SYNC_INTERVAL tick's T_ref(t) is
// committed on-chain (main.tex sec:time_ref: "T_ref(t) is committed to the
// blockchain by RSU consensus at regular intervals to provide a tamper-evident
// audit trail"), same pattern as bc_commit_dkg above.
void bc_commit_tref_to_chain(double t_ref_value, double eps_ref, double ts);
// dkg_rotate_keys defined in dkg_setup.h (included after this) — called from trust_update_negative
// per eq:key_rotation_trigger when a quarantined node is an RSU.
inline void dkg_rotate_keys(uint32_t revoked_rsu_node_index);

// crypto_log_event defined in crypto_event_log.h (included after this header in
// routing.cc, same translation unit) — forward-declared so crypto_batch_verify_tick
// can emit a "batch_verify" row into crypto_timing_log.csv (M7, eq:t_verify).
// CryptoTimePoint alias must match crypto_event_log.h exactly (legal redeclaration).
using CryptoTimePoint = std::chrono::high_resolution_clock::time_point;
inline void crypto_log_event(const char* op, uint32_t node_id, uint32_t pkt_id,
                             uint32_t flow_id, CryptoTimePoint t0, bool result);

// ── Evidence-quality debug logging ───────────────────────────────────────────
// Normal runs: CRYPTO_DEBUG_LOG = false → zero terminal noise, CSV unaffected.
// flip to true for rich per-operation output proving every
// cryptographic component is executing with real liboqs/OpenSSL values.
// High-frequency per-packet ops are gated on this flag.
// Low-frequency high-importance events (DKG, quarantine, failures, blockchain
// commits) fire unconditionally regardless of this flag.
static bool CRYPTO_DEBUG_LOG = false;  // default true for dev/debug, false for normal runs

// Formats first 4 bytes of buf as compact hex — evidence token in debug lines.
static std::string _hex4(const uint8_t* b) {
    char s[9];
    snprintf(s, sizeof(s), "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    return std::string(s);
}

// Formats first 8 bytes as hex — used in [PKT-CRYPTO] verbose field logs.
static std::string _hex8(const uint8_t* b) {
    char s[17];
    snprintf(s, sizeof(s), "%02x%02x%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
    return std::string(s);
}

// Formats a uint32 as 8-char hex — for nonce / zone / next_hop in verbose logs.
static std::string _hex32(uint32_t v) {
    char s[9];
    snprintf(s, sizeof(s), "%08x", v);
    return std::string(s);
}

// ── SHA3-512 and HMAC-SHA3-512 via OpenSSL ───────────────────────────────────

static inline bool sha3_512_hash(const uint8_t* data, size_t len, uint8_t* out_64) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    unsigned int out_len = 64;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out_64, &out_len) == 1 && out_len == 64);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static inline bool hmac_sha3_512(const uint8_t* key, size_t klen,
                           const uint8_t* data, size_t dlen, uint8_t* out_64) {
    unsigned int out_len = 64;
    return HMAC(EVP_sha3_512(), key, (int)klen, data, dlen, out_64, &out_len) != nullptr
           && out_len == 64;
}

// ── Tunable Parameters (all CLI-exposed) ─────────────────────────────────────

double   TRUST_DELTA_R      = 0.05;
double   TRUST_DELTA_P      = 0.10;
double   TRUST_T_MIN        = 0.50;
double   TRUST_T_MIN_CTRL   = 0.50;
double   TRUST_DELTA_R_CTRL = 0.05;
double   TRUST_DELTA_P_CTRL = 0.10;
double   STARK_DELTA_MAX    = 0.050;
double   ML_DSA_SIGN_DELAY  = 0.0015;
double   T_SYNC_INTERVAL    = 1.0;
uint32_t BATCH_SIZE         = 15;
double   WITNESS_WINDOW     = 10.0;
uint32_t WITNESS_F          = 1;
double   VOL_RATE_THRESH    = 5.0;

// M5 — Controller failover latency modeling (eq:sc_revoke → eq:ctrl_failover).
// Per the proposal, SC.Revoke commits the revocation on-chain and broadcasts a
// ControllerRevoked event; each affected RSU re-executes failover on receipt
// ("immediately" on arrival — the arg-min compute itself is instantaneous), so
// L_failover is dominated by event propagation under geographic dispersion.
// Modeled as a base broadcast latency plus a per-zone-distance increment to the
// RSU's NEW controller (same 1-D zone-index proxy ctrl_reassign_rsus already
// uses for d(r_k,c_j)); distant RSUs finish later, giving eq:l_failover's max
// real straggler content. Both CLI-exposed.
double   FAILOVER_BCAST_BASE_MS     = 10.0;  // on-chain commit + event emission
double   FAILOVER_BCAST_PER_ZONE_MS = 1.0;   // per unit zone-index distance

// ── Ablation gate flags (Phase 3, SIGNATURE_ATTACK_DECOUPLING_PLAN.md) ──────
// One boolean per ablated component, all defaulting to the full/proposed
// behavior (true), each checked at the single natural chokepoint for that
// component. Disabling a STARK proof makes it vacuously PASS (contributes
// nothing) rather than vacuously fail, so signatures fall back to their
// other, non-STARK conjuncts (AB4-A/B/C in docs/main.tex). All CLI-exposed
// via crypto_register_cli_params().
bool enable_lrad_obu               = true;  // AB1: OBU rule engine (lrad_obu)
bool enable_lrad_rsu               = true;  // AB1: RSU full-mode engine (lrad_rsu)
// DIAGNOSTIC ONLY (added 2026-07-25) — disables S1 + S2 (both partial and full)
// while leaving S3-S8 untouched, unlike enable_lrad_obu/rsu which are coarse
// mode-level switches that would also disable S5-S8 (they share enable_lrad_rsu's
// gate). Default false: normal/default-settings runs are completely unaffected.
// For isolating a single signature's own FPR from S1/S2 cross-signal noise on the
// shared trust ledger — NOT a replacement for default-settings evaluation numbers.
bool g_disable_s1_s2                = false;
bool enable_stark_delay            = true;  // AB4: π_delay timing proof
bool enable_stark_hop              = true;  // AB4: π_hop hop-legitimacy proof
bool enable_witness_mechanism      = true;  // AB6: witness alert/BFT mechanism
bool enable_quarantine             = true;  // AB7: trust updates + SC.Quarantine
bool enable_endorsement_requirement = true; // AB8: f+1 RSU FlowMod endorsement
bool enable_controller_failover    = true;  // AB9: controller trust/revoke/failover
bool enable_key_rotation           = true;  // AB11: DKG key rotation on RSU revocation
bool enable_lstm_inference         = false; // main.tex sec:fed_lstm: live in-sim LSTM
                                             // (lstm_inference.h). Default OFF — needs
                                             // lstm_pipeline/lstm_weights_cpp.bin to already
                                             // exist (a prior offline training run's
                                             // export_weights_cpp.py output); every other
                                             // run/script in the repo must keep working
                                             // unchanged without that file present.

// Crypto on/off switch — CLI: --disable_crypto (default 0 = crypto ON).
// When set to 1, short-circuits the DKG ceremony's key generation and the
// per-packet ML-DSA-87 sign/verify + STARK hop-proof (dkg_run_ceremony,
// mldsa87_sign, mldsa87_verify, stark_verify_hop) so they no-op instead of
// running real PQC operations for every node at startup and every packet/hop
// at runtime. Useful for runs that only need TCAM/routing behavior (e.g. S3/S4
// rate-and-capacity detection, which never reads crypto state) and don't
// depend on crypto-derived metrics (trust score, S1/S2/S5-S8 detection).
bool     g_disable_crypto   = false;

// ── Data Structures ───────────────────────────────────────────────────────────

struct NodeKeyMaterial {
    uint8_t  pk[OQS_SIG_ml_dsa_87_length_public_key];
    uint8_t  sk[OQS_SIG_ml_dsa_87_length_secret_key];
    uint8_t  hmac_key[64];
    bool     keys_generated = false;
    uint32_t node_id        = UINT32_MAX;
};
NodeKeyMaterial g_node_keys[268]; // sized to total_size

struct PacketCryptoMeta {
    uint8_t  sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t   sig_len          = 0;
    uint8_t  msg_digest[64]   = {};
    uint8_t  hmac_tag[64]     = {};
    double   sign_timestamp   = 0.0;
    uint32_t signed_next_hop  = (uint32_t)-1;  // intended next hop at sign time
    uint32_t signed_zone_id   = 0;             // zone_id at sign time (rsu_controller_assignment changes)
    uint32_t nonce            = 0;             // fresh random nonce (η_i ← RAND()) — eq:mldsa_sign
    bool     sig_valid        = false;
    bool     stark_timing_ok  = false;
    bool     stark_hop_ok     = false;
};
std::map<std::pair<uint32_t,uint32_t>, PacketCryptoMeta> g_packet_crypto;

// eq:mldsa_sign's msg_id must uniquely identify "a message"; pkt_id alone
// does not, because it is a per-flow counter that restarts at 1 for every
// flow (routing.cc: packet_id = total_packet_counter + 1). Two concurrent
// flows relaying through the same node with the same pkt_id collide on the
// same g_packet_crypto slot -- confirmed root cause of the FV688 causal-
// order failures (a downstream verify silently validated against a
// different flow's stale sign record; see docs/task8_verification/
// FUNCTIONAL_VERIFICATION_GUIDE.md investigation, 2026-07-27). Composing
// flow_id into msg_id fixes this without adding a field to eq:mldsa_sign --
// main.tex never defines msg_id's exact contents, only that it identifies
// the message. 12 bits per side comfortably covers 2*flows<=8 concurrent
// streams and Flow_size<=55 packets/flow with zero collision risk.
// Reversible so batch_verify_mldsa87() can recover the raw pair from the
// map's own stored keys.
inline uint32_t crypto_msg_key(uint32_t pkt_id, uint32_t flow_id) {
    return ((flow_id & 0xFFFu) << 12) | (pkt_id & 0xFFFu);
}
inline uint32_t crypto_msg_key_pkt(uint32_t key)  { return key & 0xFFFu; }
inline uint32_t crypto_msg_key_flow(uint32_t key) { return key >> 12; }

// Sign buffer layout per eq:mldsa_sign: msg_id(4)|ts(8)|η(4)|nh(4)|z(4) = 24 bytes
// No node_id, no padding — explicit memcpy, not struct cast.
static constexpr size_t MLDSA_SIGN_BUF = 4 + 8 + 4 + 4 + 4;

struct DKGState {
    uint8_t  vk_zkp[64]  = {};
    uint8_t  com[64][64] = {};
    bool     ceremony_done = false;
    double   last_rotation = 0.0;
};
DKGState g_dkg;

struct FlowModEndorsement {
    uint8_t               flowmod_hash[64]     = {};
    uint8_t               endorsement_hash[64] = {};
    std::vector<uint32_t> endorsing_rsus;
    bool   committed   = false;
    bool   logged      = false;
    double log_time    = 0.0;
    double commit_time = 0.0;
};
std::map<uint32_t, FlowModEndorsement> g_flowmod_endorsements;

struct StarkTimingProof { uint8_t commitment[64] = {}; bool valid = false; };
struct BatchVerifyResult { bool passed; uint32_t n_verified; double elapsed_s; uint8_t challenge[64]; };

// Verification outcome counters — for sig_valid_rate metric
static uint32_t g_verify_attempts = 0;
static uint32_t g_verify_passed   = 0;
// Batch challenge result — updated each 50ms tick; feeds LRAD b_batch (eq:batch_challenge)
static bool g_batch_passed = true;

struct WitnessLogEntry {
    uint8_t  pkt_hash[64] = {};
    uint32_t dst;
    double   ts;
};

struct WitnessAlert {
    uint32_t witness_id    = 0;
    uint8_t  alert_type   = 0; // 0 = α_w (DA), 1 = β_w (NFA)
    uint8_t  signed_digest[64] = {};                              // h_alert signed by witness
    uint8_t  alert_sig[OQS_SIG_ml_dsa_87_length_signature] = {}; // full 4595-byte ML-DSA-87 sig
    size_t   alert_sig_len = 0;
};

double g_trust_score[268]       = {};
double g_trust_last_update[268] = {};
bool   g_quarantined[268]       = {};
double g_ctrl_trust_score[268]  = {};
bool   g_ctrl_revoked[268]      = {};

// M5 — eq:l_failover instrumentation state
double   g_failover_max_ms     = 0.0; // max_k(t_reassign^(k) − t_revoke), most recent revocation event
uint32_t g_failover_events     = 0;   // SC.Revoke events fired (ControllerRevoked broadcasts)
uint32_t g_failover_reassigned = 0;   // RSU reassignment completions across all events

// M7 — eq:o_crypto / eq:t_verify / eq:t_consensus instrumentation state.
// All wall-clock (std::chrono) sums in microseconds; cumulative since sim start
// (CSV exports running averages, matching the avg_* idiom of the metrics CSV).
//
// eq:overhead_full / main.tex:5124: "proof size is modelled as ≤100KB per
// verification cycle (FRI-STARK, conservative blowup)". The ZKP layer's
// PROOF OUTCOME is intentionally modelled via the t_fwd-t_recv<=Delta_max
// constraint check (main.tex:5128-5130 — no real FRI polynomial commitments
// are constructed), but the proposal still specifies a concrete conservative
// BYTE-SIZE bound for the overhead/bandwidth characterisation in
// eq:overhead_full. STARK_PROOF_SIZE_MODELED_BYTES applies that same
// proposal-specified bound to O_crypto, rather than a smaller ad-hoc
// SHA3-512-commitment-sized placeholder unconnected to the modeled figure.
const double STARK_PROOF_SIZE_MODELED_BYTES = 100.0 * 1024.0; // 100 KB, main.tex:5124

// O_crypto counts the bytes the simulation attaches per signed packet, per
// eq:overhead_full: |σ_i| (real, measured ML-DSA-87 signature) plus
// |π_delay,i| and |π_hop,i|, each the proposal's own modeled ≤100KB bound.
// Both proofs are generated once per hop per Algorithm FCIP (alg:fcip,
// main.tex:2686-2726) regardless of which signature check later consumes
// them, so both contribute here.
double   g_m7_crypto_bytes_sum    = 0.0; // Σ (sig_len + 2*STARK_PROOF_SIZE_MODELED_BYTES)
uint64_t g_m7_signed_pkts         = 0;   // packets signed (O_crypto denominator)
double   g_m7_batch_wall_us_sum   = 0.0; // Σ wall-clock µs of batch_verify_mldsa87 calls
uint64_t g_m7_batch_calls         = 0;   // number of batch verify invocations
uint64_t g_m7_batch_pkts          = 0;   // Σ batch sizes B (for mean B)
double   g_m7_consensus_wall_us_sum = 0.0; // Σ wall-clock µs of endorse→commit sequences
uint64_t g_m7_consensus_count     = 0;   // number of FlowMod consensus rounds
// eq:o_crypto / main.tex:5123 "Proof generation overhead is modelled as
// <=10ms per packet". This measures the REAL wall-clock cost of the
// simulation's own stark_prove_timing()/stark_verify_timing()/
// stark_verify_hop() calls (a SHA3-512 hash + constraint check, so far
// smaller than the modeled 10ms bound) — a characterisation metric only,
// same as g_m7_batch_wall_us_sum/g_m7_consensus_wall_us_sum. Deliberately
// NOT injected as an artificial Simulator::Schedule delay into the packet
// forwarding pipeline, since that would change M2/M6/S1/S2 detection
// outcomes network-wide rather than simply reporting overhead.
double   g_m7_stark_wall_us_sum   = 0.0; // Σ wall-clock µs of STARK prove/verify calls
uint64_t g_m7_stark_calls         = 0;   // number of STARK prove/verify invocations

double g_T_ref = 0.0, g_T_ref_last_sync = 0.0;

// M9 — eq:eps_ref / eq:time_consensus instrumentation [Ablation only].
// T_ref(t) is the coordinate-wise median across N_RSUs simulated RSU clocks.
// The first TIME_REF_F_BAD RSUs (by index) have their clock offset by a fixed
// TIME_REF_DELTA_ATTACK seconds, modeling f_bad Byzantine-compromised clocks;
// the rest read true simulator time. eps_ref = |T_ref(t) - T_ground(t)| is
// recomputed on every sync tick, where T_ground(t) is the simulator's own
// clock (always available/authoritative in ns-3). Default f_bad=0 reproduces
// the original all-honest stub exactly (eps_ref ≡ 0).
uint32_t TIME_REF_F_BAD          = 0;    // number of compromised RSU clocks (CLI sweep var)
double   TIME_REF_DELTA_ATTACK   = 0.5;  // fixed attack offset (s) injected into compromised RSUs
double   g_eps_ref               = 0.0;  // |T_ref - T_ground| at most recent sync tick
double   g_eps_ref_cumulative    = 0.0;
uint32_t g_eps_ref_samples       = 0;

// node_clock_offset()/node_local_time() — eq:time_consensus tau_j(t).
// This node's own (possibly Byzantine-compromised) clock offset from true
// simulator time. Only RSUs can have a non-zero offset (vehicles/controllers
// always read true time). Stateless — a pure function of TIME_REF_F_BAD /
// TIME_REF_DELTA_ATTACK and the RSU's local index, so it cannot drift out of
// sync with update_T_ref()'s own per-RSU model; both now call this same
// function (single source of truth, eq:eps_ref M9 report Tier-2 item).
inline double node_clock_offset(uint32_t node) {
    if (node < N_Vehicles || node >= N_Vehicles + N_RSUs) return 0.0;
    uint32_t rsu_local_idx = node - N_Vehicles;
    return (rsu_local_idx < TIME_REF_F_BAD) ? TIME_REF_DELTA_ATTACK : 0.0;
}

// This node's own local clock reading — true simulator time plus this
// node's own (possibly wrong) offset. Per-packet "claimed" timestamps
// (eq:delay_updated t_send/t_recv) should be recorded via this function,
// not raw Simulator::Now(), so a compromised RSU's self-reported claim is
// genuinely wrong rather than always reading the same global clock as
// everyone else.
inline double node_local_time(uint32_t node) {
    return ns3::Simulator::Now().GetSeconds() + node_clock_offset(node);
}

std::map<uint32_t, std::vector<WitnessLogEntry>> g_witness_log;
std::map<uint32_t, std::vector<WitnessAlert>>    g_witness_alert_pool;
std::map<uint64_t, std::pair<uint32_t,double>>   g_msg_id_seen;
std::map<uint32_t, double> g_dst_volume_prev, g_dst_volume_curr;

struct CryptoLstmFeatures {
    float stark_timing_fail;
    float stark_hop_fail;
};
std::map<uint32_t, std::pair<uint32_t,uint32_t>> g_lstm_stark_counts;
std::map<uint32_t, uint32_t>                      g_lstm_pkt_counts;

// 2026-07-26: R_anom(r,t) (eq:feat_ranom) -- cumulative count of distinct
// unauthorized-destination receptions attributed to malicious RSU r
// (prev_sender), i.e. exactly the same event UCR/M8 already counts via
// fade_eavesdrop_counter, just broken out per-RSU instead of one global
// running total. Incremented at the SAME two MacRx insertion points (passive
// S7/S8 and active S5/S6 hidden-forwarding receive blocks in routing.cc)
// that already increment g_lstm_stark_counts[prev_sender]/g_lstm_pkt_counts,
// guarded by the same fade_eavesdropped_packets dedup check so it can never
// double-count. lstm_log_rsu_cycle() (lstm_logger.h) takes the per-cycle
// DELTA of this cumulative counter (mirrors lambda_PI's pattern exactly,
// NOT g_lstm_stark_counts' cumulative-latch "> 0 ever" pattern) to compute
// the windowed rate the equation actually specifies ("per unit time W").
std::map<uint32_t, uint32_t> g_lstm_ranom_count;

// 2026-08-02 (Issue 1 fix, HF ground-truth/feature separation): per-RSU
// count of hidden-duplicate SEND events this malicious RSU has scheduled
// (incremented at the same two call sites as g_total_copies_scheduled++ in
// routing.cc, keyed by the sending RSU instead of one global total). This
// exists ONLY to build an independent ground-truth label for A5-A8 windows
// in preprocessor.py -- it fires at attack-injection time, before any
// detection/receive logic runs, so it shares no computation path with
// r_anom (a receive-side, detection-facing signal that IS fed to the LSTM
// as input feature #10). Using r_anom>0 to both define the ground-truth
// window label AND as a raw model input let the model trivially recover
// the label from its own input for HF variants; this counter breaks that
// overlap. Logged as a label-only CSV column (hf_send_gt), excluded from
// FEATURES in preprocessor.py.
std::map<uint32_t, uint32_t> g_lstm_hf_sendgt_count;

// 2026-07-28 (main.tex:5783-5794 spec correction): D_div/A_tp (eq:feat_ddiv,
// eq:feat_atp) must be computed from "per-source per-destination byte counts"
// and "per-flow directional byte rate logs" respectively -- genuinely
// independent local delivery counters, NOT derived from R_anom/the
// blockchain receipt log (that separation is the whole point of the
// three-feature design: R_anom is the only one requiring blockchain read
// access, so D_div/A_tp must keep working from purely local RSU state).
// The previous implementation (2026-07-26) computed both as deterministic
// transforms of R_anom's delta -- a real deviation from spec, not a
// harmless simplification, since it collapsed three independent evidence
// channels main.tex explicitly designs for down to one.
//
// g_lstm_flow0_legit_count: cumulative count of flow 0's genuine final
// deliveries (packet reaches its authorized destination_f). This is the
// A_tp "authorized" numerator. Not per-RSU: flow 0 has exactly one final
// destination reached once per packet, regardless of how many RSUs relayed
// it. Delta'd against g_lstm_prev_flow0_legit once per cycle in
// lstm_logger.h. fade_received_count (efade_detection.h) is NOT usable
// directly for this -- it's only cleared per-epoch inside
// fade_detect_anomaly(), which early-returns unless fade_detection_active
// (requires the FADE-isolated !enable_lrad_obu && !enable_lrad_rsu config)
// -- in a normal run it's never cleared and grows cumulatively for the
// whole run, same problem this dedicated counter avoids via the delta
// pattern.
uint32_t g_lstm_flow0_legit_count = 0;

// g_lstm_flow0_dest_set: distinct destination node IDs that have received
// >=1 flow-0 packet this window (both the authorized destination_f AND any
// unauthorized eavesdropper/duplicate-recipient reached via hidden
// forwarding). This is the eq:feat_ddiv numerator -- a genuine
// per-destination delivery count populated directly at the MacRx receive
// sites in routing.cc, independent of g_lstm_ranom_count. |P(v,.)|=1 in
// this sim (flow 0 has exactly one authorized destination at any instant),
// so D_div = |g_lstm_flow0_dest_set| directly, no further normalization
// needed. Snapshotted then cleared once per cycle in lstm_logger.h (same
// cadence as g_lstm_flow0_legit_count's delta).
//
// g_lstm_flow0_total_delivery_count: total flow-0 delivery events this
// window (authorized + unauthorized) -- the eq:feat_atp denominator.
// Packet-count based rather than raw-byte based: this sim already measures
// every other per-cycle feature (R_anom, lambda_PI, escalation) at
// packet/event granularity, not byte granularity, and packets on a given
// flow are uniform size in this model, so a packet-count ratio equals the
// byte-count ratio main.tex specifies.
std::set<uint32_t> g_lstm_flow0_dest_set;
uint32_t            g_lstm_flow0_total_delivery_count = 0;

// ── liboqs Singleton and Zone Helper ─────────────────────────────────────────

static OQS_SIG* g_oqs_sig = nullptr;
static OQS_SIG* get_oqs_ctx() {
    if (!g_oqs_sig) g_oqs_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    return g_oqs_sig;
}

// z_i per eq:mldsa_sign: RSU → zone from rsu_controller_assignment; vehicles → 0
static inline uint32_t crypto_zone_id(uint32_t node_index) {
    if (node_index >= N_Vehicles && node_index < N_Vehicles + N_RSUs)
        return (uint32_t)rsu_controller_assignment[node_index - N_Vehicles];
    return 0;
}

// ── ML-DSA-87 Key Generation — eq:vk_commit ──────────────────────────────────

inline bool mldsa87_keygen(uint32_t node_index) {
    if (node_index >= (uint32_t)total_size) return false;
    NodeKeyMaterial& km = g_node_keys[node_index];
    if (km.keys_generated) return true;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_keygen: OQS_SIG_new(ml_dsa_87) failed for node="
                  << node_index << "\n";
        return false;
    }
    if (OQS_SIG_keypair(sig, km.pk, km.sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_keygen: OQS_SIG_keypair failed for node="
                  << node_index << "\n";
        return false;
    }
    km.keys_generated = true;
    km.node_id = node_index;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[CRYPTO-KEY] node=" << node_index
                  << " ML-DSA-87 keypair generated"
                  << " pk_len=" << OQS_SIG_ml_dsa_87_length_public_key
                  << " sk_len=" << OQS_SIG_ml_dsa_87_length_secret_key
                  << " pk[0..3]=" << _hex4(km.pk)
                  << " sk[0..3]=" << _hex4(km.sk) << "\n";
    return true;
}

// ── ML-DSA-87 Signing — eq:mldsa_sign ────────────────────────────────────────

inline bool mldsa87_sign(uint32_t signer, uint32_t pkt_id,
                          uint32_t next_hop, uint32_t seq) {
    if (g_disable_crypto) return true; // crypto disabled via --disable_crypto
    if (signer >= (uint32_t)total_size) return false;
    if (!g_node_keys[signer].keys_generated && !mldsa87_keygen(signer)) return false;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // η_i ← RAND(): fresh per-signature nonce preventing replay (eq:mldsa_sign).
    // The caller's `seq` argument is ignored for the digest — nonce is random.
    uint32_t fresh_nonce = 0;
    OQS_randombytes(reinterpret_cast<uint8_t*>(&fresh_nonce), sizeof(fresh_nonce));

    // eq:mldsa_sign: H_SHA3-512(msg_id ‖ ts_i ‖ η_i ‖ nh_i ‖ z_i) — 24-byte explicit buffer
    // msg_id = crypto_msg_key(pkt_id, seq): seq is the caller's flow_id (see
    // crypto_msg_key's declaration for why pkt_id alone is not unique).
    uint32_t msg_id = crypto_msg_key(pkt_id, seq);
    double   ts   = ns3::Simulator::Now().GetSeconds();
    uint32_t zone = crypto_zone_id(signer);
    uint8_t sign_buf[MLDSA_SIGN_BUF] = {};
    memcpy(sign_buf,    &msg_id,      4);
    memcpy(sign_buf+4,  &ts,          8);
    memcpy(sign_buf+12, &fresh_nonce, 4);
    memcpy(sign_buf+16, &next_hop,    4);
    memcpy(sign_buf+20, &zone,        4);

    uint8_t digest[64];
    if (!sha3_512_hash(sign_buf, MLDSA_SIGN_BUF, digest)) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_sign: SHA3-512 failed node=" << signer
                  << " pkt=" << pkt_id << "\n";
        return false;
    }

    PacketCryptoMeta& meta = g_packet_crypto[{signer, msg_id}];
    memcpy(meta.msg_digest, digest, 64);
    meta.sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(sig, meta.sig, &meta.sig_len,
                     digest, 64, g_node_keys[signer].sk) != OQS_SUCCESS) {
        meta.sig_len = 0;
        std::cerr << "[CRYPTO-ERROR] mldsa87_sign: OQS_SIG_sign failed node=" << signer
                  << " pkt=" << pkt_id << "\n";
        return false;
    }
    meta.sign_timestamp  = ts;
    meta.signed_next_hop = next_hop;
    meta.signed_zone_id  = zone;
    meta.nonce           = fresh_nonce;
    meta.sig_valid = true;
    // M7 eq:o_crypto — per-packet crypto bytes attached at this hop:
    // |σ_i| (real, measured sig_len) + |π_delay,i| + |π_hop,i|, both proofs
    // at the proposal's own modeled ≤100KB bound (main.tex:5124, eq:overhead_full).
    g_m7_crypto_bytes_sum += (double)meta.sig_len + 2.0 * STARK_PROOF_SIZE_MODELED_BYTES;
    ++g_m7_signed_pkts;
    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[CRYPTO-SIGN] node=" << signer
                  << " pkt=" << pkt_id
                  << " flow=" << seq
                  << " next_hop=" << next_hop
                  << " sig_len=" << meta.sig_len  // expected 4627
                  << " zone=" << zone
                  << " t=" << ts
                  << " digest[0..3]=" << _hex4(digest)
                  << " sig[0..3]=" << _hex4(meta.sig) << "\n";
        // [PKT-CRYPTO] — human-readable field-level breakdown for manual inspection
        std::cout << "[PKT-CRYPTO] ── SIGN ─────────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   node      = " << signer << "  (signer)\n"
                  << "[PKT-CRYPTO]   pkt_id    = " << pkt_id << "  (flow=" << seq << ", msg_id=" << msg_id << ")\n"
                  << "[PKT-CRYPTO]   next_hop  = " << next_hop << "\n"
                  << "[PKT-CRYPTO]   zone      = " << zone << "\n"
                  << "[PKT-CRYPTO]   t_sign    = " << ts << " s  (NS-3 simulation time)\n"
                  << "[PKT-CRYPTO]   nonce(η)  = 0x" << _hex32(fresh_nonce) << "  (random per-packet)\n"
                  << "[PKT-CRYPTO]   -- Sign buffer (eq:mldsa_sign, 24 bytes) ----------\n"
                  << "[PKT-CRYPTO]   buf[0..3]   msg_id   = " << msg_id   << "  (4 B; pkt_id|flow_id composite)\n"
                  << "[PKT-CRYPTO]   buf[4..11]  ts       = " << ts       << "  (8 B double)\n"
                  << "[PKT-CRYPTO]   buf[12..15] nonce    = 0x" << _hex32(fresh_nonce) << "  (4 B)\n"
                  << "[PKT-CRYPTO]   buf[16..19] next_hop = " << next_hop << "  (4 B)\n"
                  << "[PKT-CRYPTO]   buf[20..23] zone     = " << zone     << "  (4 B)\n"
                  << "[PKT-CRYPTO]   -- SHA3-512(buf) → 64-byte digest -----------------\n"
                  << "[PKT-CRYPTO]   digest[0..7]  = " << _hex8(digest) << "\n"
                  << "[PKT-CRYPTO]   digest[8..15] = " << _hex8(digest+8) << "\n"
                  << "[PKT-CRYPTO]   -- ML-DSA-87 signature (FIPS 204, liboqs) ---------\n"
                  << "[PKT-CRYPTO]   sig_len       = " << meta.sig_len << " bytes  (expected 4627)\n"
                  << "[PKT-CRYPTO]   sig[0..7]     = " << _hex8(meta.sig) << "\n"
                  << "[PKT-CRYPTO]   sig[8..15]    = " << _hex8(meta.sig+8) << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return true;
}

// ── ML-DSA-87 Verification ────────────────────────────────────────────────────

// is_batch_call: true when called from batch_verify_mldsa87() (50ms tick),
//                false when called at packet receive time (MacRx callback).
//                Logged as batch=0/1 so timing tools can distinguish the two call sites.
inline bool mldsa87_verify(uint32_t claimed_signer, uint32_t pkt_id,
                            uint32_t next_hop, uint32_t seq,
                            bool is_batch_call = false,
                            bool* out_broadcast_skip = nullptr) {
    // out_broadcast_skip distinguishes "this node was never the intended
    // recipient of the broadcast, so verification was never attempted" from
    // a genuine cryptographic rejection. Both paths return false below (the
    // caller-facing pass/fail semantics are unchanged), but a caller that
    // logs this outcome (e.g. crypto_timing_log*.csv) needs the distinction:
    // without it, every one of the many neighbours that merely overheard a
    // broadcast not addressed to them is indistinguishable from an actual
    // ML-DSA-87 signature rejection, which silently inflates any "verify
    // fail rate" computed from that log to mostly-meaningless noise.
    if (out_broadcast_skip) *out_broadcast_skip = false;
    if (g_disable_crypto) return true; // crypto disabled via --disable_crypto
    if (claimed_signer >= (uint32_t)total_size) return false;
    // msg_id = crypto_msg_key(pkt_id, seq): must match mldsa87_sign()'s key
    // exactly, or a genuinely-signed packet would never be found.
    uint32_t msg_id = crypto_msg_key(pkt_id, seq);
    auto it = g_packet_crypto.find({claimed_signer, msg_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) {
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                      << " pkt=" << pkt_id << " flow=" << seq
                      << " → no_record (not signed by this node)\n";
        return false;
    }

    // Broadcast MAC: every node in range overhears every packet. Only the
    // intended next hop can produce a matching digest (next_hop is embedded
    // in the signed message). Skip OQS_SIG_verify and don't count overheard
    // packets in sig_valid_rate — they would always fail and dilute the metric.
    if (it->second.signed_next_hop != (uint32_t)-1 && next_hop != it->second.signed_next_hop) {
        if (out_broadcast_skip) *out_broadcast_skip = true;
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                      << " pkt=" << pkt_id << " flow=" << seq
                      << " → skip_broadcast (intended_hop=" << it->second.signed_next_hop
                      << " actual_hop=" << next_hop << ")\n";
        return false;
    }

    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // Reconstruct eq:mldsa_sign buffer identically to sign: msg_id|ts|η|nh|z (24 bytes)
    uint8_t sign_buf[MLDSA_SIGN_BUF] = {};
    memcpy(sign_buf,    &msg_id,                   4);
    memcpy(sign_buf+4,  &it->second.sign_timestamp, 8);
    memcpy(sign_buf+12, &it->second.nonce,          4);
    memcpy(sign_buf+16, &next_hop,                  4);
    memcpy(sign_buf+20, &it->second.signed_zone_id, 4);

    uint8_t digest[64];
    if (!sha3_512_hash(sign_buf, MLDSA_SIGN_BUF, digest))
        return false;

    bool ok = OQS_SIG_verify(sig, digest, 64,
                              it->second.sig, it->second.sig_len,
                              g_node_keys[claimed_signer].pk) == OQS_SUCCESS;
    it->second.sig_valid = ok;
    g_verify_attempts++;
    if (ok) g_verify_passed++;

    if (CRYPTO_DEBUG_LOG && !is_batch_call) {
        // [PKT-CRYPTO] — human-readable field-level breakdown for manual inspection
        std::cout << "[PKT-CRYPTO] ── VERIFY ────────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   claimed   = " << claimed_signer << "  (original signer)\n"
                  << "[PKT-CRYPTO]   pkt_id    = " << pkt_id << "  (flow=" << seq << ", msg_id=" << msg_id << ")\n"
                  << "[PKT-CRYPTO]   verifier  = " << next_hop << "  (this hop)\n"
                  << "[PKT-CRYPTO]   -- Reconstructed sign buffer (must match signer) -\n"
                  << "[PKT-CRYPTO]   msg_id    = " << msg_id                        << "  ✓ (same as signed)\n"
                  << "[PKT-CRYPTO]   ts_sign   = " << it->second.sign_timestamp     << " s  (from signed record)\n"
                  << "[PKT-CRYPTO]   nonce(η)  = 0x" << _hex32(it->second.nonce)   << "  (from signed record)\n"
                  << "[PKT-CRYPTO]   next_hop  = " << next_hop                      << "  (must equal signed_next_hop=" << it->second.signed_next_hop << ")\n"
                  << "[PKT-CRYPTO]   zone      = " << it->second.signed_zone_id     << "  (from signed record)\n"
                  << "[PKT-CRYPTO]   -- SHA3-512 recomputed digest ----------------------\n"
                  << "[PKT-CRYPTO]   digest[0..7]  = " << _hex8(digest) << "\n"
                  << "[PKT-CRYPTO]   digest[8..15] = " << _hex8(digest+8) << "\n"
                  << "[PKT-CRYPTO]   -- OQS ML-DSA-87 verify result --------------------\n"
                  << "[PKT-CRYPTO]   sig[0..7]  = " << _hex8(it->second.sig) << "\n"
                  << "[PKT-CRYPTO]   pk[0..7]   = " << _hex8(g_node_keys[claimed_signer].pk) << "\n"
                  << "[PKT-CRYPTO]   result     = " << (ok ? "PASS ✓  signature authentic" : "FAIL ✗  signature invalid") << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                  << " pkt=" << pkt_id
                  << " flow=" << seq
                  << " ok=" << ok
                  << " sig_len=" << it->second.sig_len  // expected 4627
                  << " t_verify=" << ns3::Simulator::Now().GetSeconds()
                  << " t_sign=" << it->second.sign_timestamp
                  << " Δ=" << (ns3::Simulator::Now().GetSeconds() - it->second.sign_timestamp)
                  << " batch=" << is_batch_call
                  << " attempts=" << g_verify_attempts
                  << " passed=" << g_verify_passed
                  << " rate=" << (g_verify_attempts > 0
                                  ? (double)g_verify_passed / g_verify_attempts : 1.0)
                  << " pk[0..3]=" << _hex4(g_node_keys[claimed_signer].pk) << "\n";
    if (!ok)
        std::cout << "[CRYPTO-WARN] ML-DSA-87 verify FAILED:"
                  << " claimed_signer=" << claimed_signer
                  << " pkt=" << pkt_id
                  << " sig[0..3]=" << _hex4(it->second.sig)
                  << " digest[0..3]=" << _hex4(digest) << "\n";
    return ok;
}

// ── ML-DSA-87 Content-Authenticity Verify (Hidden-Forwarding copies) ────────
//
// mldsa87_verify()'s broadcast-skip branch (next_hop != signed_next_hop)
// early-returns false for ANY receiver that is not the intended next hop,
// BEFORE ever running real cryptography. That is correct for statistics like
// sig_valid_rate, but it means it can never distinguish a content-fabricated
// copy (Active HF, Attacks 5/6, eq:sig_s5/eq:sig_s6) from a content-unmodified
// copy (Passive HF, Attacks 7/8, eq:sig_s7/eq:sig_s8): an eavesdropper's
// current_hop never equals signed_next_hop in EITHER case, so the same
// early-return fires regardless of content. Hop-legitimacy (b_hop(u), the
// STARK check) is already handled independently by stark_verify_hop().
//
// This function checks ONLY content authenticity, decoupled from hop
// identity, by genuinely re-running OQS_SIG_verify() against the ORIGINAL
// signature the honest sender produced:
//   fabricated=false  reconstructs the exact digest that was signed (real
//                      nonce) — OQS_SIG_verify genuinely succeeds, matching
//                      "the passive copy's content is unmodified."
//   fabricated=true   recomputes the digest with the nonce field flipped,
//                      simulating that the attacker altered the message
//                      before forwarding it — the digest no longer matches
//                      what OQS_SIG_sign() actually signed, so
//                      OQS_SIG_verify() genuinely (not by hardcoding) fails.
// Side-effect-free: unlike mldsa87_verify(), this does not write sig_valid,
// nor touch g_verify_attempts/g_verify_passed — those belong to the
// legitimate recipient's own verify call and must not be perturbed by this
// receiver-specific, out-of-band content check performed at the eavesdropper.
//
// FIXED 2026-07-27 (was: "KNOWN LIMITATION (inherited, not introduced here):
// g_packet_crypto is keyed only by (signer, pkt_id)..."): the map is now
// keyed by (signer, crypto_msg_key(pkt_id, flow_id)) everywhere it is
// touched, so pkt_id reuse across flows/cycles no longer aliases onto the
// same slot. Caller must pass the packet's true flow_id (base_flow_id in
// s5-s8_detection.h, i.e. the marker-stripped value, not recv_flow_id).
inline bool mldsa87_verify_copy_content(uint32_t claimed_signer, uint32_t pkt_id,
                                         uint32_t flow_id, bool fabricated) {
    if (g_disable_crypto) return !fabricated; // crypto disabled: keep deterministic semantics
    if (claimed_signer >= (uint32_t)total_size) return false;
    uint32_t msg_id = crypto_msg_key(pkt_id, flow_id);
    auto it = g_packet_crypto.find({claimed_signer, msg_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return false;

    uint32_t nonce_for_digest = fabricated ? (it->second.nonce ^ 0xFFFFFFFFu)
                                            : it->second.nonce;

    uint8_t sign_buf[MLDSA_SIGN_BUF] = {};
    memcpy(sign_buf,    &msg_id,                     4);
    memcpy(sign_buf+4,  &it->second.sign_timestamp,   8);
    memcpy(sign_buf+12, &nonce_for_digest,             4);
    memcpy(sign_buf+16, &it->second.signed_next_hop,   4);
    memcpy(sign_buf+20, &it->second.signed_zone_id,    4);

    uint8_t digest[64];
    if (!sha3_512_hash(sign_buf, MLDSA_SIGN_BUF, digest)) return false;

    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    bool ok = OQS_SIG_verify(sig, digest, 64,
                              it->second.sig, it->second.sig_len,
                              g_node_keys[claimed_signer].pk) == OQS_SUCCESS;

    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[PKT-CRYPTO] ── VERIFY-COPY-CONTENT (HF) ────────────────────────\n"
                  << "[PKT-CRYPTO]   claimed_signer = " << claimed_signer << "\n"
                  << "[PKT-CRYPTO]   pkt_id         = " << pkt_id << "\n"
                  << "[PKT-CRYPTO]   fabricated     = " << fabricated << "\n"
                  << "[PKT-CRYPTO]   result         = "
                  << (ok ? "PASS ✓  content authentic" : "FAIL ✗  content fabricated") << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return ok;
}

// ── STARK Proof Simulation — eq:stark_delay / eq:stark_hop ───────────────────

inline StarkTimingProof stark_prove_timing(double t_recv, double t_fwd, uint32_t nonce) {
    StarkTimingProof proof;
    if (!enable_stark_delay) { proof.valid = true; return proof; } // AB4: π_delay removed — vacuously passes
    // M7 eq:o_crypto / main.tex:5123 "Proof generation overhead is modelled as
    // <=10ms per packet" — measures the real wall-clock cost of this simulated
    // proof-generation step (see g_m7_stark_wall_us_sum comment for scope).
    auto _st0 = std::chrono::high_resolution_clock::now();
    proof.valid = (t_fwd - t_recv) <= STARK_DELTA_MAX;
    // c_i = H_SHA3-512(ρ_i) — commit to blinding randomness only; timestamps are
    // private witnesses and must not appear in the public commitment (eq:stark_delay ZK)
    sha3_512_hash(reinterpret_cast<const uint8_t*>(&nonce), sizeof(nonce), proof.commitment);
    auto _st1 = std::chrono::high_resolution_clock::now();
    g_m7_stark_wall_us_sum += std::chrono::duration<double, std::micro>(_st1 - _st0).count();
    ++g_m7_stark_calls;
    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[PKT-CRYPTO] ── STARK-PROVE ────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   nonce(ρ_i)    = 0x" << _hex32(nonce) << "  (blinding randomness)\n"
                  << "[PKT-CRYPTO]   t_recv        = " << t_recv << " s  (private witness)\n"
                  << "[PKT-CRYPTO]   t_fwd         = " << t_fwd  << " s  (private witness)\n"
                  << "[PKT-CRYPTO]   Δ = t_fwd-t_recv = " << (t_fwd - t_recv)*1000.0 << " ms\n"
                  << "[PKT-CRYPTO]   STARK_DELTA_MAX  = " << STARK_DELTA_MAX*1000.0   << " ms\n"
                  << "[PKT-CRYPTO]   timing_valid  = " << (proof.valid ? "YES ✓  within bound" : "NO ✗   DELAY EXCEEDS LIMIT") << "\n"
                  << "[PKT-CRYPTO]   commitment    = H(ρ_i) = " << _hex8(proof.commitment) << "  (ZK: no ts in commit)\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return proof;
}

inline bool stark_verify_timing(const StarkTimingProof& proof,
                                 double t_recv, double t_fwd) {
    if (!enable_stark_delay) return true; // AB4: π_delay removed — vacuously passes
    auto _st0 = std::chrono::high_resolution_clock::now();
    bool ok = proof.valid && (t_fwd - t_recv) <= STARK_DELTA_MAX;
    auto _st1 = std::chrono::high_resolution_clock::now();
    g_m7_stark_wall_us_sum += std::chrono::duration<double, std::micro>(_st1 - _st0).count();
    ++g_m7_stark_calls;
    return ok;
}

// Verify that current_hop is the node the sender intended as its next hop
// (embedded in the signature at sign time). Re-running find_next_hop at
// verification time is unreliable in a dynamic VANET because routing tables
// change between send and receive. Using the signed_next_hop eliminates
// false positives from routing churn while still catching misdirected packets.
inline bool stark_verify_hop(uint32_t current_hop, uint32_t signer, uint32_t pkt_id,
                              uint32_t flow_id) {
    if (!enable_stark_hop) return true; // AB4: π_hop removed — vacuously passes
    if (g_disable_crypto) return true; // crypto disabled via --disable_crypto
    auto it = g_packet_crypto.find({signer, crypto_msg_key(pkt_id, flow_id)});
    if (it == g_packet_crypto.end() || it->second.signed_next_hop == (uint32_t)-1)
        return true;  // no signing record — can't verify, assume valid
    auto _st0 = std::chrono::high_resolution_clock::now();
    bool hop_ok = (current_hop == it->second.signed_next_hop);
    auto _st1 = std::chrono::high_resolution_clock::now();
    g_m7_stark_wall_us_sum += std::chrono::duration<double, std::micro>(_st1 - _st0).count();
    ++g_m7_stark_calls;
    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[PKT-CRYPTO] ── STARK-HOP ─────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   signer          = " << signer << "\n"
                  << "[PKT-CRYPTO]   pkt_id          = " << pkt_id << "\n"
                  << "[PKT-CRYPTO]   signed_next_hop = " << it->second.signed_next_hop << "  (embedded at sign time)\n"
                  << "[PKT-CRYPTO]   current_hop     = " << current_hop << "  (actual receiver)\n"
                  << "[PKT-CRYPTO]   hop_ok          = " << (hop_ok ? "YES ✓  packet on intended path"
                                                                     : "NO ✗   packet misdirected!") << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return hop_ok;
}

inline void stark_update_meta(uint32_t signer, uint32_t pkt_id, uint32_t flow_id,
                               bool timing_ok, bool hop_ok) {
    auto it = g_packet_crypto.find({signer, crypto_msg_key(pkt_id, flow_id)});
    if (it == g_packet_crypto.end()) return;
    it->second.stark_timing_ok = timing_ok;
    it->second.stark_hop_ok    = hop_ok;
    g_lstm_pkt_counts[signer]++;
    if (!timing_ok) g_lstm_stark_counts[signer].first++;
    if (!hop_ok)    g_lstm_stark_counts[signer].second++;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[STARK] signer=" << signer
                  << " pkt=" << pkt_id
                  << " flow=" << flow_id
                  << " t=" << ns3::Simulator::Now().GetSeconds()
                  << " timing_ok=" << timing_ok
                  << " hop_ok=" << hop_ok
                  << " | lstm_t_fails=" << g_lstm_stark_counts[signer].first
                  << " lstm_h_fails=" << g_lstm_stark_counts[signer].second
                  << " pkt_count=" << g_lstm_pkt_counts[signer] << "\n";
}

// ── Randomised Batch Verification — eq:batch_challenge / eq:batch_verify ─────

inline BatchVerifyResult batch_verify_mldsa87(
    const std::vector<std::pair<uint32_t,uint32_t>>& node_pkt_pairs,
    double budget_s = 0.050)
{
    BatchVerifyResult res{true, 0, 0.0};

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
    // r = H(σ_1 ‖ … ‖ σ_n ‖ m_1 ‖ … ‖ m_n) — eq:batch_challenge shared binding
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), res.challenge);

    for (auto& [node, pkt] : node_pkt_pairs) {
        if (res.elapsed_s >= budget_s) break;
        // Use the stored signed_next_hop so the broadcast-skip guard in mldsa87_verify
        // does not reject every packet when called with next_hop=0.
        auto it_bv = g_packet_crypto.find({node, pkt});
        uint32_t nh = (it_bv != g_packet_crypto.end())
                      ? it_bv->second.signed_next_hop : 0;
        // node_pkt_pairs' second element is a raw g_packet_crypto KEY (already
        // crypto_msg_key(pkt_id,flow_id) — see crypto_batch_verify_tick(),
        // which builds `pending` straight from the map's own keys). Decompose
        // it back to the raw (pkt_id, flow_id) pair mldsa87_verify() expects,
        // so its internal re-composition reproduces this exact `pkt` value
        // instead of re-encoding an already-composite number.
        if (!mldsa87_verify(node, crypto_msg_key_pkt(pkt), nh,
                             crypto_msg_key_flow(pkt), /*is_batch_call=*/true))
            res.passed = false;
        ++res.n_verified;
        res.elapsed_s += 0.001;
    }

    if (CRYPTO_DEBUG_LOG && res.n_verified > 0)
        std::cout << "[BATCH-VERIFY] n=" << res.n_verified
                  << " passed=" << res.passed
                  << " challenge[0..3]=" << (combined.empty() ? "n/a" : _hex4(res.challenge))
                  << " elapsed=" << res.elapsed_s << "s\n";
    return res;
}

// ── LSTM Feature Export Bridge — eq:lstm_input ────────────────────────────────

inline CryptoLstmFeatures crypto_get_lstm_features(uint32_t node) {
    CryptoLstmFeatures f{0.0f, 0.0f};
    auto pc = g_lstm_pkt_counts.find(node);
    if (pc == g_lstm_pkt_counts.end() || pc->second == 0) return f;
    auto sc = g_lstm_stark_counts.find(node);
    if (sc == g_lstm_stark_counts.end()) return f;
    float total = (float)pc->second;
    f.stark_timing_fail = (float)sc->second.first  / total;
    f.stark_hop_fail    = (float)sc->second.second / total;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[LSTM-FEAT] node=" << node
                  << " pkt_count=" << pc->second
                  << " stark_timing_fail=" << f.stark_timing_fail
                  << " stark_hop_fail=" << f.stark_hop_fail << "\n";
    return f;
}

inline void crypto_reset_lstm_accumulators() {
    g_lstm_pkt_counts.clear();
    g_lstm_stark_counts.clear();
}

// ── Controller RSU Re-assignment — eq:ctrl_failover ───────────────────────────

inline void ctrl_reassign_rsus(uint32_t revoked_ctrl);

// ── Trust Management — eq:trust_update / eq:quarantine ───────────────────────

inline void trust_init_all() {
    for (uint32_t i = 0; i < (uint32_t)total_size; ++i) {
        g_trust_score[i] = g_ctrl_trust_score[i] = 1.0;
        g_quarantined[i] = g_ctrl_revoked[i]      = false;
        g_trust_last_update[i] = 0.0;
        g_node_keys[i] = NodeKeyMaterial{};
    }
    g_dkg = DKGState{};
    g_T_ref = g_T_ref_last_sync = 0.0;
    g_packet_crypto.clear(); g_flowmod_endorsements.clear();
    g_witness_log.clear(); g_witness_alert_pool.clear();
    g_msg_id_seen.clear(); g_dst_volume_prev.clear(); g_dst_volume_curr.clear();
    g_lstm_pkt_counts.clear(); g_lstm_stark_counts.clear();
    g_failover_max_ms = 0.0; g_failover_events = 0; g_failover_reassigned = 0;
    g_m7_crypto_bytes_sum = 0.0; g_m7_signed_pkts = 0;
    g_m7_batch_wall_us_sum = 0.0; g_m7_batch_calls = 0; g_m7_batch_pkts = 0;
    g_m7_consensus_wall_us_sum = 0.0; g_m7_consensus_count = 0;
    g_m7_stark_wall_us_sum = 0.0; g_m7_stark_calls = 0;
    if (g_oqs_sig) { OQS_SIG_free(g_oqs_sig); g_oqs_sig = nullptr; }
}

inline void trust_update_positive(uint32_t node) {
    if (!enable_quarantine) return; // AB7-A: detection-only — trust never moves
    if (node >= (uint32_t)total_size) return;
    double old_v = g_trust_score[node];
    double v = old_v + TRUST_DELTA_R;
    g_trust_score[node] = (v < 1.0 ? v : 1.0);
    g_trust_last_update[node] = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[TRUST+] node=" << node
                  << " " << old_v << " → " << g_trust_score[node]
                  << " (Δ_r=" << TRUST_DELTA_R << ")"
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
}

inline void trust_update_negative(uint32_t node) {
    if (!enable_quarantine) return; // AB7-A: detection-only — no SC.Quarantine
    if (node >= (uint32_t)total_size) return;
    double old_v = g_trust_score[node];
    double v = old_v - TRUST_DELTA_P;
    g_trust_score[node] = (v > 0.0 ? v : 0.0);
    g_trust_last_update[node] = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[TRUST-] node=" << node
                  << " " << old_v << " → " << g_trust_score[node]
                  << " (Δ_p=" << TRUST_DELTA_P
                  << " T_min=" << TRUST_T_MIN << ")"
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
    if (g_trust_score[node] < TRUST_T_MIN && !g_quarantined[node]) {
        g_quarantined[node] = true;
        t_quarantine[node]  = ns3::Simulator::Now().GetSeconds();
        if (active_attack_variant >= 0 && active_attack_variant < NUM_ATTACK_VARIANTS)
            record_detection_event(active_attack_variant, (int)node);
        // Unconditional: quarantine is a high-importance detection event
        std::cout << "[TRUST-QUARANTINE] node=" << node
                  << " trust=" << g_trust_score[node]
                  << " < T_min=" << TRUST_T_MIN
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
        NS_LOG_WARN("[TRUST] Quarantine: node=" << node
            << " trust=" << g_trust_score[node]
            << " t=" << ns3::Simulator::Now().GetSeconds());
        // eq:key_rotation_trigger: if revoked node is an RSU, rotate all proving keys
        // AB11-A (enable_key_rotation=false): revoked RSU's key material stays live
        if (enable_key_rotation && node >= N_Vehicles && node < N_Vehicles + N_RSUs)
            dkg_rotate_keys(node);
    }
}

inline void ctrl_trust_update_positive(uint32_t ctrl) {
    if (!enable_controller_failover) return; // AB9-A: controller trust scoring inert
    if (ctrl >= N_Controllers || g_ctrl_revoked[ctrl]) return;
    double v = g_ctrl_trust_score[ctrl] + TRUST_DELTA_R_CTRL;
    g_ctrl_trust_score[ctrl] = (v < 1.0 ? v : 1.0);
}

inline void ctrl_trust_update_negative(uint32_t ctrl) {
    if (!enable_controller_failover) return; // AB9-A: no trust scoring, no revoke/failover
    if (ctrl >= N_Controllers) return;
    double old_v = g_ctrl_trust_score[ctrl];
    double v = old_v - TRUST_DELTA_P_CTRL;
    g_ctrl_trust_score[ctrl] = (v > 0.0 ? v : 0.0);
    if (g_ctrl_trust_score[ctrl] < TRUST_T_MIN_CTRL && !g_ctrl_revoked[ctrl]) {
        g_ctrl_revoked[ctrl] = true;
        ctrl_reassign_rsus(ctrl);
        // Unconditional: controller revocation is high-importance
        std::cout << "[CTRL-REVOKED] controller idx=" << ctrl
                  << " trust=" << old_v << " → " << g_ctrl_trust_score[ctrl]
                  << " < T_min_ctrl=" << TRUST_T_MIN_CTRL
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
        NS_LOG_WARN("[CTRL-TRUST] Controller revoked: idx=" << ctrl
            << " t=" << ns3::Simulator::Now().GetSeconds());
    }
}

// M5 completion handler — fires when the ControllerRevoked broadcast reaches
// RSU r. Applies the failover target chosen at revocation time (eq:ctrl_failover
// arg-min over C_trusted(t)\{c_i}) and stamps t_reassign^(k) for eq:l_failover.
inline void ctrl_complete_rsu_reassign(uint32_t r, uint32_t best,
                                       uint32_t revoked_ctrl, double t_revoke) {
    rsu_controller_assignment[r] = (int)best;
    ++g_failover_reassigned;
    double lat_ms = (ns3::Simulator::Now().GetSeconds() - t_revoke) * 1000.0;
    if (lat_ms > g_failover_max_ms) g_failover_max_ms = lat_ms;
    NS_LOG_WARN("[CTRL-FAILOVER] RSU " << r << " ctrl " << revoked_ctrl
        << " → " << best << " L=" << lat_ms << "ms");
    // eq:l_failover target: L_failover ≤ 100 ms (proposal Table, M5)
    if (lat_ms > 100.0)
        std::cout << "[CTRL-FAILOVER] WARNING: RSU " << r
                  << " reassignment latency " << lat_ms
                  << " ms EXCEEDS 100ms bound\n";
}

inline void ctrl_reassign_rsus(uint32_t revoked_ctrl) {
    std::vector<uint32_t> trusted;
    for (uint32_t c = 0; c < N_Controllers; ++c)
        if (!g_ctrl_revoked[c]) trusted.push_back(c);
    if (trusted.empty()) {
        std::cerr << "[CRYPTO-ERROR] ctrl_reassign_rsus: ALL controllers revoked"
                  << " — no failover possible\n";
        NS_LOG_ERROR("[CTRL] All controllers revoked — no failover possible");
        return;
    }
    // t_revoke — SC.Revoke has just fired (eq:sc_revoke); the ControllerRevoked
    // event broadcast starts now.
    //
    // g_failover_max_ms is a MONOTONIC running max across the whole simulation
    // (never reset here) — deliberately NOT reset per-event. An earlier version
    // reset it to 0.0 on every call, which is race-prone whenever two
    // revocations overlap in time (realistic under the proposal's "2
    // compromised controllers" scenario, since the default broadcast
    // completion delay is only ~10-15ms): a second revocation's reset could
    // discard an in-flight first revocation's already-recorded latency, and
    // the first revocation's still-pending completions would then update a
    // max that was reset for an unrelated event, mixing two events' latencies
    // together. Reporting the worst L_failover observed by ANY revocation
    // event so far in the run avoids the race entirely and still answers the
    // proposal's target-bound question (does L_failover stay <= 100ms across
    // every event). See docs/METRICS_DEVIATIONS_FROM_PROPOSAL.md.
    double t_revoke = ns3::Simulator::Now().GetSeconds();
    ++g_failover_events;
    uint32_t zone_size = N_RSUs / N_Controllers;
    uint32_t affected = 0;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        if ((uint32_t)rsu_controller_assignment[r] != revoked_ctrl) continue;
        uint32_t rsu_zone = r / (zone_size > 0 ? zone_size : 1);
        // eq:ctrl_failover — target selected from C_trusted(t)\{c_i} at t_revoke
        uint32_t best = trusted[0], min_d = UINT32_MAX;
        for (uint32_t c : trusted) {
            uint32_t d = (rsu_zone > c) ? rsu_zone - c : c - rsu_zone;
            if (d < min_d) { min_d = d; best = c; }
        }
        // Reassignment completes when the ControllerRevoked event reaches RSU r
        // and it re-attaches to its new controller: base broadcast latency plus
        // a geographic-dispersion increment proportional to the zone distance
        // min_d to that new controller. Until the event fires, the RSU still
        // points at the revoked controller — the realistic vulnerability window
        // whose worst case eq:l_failover's max is designed to capture.
        double delay_ms = FAILOVER_BCAST_BASE_MS
                        + FAILOVER_BCAST_PER_ZONE_MS * (double)min_d;
        ns3::Simulator::Schedule(ns3::Seconds(delay_ms / 1000.0),
                                 &ctrl_complete_rsu_reassign,
                                 r, best, revoked_ctrl, t_revoke);
        ++affected;
    }
    // Unconditional: failover summary
    std::cout << "[CTRL-FAILOVER] SC.Revoke ctrl=" << revoked_ctrl
              << " t_revoke=" << t_revoke
              << " ControllerRevoked broadcast to " << affected
              << " affected RSUs (trusted_count=" << trusted.size()
              << "); completions scheduled at " << FAILOVER_BCAST_BASE_MS
              << "ms + " << FAILOVER_BCAST_PER_ZONE_MS << "ms/zone\n";
}

// ── Distributed Time Reference — eq:time_consensus ───────────────────────────

inline void update_T_ref() {
    double t_ground = ns3::Simulator::Now().GetSeconds(); // eq:eps_ref T_ground(t)
    std::vector<double> times;
    times.reserve(N_RSUs);
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        // eq:time_consensus tau_j(t): each RSU's own local clock reading,
        // via the same node_clock_offset() every per-packet timestamp uses
        // (single source of truth — see M9 report Tier-2 item).
        times.push_back(node_local_time(N_Vehicles + r));
    }
    std::sort(times.begin(), times.end());
    g_T_ref           = times[times.size() / 2];
    g_T_ref_last_sync = t_ground;

    // M9 — eq:eps_ref: deviation of the consensus median from ground truth.
    g_eps_ref = (g_T_ref > t_ground) ? (g_T_ref - t_ground) : (t_ground - g_T_ref);
    g_eps_ref_cumulative += g_eps_ref;
    ++g_eps_ref_samples;

    // sec:time_ref — commit this tick's T_ref(t) to the blockchain (tamper-evident
    // audit trail), same T_SYNC_INTERVAL cadence as bc_anchor_to_global().
    bc_commit_tref_to_chain(g_T_ref, g_eps_ref, t_ground);

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[T-REF] Distributed time synced T_ref=" << g_T_ref
                  << " from " << N_RSUs << " RSUs (f_bad=" << TIME_REF_F_BAD
                  << ", delta_attack=" << TIME_REF_DELTA_ATTACK << "s)"
                  << " eps_ref=" << g_eps_ref << "s t=" << g_T_ref_last_sync << "\n";
}

inline void update_T_ref_recurring() {
    update_T_ref();
    ns3::Simulator::Schedule(ns3::Seconds(T_SYNC_INTERVAL), &update_T_ref_recurring);
}

// ── Map Eviction ──────────────────────────────────────────────────────────────

inline void crypto_evict_old_entries() {
    double cutoff = ns3::Simulator::Now().GetSeconds() - 5.0;
    size_t before = g_packet_crypto.size();
    for (auto it = g_packet_crypto.begin(); it != g_packet_crypto.end(); )
        it = (it->second.sign_timestamp < cutoff)
             ? g_packet_crypto.erase(it) : std::next(it);
    double wcut = ns3::Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    for (auto& [w, entries] : g_witness_log)
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [wcut](const WitnessLogEntry& e){ return e.ts < wcut; }),
            entries.end());
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[EVICT] crypto_map " << before << " → " << g_packet_crypto.size()
                  << " (cutoff t=" << cutoff << ")\n";
}

inline void crypto_evict_old_entries_recurring() {
    crypto_evict_old_entries();
    ns3::Simulator::Schedule(ns3::Seconds(5.0), &crypto_evict_old_entries_recurring);
}

// ── Batch Verify Tick (recurring, 50 ms) ─────────────────────────────────────

inline void crypto_batch_verify_tick() {
    std::vector<std::pair<uint32_t,uint32_t>> pending;
    double window = ns3::Simulator::Now().GetSeconds() - 0.050;
    for (auto& [key, meta] : g_packet_crypto)
        if (meta.sign_timestamp >= window) pending.push_back(key);
    if (!pending.empty()) {
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[BATCH-TICK] t=" << ns3::Simulator::Now().GetSeconds()
                      << " pending=" << pending.size() << " pkts in 50ms window\n";
        // M7 eq:t_verify — T_batch(B): real wall-clock time of BatchVerify over B pkts
        auto _bt0 = std::chrono::high_resolution_clock::now();
        auto result = batch_verify_mldsa87(pending);
        auto _bt1 = std::chrono::high_resolution_clock::now();
        double _b_us = std::chrono::duration<double, std::micro>(_bt1 - _bt0).count();
        g_m7_batch_wall_us_sum += _b_us;
        ++g_m7_batch_calls;
        g_m7_batch_pkts += pending.size();
        // per-op row: node_id column carries B (batch size), pkt_id carries
        // n_verified; not a single-packet/single-flow event, so flow_id is
        // UINT32_MAX (not applicable).
        crypto_log_event("batch_verify", (uint32_t)pending.size(),
                         result.n_verified, UINT32_MAX, _bt0, result.passed);
        g_batch_passed = result.passed; // feed b_batch into LRAD (eq:batch_challenge)
        if (!result.passed) {
            std::cerr << "[CRYPTO-ERROR] Batch verify tick FAILED:"
                      << " " << pending.size() << " pkts"
                      << " verified=" << result.n_verified << "\n";
            NS_LOG_WARN("[BATCH] Verify failed: " << pending.size() << " pkts");
        }
    }
    ns3::Simulator::Schedule(ns3::Seconds(0.050), &crypto_batch_verify_tick);
}

// ── Witness Mechanism — eq:da_sign, eq:nfa_sign, eq:bft_penalty ──────────────

inline void witness_log_packet(uint32_t witness, const uint8_t* pkt_hash,
                                uint32_t dst, double ts) {
    WitnessLogEntry e;
    memcpy(e.pkt_hash, pkt_hash, 64); e.dst = dst; e.ts = ts;
    g_witness_log[witness].push_back(e);
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-LOG] witness=" << witness
                  << " dst=" << dst
                  << " hash[0..3]=" << _hex4(pkt_hash)
                  << " log_size=" << g_witness_log[witness].size() << "\n";
}

inline bool witness_check_duplication(uint32_t witness, const uint8_t* pkt_hash,
                                       uint32_t dst_seen_now) {
    auto it = g_witness_log.find(witness);
    if (it == g_witness_log.end()) return false;
    double cutoff = ns3::Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    for (auto& e : it->second)
        if (memcmp(e.pkt_hash, pkt_hash, 64) == 0 &&
            e.dst != dst_seen_now && e.ts >= cutoff) {
            if (CRYPTO_DEBUG_LOG)
                std::cout << "[WITNESS-DUP] witness=" << witness
                          << " hash[0..3]=" << _hex4(pkt_hash)
                          << " prev_dst=" << e.dst
                          << " new_dst=" << dst_seen_now
                          << " → DUPLICATION DETECTED\n";
            return true;
        }
    return false;
}

// α_w: duplication alert — same packet at two destinations (eq:da_sign)
inline void witness_submit_duplication_alert(uint32_t witness, uint32_t target_node,
                                              uint32_t pkt_id, uint32_t flow_id,
                                              uint32_t dst, uint32_t dup_dst) {
    if (!enable_witness_mechanism) return; // AB6-A: no alerts submitted or pooled
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    // H(p) = SHA3-512 of target's ML-DSA-87 signature on the packet (eq:da_sign)
    uint8_t h_p[64] = {};
    auto it_pkt = g_packet_crypto.find({target_node, crypto_msg_key(pkt_id, flow_id)});
    if (it_pkt != g_packet_crypto.end() && it_pkt->second.sig_len > 0)
        sha3_512_hash(it_pkt->second.sig, it_pkt->second.sig_len, h_p);

    // α_w message: H(p)(64) ‖ dst(4) ‖ dst'(4) ‖ ts_w(8) = 80 bytes (eq:da_sign)
    double ts_w = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[80] = {};
    memcpy(msg,    h_p,      64);
    memcpy(msg+64, &dst,     4);
    memcpy(msg+68, &dup_dst, 4);
    memcpy(msg+72, &ts_w,    8);
    uint8_t h_alert[64];
    sha3_512_hash(msg, sizeof(msg), h_alert);

    WitnessAlert alert;
    alert.witness_id  = witness;
    alert.alert_type  = 0;
    memcpy(alert.signed_digest, h_alert, 64);
    alert.alert_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, alert.alert_sig, &alert.alert_sig_len,
                     h_alert, 64, g_node_keys[witness].sk) != OQS_SUCCESS) return;

    g_witness_alert_pool[target_node].push_back(alert);
    uint32_t threshold = 2 * WITNESS_F + 1;

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-DA] witness=" << witness
                  << " → target=" << target_node
                  << " pkt=" << pkt_id
                  << " flow=" << flow_id
                  << " t_alert=" << ts_w
                  << " pool=" << g_witness_alert_pool[target_node].size() << "/" << threshold << "\n";

    // BFT penalty: count only cryptographically verified alerts (eq:bft_penalty)
    uint32_t verified = 0;
    for (auto& wa : g_witness_alert_pool[target_node]) {
        if (!g_node_keys[wa.witness_id].keys_generated) continue;
        if (OQS_SIG_verify(oqs, wa.signed_digest, 64,
                           wa.alert_sig, wa.alert_sig_len,
                           g_node_keys[wa.witness_id].pk) == OQS_SUCCESS)
            ++verified;
    }
    if (verified >= threshold) {
        std::cout << "[WITNESS-DA-BFT] " << verified << " verified alerts >= 2f+1=" << threshold
                  << " → trust_update_negative(target=" << target_node << ")\n";
        NS_LOG_WARN("[WITNESS-DA] BFT threshold reached for node " << target_node);
        trust_update_negative(target_node);
        // M12 — WAP-R: count this threshold-crossing event once per node per run.
        //
        // FIXED 2026-07-11 — main.tex's M12 definition (§"Witness Alert
        // Precision and Recall") is scoped "specifically against Variants 7
        // and 8" (passive HF) — it is NOT meant to score threshold-crossing
        // events from any other scenario. This function (the duplication
        // alert, eq:dup_alert_cond) also fires correctly during ACTIVE HF
        // (Variants 5/6, gated on present_active_hf_attack||present_passive_hf_attack
        // at its only call site in routing.cc), and previously classified
        // every one of those GENUINE active-HF detections as a WAP-R false
        // positive (the `else` branch), since `present_passive_hf_attack` is
        // false during an active-only run. Empirically confirmed: A5/A6 runs
        // reported TP_W=0, FP_W=30-33, P_W=0.000% — completely misleading,
        // since those 30+ events were correct detections of a real attacker,
        // not false accusations. Now only counted when the run is genuinely
        // passive-HF-flagged; active-HF and non-HF threshold events are
        // correctly excluded from WAP-R's tally entirely (M12 is simply not
        // applicable there, not "0% precision").
        if (!g_witness_da_threshold_fired[target_node]) {
            g_witness_da_threshold_fired[target_node] = true;
            if (present_passive_hf_attack) {
                if (passive_hf_malicious_nodes[target_node])
                    ++g_witness_TP_W;
                else
                    ++g_witness_FP_W;
            }
        }
    }
}

// β_w: non-forwarding alert — packet received but not forwarded within T_fwd (eq:nfa_sign)
inline void witness_submit_nfa_alert(uint32_t witness, uint32_t target_node,
                                      uint32_t pkt_id, uint32_t flow_id, double T_fwd) {
    if (!enable_witness_mechanism) return; // AB6-A: no alerts submitted or pooled
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    // H(p) = SHA3-512 of target's ML-DSA-87 signature on the packet (eq:nfa_sign)
    uint8_t h_p[64] = {};
    auto it_pkt = g_packet_crypto.find({target_node, crypto_msg_key(pkt_id, flow_id)});
    if (it_pkt != g_packet_crypto.end() && it_pkt->second.sig_len > 0)
        sha3_512_hash(it_pkt->second.sig, it_pkt->second.sig_len, h_p);

    // β_w message: H(p)(64) ‖ v_i(4) ‖ ts_w(8) ‖ T_fwd(8) = 84 bytes (eq:nfa_sign)
    double ts_w = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[84] = {};
    memcpy(msg,    h_p,          64);
    memcpy(msg+64, &target_node, 4);
    memcpy(msg+68, &ts_w,        8);
    memcpy(msg+76, &T_fwd,       8);
    uint8_t h_alert[64];
    sha3_512_hash(msg, sizeof(msg), h_alert);

    WitnessAlert alert;
    alert.witness_id  = witness;
    alert.alert_type  = 1;
    memcpy(alert.signed_digest, h_alert, 64);
    alert.alert_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, alert.alert_sig, &alert.alert_sig_len,
                     h_alert, 64, g_node_keys[witness].sk) != OQS_SUCCESS) return;

    g_witness_alert_pool[target_node].push_back(alert);
    uint32_t threshold = 2 * WITNESS_F + 1;

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-NFA] witness=" << witness
                  << " → target=" << target_node
                  << " pkt=" << pkt_id
                  << " flow=" << flow_id
                  << " t_alert=" << ts_w
                  << " T_fwd=" << T_fwd << "s"
                  << " pool=" << g_witness_alert_pool[target_node].size() << "/" << threshold << "\n";

    // BFT penalty: count only cryptographically verified alerts (eq:bft_penalty)
    uint32_t verified = 0;
    for (auto& wa : g_witness_alert_pool[target_node]) {
        if (!g_node_keys[wa.witness_id].keys_generated) continue;
        if (OQS_SIG_verify(oqs, wa.signed_digest, 64,
                           wa.alert_sig, wa.alert_sig_len,
                           g_node_keys[wa.witness_id].pk) == OQS_SUCCESS)
            ++verified;
    }
    if (verified >= threshold) {
        std::cout << "[WITNESS-NFA-BFT] " << verified << " verified alerts >= 2f+1=" << threshold
                  << " → trust_update_negative(target=" << target_node << ")\n";
        NS_LOG_WARN("[WITNESS-NFA] BFT threshold reached for node " << target_node);
        trust_update_negative(target_node);
        // M12 (WAP-R) intentionally NOT counted here (fixed 2026-07-11).
        // main.tex scopes M12 to the duplication-alert mechanism only
        // (eq:dup_alert_cond, "specifically against Variants 7 and 8") — this
        // is the non-forwarding alert (eq:nfwd_detect), a different mechanism
        // tied to delay-equivalent non-delivery for Selective Time Delay
        // (Variants 1-4), not Hidden Forwarding. It previously shared
        // g_witness_threshold_fired with the duplication-alert path, so an
        // NFA crossing here could pre-set a node's flag and silently skip a
        // later, genuine duplication-alert crossing for that same node,
        // undercounting M12's TP_W. trust_update_negative() above still
        // fires correctly regardless — only the M12-specific bookkeeping is
        // removed from this function.
    }
}

// ── Volume Rate Tracking — S7, eq:sig_s7 ─────────────────────────────────────

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

// ── Msg-ID Duplication Cache — S6 ────────────────────────────────────────────

inline bool check_msg_duplication(const uint8_t* pkt_hash, uint32_t dst_now) {
    uint64_t key; memcpy(&key, pkt_hash, 8);
    auto it = g_msg_id_seen.find(key);
    if (it == g_msg_id_seen.end()) {
        g_msg_id_seen[key] = {dst_now, ns3::Simulator::Now().GetSeconds()};
        return false;
    }
    return (it->second.first != dst_now);
}

// ── FlowMod RSU Endorsement — eq:rsu_endorsement ─────────────────────────────

inline bool flowmod_endorse(uint32_t rsu_idx, uint32_t flow_id,
                             const uint8_t* flowmod_params, size_t params_len) {
    if (rsu_idx >= (uint32_t)total_size) return false;
    if (!g_node_keys[rsu_idx].keys_generated && !mldsa87_keygen(rsu_idx)) return false;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return false;

    double   ts            = ns3::Simulator::Now().GetSeconds();
    uint32_t rsu_local_idx = rsu_idx - N_Vehicles;
    uint32_t zone          = crypto_zone_id(rsu_idx);

    uint8_t topo_in[8];
    memcpy(topo_in,   &zone,          4);
    memcpy(topo_in+4, &rsu_local_idx, 4);
    uint8_t T_rj[64];
    sha3_512_hash(topo_in, 8, T_rj);

    uint8_t flowmod_hash[64] = {};
    if (params_len > 0 && flowmod_params)
        sha3_512_hash(flowmod_params, params_len, flowmod_hash);
    else
        sha3_512_hash(reinterpret_cast<const uint8_t*>(&flow_id), 4, flowmod_hash);

    std::vector<uint8_t> msg(params_len + 8 + 64);
    size_t off = 0;
    if (params_len && flowmod_params) { memcpy(msg.data(), flowmod_params, params_len); off += params_len; }
    memcpy(msg.data() + off, &ts,  8);  off += 8;
    memcpy(msg.data() + off, T_rj, 64);

    uint8_t msg_digest[64];
    sha3_512_hash(msg.data(), msg.size(), msg_digest);

    uint8_t endorsement_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  endorsement_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, endorsement_sig, &endorsement_sig_len,
                     msg_digest, 64, g_node_keys[rsu_idx].sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] flowmod_endorse: OQS_SIG_sign failed rsu="
                  << rsu_idx << " flow=" << flow_id << "\n";
        return false;
    }

    FlowModEndorsement& e = g_flowmod_endorsements[flow_id];
    if (e.endorsing_rsus.empty()) {
        // First endorser: seed the accumulator with H(sig_1)
        memcpy(e.flowmod_hash, flowmod_hash, 64);
        sha3_512_hash(endorsement_sig, endorsement_sig_len, e.endorsement_hash);
    } else {
        // Each subsequent endorser: H_new = SHA3-512(H_prev ‖ sig_j)
        // Binds all {ε_j} per eq:endorsed_commit: C_P = BC.Commit(H(FlowMod) ‖ {ε_j} ‖ ts)
        uint8_t rolling[64 + OQS_SIG_ml_dsa_87_length_signature];
        memcpy(rolling,    e.endorsement_hash, 64);
        memcpy(rolling+64, endorsement_sig,    endorsement_sig_len);
        sha3_512_hash(rolling, sizeof(rolling), e.endorsement_hash);
    }
    e.endorsing_rsus.push_back(rsu_idx);
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[FLOWMOD-ENDORSE] rsu=" << rsu_idx
                  << " flow=" << flow_id
                  << " zone=" << zone
                  << " sig_len=" << endorsement_sig_len  // expected 4627
                  << " sig[0..3]=" << _hex4(endorsement_sig)
                  << " flowmod_hash[0..3]=" << _hex4(flowmod_hash)
                  << " T_rj[0..3]=" << _hex4(T_rj)
                  << " endorsers_so_far=" << e.endorsing_rsus.size() << "\n";
    return true;
}

// ── CLI Parameter Registration ────────────────────────────────────────────────

inline void crypto_register_cli_params(ns3::CommandLine& cmd) {
    cmd.AddValue("trust_delta_r",      "Trust reward Δ_r",                   TRUST_DELTA_R);
    cmd.AddValue("trust_delta_p",      "Trust penalty Δ_p (must be > Δ_r)",  TRUST_DELTA_P);
    cmd.AddValue("trust_t_min",        "Quarantine threshold T_min",          TRUST_T_MIN);
    cmd.AddValue("trust_t_min_ctrl",   "Controller revocation threshold",     TRUST_T_MIN_CTRL);
    cmd.AddValue("trust_delta_r_ctrl", "Controller reward Δ_r^ctrl",          TRUST_DELTA_R_CTRL);
    cmd.AddValue("trust_delta_p_ctrl", "Controller penalty Δ_p^ctrl",         TRUST_DELTA_P_CTRL);
    cmd.AddValue("t_sync",             "T_ref sync interval (s)",             T_SYNC_INTERVAL);
    cmd.AddValue("time_ref_f_bad",
                 "M9: number of Byzantine-compromised RSU clocks (eq:eps_ref sweep var)",
                 TIME_REF_F_BAD);
    cmd.AddValue("time_ref_delta_attack",
                 "M9: fixed clock offset (s) injected into compromised RSUs",
                 TIME_REF_DELTA_ATTACK);
    cmd.AddValue("batch_size",         "Packets per batch verify cycle B",    BATCH_SIZE);
    cmd.AddValue("witness_window",     "Witness observation window W (s)",    WITNESS_WINDOW);
    cmd.AddValue("witness_f",          "Witness BFT parameter f",             WITNESS_F);
    cmd.AddValue("vol_rate_thresh",    "Volume rate threshold ε_vol (pkt/s)", VOL_RATE_THRESH);
    cmd.AddValue("failover_bcast_base_ms",
                 "M5: ControllerRevoked broadcast base latency (ms)",
                 FAILOVER_BCAST_BASE_MS);
    cmd.AddValue("failover_bcast_per_zone_ms",
                 "M5: added broadcast latency per zone-distance unit (ms)",
                 FAILOVER_BCAST_PER_ZONE_MS);
    cmd.AddValue("disable_crypto",     "Disable DKG keygen + ML-DSA-87 sign/verify + STARK hop-proof "
                                       "(0=crypto ON [default], 1=crypto OFF). Speeds up runs that don't "
                                       "need crypto-derived metrics (trust score, S1/S2/S5-S8 detection) -- "
                                       "S3/S4 TCAM detection is unaffected either way since it never reads "
                                       "crypto state.", g_disable_crypto);

    // Per-signature (S1/S2/S5-S8) CLI overrides removed 2026-07-09: main.tex
    // specifies no such ablation anywhere (the only mode-level ablation for
    // this part of the architecture is AB1 — enable_lrad_obu/enable_lrad_rsu
    // below). Signatures now evaluate continuously whenever their owning
    // engine (OBU or RSU) is on, matching alg:lrad_obu/alg:lrad_rsu's own
    // OR-across-all-signatures composite and main.tex:4621's "all eight
    // attack variants operate simultaneously in every experiment."

    // Ablation gate flags (Phase 3) — all default true (full proposed behavior);
    // flip one to its ablated value per run to reproduce AB1/AB4/AB6/AB7/AB8/AB9/AB11.
    cmd.AddValue("g_disable_s1_s2",               "DIAGNOSTIC: disable S1+S2 only, keep S3-S8 active (isolate a signature's own FPR)", g_disable_s1_s2);
    cmd.AddValue("enable_lrad_obu",               "AB1: enable OBU rule engine (lrad_obu)",        enable_lrad_obu);
    cmd.AddValue("enable_lrad_rsu",               "AB1: enable RSU full-mode engine (lrad_rsu)",   enable_lrad_rsu);
    cmd.AddValue("enable_stark_delay",            "AB4: enable STARK timing proof π_delay",        enable_stark_delay);
    cmd.AddValue("enable_stark_hop",              "AB4: enable STARK hop-legitimacy proof π_hop",  enable_stark_hop);
    cmd.AddValue("enable_witness_mechanism",      "AB6: enable witness alert/BFT mechanism",       enable_witness_mechanism);
    cmd.AddValue("enable_quarantine",             "AB7: enable trust updates + SC.Quarantine",     enable_quarantine);
    cmd.AddValue("enable_endorsement_requirement","AB8: require f+1 RSU FlowMod endorsement",      enable_endorsement_requirement);
    cmd.AddValue("enable_controller_failover",    "AB9: enable controller trust/revoke/failover",  enable_controller_failover);
    cmd.AddValue("enable_key_rotation",           "AB11: rotate ZKP keys on RSU revocation",       enable_key_rotation);
    cmd.AddValue("enable_lstm_inference",         "sec:fed_lstm: live in-sim LSTM inference "
                                                   "(needs lstm_weights_cpp.bin already exported)", enable_lstm_inference);
}

#endif // CRYPTO_LAYER_H
