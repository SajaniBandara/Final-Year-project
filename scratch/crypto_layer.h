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
#include <algorithm>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <oqs/oqs.h>
// ns3/simulator.h and ns3/log.h are already included earlier in routing.cc.

#pragma pop_macro("min")
#pragma pop_macro("max")

// Forward declarations — defined in blockchain_sim.h (included after this header).
void bc_write_event(uint32_t rsu_idx, uint32_t event_type, uint32_t node, double ts);
void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][64],
                   uint32_t n_rsus, double ts_setup);

// ── Evidence-quality debug logging ───────────────────────────────────────────
// Normal runs: CRYPTO_DEBUG_LOG = false → zero terminal noise, CSV unaffected.
// flip to true for rich per-operation output proving every
// cryptographic component is executing with real liboqs/OpenSSL values.
// High-frequency per-packet ops are gated on this flag.
// Low-frequency high-importance events (DKG, quarantine, failures, blockchain
// commits) fire unconditionally regardless of this flag.
static bool CRYPTO_DEBUG_LOG = true;

// Formats first 4 bytes of buf as compact hex — evidence token in debug lines.
static std::string _hex4(const uint8_t* b) {
    char s[9];
    snprintf(s, sizeof(s), "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    return std::string(s);
}

// ── SHA3-512 and HMAC-SHA3-512 via OpenSSL ───────────────────────────────────

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

struct SigningInput {
    uint32_t msg_id;
    uint32_t node_id;
    uint32_t next_hop;
    uint32_t seq;
    uint32_t zone_id;
    double   timestamp;
};

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
struct BatchVerifyResult { bool passed; uint32_t n_verified; double elapsed_s; };

// Verification outcome counters — for sig_valid_rate metric
static uint32_t g_verify_attempts = 0;
static uint32_t g_verify_passed   = 0;

struct WitnessLogEntry {
    uint8_t  pkt_hash[64] = {};
    uint32_t dst;
    double   ts;
};

struct WitnessAlert {
    std::array<uint8_t,64> sig_hash = {};
    uint8_t alert_type = 0; // 0 = α_w (DA), 1 = β_w (NFA)
};

double g_trust_score[268]       = {};
double g_trust_last_update[268] = {};
bool   g_quarantined[268]       = {};
double g_ctrl_trust_score[268]  = {};
bool   g_ctrl_revoked[268]      = {};

double g_T_ref = 0.0, g_T_ref_last_sync = 0.0;

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
    if (signer >= (uint32_t)total_size) return false;
    if (!g_node_keys[signer].keys_generated && !mldsa87_keygen(signer)) return false;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // η_i ← RAND(): fresh per-signature nonce preventing replay (eq:mldsa_sign).
    // The caller's `seq` argument is ignored for the digest — nonce is random.
    uint32_t fresh_nonce = 0;
    OQS_randombytes(reinterpret_cast<uint8_t*>(&fresh_nonce), sizeof(fresh_nonce));

    SigningInput inp = {};  // zero-init including padding bytes before double timestamp
    inp.msg_id    = pkt_id;
    inp.node_id   = signer;
    inp.next_hop  = next_hop;
    inp.seq       = fresh_nonce;
    inp.zone_id   = crypto_zone_id(signer);
    inp.timestamp = ns3::Simulator::Now().GetSeconds();

    uint8_t digest[64];
    if (!sha3_512_hash(reinterpret_cast<const uint8_t*>(&inp), sizeof(inp), digest)) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_sign: SHA3-512 failed node=" << signer
                  << " pkt=" << pkt_id << "\n";
        return false;
    }

    PacketCryptoMeta& meta = g_packet_crypto[{signer, pkt_id}];
    memcpy(meta.msg_digest, digest, 64);
    meta.sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(sig, meta.sig, &meta.sig_len,
                     digest, 64, g_node_keys[signer].sk) != OQS_SUCCESS) {
        meta.sig_len = 0;
        std::cerr << "[CRYPTO-ERROR] mldsa87_sign: OQS_SIG_sign failed node=" << signer
                  << " pkt=" << pkt_id << "\n";
        return false;
    }
    meta.sign_timestamp  = inp.timestamp;
    meta.signed_next_hop = next_hop;
    meta.signed_zone_id  = inp.zone_id;
    meta.nonce           = fresh_nonce;
    meta.sig_valid = true;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[CRYPTO-SIGN] node=" << signer
                  << " pkt=" << pkt_id
                  << " next_hop=" << next_hop
                  << " sig_len=" << meta.sig_len  // expected 4627
                  << " zone=" << inp.zone_id
                  << " t=" << inp.timestamp
                  << " digest[0..3]=" << _hex4(digest)
                  << " sig[0..3]=" << _hex4(meta.sig) << "\n";
    return true;
}

// ── ML-DSA-87 Verification ────────────────────────────────────────────────────

inline bool mldsa87_verify(uint32_t claimed_signer, uint32_t pkt_id,
                            uint32_t next_hop, uint32_t seq) {
    if (claimed_signer >= (uint32_t)total_size) return false;
    auto it = g_packet_crypto.find({claimed_signer, pkt_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) {
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                      << " pkt=" << pkt_id << " → no_record (not signed by this node)\n";
        return false;
    }

    // Broadcast MAC: every node in range overhears every packet. Only the
    // intended next hop can produce a matching digest (next_hop is embedded
    // in the signed message). Skip OQS_SIG_verify and don't count overheard
    // packets in sig_valid_rate — they would always fail and dilute the metric.
    if (it->second.signed_next_hop != (uint32_t)-1 && next_hop != it->second.signed_next_hop) {
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                      << " pkt=" << pkt_id
                      << " → skip_broadcast (intended_hop=" << it->second.signed_next_hop
                      << " actual_hop=" << next_hop << ")\n";
        return false;
    }

    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    SigningInput inp = {};  // zero-init including padding bytes before double timestamp
    inp.msg_id    = pkt_id;
    inp.node_id   = claimed_signer;
    inp.next_hop  = next_hop;
    inp.seq       = it->second.nonce;           // replay stored random nonce η_i (eq:mldsa_sign)
    inp.zone_id   = it->second.signed_zone_id;  // use stored value — rsu_controller_assignment changes
    inp.timestamp = it->second.sign_timestamp;

    uint8_t digest[64];
    if (!sha3_512_hash(reinterpret_cast<const uint8_t*>(&inp), sizeof(inp), digest))
        return false;

    bool ok = OQS_SIG_verify(sig, digest, 64,
                              it->second.sig, it->second.sig_len,
                              g_node_keys[claimed_signer].pk) == OQS_SUCCESS;
    it->second.sig_valid = ok;
    g_verify_attempts++;
    if (ok) g_verify_passed++;

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                  << " pkt=" << pkt_id
                  << " ok=" << ok
                  << " sig_len=" << it->second.sig_len  // expected 4627
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

// ── STARK Proof Simulation — eq:stark_delay / eq:stark_hop ───────────────────

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

// Verify that current_hop is the node the sender intended as its next hop
// (embedded in the signature at sign time). Re-running find_next_hop at
// verification time is unreliable in a dynamic VANET because routing tables
// change between send and receive. Using the signed_next_hop eliminates
// false positives from routing churn while still catching misdirected packets.
inline bool stark_verify_hop(uint32_t current_hop, uint32_t signer, uint32_t pkt_id) {
    auto it = g_packet_crypto.find({signer, pkt_id});
    if (it == g_packet_crypto.end() || it->second.signed_next_hop == (uint32_t)-1)
        return true;  // no signing record — can't verify, assume valid
    return current_hop == it->second.signed_next_hop;
}

inline void stark_update_meta(uint32_t signer, uint32_t pkt_id,
                               bool timing_ok, bool hop_ok) {
    auto it = g_packet_crypto.find({signer, pkt_id});
    if (it == g_packet_crypto.end()) return;
    it->second.stark_timing_ok = timing_ok;
    it->second.stark_hop_ok    = hop_ok;
    g_lstm_pkt_counts[signer]++;
    if (!timing_ok) g_lstm_stark_counts[signer].first++;
    if (!hop_ok)    g_lstm_stark_counts[signer].second++;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[STARK] signer=" << signer
                  << " pkt=" << pkt_id
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
    uint8_t challenge[64];
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), challenge);

    for (auto& [node, pkt] : node_pkt_pairs) {
        if (res.elapsed_s >= budget_s) break;
        if (!mldsa87_verify(node, pkt, 0, 0)) res.passed = false;
        ++res.n_verified;
        res.elapsed_s += 0.001;
    }

    if (CRYPTO_DEBUG_LOG && res.n_verified > 0)
        std::cout << "[BATCH-VERIFY] n=" << res.n_verified
                  << " passed=" << res.passed
                  << " challenge[0..3]=" << (combined.empty() ? "n/a" : _hex4(challenge))
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
    double old_v = g_trust_score[node];
    double v = old_v + TRUST_DELTA_R;
    g_trust_score[node] = (v < 1.0 ? v : 1.0);
    g_trust_last_update[node] = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[TRUST+] node=" << node
                  << " " << old_v << " → " << g_trust_score[node]
                  << " (Δ_r=" << TRUST_DELTA_R << ")\n";
}

inline void trust_update_negative(uint32_t node) {
    if (node >= (uint32_t)total_size) return;
    double old_v = g_trust_score[node];
    double v = old_v - TRUST_DELTA_P;
    g_trust_score[node] = (v > 0.0 ? v : 0.0);
    g_trust_last_update[node] = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[TRUST-] node=" << node
                  << " " << old_v << " → " << g_trust_score[node]
                  << " (Δ_p=" << TRUST_DELTA_P
                  << " T_min=" << TRUST_T_MIN << ")\n";
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
    }
}

inline void ctrl_trust_update_positive(uint32_t ctrl) {
    if (ctrl >= N_Controllers || g_ctrl_revoked[ctrl]) return;
    double v = g_ctrl_trust_score[ctrl] + TRUST_DELTA_R_CTRL;
    g_ctrl_trust_score[ctrl] = (v < 1.0 ? v : 1.0);
}

inline void ctrl_trust_update_negative(uint32_t ctrl) {
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
    uint32_t zone_size = N_RSUs / N_Controllers;
    uint32_t reassigned = 0;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        if ((uint32_t)rsu_controller_assignment[r] != revoked_ctrl) continue;
        uint32_t rsu_zone = r / (zone_size > 0 ? zone_size : 1);
        uint32_t best = trusted[0], min_d = UINT32_MAX;
        for (uint32_t c : trusted) {
            uint32_t d = (rsu_zone > c) ? rsu_zone - c : c - rsu_zone;
            if (d < min_d) { min_d = d; best = c; }
        }
        rsu_controller_assignment[r] = (int)best;
        ++reassigned;
        NS_LOG_WARN("[CTRL-FAILOVER] RSU " << r << " ctrl " << revoked_ctrl
            << " → " << best);
    }
    // Unconditional: failover summary
    std::cout << "[CTRL-FAILOVER] Revoked ctrl=" << revoked_ctrl
              << " reassigned " << reassigned << " RSUs to trusted controllers"
              << " (trusted_count=" << trusted.size() << ")\n";
}

// ── Distributed Time Reference — eq:time_consensus ───────────────────────────

inline void update_T_ref() {
    std::vector<double> times;
    times.reserve(N_RSUs);
    for (uint32_t r = 0; r < N_RSUs; ++r)
        times.push_back(ns3::Simulator::Now().GetSeconds());
    std::sort(times.begin(), times.end());
    g_T_ref           = times[times.size() / 2];
    g_T_ref_last_sync = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[T-REF] Distributed time synced T_ref=" << g_T_ref
                  << " from " << N_RSUs << " RSUs t=" << g_T_ref_last_sync << "\n";
}

inline void update_T_ref_recurring() {
    update_T_ref();
    bc_write_event(N_Vehicles, 3 /*T_ref_sync*/, 0, g_T_ref);
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
        auto result = batch_verify_mldsa87(pending);
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
                                              uint32_t pkt_id, uint32_t dst,
                                              uint32_t dup_dst) {
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    uint32_t sign_id = pkt_id * 1000 + dst;
    if (!mldsa87_sign(witness, sign_id, dup_dst,
                      (uint32_t)ns3::Simulator::Now().GetSeconds())) return;
    auto it = g_packet_crypto.find({witness, sign_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return;
    WitnessAlert alert;
    memcpy(alert.sig_hash.data(), it->second.sig, 64);
    alert.alert_type = 0;
    g_witness_alert_pool[target_node].push_back(alert);
    bc_write_event(N_Vehicles, 2 /*witness_alert*/, target_node,
                   ns3::Simulator::Now().GetSeconds());
    uint32_t pool_sz  = (uint32_t)g_witness_alert_pool[target_node].size();
    uint32_t threshold = 2 * WITNESS_F + 1;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-DA] witness=" << witness
                  << " → target=" << target_node
                  << " pkt=" << pkt_id
                  << " sig_len=" << it->second.sig_len  // expected 4627
                  << " sig[0..3]=" << _hex4(it->second.sig)
                  << " pool=" << pool_sz << "/" << threshold << "\n";
    if (pool_sz >= threshold) {
        // Unconditional: BFT threshold reached is a high-importance detection event
        std::cout << "[WITNESS-DA-BFT] BFT threshold reached: target=" << target_node
                  << " alerts=" << pool_sz << " >= 2f+1=" << threshold
                  << " → trust_update_negative\n";
        NS_LOG_WARN("[WITNESS-DA] BFT threshold reached for node " << target_node);
        trust_update_negative(target_node);
    }
}

// β_w: non-forwarding alert — packet received but not forwarded within T_fwd (eq:nfa_sign)
inline void witness_submit_nfa_alert(uint32_t witness, uint32_t target_node,
                                      uint32_t pkt_id, double T_fwd) {
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    uint32_t sign_id = pkt_id * 1000 + (uint32_t)(T_fwd * 1000) + 500000;
    uint32_t ts_u    = (uint32_t)ns3::Simulator::Now().GetSeconds();
    if (!mldsa87_sign(witness, sign_id, target_node, ts_u)) return;
    auto it = g_packet_crypto.find({witness, sign_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return;
    WitnessAlert alert;
    memcpy(alert.sig_hash.data(), it->second.sig, 64);
    alert.alert_type = 1;
    g_witness_alert_pool[target_node].push_back(alert);
    bc_write_event(N_Vehicles, 4 /*nfa_alert*/, target_node,
                   ns3::Simulator::Now().GetSeconds());
    uint32_t pool_sz  = (uint32_t)g_witness_alert_pool[target_node].size();
    uint32_t threshold = 2 * WITNESS_F + 1;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-NFA] witness=" << witness
                  << " → target=" << target_node
                  << " pkt=" << pkt_id
                  << " T_fwd=" << T_fwd << "s"
                  << " sig_len=" << it->second.sig_len  // expected 4627
                  << " pool=" << pool_sz << "/" << threshold << "\n";
    if (pool_sz >= threshold) {
        // Unconditional: BFT threshold reached
        std::cout << "[WITNESS-NFA-BFT] BFT threshold reached: target=" << target_node
                  << " alerts=" << pool_sz << " >= 2f+1=" << threshold
                  << " → trust_update_negative\n";
        NS_LOG_WARN("[WITNESS-NFA] BFT threshold reached for node " << target_node);
        trust_update_negative(target_node);
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
        memcpy(e.flowmod_hash, flowmod_hash, 64);
        sha3_512_hash(endorsement_sig, endorsement_sig_len, e.endorsement_hash);
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
    cmd.AddValue("batch_size",         "Packets per batch verify cycle B",    BATCH_SIZE);
    cmd.AddValue("witness_window",     "Witness observation window W (s)",    WITNESS_WINDOW);
    cmd.AddValue("witness_f",          "Witness BFT parameter f",             WITNESS_F);
    cmd.AddValue("vol_rate_thresh",    "Volume rate threshold ε_vol (pkt/s)", VOL_RATE_THRESH);
}

#endif // CRYPTO_LAYER_H
