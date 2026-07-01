#ifndef BLOCKCHAIN_SIM_H
#define BLOCKCHAIN_SIM_H

#include <fstream>
#include <sstream>
#include <iomanip>

struct BlockchainCommit {
    uint8_t  commit_hash[64];
    double   timestamp;
    uint32_t num_endorsements;
    uint32_t tier; // 0 = RSU-chain, 1 = global anchor
};

std::vector<BlockchainCommit> g_rsu_chain;
std::vector<BlockchainCommit> g_global_chain;

// Pre-installation audit log — called IMMEDIATELY on FlowMod receipt, BEFORE endorsement.
// Corrected order per eq:flowmod_log (Gap 4 fix): receipt → log → endorse → commit.
inline bool bc_log_flowmod(const FlowModEndorsement& e, uint32_t /*rsu_idx*/) {
    BlockchainCommit entry;
    entry.timestamp        = ns3::Simulator::Now().GetSeconds();
    entry.num_endorsements = (uint32_t)e.endorsing_rsus.size();
    entry.tier             = 0;
    uint8_t buf[72];
    memcpy(buf,    e.flowmod_hash, 64);
    memcpy(buf+64, &entry.timestamp, 8);
    if (!sha3_512_hash(buf, 72, entry.commit_hash)) return false;
    g_rsu_chain.push_back(entry);
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-LOG] FlowMod pre-install logged"
                  << " endorsers=" << entry.num_endorsements
                  << " flowmod_hash[0..3]=" << _hex4(e.flowmod_hash)
                  << " commit_hash[0..3]=" << _hex4(entry.commit_hash)
                  << " rsu_chain_len=" << g_rsu_chain.size() << "\n";
    return true;
}

// C_P = BC.Commit(H(FlowMod) ‖ {ε_j}^{f+1} ‖ ts_commit) per eq:endorsed_commit.
// Returns false → S1 detection signal: f+1 endorsements not met.
inline bool bc_commit_flowmod(FlowModEndorsement& e) {
    uint32_t f_plus_1 = (N_RSUs / 3) + 1;
    if ((uint32_t)e.endorsing_rsus.size() < f_plus_1) {
        // Unconditional: BFT rejection is a detection event
        std::cerr << "[BC-REJECT] FlowMod rejected: endorsers="
                  << e.endorsing_rsus.size() << " < required f+1=" << f_plus_1
                  << " → S1 detection signal\n";
        NS_LOG_WARN("[BC] FlowMod rejected: " << e.endorsing_rsus.size()
            << " < required " << f_plus_1 << " — S1 signal");
        return false;
    }
    BlockchainCommit commit;
    commit.timestamp        = ns3::Simulator::Now().GetSeconds();
    commit.num_endorsements = (uint32_t)e.endorsing_rsus.size();
    commit.tier             = 0;
    uint8_t buf[136];
    memcpy(buf,     e.flowmod_hash,     64);
    memcpy(buf+64,  e.endorsement_hash, 64);
    memcpy(buf+128, &commit.timestamp,   8);
    if (!sha3_512_hash(buf, 136, commit.commit_hash)) return false;
    g_rsu_chain.push_back(commit);
    e.committed   = true;
    e.commit_time = commit.timestamp;
    // Unconditional: successful blockchain commit is important
    std::cout << "[BC-COMMIT] FlowMod COMMITTED: endorsers="
              << commit.num_endorsements << "/" << f_plus_1
              << " commit_hash[0..3]=" << _hex4(commit.commit_hash)
              << " rsu_chain_len=" << g_rsu_chain.size() << "\n";
    return true;
}

// RSU-initiated write with real ML-DSA-87 signature per eq:rsu_write.
// Controller MUST NOT call this function.
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

    uint8_t rsu_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  rsu_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, rsu_sig, &rsu_sig_len,
                     content_hash, 64,
                     g_node_keys[rsu_idx].sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] bc_write_event: OQS_SIG_sign failed"
                  << " rsu=" << rsu_idx << " event=" << event_type
                  << " node=" << node << "\n";
        return;
    }

    BlockchainCommit entry;
    entry.timestamp = ts; entry.num_endorsements = 1; entry.tier = 0;
    sha3_512_hash(rsu_sig, rsu_sig_len, entry.commit_hash);
    g_rsu_chain.push_back(entry);

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-WRITE] rsu=" << rsu_idx
                  << " event=" << event_type
                  << " (2=da,3=T_ref,4=nfa,5=model)"
                  << " node=" << node
                  << " t=" << ts
                  << " sig_len=" << rsu_sig_len  // expected 4627
                  << " sig[0..3]=" << _hex4(rsu_sig)
                  << " commit_hash[0..3]=" << _hex4(entry.commit_hash)
                  << " rsu_chain_len=" << g_rsu_chain.size() << "\n";
}

// ── DKG ceremony/rotation commit (eq:vk_commit, eq:vk_commit_rotated) ────────
// Writes to bc_dkg_log.csv → bridge tailer → CommitDKG chaincode on Fabric.
// vk_zkp = SHA3-512(Com_0 ‖ … ‖ Com_{n_rsus-1}) — already the compact hash.
// Also pushes to the in-memory global chain (tier=1).

static std::ofstream g_bc_dkg_csv;
static bool          g_bc_dkg_open  = false;
static int           g_dkg_round    = 0; // incremented per ceremony/rotation

static void bc_open_dkg_csv() {
    if (g_bc_dkg_open) return;
    const std::string dir =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
    g_bc_dkg_csv.open(dir + "bc_dkg_log.csv", std::ios::trunc);
    if (g_bc_dkg_csv.is_open())
        g_bc_dkg_csv << "rsu_id,round,vk_zkp,n_rsus,timestamp_ms\n";
    g_bc_dkg_open = true;
}

inline void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][64],
                           uint32_t n_rsus, double ts_setup) {
    int round = ++g_dkg_round;

    // vk_zkp is already H(all per-RSU commitments) — hex-encode for CSV
    std::ostringstream vk_hex;
    for (int i = 0; i < 64; ++i)
        vk_hex << std::hex << std::setw(2) << std::setfill('0') << (int)vk_zkp[i];

    long long ts_ms = (long long)(ts_setup * 1000.0);

    // RSU 0 (first RSU, node_id = N_Vehicles) is the submitting identity
    uint32_t reporting_rsu = N_Vehicles;

    bc_open_dkg_csv();
    if (g_bc_dkg_csv.is_open()) {
        g_bc_dkg_csv
            << reporting_rsu   << ","
            << round           << ","
            << vk_hex.str()    << ","
            << n_rsus          << ","
            << ts_ms           << "\n";
        g_bc_dkg_csv.flush();
    }

    // Keep in-memory global chain (tier=1) for g_global_chain metric
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

    std::cout << "[DKG-BC] vk_ZKP committed to global chain (Fabric round=" << round << ")"
              << " t=" << ts_setup
              << " n_rsus=" << n_rsus
              << " vk_zkp[0..3]=" << _hex4(vk_zkp)
              << " commit_hash[0..3]=" << _hex4(entry.commit_hash)
              << " global_chain_len=" << g_global_chain.size() << "\n";
    NS_LOG_INFO("[DKG-BC] vk_ZKP committed to global chain at t=" << ts_setup);
}

// Query whether a committed (f+1 endorsed) FlowMod exists for flow_key.
// Used for S3/S5 detection (eq:unauth_flowmod).
inline bool bc_query_flowmod(uint32_t flow_key) {
    auto it = g_flowmod_endorsements.find(flow_key);
    return (it != g_flowmod_endorsements.end()) && it->second.committed;
}

// Periodic global anchor commit per eq:anchor_hash.
// H_anchor^{(r)} = H(H_root_RSU ‖ ts_anchor ‖ H_prev_global)
inline void bc_anchor_to_global() {
    if (g_rsu_chain.empty()) return;
    BlockchainCommit anchor;
    anchor.timestamp = ns3::Simulator::Now().GetSeconds();
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
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-ANCHOR] Global anchor committed"
                  << " rsu_chain_len=" << g_rsu_chain.size()
                  << " global_chain_len=" << g_global_chain.size()
                  << " t=" << anchor.timestamp
                  << " anchor_hash[0..3]=" << _hex4(anchor.commit_hash) << "\n";
}

inline void bc_anchor_recurring() {
    bc_anchor_to_global();
    ns3::Simulator::Schedule(ns3::Seconds(T_SYNC_INTERVAL), &bc_anchor_recurring);
}

// ── Federated LSTM model hash verification stubs (Gap 7) ─────────────────────
// eq:bc_model_verify: SC.VerifyModelHash(H(W_local^k), CommittedHash^k)
//
// bc_commit_model_hash() writes to bc_model_log.csv in addition to the
// in-memory chain. The Node.js bridge tails the CSV and calls
// CommitModelHash(round, hash, committedAt) on Fabric (model.go, Eq 3.39).

std::map<uint32_t, std::array<uint8_t,64>> g_committed_model_hashes;

// Per-RSU training round counter — incremented on every commit call.
static std::map<uint32_t, int> g_model_round;

static std::ofstream g_bc_model_csv;
static bool          g_bc_model_open = false;

static void bc_open_model_csv() {
    if (g_bc_model_open) return;
    const std::string dir =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
    g_bc_model_csv.open(dir + "bc_model_log.csv", std::ios::trunc);
    if (g_bc_model_csv.is_open())
        g_bc_model_csv << "rsu_id,round,model_hash,timestamp_ms\n";
    g_bc_model_open = true;
}

inline void bc_commit_model_hash(uint32_t rsu_idx, const uint8_t* model_hash_64) {
    std::array<uint8_t,64> arr;
    memcpy(arr.data(), model_hash_64, 64);
    g_committed_model_hashes[rsu_idx] = arr;

    // Advance round counter for this RSU (chaincode key: model:{rsuId}:{round})
    int round = ++g_model_round[rsu_idx];

    // Hex-encode 64-byte model hash for CSV/chaincode transport
    std::ostringstream hash_hex;
    for (int i = 0; i < 64; ++i)
        hash_hex << std::hex << std::setw(2) << std::setfill('0') << (int)model_hash_64[i];

    double ts = ns3::Simulator::Now().GetSeconds();
    long long ts_ms = (long long)(ts * 1000.0);

    // Write CSV row — bridge tails this and calls CommitModelHash on Fabric
    bc_open_model_csv();
    if (g_bc_model_csv.is_open()) {
        g_bc_model_csv
            << rsu_idx         << ","
            << round           << ","
            << hash_hex.str()  << ","
            << ts_ms           << "\n";
        g_bc_model_csv.flush();
    }

    // Keep in-memory chain for rsu_chain_len metric
    bc_write_event(N_Vehicles + (rsu_idx < N_RSUs ? rsu_idx : 0),
                   5 /*model_hash_commit*/, rsu_idx, ts);

    std::cout << "[BC-MODEL] RSU " << rsu_idx
              << " round=" << round
              << " model hash committed"
              << " hash[0..3]=" << _hex4(model_hash_64)
              << " t=" << ts << "s\n";
}

inline bool bc_verify_model_hash(uint32_t rsu_idx, const uint8_t* submitted_hash_64) {
    auto it = g_committed_model_hashes.find(rsu_idx);
    if (it == g_committed_model_hashes.end()) return false;
    return memcmp(it->second.data(), submitted_hash_64, 64) == 0;
}

// ── bc_detection_log.csv writer ───────────────────────────────────────────────
// Opened lazily; flushed after every row so the Node.js bridge tailer sees
// each detection event in real time.
static std::ofstream g_bc_detection_csv;
static bool          g_bc_detection_open = false;

static void bc_open_detection_csv() {
    if (g_bc_detection_open) return;
    const std::string dir =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
    g_bc_detection_csv.open(dir + "bc_detection_log.csv", std::ios::trunc);
    if (g_bc_detection_csv.is_open())
        g_bc_detection_csv << "rsu_id,suspect_node,signal_idx,timestamp_ms,rsu_sig\n";
    g_bc_detection_open = true;
}

// BC.Write(rk, vs || Si || ts || MLDSA.Sign(sk_rk, H(vs||Si||ts))) — eq:rsu_write
//
// Connects to the LogDetection chaincode via bc_detection_log.csv → bridge tailer.
// signal_idx must be in [1,8] corresponding to S1-S8 (enforced by the chaincode).
// Call once per fired signal per detection event so each is attributable to a
// specific signature (the chaincode key is detect:{suspectNode}:{timestamp_ms}).
//
// Also appends to the in-memory g_rsu_chain so rsu_chain_len stays accurate.
// The original bc_write_event() is kept for internal simulation events
// (event_type=2 da, 3 T_ref, 4 nfa, 5 model) that do not map to S1-S8.
inline void bc_write_detection_event(uint32_t rsu_idx, uint32_t suspect_node,
                                      int signal_idx, double ts)
{
    if (rsu_idx >= (uint32_t)total_size) return;
    if (signal_idx < 1 || signal_idx > 8) return; // chaincode enforces this too
    if (!g_node_keys[rsu_idx].keys_generated) mldsa87_keygen(rsu_idx);
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    // H(vs || Si || ts) per eq:rsu_write
    uint8_t buf[16];
    memcpy(buf,    &suspect_node, 4);
    memcpy(buf+4,  &signal_idx,   4);
    memcpy(buf+8,  &ts,           8);
    uint8_t content_hash[64];
    sha3_512_hash(buf, 16, content_hash);

    uint8_t rsu_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  rsu_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, rsu_sig, &rsu_sig_len,
                     content_hash, 64,
                     g_node_keys[rsu_idx].sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] bc_write_detection_event: OQS_SIG_sign failed"
                  << " rsu=" << rsu_idx << " S" << signal_idx
                  << " suspect=" << suspect_node << "\n";
        return;
    }

    // Hex-encode signature for CSV transport (bridge re-verifies on Fabric side)
    std::ostringstream sig_hex;
    for (size_t i = 0; i < rsu_sig_len; ++i)
        sig_hex << std::hex << std::setw(2) << std::setfill('0') << (int)rsu_sig[i];

    // Write CSV row — bridge tails this and calls LogDetection on Fabric
    bc_open_detection_csv();
    long long ts_ms = (long long)(ts * 1000.0);
    if (g_bc_detection_csv.is_open()) {
        g_bc_detection_csv
            << rsu_idx          << ","
            << suspect_node     << ","
            << signal_idx       << ","
            << ts_ms            << ","
            << sig_hex.str()    << "\n";
        g_bc_detection_csv.flush();
    }

    // Keep in-memory chain for rsu_chain_len metric
    BlockchainCommit entry;
    entry.timestamp        = ts;
    entry.num_endorsements = 1;
    entry.tier             = 0;
    sha3_512_hash(rsu_sig, rsu_sig_len, entry.commit_hash);
    g_rsu_chain.push_back(entry);

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-DETECT] rsu=" << rsu_idx
                  << " S" << signal_idx
                  << " suspect=" << suspect_node
                  << " t=" << ts
                  << " sig[0..3]=" << _hex4(rsu_sig)
                  << " rsu_chain_len=" << g_rsu_chain.size() << "\n";
}

#endif // BLOCKCHAIN_SIM_H
