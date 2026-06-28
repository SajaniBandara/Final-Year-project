#ifndef BLOCKCHAIN_SIM_H
#define BLOCKCHAIN_SIM_H

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
    return true;
}

// C_P = BC.Commit(H(FlowMod) ‖ {ε_j}^{f+1} ‖ ts_commit) per eq:endorsed_commit.
// Returns false → S1 detection signal: f+1 endorsements not met.
inline bool bc_commit_flowmod(FlowModEndorsement& e) {
    uint32_t f_plus_1 = (N_RSUs / 3) + 1;
    if ((uint32_t)e.endorsing_rsus.size() < f_plus_1) {
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
                     g_node_keys[rsu_idx].sk) != OQS_SUCCESS) return;

    BlockchainCommit entry;
    entry.timestamp = ts; entry.num_endorsements = 1; entry.tier = 0;
    sha3_512_hash(rsu_sig, rsu_sig_len, entry.commit_hash);
    g_rsu_chain.push_back(entry);
}

// DKG ceremony/rotation commit per eq:vk_commit → global chain (tier=1).
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
}

inline void bc_anchor_recurring() {
    bc_anchor_to_global();
    ns3::Simulator::Schedule(ns3::Seconds(T_SYNC_INTERVAL), &bc_anchor_recurring);
}

// ── Federated LSTM model hash verification stubs (Gap 7) ─────────────────────
// eq:bc_model_verify: SC.VerifyModelHash(H(W_local^k), CommittedHash^k)

std::map<uint32_t, std::array<uint8_t,64>> g_committed_model_hashes;

inline void bc_commit_model_hash(uint32_t rsu_idx, const uint8_t* model_hash_64) {
    std::array<uint8_t,64> arr;
    memcpy(arr.data(), model_hash_64, 64);
    g_committed_model_hashes[rsu_idx] = arr;
    bc_write_event(N_Vehicles + (rsu_idx < N_RSUs ? rsu_idx : 0),
                   5 /*model_hash_commit*/, rsu_idx,
                   ns3::Simulator::Now().GetSeconds());
}

inline bool bc_verify_model_hash(uint32_t rsu_idx, const uint8_t* submitted_hash_64) {
    auto it = g_committed_model_hashes.find(rsu_idx);
    if (it == g_committed_model_hashes.end()) return false;
    return memcmp(it->second.data(), submitted_hash_64, 64) == 0;
}

#endif // BLOCKCHAIN_SIM_H
