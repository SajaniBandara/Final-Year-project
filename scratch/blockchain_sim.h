#ifndef BLOCKCHAIN_SIM_H
#define BLOCKCHAIN_SIM_H

// blockchain_sim.h — thin Fabric-bridge stub (replaces in-memory simulation).
//
// NS-3 now writes CSV files that the Node.js bridge tails in real time to call
// mobiguard-cc chaincode on Hyperledger Fabric. Only three synchronous functions
// remain here (bc_log_flowmod, bc_commit_flowmod, bc_query_flowmod). All CSV
// writers live in bc_blockchain_helper.h, which is included after this file in
// routing.cc (via tcam_attack_helper.h). Shared state must be defined HERE so
// bc_blockchain_helper.h can reference it without redefinition.

#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <array>
#include <map>

// SHA3-512 output size in bytes. Single authoritative definition — all buffer
// sizes across blockchain_sim.h and bc_blockchain_helper.h derive from this.
static constexpr size_t SHA3_512_BYTES = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Shared state — defined once here, used by bc_blockchain_helper.h functions.
// ─────────────────────────────────────────────────────────────────────────────

// Shadow list of every committed RSU-chain event hash (FlowMod + detection +
// model). Fed by bc_commit_flowmod (here) and by bc_write_detection_event /
// bc_commit_model_hash (bc_blockchain_helper.h). Used as Merkle leaf input
// in bc_anchor_to_global().
static std::vector<std::array<uint8_t,SHA3_512_BYTES>> g_rsu_commit_hashes;

// Count of global-chain commits (DKG + anchor).
// Incremented by bc_commit_dkg() and bc_anchor_to_global() in bc_blockchain_helper.h.
static int g_bc_global_commit_count = 0;

// Per-RSU committed model hash store for synchronous bc_verify_model_hash().
static std::map<uint32_t, std::array<uint8_t,SHA3_512_BYTES>> g_committed_model_hashes;
static std::map<uint32_t, int> g_model_round;

// CSV file handles — opened lazily by bc_open_*_csv() in bc_blockchain_helper.h.
static std::ofstream g_bc_detection_csv;
static bool          g_bc_detection_open = false;
static std::ofstream g_bc_model_csv;
static bool          g_bc_model_open     = false;
static std::ofstream g_bc_dkg_csv;
static bool          g_bc_dkg_open       = false;
static std::ofstream g_bc_anchor_csv;
static bool          g_bc_anchor_open    = false;
static int           g_dkg_round         = 0;
static int           g_anchor_seq        = 0;
static uint8_t       g_prev_anchor_hash[SHA3_512_BYTES] = {};

static const std::string BC_RESULTS_DIR =
    "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";

// Forward declaration — defined in bc_blockchain_helper.h (included later via
// tcam_attack_helper.h). Needed because routing.cc schedules bc_anchor_recurring
// at line ~114905, before bc_blockchain_helper.h is included at ~120617.
void bc_anchor_recurring();

// ─────────────────────────────────────────────────────────────────────────────
// bc_log_flowmod() — pre-install audit log.
// No-op in Fabric mode: the bridge's flowmod tailer handles LogFlowMod via
// bc_flowmod_log.csv. Return true unconditionally.
// ─────────────────────────────────────────────────────────────────────────────
inline bool bc_log_flowmod(const FlowModEndorsement& /*e*/, uint32_t /*rsu_idx*/) {
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_commit_flowmod() — BFT endorsement check (eq:endorsed_commit).
// Returns false → S1 detection signal (f+1 endorsements not met).
// On success, appends the FlowMod commit hash to g_rsu_commit_hashes so it
// contributes to the next periodic Merkle root (eq:anchor_hash).
// ─────────────────────────────────────────────────────────────────────────────
inline bool bc_commit_flowmod(FlowModEndorsement& e) {
    uint32_t f_plus_1 = (N_RSUs / 3) + 1;
    if ((uint32_t)e.endorsing_rsus.size() < f_plus_1) {
        std::cerr << "[BC-REJECT] FlowMod rejected: endorsers="
                  << e.endorsing_rsus.size() << " < required f+1=" << f_plus_1
                  << " → S1 detection signal\n";
        NS_LOG_WARN("[BC] FlowMod rejected: " << e.endorsing_rsus.size()
            << " < required " << f_plus_1 << " — S1 signal");
        return false;
    }
    double ts = ns3::Simulator::Now().GetSeconds();
    // H(flowmod_hash || endorsement_hash || ts_commit)
    uint8_t buf[SHA3_512_BYTES * 2 + sizeof(double)];
    memcpy(buf,                    e.flowmod_hash,     SHA3_512_BYTES);
    memcpy(buf + SHA3_512_BYTES,   e.endorsement_hash, SHA3_512_BYTES);
    memcpy(buf + SHA3_512_BYTES*2, &ts,                sizeof(double));
    std::array<uint8_t,SHA3_512_BYTES> commit_hash;
    if (!sha3_512_hash(buf, sizeof(buf), commit_hash.data())) return false;
    g_rsu_commit_hashes.push_back(commit_hash);
    e.committed   = true;
    e.commit_time = ts;
    std::cout << "[BC-COMMIT] FlowMod COMMITTED: endorsers="
              << e.endorsing_rsus.size() << "/" << f_plus_1
              << " commit_hash[0..3]=" << _hex4(commit_hash.data())
              << " rsu_chain_len=" << g_rsu_commit_hashes.size() << "\n";
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_query_flowmod() — check if a FlowMod was committed (f+1 endorsed).
// Used for S3/S5 detection (eq:unauth_flowmod).
// ─────────────────────────────────────────────────────────────────────────────
inline bool bc_query_flowmod(uint32_t flow_key) {
    auto it = g_flowmod_endorsements.find(flow_key);
    return (it != g_flowmod_endorsements.end()) && it->second.committed;
}

#endif // BLOCKCHAIN_SIM_H
