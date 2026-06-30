#ifndef LRAD_H
#define LRAD_H

// =========================================================================
// lrad.h — MOBIGUARD Unified Detection Engine (LRAD-OBU + LRAD-RSU)
//
// Implements Algorithms alg:lrad_obu (thesis lines 1983–2027) and
// alg:lrad_rsu (thesis lines 2035–2086), the missing link between the
// post-quantum crypto layer (ML-DSA-87 + STARK) and the MOBIGUARD S1–S8
// signature detectors.
//
// Include order requirement:
//   Must appear AFTER:
//     s1_detection.h … s8_detection.h   (for s*_detect_packet() / s*_detect())
//     crypto_layer.h                     (for g_packet_crypto, hmac_sha3_512,
//                                          g_node_keys, trust_update_*)
//     crypto_event_log.h                 (for crypto_log_start/event)
//     blockchain_sim.h                   (for bc_write_event)
//     tcam_detection.h                   (for g_prev_rule_count,
//                                          g_prev_slowpath_hits, TCAM_HW_SIZE)
//     tcam_attack_helper.h               (for g_tcam_table, TcamEntry)
//     hf_attack_helper.h                 (for active/passive_hf_malicious_nodes)
//
// All symbols from routing.cc (N_Vehicles, N_RSUs, total_size, Flow_size,
// linklifetimeMatrix_dsrc, link_lifetime_threshold, is_safety_critical_flow,
// t_claimed_packet, g_slowpath_hit_count, etc.) are in scope because this
// header is included inside routing.cc after those declarations.
// =========================================================================

#include <map>
#include <vector>
#include <cstring>  // memcmp, memcpy
#include "ns3/simulator.h"

// =========================================================================
// Phase 1 — Structs and global state
// =========================================================================

// OBU-side detection results (alg:lrad_obu output).
struct LRADOBUFlags {
    bool flag_S1  = false;  // Selective delay CP: δp > δ̄ + k·σr ∧ HIGH priority
    bool flag_S2p = false;  // S2-partial: (t_now - ts_recv) > Δmax (HMAC path)
    bool flag_S3  = false;  // TCAM exhaustion CP: λ̂a > λthresh ∧ U_TCAM > U_thresh
    bool flag_S4  = false;  // TCAM exhaustion DP: λPI > λPI,thresh ∧ U_TCAM > U_thresh
    bool D_OBU    = false;  // flag_S1 ∨ flag_S2p ∨ flag_S3 ∨ flag_S4
};

// RSU-side detection results (alg:lrad_rsu output).
struct LRADRSUFlags {
    bool flag_S2f = false;  // S2-full: STARK delay proof fails
    bool flag_S5  = false;  // Active HF CP: ¬b_batch ∧ FlowMod ∉ BC.Query
    bool flag_S6  = false;  // Active HF DP: ¬b_batch ∧ DUP(msg_id, W)
    bool flag_S7  = false;  // Passive HF CP: vol > εvol ∧ b_hop=0
    bool flag_S8  = false;  // Passive HF DP: b_batch ∧ b_hop=0
    bool D_RSU    = false;  // flag_S2f ∨ flag_S5 ∨ flag_S6 ∨ flag_S7 ∨ flag_S8
};

// Carries OBU detection flags from vehicle to RSU via escalate_to_rsu().
struct EscalationEvent {
    uint32_t     vehicle_id;
    uint32_t     rsu_id;
    uint32_t     pkt_id;
    uint32_t     flow_id;
    double       t_escalate;
    LRADOBUFlags obu_flags;
};

// Per-RSU queue of pending escalation events.
// Drained by process_escalation_at_rsu() after a 1 ms simulated OBU→RSU delay.
static std::map<uint32_t, std::vector<EscalationEvent>> g_escalation_queue;

// Per-packet HMAC timestamp tag (for S2-partial at OBU).
// Populated at send time by lrad_hmac_tag_packet(); read at receive time
// by lrad_s2_partial_check().
struct HmacTag { uint8_t tag[64]; double ts; uint32_t nonce; bool valid; };
static std::map<std::pair<uint32_t,uint32_t>, HmacTag> g_hmac_tags;

// Per-RSU lightweight TCAM snapshot result (for S3/S4 in lrad_obu).
struct LRADTcamSnapshot { bool flag_s3; bool flag_s4; };

// Detection event counters — written to CSV in Phase 8.
static uint32_t g_d_obu_count      = 0;
static uint32_t g_d_rsu_count      = 0;
static uint32_t g_escalation_count = 0;

// =========================================================================
// lrad_reset_state():
// Clears all per-run LRAD state. Call from routing.cc's init sequence
// immediately after trust_init_all() — NOT inside trust_init_all() itself,
// because crypto_layer.h is compiled before lrad.h in the translation unit.
// =========================================================================
inline void lrad_reset_state()
{
    g_d_obu_count = g_d_rsu_count = g_escalation_count = 0;
    g_escalation_queue.clear();
    g_hmac_tags.clear();
}

// =========================================================================
// Forward declarations (function bodies added in subsequent phases).
// Declared here so lrad_obu() can reference escalate_to_rsu() and
// escalate_to_rsu() can reference process_escalation_at_rsu() and
// lrad_rsu() before those bodies appear in the file.
// =========================================================================
inline void    escalate_to_rsu(uint32_t vehicle, uint32_t pkt_id,
                                uint32_t fid, LRADOBUFlags obu_flags);
inline void    process_escalation_at_rsu(uint32_t rsu_id);
inline LRADRSUFlags lrad_rsu(uint32_t rsu, uint32_t prev_sender,
                              uint32_t pkt_id, uint32_t fid,
                              LRADOBUFlags obu_flags, double t_now);
inline void    btmm(uint32_t node, bool b_batch, bool b_hop, bool timing_ok);
inline bool    lrad_s2_partial_check(uint32_t vehicle,
                                     uint32_t pkt_id, double t_now);
inline LRADTcamSnapshot lrad_tcam_snapshot(uint32_t rsu_node_id);
inline uint32_t lookup_vehicle_associated_rsu_local_idx(uint32_t vehicle);

// =========================================================================
// Phase 2.5 — HMAC-SHA3-512 packet tagging (S2-partial at OBU)
//
// Implements eq:hmac_light:  τ_i = HMAC-SHA3-512(k_i, pkt_id ‖ ts_i ‖ η_i)
//
// lrad_hmac_tag_packet(): called at SEND time (OBU only), alongside
//   record_claimed_forward_timestamp(), to stamp the departure timestamp
//   under the vehicle's HMAC key.
//
// lrad_s2_partial_check(): called at RECEIVE time from lrad_obu().
//   Re-derives the HMAC tag from the stored key and compares; on success
//   checks (t_now - ts) > S2_DELTA_MAX — the S2-partial conjunction.
// =========================================================================

inline void lrad_hmac_tag_packet(uint32_t node, uint32_t pkt_id, uint32_t nonce)
{
    // OBU (vehicle) only — RSUs use STARK-based S2-full path.
    if (node >= (uint32_t)N_Vehicles) return;
    if (pkt_id >= (uint32_t)(Flow_size + 2)) return;
    if (!g_node_keys[node].keys_generated) return;

    double  ts = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[16];
    memcpy(msg,    &pkt_id, 4);
    memcpy(msg+4,  &ts,     8);
    memcpy(msg+12, &nonce,  4);

    HmacTag h{};
    h.ts    = ts;
    h.nonce = nonce;
    h.valid = hmac_sha3_512(g_node_keys[node].hmac_key, 64, msg, 16, h.tag);
    g_hmac_tags[{node, pkt_id}] = h;
}

// flag_S2p = HMAC.Verify(τ_i, k_i, msg) ∧ (t_now − ts_recv) > Δ_max
inline bool lrad_s2_partial_check(uint32_t vehicle, uint32_t pkt_id, double t_now)
{
    auto it = g_hmac_tags.find({vehicle, pkt_id});
    if (it == g_hmac_tags.end() || !it->second.valid) return false;
    if (!g_node_keys[vehicle].keys_generated) return false;

    // Recompute tag with stored (pkt_id, ts, nonce) and vehicle's HMAC key.
    uint8_t msg[16];
    memcpy(msg,    &pkt_id,           4);
    memcpy(msg+4,  &it->second.ts,    8);
    memcpy(msg+12, &it->second.nonce, 4);

    uint8_t recomputed[64];
    if (!hmac_sha3_512(g_node_keys[vehicle].hmac_key, 64, msg, 16, recomputed))
        return false;

    // Constant-time compare (memcmp is fine here — timing side-channel
    // is irrelevant inside a simulator with no real attacker observing it).
    if (memcmp(recomputed, it->second.tag, 64) != 0) return false;

    return (t_now - it->second.ts) > S2_DELTA_MAX;
}

// =========================================================================
// Phase 2.6 — Lightweight per-RSU TCAM snapshot (S3/S4 in lrad_obu)
//
// Read-only view over the same globals ComputeTcamDetection() owns.
// Does NOT advance g_prev_rule_count / g_prev_slowpath_hits — only the
// periodic cycle-level ComputeTcamDetection() does that. Calling this
// per-packet is therefore safe: no side-effects on the baseline counters.
// =========================================================================

inline LRADTcamSnapshot lrad_tcam_snapshot(uint32_t rsu_node_id)
{
    LRADTcamSnapshot snap{false, false};
    if (rsu_node_id >= 300) return snap;

    // TCAM utilisation: rules currently installed vs hardware capacity.
    double tcam_util = g_tcam_rule_count[rsu_node_id] / (double)TCAM_HW_SIZE;
    if (tcam_util < 0.0) tcam_util = 0.0;
    if (tcam_util > 1.0) tcam_util = 1.0;

    // Rules and slow-path hits accumulated since the last periodic baseline
    // update (g_prev_* advanced only by ComputeTcamDetection()).
    int rules_delta = g_tcam_rule_count[rsu_node_id] - g_prev_rule_count[rsu_node_id];
    int hits_delta  = g_slowpath_hit_count[rsu_node_id] - g_prev_slowpath_hits[rsu_node_id];
    double lambda_fm = (rules_delta > 0) ? (double)rules_delta : 0.0;
    double lambda_pi = (hits_delta  > 0) ? (double)hits_delta  : 0.0;

    // Count malicious entries injected by the attacker into this RSU's table.
    int malicious_count = 0;
    for (const auto& e : g_tcam_table)
        if (e.node_id == rsu_node_id && e.is_malicious) ++malicious_count;

    // Expected legitimate FlowMod rate at current vehicle density.
    // Using N_Vehicles as the density proxy, consistent with the existing
    // ComputeTcamDetection() call site at routing.cc:117172.
    double E_lambda_l   = 1.0 + 0.8 * (double)N_Vehicles;
    double lambda_hat_a = lambda_fm - E_lambda_l;

    // Thresholds match ComputeTcamDetection()'s call-site values.
    snap.flag_s3 = (lambda_hat_a > 10.0) && (malicious_count > 0);  // S3: CP flooding
    snap.flag_s4 = (lambda_pi    > 15.0) && (tcam_util > 0.80);     // S4: DP injection

    return snap;
}

// =========================================================================
// Phase 3 — Vehicle → associated RSU lookup
//
// Finds the RSU with the strongest current DSRC link to `vehicle` using
// linklifetimeMatrix_dsrc[][] (routing.cc:115872), the same matrix the
// routing engine uses to gate weak links (routing.cc:116254).
// Returns N_RSUs as a sentinel meaning "no RSU currently in DSRC range".
// =========================================================================

inline uint32_t lookup_vehicle_associated_rsu_local_idx(uint32_t vehicle)
{
    if (vehicle >= linklifetimeMatrix_dsrc.size()) return N_RSUs;

    uint32_t best_local_idx = N_RSUs;
    double   best_lifetime  = 0.0;

    for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r) {
        uint32_t rsu_node_id = N_Vehicles + r;
        if (rsu_node_id < linklifetimeMatrix_dsrc[vehicle].size() &&
            linklifetimeMatrix_dsrc[vehicle][rsu_node_id] > link_lifetime_threshold &&
            linklifetimeMatrix_dsrc[vehicle][rsu_node_id] > best_lifetime)
        {
            best_lifetime  = linklifetimeMatrix_dsrc[vehicle][rsu_node_id];
            best_local_idx = r;
        }
    }
    return best_local_idx;
}

// =========================================================================
// Function bodies — Phase 2 / 4 / 5 / 6 added in subsequent commits.
// =========================================================================

#endif // LRAD_H
