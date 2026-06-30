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
// Function bodies — added phase by phase.
// (Phase 2 / 2.5 / 2.6 / 3 / 4 / 5 / 6 go here in subsequent commits.)
// =========================================================================

#endif // LRAD_H
