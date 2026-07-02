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
    // Suspects for per-signal BC.Write (eq:rsu_write) at the RSU:
    //   orig_prev_sender   — forwarding node suspected by S1/S2p
    //   assoc_rsu_node_id  — associated RSU node ID suspected by S3/S4
    // Without these, lrad_rsu() only has vehicle_id (the OBU reporter),
    // which is NOT the suspect and must not be logged on the ledger.
    uint32_t     orig_prev_sender;    // UINT32_MAX = unknown/not applicable
    uint32_t     assoc_rsu_node_id;   // UINT32_MAX = no RSU in range
};

// Per-RSU queue of pending escalation events.
// Drained by process_escalation_at_rsu() after a 1 ms simulated OBU→RSU delay.
static std::map<uint32_t, std::vector<EscalationEvent>> g_escalation_queue;

// HmacTag, g_hmac_tags, lrad_hmac_tag_packet — defined in lrad_hmac.h
// (included early in routing.cc so the RSU routing loop can stamp pre-delay).

// Per-RSU lightweight TCAM snapshot result (for S3/S4 in lrad_obu).
struct LRADTcamSnapshot { bool flag_s3; bool flag_s4; };

// Detection event counters — written to CSV in Phase 8.
// Defined in routing.cc (before write_security_metrics_csv) so they are
// visible both to the CSV writer (included before lrad.h) and to lrad.h
// function bodies (included after the definitions).
extern uint32_t g_d_obu_count;
extern uint32_t g_d_rsu_count;
extern uint32_t g_escalation_count;

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
                                uint32_t fid, LRADOBUFlags obu_flags,
                                uint32_t orig_prev_sender,
                                uint32_t assoc_rsu_node_id);
inline void    process_escalation_at_rsu(uint32_t rsu_id);
inline LRADRSUFlags lrad_rsu(uint32_t rsu, uint32_t prev_sender,
                              uint32_t pkt_id, uint32_t fid,
                              LRADOBUFlags obu_flags, double t_now,
                              uint32_t obu_orig_prev_sender  = UINT32_MAX,
                              uint32_t obu_assoc_rsu_node_id = UINT32_MAX);
inline void    btmm(uint32_t node, bool b_batch, bool b_hop, bool timing_ok);
inline bool    lrad_s2_partial_check(uint32_t vehicle,
                                     uint32_t pkt_id, double t_now);
inline LRADTcamSnapshot lrad_tcam_snapshot(uint32_t rsu_node_id);
inline uint32_t lookup_vehicle_associated_rsu_local_idx(uint32_t vehicle);

// =========================================================================
// Phase 2.5 — HMAC-SHA3-512 packet tagging (S2-partial at OBU)
// lrad_hmac_tag_packet() is defined in lrad_hmac.h (included early).
// lrad_s2_partial_check() reads g_hmac_tags written by lrad_hmac_tag_packet().
// =========================================================================

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

    // Count legitimate (non-malicious) active flows at this RSU.
    // Thesis eq:sig_s3 second conjunct: ¬∃v: flow(r) ∈ F_active(v)
    // i.e. S3 fires only when there are NO legitimate active vehicle flows —
    // the excess FlowMods cannot be attributed to real traffic.
    int legit_flow_count = 0;
    for (const auto& e : g_tcam_table)
        if (e.node_id == rsu_node_id && !e.is_malicious) ++legit_flow_count;

    // Expected legitimate FlowMod rate at current vehicle density.
    // Using N_Vehicles as the density proxy, consistent with the existing
    // ComputeTcamDetection() call site at routing.cc:117172.
    double E_lambda_l   = 1.0 + 0.8 * (double)N_Vehicles;
    double lambda_hat_a = lambda_fm - E_lambda_l;

    // Thresholds match ComputeTcamDetection()'s call-site values.
    snap.flag_s3 = (lambda_hat_a > 10.0) && (legit_flow_count == 0);  // S3: CP flooding, no legit flows
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
// Phase 6 — btmm()
//
// Per-packet trust update (Algorithm BTMM, eq:trust_update).
// Called UNCONDITIONALLY for every verified packet — NOT gated behind D_RSU.
// Matches the existing pattern at routing.cc:120942–948.
// =========================================================================

inline void btmm(uint32_t node, bool b_batch, bool b_hop, bool timing_ok)
{
    if (b_batch && b_hop && timing_ok)
        trust_update_positive(node);
    else
        trust_update_negative(node);
}

// =========================================================================
// Phase 5 — lrad_rsu()   (alg:lrad_rsu, thesis lines 2035–2086)
//
// Evaluates S2-full, S5, S6, S7, S8 at the RSU and writes D_RSU.
// Calls the REAL s2_detect_packet()/s5_detect()…s8_detect() — not a
// reimplementation — so all existing guards are preserved intact.
// record_detection_event() is already called inside whichever s*_detect()
// fires; do NOT call it again here (would double-count TP/FP metrics).
// =========================================================================

inline LRADRSUFlags lrad_rsu(
    uint32_t     rsu,                              // current_hop / receiving RSU
    uint32_t     prev_sender,                      // suspected sending node
    uint32_t     pkt_id,
    uint32_t     fid,
    LRADOBUFlags obu_flags,                        // from escalation (zero if not escalated)
    double       t_now,
    uint32_t     obu_orig_prev_sender   /* = UINT32_MAX */,  // S1/S2p suspect
    uint32_t     obu_assoc_rsu_node_id  /* = UINT32_MAX */)  // S3/S4 suspect
{
    LRADRSUFlags flags;
    auto _t0 = crypto_log_start();

    // Use .find() — never operator[] — to avoid silently inserting a
    // default-constructed "verification failed" record for unsigned packets.
    auto it         = g_packet_crypto.find({prev_sender, pkt_id});
    bool have_crypto = (it != g_packet_crypto.end() && it->second.sig_len > 0);

    // ── S2-full (line 1 of alg:lrad_rsu): STARK.Verify(π_delay) = 0 ────────
    // s2_detect_packet() internally evaluates both the delay threshold AND
    // the STARK timing proof, covering the full eq:stark_delay_verify check.
    flags.flag_S2f = s2_detect_packet(prev_sender, t_now,
                                       is_safety_critical_flow[fid],
                                       rsu, pkt_id, fid);

    // ── S5–S8 (lines 5–8 of alg:lrad_rsu) ──────────────────────────────────
    // recv_flow_id approximated as fid: these functions prefer g_packet_crypto
    // evidence over the 0xDEAD0000 marker whenever a crypto record exists.
    uint32_t base_fid = fid & 0xFFFFu;
    flags.flag_S5 = s5_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S6 = s6_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S7 = s7_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S8 = s8_detect(fid, prev_sender, rsu, pkt_id, base_fid);

    flags.D_RSU = flags.flag_S2f || flags.flag_S5 || flags.flag_S6 ||
                  flags.flag_S7 || flags.flag_S8;

    // ── BC.Write per-signal + BTMM (eq:rsu_write, alg:lrad_rsu) ─────────────
    // Per thesis alg:lrad_rsu: BTMM and BC.Write are BOTH inside the D_RSU gate.
    // Positive trust rewards for clean packets come from routing.cc (outside lrad_rsu).
    if (flags.D_RSU) {
        g_d_rsu_count++;
        // BTMM trust penalty (eq:trust_update) — inside D_RSU per alg:lrad_rsu.
        // trust_update_negative fires when sig or hop proof fails; for volume-based
        // signals (S7/S8) the negative path is forced via have_crypto being true
        // but the detection having already confirmed attack behaviour.
        if (have_crypto)
            btmm(prev_sender, it->second.sig_valid && g_batch_passed,
                 it->second.stark_hop_ok, !flags.flag_S2f);
        if (flags.flag_S2f) bc_write_detection_event(rsu, prev_sender, 2, t_now);
        if (flags.flag_S5)  bc_write_detection_event(rsu, prev_sender, 5, t_now);
        if (flags.flag_S6)  bc_write_detection_event(rsu, prev_sender, 6, t_now);
        if (flags.flag_S7)  bc_write_detection_event(rsu, prev_sender, 7, t_now);
        if (flags.flag_S8)  bc_write_detection_event(rsu, prev_sender, 8, t_now);
    }

    // OBU-escalated signals (S1/S2p/S3/S4): RSU writes on behalf of the OBU
    // observation, using the correct suspects carried through EscalationEvent.
    // Guards against UINT32_MAX (sentinel = unknown) before writing.
    if (obu_flags.D_OBU) {
        if (obu_flags.flag_S1  && obu_orig_prev_sender  != UINT32_MAX)
            bc_write_detection_event(rsu, obu_orig_prev_sender,  1, t_now);
        if (obu_flags.flag_S2p && obu_orig_prev_sender  != UINT32_MAX)
            bc_write_detection_event(rsu, obu_orig_prev_sender,  2, t_now);
        if (obu_flags.flag_S3  && obu_assoc_rsu_node_id != UINT32_MAX)
            bc_write_detection_event(rsu, obu_assoc_rsu_node_id, 3, t_now);
        if (obu_flags.flag_S4  && obu_assoc_rsu_node_id != UINT32_MAX)
            bc_write_detection_event(rsu, obu_assoc_rsu_node_id, 4, t_now);
    }

    crypto_log_event("lrad_rsu", prev_sender, pkt_id, _t0, flags.D_RSU);
    return flags;
}

// =========================================================================
// Phase 4 — process_escalation_at_rsu()
//
// Drains the escalation queue for rsu_id and runs lrad_rsu() for each
// pending OBU escalation event. Invoked via Simulator::Schedule 1 ms after
// the OBU detection, modelling the OBU→RSU escalation latency.
// Note: if multiple vehicles escalate to the same RSU within 1 ms, the
// first scheduled call drains all of them — each still processed exactly once.
// =========================================================================

inline void process_escalation_at_rsu(uint32_t rsu_id)
{
    auto& queue = g_escalation_queue[rsu_id];
    for (auto& ev : queue)
        lrad_rsu(rsu_id, ev.vehicle_id, ev.pkt_id, ev.flow_id,
                 ev.obu_flags, ns3::Simulator::Now().GetSeconds(),
                 ev.orig_prev_sender, ev.assoc_rsu_node_id);
    queue.clear();
}

// =========================================================================
// Phase 3 — escalate_to_rsu()
//
// Called by lrad_obu() when D_OBU=1.  Enqueues the escalation event at
// the vehicle's current associated RSU and schedules processing 1 ms later.
// Silently drops (returns false) when no RSU is in DSRC range — valid state,
// not an error (vehicle between coverage zones).
// =========================================================================

inline void escalate_to_rsu(
    uint32_t vehicle, uint32_t pkt_id, uint32_t fid, LRADOBUFlags obu_flags,
    uint32_t orig_prev_sender, uint32_t assoc_rsu_node_id)
{
    auto _t0 = crypto_log_start();

    uint32_t rsu_local_idx = lookup_vehicle_associated_rsu_local_idx(vehicle);
    if (rsu_local_idx >= (uint32_t)N_RSUs) {
        // No RSU in DSRC range — drop gracefully.
        crypto_log_event("escalate_to_rsu", vehicle, pkt_id, _t0, false);
        return;
    }
    uint32_t rsu_id = N_Vehicles + rsu_local_idx;

    EscalationEvent ev;
    ev.vehicle_id        = vehicle;
    ev.rsu_id            = rsu_id;
    ev.pkt_id            = pkt_id;
    ev.flow_id           = fid;
    ev.t_escalate        = ns3::Simulator::Now().GetSeconds();
    ev.obu_flags         = obu_flags;
    ev.orig_prev_sender  = orig_prev_sender;
    ev.assoc_rsu_node_id = assoc_rsu_node_id;

    g_escalation_queue[rsu_id].push_back(ev);
    g_escalation_count++;

    crypto_log_event("escalate_to_rsu", vehicle, pkt_id, _t0, true);

    // Model 1 ms OBU→RSU escalation latency (upper bound — see plan note).
    ns3::Simulator::Schedule(ns3::Seconds(0.001),
                             &process_escalation_at_rsu, rsu_id);
}

// =========================================================================
// Phase 2 — lrad_obu()   (alg:lrad_obu, thesis lines 1983–2027)
//
// Evaluates S1, S2-partial, S3, S4 at the OBU (vehicle) and writes D_OBU.
// If D_OBU=1, triggers escalation to the associated RSU.
//
// prev_sender: the node that forwarded this packet to `vehicle`; used as
//   sender_node_id in s1_detect_packet() so record_detection_event() targets
//   the forwarding RSU (the potential attacker), NOT the receiving vehicle.
//   Passing vehicle here would corrupt TP/FP/FN counts.
// =========================================================================

inline LRADOBUFlags lrad_obu(
    uint32_t vehicle,
    uint32_t prev_sender,           // forwarding node — see note above
    uint32_t pkt_id,
    uint32_t fid,
    bool     is_high_priority,
    double   t_now,
    double   delta_p,
    uint32_t assoc_rsu_local_idx)   // RSU local index (0..N_RSUs-1)
{
    LRADOBUFlags flags;
    auto _t0 = crypto_log_start();

    // ── S1: δp > δ̄_r(t) + k·σ_r(t)  ∧  Priority(p)=HIGH  (Eq. 3.4) ──────
    // Reads the associated RSU's existing EWMA baseline/variance state
    // directly — simulation shortcut documented in the LRAD plan.
    if (assoc_rsu_local_idx < (uint32_t)N_RSUs) {
        flags.flag_S1 = s1_detect_packet(
            assoc_rsu_local_idx, delta_p, is_high_priority,
            prev_sender,            // sender_node_id → fed into record_detection_event
            vehicle,                // current_hop (receiver / OBU)
            pkt_id, fid);
    }

    // ── S2-partial: HMAC.Verify(τ_i) ∧ (t_now − ts_recv) > Δ_max  ─────────
    // Tag was stamped by the SENDER (prev_sender) not by the receiving vehicle.
    flags.flag_S2p = lrad_s2_partial_check(prev_sender, pkt_id, t_now);

    // ── S3 / S4: TCAM flooding / injection (lightweight snapshot) ───────────
    uint32_t assoc_rsu_node_id = UINT32_MAX; // sentinel: no RSU in range
    if (assoc_rsu_local_idx < (uint32_t)N_RSUs) {
        assoc_rsu_node_id = N_Vehicles + assoc_rsu_local_idx;
        LRADTcamSnapshot snap = lrad_tcam_snapshot(assoc_rsu_node_id);
        flags.flag_S3 = snap.flag_s3;
        flags.flag_S4 = snap.flag_s4;
    }

    // ── D_OBU (Eq. composite_light) ─────────────────────────────────────────
    flags.D_OBU = flags.flag_S1 || flags.flag_S2p ||
                  flags.flag_S3 || flags.flag_S4;

    crypto_log_event("lrad_obu", vehicle, pkt_id, _t0, flags.D_OBU);

    if (flags.D_OBU) {
        g_d_obu_count++;
        // Pass suspects explicitly so the RSU can write correct BC.Write records
        // for each OBU-side signal (eq:rsu_write):
        //   prev_sender       → suspect for S1/S2p (the forwarding node)
        //   assoc_rsu_node_id → suspect for S3/S4  (the TCAM-anomalous RSU)
        escalate_to_rsu(vehicle, pkt_id, fid, flags,
                        prev_sender, assoc_rsu_node_id);
    }
    return flags;
}

#endif // LRAD_H
