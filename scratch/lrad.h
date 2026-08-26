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
//                                          g_prev_slowpath_hits, TCAM_CAPACITY)
//     lstm_logger.h                      (for g_lstm_escalation_count —
//                                          main.tex §5039/5307 escalation
//                                          to LSTM detector, see
//                                          process_escalation_at_rsu())
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
    bool D_OBU    = false;  // flag_S1 ∨ flag_S2p (eq:composite_light, main.tex:2354-2357).
    // S3/S4 are NOT OBU-side signatures per spec — main.tex:2364-2368 is explicit
    // that they require RSU-observable infrastructure metrics (FlowMod rate,
    // TCAM utilisation, PACKET_IN rate per source) unavailable to OBUs, and
    // are evaluated exclusively at the RSU via tcam_detection.h's
    // ComputeTcamDetection(). A previous OBU-side rate-based approximation
    // (λ̂a>10 for S3, λPI>15∧U_TCAM>0.80 for S4) was removed 2026-08-03: it
    // contradicted both eq:composite_light (which excludes S3/S4 from D_OBU)
    // and the thesis's own S3/S4 formulas (eq:rule_s3 is the blockchain
    // f_unauth check, not a rate threshold; eq:rule_s4 is U_TCAM alone, with
    // PACKET_IN rate explicitly barred from gating per main.tex:2346-2347).
};

// RSU-side detection results (alg:lrad_rsu output).
struct LRADRSUFlags {
    bool flag_S2f = false;  // S2-full: STARK delay proof fails
    bool flag_S5  = false;  // Active HF CP: ¬b_batch ∧ FlowMod∉BC.Query ∧ CopyVerify=0 ∧ b_hop=0
    bool flag_S6  = false;  // Active HF DP: DUP(msg_id,W) ∧ NoFM_d' ∧ CopyVerify=0 ∧ b_hop=0
    bool flag_S7  = false;  // Passive HF CP: vol > εvol ∧ b_hop=0
    bool flag_S8  = false;  // Passive HF DP: b_batch ∧ b_hop=0
    // flag_LSTM = D_LSTM^(k), the live federated-LSTM per-RSU anomaly
    // output (main.tex eq:lstm_detection, post-2026-07-20 dev merge —
    // see docs/DEV_MERGE_SPEC_CHANGES.md item #10). Complementary signal,
    // "covers residual anomalies" not caught by S2f/S5-S8.
    bool flag_LSTM = false;
    // Supervisor Fix 2 (2026-08-14): true iff flag_LSTM fired AND the score
    // cleared the high-confidence tier (score > LSTM_HC_MULT * theta_used,
    // lstm_logger.h). Confusion-matrix recording (record_detection_event())
    // still keys on flag_LSTM alone, unchanged, per the fix spec ("confusion
    // matrix records detections at theta as before") -- this field only
    // gates whether an LSTM-only D_RSU trigger is allowed to reach the
    // shared BTMM trust-evaluation call below.
    bool flag_LSTM_high_conf = false;
    // D_RSU = flag_S2f ∨ flag_S5 ∨ flag_S6 ∨ flag_S7 ∨ flag_S8 ∨ flag_LSTM.
    // S3/S4 are intentionally NOT members here: they are evaluated and
    // recorded independently by tcam_detection.h's ComputeTcamDetection()
    // (the RSU-cycle detector using the blockchain f_unauth check for S3 and
    // U_TCAM-only threshold for S4, matching eq:rule_s3/eq:rule_s4), not by
    // lrad_rsu(). See the LRADOBUFlags comment above for why the older
    // OBU-side S3/S4 approximation was removed rather than folded in here.
    bool D_RSU    = false;  // flag_S2f ∨ flag_S5 ∨ flag_S6 ∨ flag_S7 ∨ flag_S8 ∨ flag_LSTM
};

// Carries OBU detection flags from vehicle to RSU via escalate_to_rsu().
struct EscalationEvent {
    uint32_t     vehicle_id;
    uint32_t     rsu_id;
    uint32_t     pkt_id;
    uint32_t     flow_id;
    double       t_escalate;
    LRADOBUFlags obu_flags;
    // Suspect for per-signal BC.Write (eq:rsu_write) at the RSU:
    //   orig_prev_sender — forwarding node suspected by S1/S2p
    // Without this, lrad_rsu() only has vehicle_id (the OBU reporter),
    // which is NOT the suspect and must not be logged on the ledger.
    uint32_t     orig_prev_sender;    // UINT32_MAX = unknown/not applicable
};

// Per-RSU queue of pending escalation events.
// Drained by process_escalation_at_rsu() after a 1 ms simulated OBU→RSU delay.
static std::map<uint32_t, std::vector<EscalationEvent>> g_escalation_queue;

// HmacTag, g_hmac_tags, lrad_hmac_tag_packet — defined in lrad_hmac.h
// (included early in routing.cc so the RSU routing loop can stamp pre-delay).

// Detection event counters — written to CSV in Phase 8.
// Defined in routing.cc (before write_security_metrics_csv) so they are
// visible both to the CSV writer (included before lrad.h) and to lrad.h
// function bodies (included after the definitions).
extern uint32_t g_d_obu_count;
extern uint32_t g_d_rsu_count;
extern uint32_t g_escalation_count;

// Counts flag_LSTM firings actually suppressed by the S3/S4 gate below
// (lrad_rsu()) -- diagnostic only, not written to the security-metrics CSV.
static uint32_t g_lstm_gate_suppressed_count = 0;

// Decision 2 (2026-08-21): set per packet in lrad_rsu() when the R_anom
// zero-tolerance rule fired for this RSU, so the eq:lstm_gate block below can
// suppress the LSTM's redundant S7/S8 contribution -- the same asymmetric
// pattern as the S3/S4 gate (rule flag computed unconditionally, only the
// LSTM's overlap suppressed).
static bool g_ranom_rule_fired_this_pkt = false;

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
                                uint32_t orig_prev_sender);
inline void    process_escalation_at_rsu(uint32_t rsu_id);
inline LRADRSUFlags lrad_rsu(uint32_t rsu, uint32_t prev_sender,
                              uint32_t pkt_id, uint32_t fid,
                              LRADOBUFlags obu_flags, double t_now,
                              uint32_t obu_orig_prev_sender  = UINT32_MAX);
inline void    btmm(uint32_t node, bool b_batch, bool b_hop, bool timing_ok);
inline bool    lrad_s2_partial_check(uint32_t vehicle,
                                     uint32_t pkt_id, double t_now);
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
    else {
        g_current_trust_source = DSRC_BTMM_PACKET;
        trust_update_negative(node);
        g_current_trust_source = DSRC_NONE;
    }
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
    uint32_t     obu_orig_prev_sender   /* = UINT32_MAX */)  // S1/S2p suspect
{
    LRADRSUFlags flags;
    if (!enable_lrad_rsu) return flags; // AB1-A: RSU engine off — all-false, no escalation processing
    auto _t0 = crypto_log_start();

    // Use .find() — never operator[] — to avoid silently inserting a
    // default-constructed "verification failed" record for unsigned packets.
    //
    // KEY MUST BE crypto_msg_key(pkt_id, fid), NOT the raw pkt_id (fixed
    // 2026-08-06). g_packet_crypto is written by mldsa87_sign() as
    // {signer, crypto_msg_key(pkt_id, seq)} (crypto_layer.h:585) and read
    // everywhere else with the same composite key. Since
    // crypto_msg_key = ((flow_id & 0xFFF) << 12) | (pkt_id & 0xFFF), a raw
    // pkt_id lookup only ever matched flow_id == 0 (and pkt_id < 4096), so
    // have_crypto was false for essentially all traffic. Consequences while
    // this was live: the RSU-side BTMM update below never fired, and S2f /
    // S5-S8 lost the sig_valid / stark_hop_ok evidence they read from `it`.
    // Matches the sibling verify call at routing.cc:121857, which passes the
    // same `fid` in the same scope.
    auto it         = g_packet_crypto.find({prev_sender, crypto_msg_key(pkt_id, fid)});
    bool have_crypto = (it != g_packet_crypto.end() && it->second.sig_len > 0);

    // ── S2-full (line 1 of alg:lrad_rsu): STARK.Verify(π_delay) = 0 ────────
    // s2_detect_packet() internally evaluates both the delay threshold AND
    // the STARK timing proof, covering the full eq:stark_delay_verify check.
    // g_disable_s1_s2 is applied to the FLAG, not to the call — s2_detect_packet()
    // latches g_s2_gt_delay_exceeded[], which is A2's ground truth at
    // routing.cc:117329. Skipping the call zeroed that ground truth, so A2
    // reported TP+FN=0 in every config with the flag set (Q2/Q3/Q4). The
    // record_detection_event() inside is separately gated on the same flag.
    // Same asymmetry as g_disable_s3_s4; see crypto_layer.h.
    const bool _s2f = s2_detect_packet(prev_sender, t_now,
                                       is_safety_critical_flow[fid],
                                       rsu, pkt_id, fid);
    flags.flag_S2f = g_disable_s1_s2 ? false : _s2f;

    // ── S5–S8 (lines 5–8 of alg:lrad_rsu) ──────────────────────────────────
    // recv_flow_id approximated as fid: these functions prefer g_packet_crypto
    // evidence over the 0xDEAD0000 marker whenever a crypto record exists.
    // g_disable_s5_s6 / g_disable_s7_s8: diagnostic ablation gates (crypto_layer.h).
    // Applied HERE, to the flag itself, rather than to the record_detection_event()
    // call inside each detector — because per alg:lrad_rsu (main.tex:2544-2546)
    // these flags feed D_RSU, and through D_RSU the BTMM trust penalty and the
    // BC.Write detection-event record below. Gating only the confusion-matrix call
    // would leave a "disabled" signature still penalising trust and writing to the
    // ledger, so Q4 ("witness only") and Q2 ("crypto only") would not actually
    // isolate their component. Contrast g_disable_s3_s4, which is deliberately NOT
    // applied to flag_s3/flag_s4 — those have a structural consumer (the
    // eq:lstm_gate suppression below) that must keep seeing the raw condition.
    uint32_t base_fid = fid & 0xFFFFu;
    flags.flag_S5 = g_disable_s5_s6 ? false : s5_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S6 = g_disable_s5_s6 ? false : s6_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    // Supervisor Decision 2 (2026-08-21): R_anom > 0 is an additional
    // OR-condition feeding S7/S8, alongside the existing witness path.
    // Zero-tolerance, no calibration -- verified r_anom is EXACTLY 0 across
    // all 95,360 benign rows of the collected dataset, every seed.
    //
    // Computed UNCONDITIONALLY (the latch is published every cycle by
    // lstm_log_rsu_cycle regardless of config); only its contribution to the
    // FLAG is gated below, the same asymmetry as g_tcam_flag_s3_last/s4_last.
    const uint32_t _rsu_local = (rsu >= (uint32_t)N_Vehicles)
                              ? (rsu - (uint32_t)N_Vehicles) : UINT32_MAX;
    const bool _ranom_rule = (_rsu_local != UINT32_MAX)
                          && (_rsu_local < g_ranom_flag_last.size())
                          && (g_ranom_flag_last[_rsu_local] != 0);

    const bool _s7_raw = s7_detect(fid, prev_sender, rsu, pkt_id, base_fid) || _ranom_rule;
    const bool _s8_raw = s8_detect(fid, prev_sender, rsu, pkt_id, base_fid) || _ranom_rule;
    flags.flag_S7 = g_disable_s7_s8 ? false : _s7_raw;
    flags.flag_S8 = g_disable_s7_s8 ? false : _s8_raw;

    // Suppress the LSTM's redundant contribution when the rule already fired,
    // exactly the S3/S4 pattern (eq:lstm_gate). Published for the flag_LSTM
    // computation further down.
    g_ranom_rule_fired_this_pkt = _ranom_rule;

    // Decision 2 (2026-08-21): the rule must REACH the confusion matrix, not
    // just raise the flag. record_detection_event() lives inside
    // s7_detect()/s8_detect(), and the OR above is applied to their RETURN
    // value, so a rule-only firing would otherwise be invisible to
    // is_detected_node[][] and print no [S7]/[S8] line.
    //
    // Recorded against active_attack_variant, NOT S7_HOME_VARIANT: R_anom
    // fires on every HF variant (A5-A8), while S7_HOME_VARIANT is fixed at 6
    // (Attack 7). Using the home variant would log Attack-7 detections during
    // an Attack-5 run and corrupt that variant's matrix. This matches how the
    // LSTM path already records (same file, flag_LSTM block).
    //
    // Attributed to `rsu` -- the RSU this rule fired for -- rather than
    // prev_sender. That is the whole point of using R_anom: its counter is
    // keyed by hf_gt_attribution_node(), the malicious forwarder's covering
    // RSU, so it does not inherit the prev_sender misattribution that puts
    // 79.2% of the witness path's duplication alerts on vehicle relays.
    if (_ranom_rule && !g_disable_s7_s8 &&
        active_attack_variant >= 0 &&
        active_attack_variant < NUM_ATTACK_VARIANTS &&
        rsu < (uint32_t)total_size &&
        !is_detected_node[active_attack_variant][rsu])
    {
        record_detection_event(active_attack_variant, rsu, DSRC_RULE_RANOM);
        std::cout << "[S7-RANOM] R_anom>0 rule fired at RSU " << rsu
                  << " variant=" << active_attack_variant
                  << " t=" << t_now << std::endl;
    }

    // ── flag_LSTM = D_LSTM^(k) (eq:lstm_detection), gated for S3/S4 ─────────
    // `rsu` is the sim node id (N_Vehicles + local RSU index, per
    // process_escalation_at_rsu()/every call site below); g_lstm_last_dlstm[]
    // is indexed by local index (lstm_logger.h convention). g_lstm_last_dlstm
    // is only populated once --enable_lstm_inference=1 AND the per-RSU
    // window has bootstrapped (LSTM_WINDOW cycles) — defaults to false
    // (fail-closed: no live LSTM signal available yet) otherwise.
    //
    // Gate (supervisor diagnosis, 2026-07-30): when this RSU's most recent
    // TCAM cycle had S3 or S4 fire (g_tcam_flag_s3_last/s4_last,
    // tcam_detection.h -- the RSU-side, spec-correct rule-based TCAM
    // detector, independent of the LSTM), suppress flag_LSTM for this RSU.
    // S3/S4 are architecturally definitive for TCAM exhaustion (blockchain
    // endorsement / TCAM-utilisation threshold); the LSTM's reconstruction
    // error is structurally elevated by residual TCAM occupancy during
    // these events and adds false positives without adding coverage the
    // rule-based layer doesn't already have. main.tex's alg:lrad_rsu was
    // updated (2026-08-03) to match this gated behaviour exactly -- no
    // longer a deviation from the paper's literal flat OR of flag_LSTM
    // into D_RSU.
    if (rsu >= (uint32_t)N_Vehicles) {
        uint32_t rsu_local_idx = rsu - (uint32_t)N_Vehicles;
        bool tcam_covers_this_rsu = (rsu < 300) &&
            (g_tcam_flag_s3_last[rsu] || g_tcam_flag_s4_last[rsu]);
        // Decision 2 (2026-08-21): the R_anom zero-tolerance rule covers S7/S8
        // the same way S3/S4 cover the TCAM family, so suppress the LSTM's
        // redundant contribution on those RSUs too. Variable name kept
        // ("tcam_covers") to avoid churn at the three use sites below; it now
        // means "a rule-based detector already covers this RSU".
        tcam_covers_this_rsu = tcam_covers_this_rsu || g_ranom_rule_fired_this_pkt;
        bool lstm_would_fire = rsu_local_idx < g_lstm_last_dlstm.size() &&
            g_lstm_last_dlstm[rsu_local_idx];
        if (tcam_covers_this_rsu && lstm_would_fire) {
            // Gate actually suppressed a would-be flag_LSTM firing this
            // cycle -- rare/high-importance event, printed unconditionally
            // like TRIGGERED/detection-event lines elsewhere in this file.
            ++g_lstm_gate_suppressed_count;
            std::cout << "[LSTM-GATE] suppressed flag_LSTM at RSU " << rsu
                      << " (S3=" << g_tcam_flag_s3_last[rsu]
                      << " S4=" << g_tcam_flag_s4_last[rsu] << ")"
                      << " t=" << Simulator::Now().GetSeconds() << "s"
                      << " total_suppressed=" << g_lstm_gate_suppressed_count
                      << std::endl;
        } else if (!tcam_covers_this_rsu) {
            flags.flag_LSTM = lstm_would_fire;
            flags.flag_LSTM_high_conf = lstm_would_fire &&
                rsu_local_idx < g_lstm_high_confidence.size() &&
                g_lstm_high_confidence[rsu_local_idx];
        }
    }

    flags.D_RSU = flags.flag_S2f || flags.flag_S5 || flags.flag_S6 ||
                  flags.flag_S7 || flags.flag_S8 || flags.flag_LSTM;
    if (flags.D_RSU) dw_mark_rsu(rsu);   // M1 window grid (detector_windows.h)
    // Primary-detector grid: ONLY the detector this variant is scored by, per
    // the supervisor's 2026-08-21 assignment. Excludes the OR-composite so
    // e.g. S2f firings during an A5 run (measured 1,572-3,313 per run, all
    // recorded into variant 1's bucket and therefore invisible in A5's own
    // node-level matrix) can no longer pollute A5's window score.
    {
        bool _prim = false;
        switch (active_attack_variant) {
            case 0: case 1: _prim = flags.flag_S2f; break;              // A1/A2 -> S1/S2
            case 2: case 3:                                             // A3/A4 -> S3/S4
                // FIX (2026-08-26, n11 debug session): this fell into `default`
                // below and used flags.D_RSU -- the full OR-composite, INCLUDING
                // flag_LSTM -- despite the comment claiming "recorded by
                // tcam_detection.h". Isolated via a 3-way ablation (LSTM-only /
                // witness-only / BTMM-only vs. the Q5 baseline, A3 @60% seed1
                // 300s): LSTM-only alone reproduced Q6's FP explosion exactly
                // (TP=429 FP=413, byte-identical to full Q6), witness-only and
                // BTMM-only both matched the Q5 baseline byte-for-byte
                // (TP=318 FP=2) -- the LSTM is entirely responsible, witness and
                // BTMM are bystanders here. Mechanism: the LSTM-suppression gate
                // above only silences flag_LSTM at an RSU where THAT SAME RSU's
                // S3/S4 fired last cycle; per this file's own comment on that
                // gate, "the LSTM's reconstruction error is structurally
                // elevated by residual TCAM occupancy... independently of any
                // co-firing signature" -- i.e. a bystander RSU with no local
                // TCAM exhaustion can still see flag_LSTM fire, ungated, and
                // flags.D_RSU let that pollute A3/A4's window score exactly the
                // way S2f polluted A5's before the 2026-08-21 primary-detector
                // fix. Scoped to the same rule-based signal the LSTM-gate above
                // already reads (g_tcam_flag_s3_last/s4_last, tcam_detection.h),
                // same pattern as every other variant's primary case.
                //
                // SUPERSEDED (2026-08-27): marking is done in dw_end_cycle()
                // instead -- see below. Left as an explicit no-op case so A3/A4
                // cannot silently fall through to `default` (flags.D_RSU) again,
                // which is the original bug this case was added to fix.
                //
                // Two further problems with doing it here, both found before any
                // of these numbers were trusted:
                //
                //  1. WRONG NODE. This site marks prev_sender (correct for every
                //     OTHER variant, whose detectors accuse the sender), but the
                //     value read is g_tcam_flag_s3_last[rsu] -- the flag of the
                //     RSU PROCESSING the packet. A3/A4 ground truth labels the
                //     VICTIM RSU ("any RSU holding >=1 malicious TCAM entry",
                //     lstm_rsu_ground_truth_label(), lstm_logger.h), and S3/S4
                //     fire at that same victim. So the read node and the marked
                //     node are different roles, and crediting the victim's
                //     detection to whatever node happened to send the packet
                //     inflates FP. The "mark the suspect, not the observer" rule
                //     INVERTS for the TCAM family: here the observer IS the
                //     labelled subject.
                //
                //  2. WRONG GATE SEMANTICS. g_tcam_flag_s3_last/s4_last are
                //     deliberately never gated by g_disable_s3_s4
                //     (tcam_detection.h keeps them live so the LSTM-suppression
                //     gate still works during ablation runs). Reading them raw
                //     made A3/A4's primary score insensitive to g_disable_s3_s4
                //     -- caught when a Q1-Q6 rerun returned Q1..Q5 byte-identical
                //     for both A3 and A4, impossible when Q2/Q3/Q4 set
                //     g_disable_s3_s4=1 specifically to isolate S3/S4 out.
                //
                // dw_end_cycle() already solves both: it folds the same flags in
                // per-RSU under `if (!g_disable_s3_s4)`, indexing r directly.
                _prim = false;
                break;
            case 4: case 5: _prim = flags.flag_S5 || flags.flag_S6; break; // A5/A6 -> crypto/S5/S6
            case 6: case 7: _prim = flags.flag_S7 || flags.flag_S8; break; // A7/A8 -> S7/S8 (+R_anom, already OR'd in)
            default: _prim = flags.D_RSU; break;                        // unassigned variant, no home detector
        }
        // ATTRIBUTION FIX (2026-08-22): mark the SUSPECT, not the observer.
        //
        // dw_mark_rsu() above marks `rsu` -- the RSU processing this packet --
        // while every detector RECORDS against `prev_sender` (the accused;
        // see record_detection_event(S5_HOME_VARIANT, prev_sender, ...) in
        // s5_detection.h:259) and the window TRUTH column asks whether that
        // same RSU index is malicious. Those are three different subjects.
        //
        // Consequence, measured on A5: node-level reports S5(TP=39, FP=0)
        // while the same run's window grid reports FP=186 -- a benign RSU
        // that correctly detects a malicious neighbour gets score=1 against
        // its own truth=0, i.e. penalised for detecting. That is why benign
        // nodes fire in 58/58 windows, and why all six detectors with
        // node-level FP=0 (S3-S8) still collapse at window level.
        dw_mark_rsu_primary(prev_sender, _prim);
    }

    // ── BC.Write per-signal + BTMM (eq:rsu_write, alg:lrad_rsu) ─────────────
    // Per thesis alg:lrad_rsu: BTMM and BC.Write are BOTH inside the D_RSU gate.
    // Positive trust rewards for clean packets come from routing.cc (outside lrad_rsu).
    if (flags.D_RSU) {
        g_d_rsu_count++;
        // BTMM trust penalty (eq:trust_update) — inside D_RSU per alg:lrad_rsu.
        // trust_update_negative fires when sig or hop proof fails; for volume-based
        // signals (S7/S8) the negative path is forced via have_crypto being true
        // but the detection having already confirmed attack behaviour.
        // g_disable_btmm_trust also gates THIS BTMM site, not just the one at
        // routing.cc:121919 (fixed 2026-08-06 — the first pass missed it). Both
        // reach trust_update_negative() -> quarantine -> record_detection_event(),
        // so leaving either ungated re-contaminates the ablation's confusion
        // matrix. This one was previously unreachable anyway because the
        // g_packet_crypto lookup above used the wrong key; with that fixed it
        // becomes live, which is exactly why it now needs the gate.
        // Supervisor Fix 2 (2026-08-14): if the ONLY reason D_RSU fired is a
        // soft (sub-2x-theta) flag_LSTM detection -- no S2f/S5-S8 present --
        // skip the BTMM trust evaluation entirely rather than let it run.
        // This is the closest faithful mapping onto this codebase of "soft
        // LSTM detections do not trigger trust_update_negative()": there is
        // no LSTM-keyed trust_update_negative() call anywhere in the tree
        // (every call site is crypto/timing-keyed — see
        // docs/SUPERVISOR_FIXES_2026-08-14.md Fix 2 section) for the literal
        // instruction to gate, so instead this prevents a soft LSTM firing
        // from opening the shared BTMM gate at all -- for EITHER outcome,
        // not just the negative one, since btmm()'s reward/punish decision
        // here is keyed on crypto/S2f, not on flag_LSTM's own truth value,
        // so letting it run on a soft-LSTM-only trigger would just as often
        // hand out an unearned trust_update_positive().
        bool lstm_only_soft = flags.flag_LSTM && !flags.flag_LSTM_high_conf &&
            !flags.flag_S2f && !flags.flag_S5 && !flags.flag_S6 &&
            !flags.flag_S7 && !flags.flag_S8;
        if (have_crypto && !g_disable_btmm_trust && !lstm_only_soft)
            btmm(prev_sender, it->second.sig_valid && g_batch_passed,
                 it->second.stark_hop_ok, !flags.flag_S2f);
        if (flags.flag_S2f) bc_write_detection_event(rsu, prev_sender, 2, t_now);
        if (flags.flag_S5) {
            bc_write_detection_event(rsu, prev_sender, 5, t_now);
            // Dual attribution (2026-07-20 alg:lrad_rsu revision, eq:batch_fallback):
            // on S5 detection, penalize BOTH the controller (ctrl-plane — done at
            // the active-HF eavesdropper receive site in routing.cc via
            // ctrl_trust_update_negative(), unconditionally whenever this reception
            // event occurs) AND the forwarding node identified as
            // v_atk,copy = argmin{i : ML-DSA-87.Verify(σ_i,pk_i,m_i)=0} (data-plane).
            // In this simulation the batch never has more than one attacker-
            // fabricated entry per packet, already isolated by s5_detect()'s own
            // conjunction 2 (active_hf_malicious_nodes[prev_sender]), so
            // v_atk,copy == prev_sender here — no separate batch scan is needed.
            // Explicit and unconditional (not folded into the have_crypto-gated
            // btmm() call above): g_packet_crypto is keyed by the ORIGINAL
            // signer, not the forwarding node u, so a {prev_sender, pkt_id}
            // record frequently does not exist for the eavesdropper path and
            // that btmm() call would otherwise silently skip this penalty.
            trust_update_negative(prev_sender);
        }
        if (flags.flag_S6)  bc_write_detection_event(rsu, prev_sender, 6, t_now);
        if (flags.flag_S7)  bc_write_detection_event(rsu, prev_sender, 7, t_now);
        // flag_LSTM: unlike S2f/S5-S8, no s*_detect() call recorded this
        // detection, so it must be recorded here or it never reaches the
        // TP/FP confusion-matrix counters (is_detected_node[][], read by
        // write_security_metrics_csv()'s cur_DR/cur_FPR/cur_MCC every
        // cycle). Attributed to prev_sender, matching S5-S8's own
        // attribution (same variable, no separate suspect concept exists
        // for a per-RSU rather than per-packet signal). This is the
        // spec-correct attribution, not a placeholder: main.tex:2579-2581's
        // composite-decision Else branch literally reads "Data-plane or
        // LSTM: attacker is vehicle/RSU" — the paper itself buckets
        // LSTM-only detections into the same data-plane (v/prev_sender)
        // attribution path used here, not the control-plane c_atk path
        // used by S3/S5/S7 (DEV_MERGE_SPEC_CHANGES.md #11's restructure is
        // about THAT path and doesn't add scope for LSTM). signal 9 (LSTM)
        // is a valid bc_write_detection_event() signal_idx as of
        // 2026-07-27 (see docs/LSTM_LIVE_INTEGRATION_STATUS.md) so the
        // blockchain audit trail now covers LSTM detections too.
        // Supervisor Fix A (2026-08-18): gate the sticky per-node latch itself
        // on high-confidence LSTM detections only (score > 2x theta), not on
        // flag_LSTM alone. This is the mechanically-correct extension flagged
        // (not applied) under Fix 2 in docs/SUPERVISOR_FIXES_2026-08-14.md --
        // now explicitly approved. Scope: LSTM path only. The rule-engine
        // path (S1-S8, above/below) is untouched and continues to set
        // is_detected_node[][] unconditionally on its own flags. A soft
        // (at-theta) LSTM detection still writes to bc_write_detection_event
        // below and to the per-cycle CSV (lstm_logger.h, unconditional on
        // flag_LSTM) for the window-level LSTM-only reference metric that
        // evaluator.py computes independently from raw scores -- only the
        // permanent TP/FP confusion-matrix latch is withheld from soft hits.
        if (flags.flag_LSTM && flags.flag_LSTM_high_conf &&
            active_attack_variant >= 0 &&
            active_attack_variant < NUM_ATTACK_VARIANTS &&
            prev_sender < (uint32_t)total_size &&
            !is_detected_node[active_attack_variant][prev_sender])
        {
            record_detection_event(active_attack_variant, prev_sender, DSRC_LSTM);
        }
        if (flags.flag_LSTM) bc_write_detection_event(rsu, prev_sender, 9, t_now);
        if (flags.flag_S8)  bc_write_detection_event(rsu, prev_sender, 8, t_now);
    }

    // OBU-escalated signals (S1/S2p): RSU writes on behalf of the OBU
    // observation, using the correct suspect carried through EscalationEvent.
    // Guards against UINT32_MAX (sentinel = unknown) before writing.
    if (obu_flags.D_OBU) {
        if (obu_flags.flag_S1  && obu_orig_prev_sender  != UINT32_MAX)
            bc_write_detection_event(rsu, obu_orig_prev_sender,  1, t_now);
        if (obu_flags.flag_S2p && obu_orig_prev_sender  != UINT32_MAX)
            bc_write_detection_event(rsu, obu_orig_prev_sender,  2, t_now);
    }

    crypto_log_event("lrad_rsu", prev_sender, pkt_id, fid, _t0, flags.D_RSU);
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
    for (auto& ev : queue) {
        lrad_rsu(rsu_id, ev.vehicle_id, ev.pkt_id, ev.flow_id,
                 ev.obu_flags, ns3::Simulator::Now().GetSeconds(),
                 ev.orig_prev_sender);
        // RSU.Confirm(v,r) — full-mode analysis for this escalation is complete,
        // so eq:local_quarantine's hold on the vehicle is released. This is the
        // release arm of "until RSU.Confirm(v,r) ∨ t > t_detect + T_hold"; the
        // timeout arm is handled lazily in fwd_hold_remaining().
        rsu_confirm_release(ev.vehicle_id);
    }

    // main.tex §5039/5307 "Escalation to LSTM detector": the same D_OBU
    // escalation that reaches LRAD-RSU above must also reach the LSTM side
    // (main.tex:4159-4160 — "LRAD-OBU pre-filters, escalates to LRAD-RSU
    // and BRFA-v2 LSTM"). g_lstm_escalation_count is defined in
    // lstm_logger.h (included before this header) and drained once per
    // cycle by lstm_log_rsu_cycle(). rsu_id here is N_Vehicles + local
    // index (per escalate_to_rsu()'s construction) — convert back to the
    // local RSU index lstm_log_rsu_cycle() indexes by.
    if (rsu_id >= (uint32_t)N_Vehicles)
    {
        uint32_t rsu_local_idx = rsu_id - (uint32_t)N_Vehicles;
        if (rsu_local_idx < g_lstm_escalation_count.size())
            g_lstm_escalation_count[rsu_local_idx] += (uint32_t)queue.size();
    }

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
    uint32_t orig_prev_sender)
{
    auto _t0 = crypto_log_start();

    uint32_t rsu_local_idx = lookup_vehicle_associated_rsu_local_idx(vehicle);
    if (rsu_local_idx >= (uint32_t)N_RSUs) {
        // No RSU in DSRC range — drop gracefully.
        crypto_log_event("escalate_to_rsu", vehicle, pkt_id, fid, _t0, false);
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

    g_escalation_queue[rsu_id].push_back(ev);
    g_escalation_count++;

    crypto_log_event("escalate_to_rsu", vehicle, pkt_id, fid, _t0, true);

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
// prev_sender: the node that forwarded this packet to `vehicle`. Used for
//   S2-partial's HMAC lookup below (that tag was stamped by prev_sender).
//   NOT used for S1's ground-truth attribution (see note at the S1 call
//   below) — main.tex's alg:lrad_obu takes no "previous sender" parameter
//   at all; it evaluates the baseline for RSU r and escalates to that same
//   r, with no separate sender concept.
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
    if (!enable_lrad_obu) return flags; // AB1-B: OBU engine off — all-false, no escalation
    auto _t0 = crypto_log_start();

    // ── S1: δp > δ̄_r(t) + k·σ_r(t)  ∧  Priority(p)=HIGH  (Eq. 3.4) ──────
    // Reads the associated RSU's existing EWMA baseline/variance state
    // directly — simulation shortcut documented in the LRAD plan.
    // g_disable_s1_s2 applied to the FLAG, not the call — s1_detect_packet()
    // latches g_s1_gt_delay_exceeded[] (A1's ground truth, routing.cc:117328)
    // and maintains the per-RSU EWMA baseline, both of which must stay live
    // across every ablation config. Its record_detection_event() is gated on
    // the same flag internally. See s1_detection.h.
    if (assoc_rsu_local_idx < (uint32_t)N_RSUs) {
        const bool _s1 = s1_detect_packet(
            assoc_rsu_local_idx, vehicle, delta_p, is_high_priority,
            // sender_node_id → fed into record_detection_event. Must be the
            // associated RSU (matching alg:lrad_obu's ESCALATE(p,v,r,...)
            // and the ground-truth model, which marks RSUs malicious via
            // controller compromise — never vehicles). prev_sender is the
            // immediate previous hop, which in multi-hop VANET routing is
            // very often another vehicle; since ground truth never marks
            // vehicles malicious, that misattribution was a guaranteed
            // false positive whenever it happened — confirmed empirically:
            // 265 of 276 S1 firings targeted vehicle-range IDs in a 0%-
            // attack (zero ground-truth-malicious) baseline run.
            N_Vehicles + assoc_rsu_local_idx,
            vehicle,                // current_hop (receiver / OBU)
            pkt_id, fid);
        flags.flag_S1 = g_disable_s1_s2 ? false : _s1;
    }

    // ── S2-partial: HMAC.Verify(τ_i) ∧ (t_now − ts_recv) > Δ_max  ─────────
    // Tag was stamped by the SENDER (prev_sender) not by the receiving vehicle.
    flags.flag_S2p = g_disable_s1_s2 ? false : lrad_s2_partial_check(prev_sender, pkt_id, t_now);

    // ── D_OBU (Eq. composite_light, main.tex:2354-2357) ─────────────────────
    // S3/S4 are not OBU-side signatures — see the LRADOBUFlags comment for
    // why the previous rate-based OBU snapshot was removed rather than
    // included here; they are evaluated exclusively at the RSU via
    // tcam_detection.h's ComputeTcamDetection().
    flags.D_OBU = flags.flag_S1 || flags.flag_S2p;

    crypto_log_event("lrad_obu", vehicle, pkt_id, fid, _t0, flags.D_OBU);

    if (flags.D_OBU) {
        g_d_obu_count++;
        dw_mark_obu(vehicle);   // M1 window grid (detector_windows.h)
        // alg:lrad_obu line 1 of the D_OBU branch: HOLD_FORWARD(v,r).
        // eq:local_quarantine — suspend forwarding of the flagged flow pending
        // RSU confirmation or T_hold timeout. Gated by enable_local_quarantine
        // (default off; see its declaration in crypto_layer.h for why).
        hold_forward(vehicle, fid);
        // prev_sender → suspect for S1/S2p (the forwarding node), passed so
        // the RSU can write the correct BC.Write record (eq:rsu_write).
        escalate_to_rsu(vehicle, pkt_id, fid, flags, prev_sender);
    }
    return flags;
}

#endif // LRAD_H
