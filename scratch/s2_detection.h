#ifndef S2_DETECTION_H
#define S2_DETECTION_H

// See s1_detection.h — same DETECTION_DEBUG_LOG gating convention.
static bool DETECTION_DEBUG_LOG_S2 = false; // set true to log every S2 evaluation (spammy)

// =========================================================================
// s2_detection.h — MOBIGUARD Signature S2 Detection
//
// Implements Signature S2 (Selective Time Delay, Data Plane) from the
// proposal, as defined in Equation 3.5.
//
// S2 (Attack 2 — Selective Time Delay, Data Plane):
//   t_recv_{u+1} − t_fwd_u > Δ_max  ∧  π_delay(u) = ⊥
//   Eq. 3.5, §1632–1648
//   t_fwd_u is the forwarding node's CLAIMED timestamp (t_claimed_packet),
//   per thesis §1637. Δ_max = 50 ms (proposal §3463).
//
// DESIGN NOTE:
//   This header is included inside routing.cc AFTER all global variables
//   have been declared, so it reads globals directly without externs (same
//   pattern as tap_detection.h and s1_detection.h). Do not include it
//   before the global declarations.
//
// INDEPENDENCE:
//   S2 has no individual master-enable flag — gated solely by
//   enable_lrad_rsu (AB1, lrad.h) via s2_detect_packet()'s only call site
//   inside lrad_rsu(). No per-signature toggle is specified anywhere in
//   main.tex; removed 2026-07-09.
// =========================================================================

#include <iostream>
#include <cmath>
#include <fstream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// S2 threshold Δ_max (seconds).
// Proposal §3463 + simulation table: "Hop-delay detection threshold = 50 ms".
static const double S2_DELTA_MAX = 0.050; // 50 ms

// =========================================================================
// s2_detect_packet():
// Evaluates Signature S2 for one packet at one intermediate hop (Eq. 3.5).
//
// Returns true when BOTH hold:
//   1. t_recv_{u+1} − t_fwd_u > Δ_max      [hop-delay threshold violation]
//   2. π_delay(u) = ⊥                       [ZKP timing proof failure]
//
// The ZKP second conjunction is inferred from the threshold violation in
// simulation (the delay itself would cause the STARK timing proof to fail).
//
//   sender_sim_index — node index of the forwarding node (u)
//   t_recv_now       — reception time at the next hop (seconds)
//   is_safety_crit   — Priority(p) = HIGH
//   current_hop      — receiving node ID (for logging)
//   packet_id        — packet ID (for logging)
//   flow_id          — flow ID (for logging)
// =========================================================================
inline bool s2_detect_packet(uint32_t sender_sim_index,
                              double   t_recv_now,
                              bool     is_safety_crit,
                              uint32_t current_hop,
                              uint32_t packet_id,
                              uint32_t flow_id)
{
    if (sender_sim_index >= (uint32_t)var) return false;
    if (packet_id >= (uint32_t)(Flow_size + 2)) return false;

    // Condition 2 conjunction: safety-critical packets only (Eq. 3.5).
    if (!is_safety_crit) return false;

    // t_fwd_u = claimed forwarding timestamp (before any attack buffering).
    // Per thesis §1637: "the forwarding node's claimed timestamp."
    // Using t_claimed_packet ensures hop_delay = attack_delay + propagation,
    // correctly exceeding Δ_max for malicious nodes.
    double t_fwd_by_sender = t_claimed_packet[sender_sim_index][packet_id];
    if (t_fwd_by_sender <= 0.0) return false;

    // eq:delay_updated — t_fwd_by_sender is the sender's own (possibly
    // Byzantine-compromised) clock reading (node_local_time(), M9
    // TIME_REF_F_BAD/TIME_REF_DELTA_ATTACK); anchor it using the sender's
    // known offset before computing the hop delay, so a compromised sender
    // cannot inflate its own claim to hide a real delay from THIS signature's
    // own detection decision (see docs/METRICS_DEVIATIONS_FROM_PROPOSAL.md —
    // this correction was originally missed here, fixed on re-audit).
    double t_fwd_anchored = t_fwd_by_sender - node_clock_offset(sender_sim_index);
    double hop_delay = t_recv_now - t_fwd_anchored;

    // Eq. 3.5 — Conjunction 1: t_recv_{u+1} − t_fwd_u > Δ_max
    bool delay_exceeds = (hop_delay > S2_DELTA_MAX);

    // Issue 5 fix (2026-08-02) -- see g_s1_gt_delay_exceeded's comment
    // (s1_detection.h) for the full rationale; same pattern here, latched
    // independently of the ZKP conjunct below.
    if (delay_exceeds && sender_sim_index < (uint32_t)total_size)
        g_s2_gt_delay_exceeded[sender_sim_index] = true;

    // Eq. 3.5 — Conjunction 2: π_delay(u) = ⊥  (eq:stark_delay_verify)
    // Must use the same anchored timestamp as hop_delay above — otherwise a
    // compromised sender's offset would make delay_exceeds and zkp_proof_fails
    // disagree (STARK's own internal threshold re-check would see the raw,
    // deceptively-small interval and could pass even when the anchored
    // hop_delay correctly flags a violation), silently suppressing S2.
    StarkTimingProof proof = stark_prove_timing(t_fwd_anchored, t_recv_now,
                                                (uint32_t)packet_id);
    bool zkp_proof_fails   = !stark_verify_timing(proof, t_fwd_anchored, t_recv_now);

    if (DETECTION_DEBUG_LOG_S2)
        cout << "[S2] sender=" << sender_sim_index
             << " receiver=" << current_hop
             << " flow=" << flow_id
             << " pkt=" << packet_id
             << " hop_delay=" << hop_delay * 1000.0 << "ms"
             << " Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms"
             << " delay_exceeds=" << delay_exceeds
             << " zkp_proof_fails=" << zkp_proof_fails
             << " [SAFETY-CRITICAL]" << endl;

    if (delay_exceeds && zkp_proof_fails)
    {
        cout << "[S2] ⚠️ SIGNATURE S2 TRIGGERED!"
             << " hop_delay=" << hop_delay * 1000.0
             << "ms > Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms"
             << " AND π_delay(u)=⊥ (ZKP timing proof fails)"
             << " on safety-critical flow " << flow_id
             << " sender node " << sender_sim_index
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        // Bucket is S2's OWN designated variant (1 = Attack 2, Selective Delay
        // DP), NOT active_attack_variant — same misattribution fix as S1
        // (see s1_detection.h). main.tex: "one primary signature per variant."
        const int S2_HOME_VARIANT = 1;   // Attack 2, per main.tex Signature S2
        if (sender_sim_index < (uint32_t)total_size &&
            !is_detected_node[S2_HOME_VARIANT][sender_sim_index])
        {
            record_detection_event(S2_HOME_VARIANT, sender_sim_index);
            cout << "[S2] record_detection_event fired for node "
                 << sender_sim_index << " variant=" << S2_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    if (DETECTION_DEBUG_LOG_S2)
        cout << "[S2] No violation: hop_delay=" << hop_delay * 1000.0
             << "ms within Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms" << endl;
    return false;
}

#endif // S2_DETECTION_H
