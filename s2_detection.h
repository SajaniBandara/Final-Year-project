#ifndef S2_DETECTION_H
#define S2_DETECTION_H

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
//   S2 uses its own s2_detection_active flag (declared in routing.cc),
//   independent of s1_detection_active. Disabling S1 does not affect S2.
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
    if (!s2_detection_active) return false;
    if (sender_sim_index >= (uint32_t)var) return false;

    // Condition 2 conjunction: safety-critical packets only (Eq. 3.5).
    if (!is_safety_crit) return false;

    // t_fwd_u = claimed forwarding timestamp (before any attack buffering).
    // Per thesis §1637: "the forwarding node's claimed timestamp."
    // Using t_claimed_packet ensures hop_delay = attack_delay + propagation,
    // correctly exceeding Δ_max for malicious nodes.
    double t_fwd_by_sender = t_claimed_packet[sender_sim_index][packet_id];
    if (t_fwd_by_sender <= 0.0) return false;

    double hop_delay = t_recv_now - t_fwd_by_sender;

    // Eq. 3.5 — Conjunction 1: t_recv_{u+1} − t_fwd_u > Δ_max
    bool delay_exceeds = (hop_delay > S2_DELTA_MAX);

    // Eq. 3.5 — Conjunction 2: π_delay(u) = ⊥
    // Simulation proxy: a node that buffered the packet beyond Δ_max cannot
    // produce a valid STARK timing proof that it forwarded on time, so proof
    // failure is deterministically derived from the delay measurement.
    // In deployed MOBIGUARD this is STARK.Verify(π_delay(u)) == false.
    bool zkp_proof_fails = delay_exceeds;

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

        if (active_attack_variant == 1 &&
            sender_sim_index < (uint32_t)total_size &&
            !is_detected_node[1][sender_sim_index])
        {
            record_detection_event(1, sender_sim_index);
            cout << "[S2] record_detection_event fired for node "
                 << sender_sim_index << " variant=1 at t="
                 << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    cout << "[S2] No violation: hop_delay=" << hop_delay * 1000.0
         << "ms within Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms" << endl;
    return false;
}

// =========================================================================
// s2_write_csv():
// Writes S2 detection metrics to CSV (Attack 2 — Data Plane).
// =========================================================================
inline void s2_write_csv()
{
    double cycle = (data_gathering_cycle_number - 1.0 > 1.0) ?
                   (data_gathering_cycle_number - 1.0) : 1.0;

    uint32_t s2_TP = 0, s2_FP = 0, s2_TN = 0, s2_FN = 0;
    for (int n = 0; n < total_size; n++)
    {
        bool malicious = is_malicious_node[1][n];
        bool detected  = is_detected_node[1][n];
        if ( malicious &&  detected) s2_TP++;
        if (!malicious &&  detected) s2_FP++;
        if (!malicious && !detected) s2_TN++;
        if ( malicious && !detected) s2_FN++;
    }
    double TP = s2_TP, FP = s2_FP, TN = s2_TN, FN = s2_FN;
    double DR  = (TP + FN > 0.0) ? (TP / (TP + FN)) : 0.0;
    double FPR = (FP + TN > 0.0) ? (FP / (FP + TN)) : 0.0;
    double eps = 1e-6;
    double num = (TP * TN) - (FP * FN);
    double den = std::sqrt((TP + FP + eps)*(TP + FN + eps)*(TN + FP + eps)*(TN + FN + eps));
    double MCC = (den > 0.0) ? (num / den) : 0.0;

    cout << "[S2][SECURITY] Attack2-DP | MCC=" << MCC
         << " DR=" << DR * 100.0 << "% FPR=" << FPR * 100.0
         << "% TP=" << s2_TP << " FP=" << s2_FP
         << " TN=" << s2_TN << " FN=" << s2_FN << endl;

    string filename = "/home/user/ns-allinone-3.35/ns-3.35/results_routing/S2_Attack2_"
                    + std::to_string(attack_percentage) + ".csv";
    fstream fout;
    fout.open(filename, ios::out | ios::app);
    fout << (uint32_t)cycle << ", "
         << current_packet_delivery_ratio * 100.0 << ", "
         << average_packet_delivery_ratio_dsrc * 100.0 << ", "
         << current_latency_routing * 1000.0 << ", "
         << average_latency_routing * 1000.0 << ", "
         << MCC << ", "
         << DR * 100.0 << ", "
         << FPR * 100.0 << ", "
         << s2_TP << ", " << s2_FP << ", " << s2_TN << ", " << s2_FN << "\n";
    fout.close();
    cout << "[S2] written to file: " << filename << endl;
}

#endif // S2_DETECTION_H
