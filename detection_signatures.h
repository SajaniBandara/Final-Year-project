#ifndef DETECTION_SIGNATURES_H
#define DETECTION_SIGNATURES_H

// =========================================================================
// detection_signatures.h — MOBIGUARD Selective Time Delay Detection
//
// Implements Signatures S1 and S2 from the proposal exactly as defined
// in Equations 3.4, 3.5, 3.11, 3.12, 3.13, 3.14.
//
// S1 (Attack 1 — Selective Time Delay, Control Plane):
//   δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)  ∧  Priority(p) = HIGH
//   Eq. 3.4, §1608–1627
//   Detection uses a per-RSU mobility-adjusted baseline delay (Eq. 3.11)
//   and an EWMA variance estimator (Eq. 3.12/3.13).
//
// S2 (Attack 2 — Selective Time Delay, Data Plane):
//   t_recv_{u+1} − t_fwd_u > Δ_max  ∧  π_delay(u) = ⊥
//   Eq. 3.5, §1632–1648
//   Detection uses the actual recorded forwarding timestamp (t_fwd_packet)
//   at the receiver and compares against Δ_max = 50 ms (proposal §3463,
//   simulation table: "Hop-delay detection threshold = 50 ms").
//
// DESIGN NOTE:
//   This header is included inside routing.cc AFTER all global variables
//   have been declared, so it reads globals directly without externs (same
//   pattern as tap_detection.h and tcam_detection.h). Do not include it
//   before the global declarations.
//
// SEPARATION FROM TAP:
//   TAP (tap_detection.h) is a state-of-the-art baseline from Arsalan &
//   Rehman (FIT 2018) and is implemented faithfully per that paper.
//   S1/S2 here are MOBIGUARD's own proposed detection signatures, distinct
//   from TAP. Both run in parallel; their metrics are reported separately.
// =========================================================================

#include <iostream>
#include <cmath>
#include <fstream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// =========================================================================
// S1 per-RSU state — mobility-adjusted baseline and EWMA variance
// =========================================================================

// Mobility-adjusted baseline delay δ̄_r(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
// Eq. 3.11. One entry per RSU (indexed 0..N_RSUs-1, NOT by node ID).
// Updated at each data-gathering cycle when vehicle density and speed
// estimates are refreshed.

// Baseline intercept δ₀ (static propagation baseline, seconds).
// Calibrated from benign (0% attack) SUMO traces via least-squares regression.
// Initial value: 2 ms — typical DSRC propagation + MAC overhead at zero load.
// CLI: --s1_delta0 (tbd, sweep ±{10,20,30}% per proposal §3464–3468).
double s1_delta0 = 0.002;

// Density sensitivity coefficient α_ρ (s per vehicle).
// Calibrated offline. Initial value: 0.0001 s/vehicle (0.1 ms per additional
// vehicle), consistent with increasing queuing delay at higher density.
// CLI: --s1_alpha_rho (tbd, calibrated from SUMO traces).
double s1_alpha_rho = 0.0001;

// Speed sensitivity coefficient α_v (s·m/s = s²/m).
// Calibrated offline. Larger speed → shorter zone residence → more handoffs
// per second → slightly higher baseline delay. Initial: 0.05.
// CLI: --s1_alpha_v (tbd, calibrated from SUMO traces).
double s1_alpha_v = 0.05;

// Standard-deviation multiplier k for the S1 threshold (Eq. 3.14).
// Rule of thumb: k=3 (three-sigma rule) as the initial candidate per proposal
// §3485. CLI: --s1_k (tbd, sweep {1,2,3}, best MCC at ≤1% FPR).
double s1_k = 3.0;

// EWMA forgetting factor β ∈ (0,1) for the variance estimator (Eq. 3.12).
// β closer to 1 → slower adaptation (more history weight).
// β closer to 0 → faster adaptation (prioritises recent observations).
// Initial: 0.9. CLI: --s1_beta (tbd, sweep {0.7, 0.8, 0.9, 0.95}).
double s1_beta = 0.9;

// Per-RSU EWMA baseline and variance, indexed by RSU index (0..N_RSUs-1).
// Initialised to 0 before the first cycle; updated in s1_update_baseline().
double s1_delta_bar[300] = {0.0};   // δ̄_r(t): mobility-adjusted baseline per RSU
double s1_sigma2[300]    = {0.0};   // σ²_r(t): EWMA variance per RSU

// S2 threshold Δ_max (seconds).
// Proposal §3463 + simulation table: "Hop-delay detection threshold = 50 ms".
// Matches delta_max_s2 in routing.cc; reproduced here for clarity.
static const double S2_DELTA_MAX = 0.050; // 50 ms

// =========================================================================
// S1 helper: update mobility-adjusted baseline for one RSU
// Called once per data-gathering cycle for each RSU after vehicle density
// and mean speed have been computed from the SUMO mobility trace.
//
// Parameters:
//   rsu_idx      — RSU index (0..N_RSUs-1), NOT the ns-3 node ID
//   rho_t        — current vehicle density ρ(t) (vehicles active in network)
//   v_bar_t      — current mean vehicle speed v̄(t) in m/s; if 0, treated as
//                  very slow (to avoid division by zero)
//   observed_delay — δ_r(t): last measured baseline forwarding delay for this
//                  RSU during the benign window (seconds). Used for EWMA.
// =========================================================================
inline void s1_update_baseline(uint32_t rsu_idx,
                                double   rho_t,
                                double   v_bar_t,
                                double   observed_delay)
{
    if (rsu_idx >= (uint32_t)N_RSUs) return;

    // Eq. 3.11: δ̄_r(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
    double inv_v = (v_bar_t > 0.1) ? (1.0 / v_bar_t) : 10.0; // cap at 10 s/m
    s1_delta_bar[rsu_idx] = s1_delta0 + s1_alpha_rho * rho_t + s1_alpha_v * inv_v;

    // Eq. 3.12/3.13 (EWMA variance):
    // σ²_r(t) = β·σ²_r(t-1) + (1-β)·(δ_r(t) − δ̄_r(t))²
    double deviation = observed_delay - s1_delta_bar[rsu_idx];
    s1_sigma2[rsu_idx] = s1_beta * s1_sigma2[rsu_idx]
                       + (1.0 - s1_beta) * deviation * deviation;
}

// =========================================================================
// s1_detect_packet():
// Evaluates Signature S1 for one packet at one RSU (Eq. 3.4 / 3.14).
//
// Returns true (S1 triggered) when BOTH conditions hold:
//   1. δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)   [delay threshold violation]
//   2. Priority(p) = HIGH                   [safety-critical packet only]
//
// Parameters:
//   rsu_idx         — RSU index (0..N_RSUs-1)
//   packet_delay_s  — measured per-hop forwarding delay δ_p(v,r,t) in seconds
//                     = t_recv - t_send for this hop, with both timestamps
//                       anchored to T_ref(t) (Eq. 3.8 / proposal §1856–1865).
//   is_safety_crit  — Priority(p) = HIGH (true for BSM/collision-avoidance flows)
//   current_hop     — node ID of the forwarding RSU (for logging)
//   packet_id       — packet ID (for logging)
//   flow_id         — flow ID (for logging)
// =========================================================================
inline bool s1_detect_packet(uint32_t rsu_idx,
                              double   packet_delay_s,
                              bool     is_safety_crit,
                              uint32_t current_hop,
                              uint32_t packet_id,
                              uint32_t flow_id)
{
    if (!s2_detection_active) return false; // shared enable flag
    if (rsu_idx >= (uint32_t)N_RSUs) return false;

    // Condition 2: Priority(p) = HIGH — mandatory conjunction (Eq. 3.4)
    if (!is_safety_crit) return false;

    double delta_bar = s1_delta_bar[rsu_idx];
    double sigma     = std::sqrt(s1_sigma2[rsu_idx]);
    double threshold = delta_bar + s1_k * sigma;

    cout << "[S1] RSU_idx=" << rsu_idx
         << " node=" << current_hop
         << " flow=" << flow_id
         << " pkt=" << packet_id
         << " delay=" << packet_delay_s * 1000.0 << "ms"
         << " baseline=" << delta_bar * 1000.0 << "ms"
         << " sigma=" << sigma * 1000.0 << "ms"
         << " threshold=" << threshold * 1000.0 << "ms"
         << " [SAFETY-CRITICAL]" << endl;

    // Condition 1: δ_p > δ̄_r(t) + k·σ_r(t)  (Eq. 3.14)
    if (packet_delay_s > threshold)
    {
        cout << "[S1] ⚠️ SIGNATURE S1 TRIGGERED!"
             << " Delay " << packet_delay_s * 1000.0
             << "ms exceeds threshold " << threshold * 1000.0 << "ms"
             << " (baseline=" << delta_bar * 1000.0
             << "ms + " << s1_k << "σ=" << (s1_k * sigma * 1000.0) << "ms)"
             << " on safety-critical flow " << flow_id
             << " at RSU node " << current_hop
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        // Record detection event for variant 0 (Attack 1 CP)
        if (active_attack_variant == 0 &&
            current_hop < (uint32_t)total_size &&
            !is_detected_node[0][current_hop])
        {
            record_detection_event(0, current_hop);
            cout << "[S1] record_detection_event fired for node "
                 << current_hop << " variant=0 at t="
                 << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    cout << "[S1] No violation: delay " << packet_delay_s * 1000.0
         << "ms within threshold " << threshold * 1000.0 << "ms" << endl;
    return false;
}

// =========================================================================
// s2_detect_packet():
// Evaluates Signature S2 for one packet at one intermediate hop (Eq. 3.5).
//
// Returns true (S2 triggered) when BOTH conditions hold:
//   1. t_recv_{u+1} − t_fwd_u > Δ_max      [hop-delay threshold violation]
//   2. π_delay(u) = ⊥                       [ZKP timing proof failure]
//
// In the NS-3 simulation, ZKP proof generation is not fully implemented;
// the proof failure is INFERRED from the delay condition itself — if the
// hop delay exceeds Δ_max, the STARK timing proof would fail in the full
// system (since the proof asserts t_fwd - t_recv ≤ Δ_max). This is a
// faithful simulation of the detectability criterion.
//
// Parameters:
//   sender_sim_index — node index of the forwarding node (u)
//   t_recv_now       — wall-clock reception time at the next hop (seconds)
//   is_safety_crit   — Priority(p) = HIGH; S2 targets safety-critical flows
//                      per the selectivity model (proposal §1268–1269)
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

    // Condition 2 conjunction: Safety-critical packet only.
    // The proposal's S2 targets the same selective attack behaviour as S1;
    // best-effort packets are not delayed by the attack and should not trigger.
    if (!is_safety_crit) return false;

    // Read actual forwarding timestamp recorded by the sender
    // (after any attack-injected delay, so it reflects real wire-departure time)
    double t_fwd_by_sender = t_fwd_packet[sender_sim_index][packet_id];
    if (t_fwd_by_sender <= 0.0) return false; // no valid timestamp yet

    // Condition 1: t_recv − t_fwd > Δ_max  (Eq. 3.5 first conjunction)
    double hop_delay = t_recv_now - t_fwd_by_sender;

    cout << "[S2] sender=" << sender_sim_index
         << " receiver=" << current_hop
         << " flow=" << flow_id
         << " pkt=" << packet_id
         << " hop_delay=" << hop_delay * 1000.0 << "ms"
         << " Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms"
         << " [SAFETY-CRITICAL]" << endl;

    if (hop_delay > S2_DELTA_MAX)
    {
        // Condition 2: π_delay(u) = ⊥ (inferred — the delay itself would
        // cause the STARK timing proof to fail: Eq. 3.5 second conjunction).
        // In the full MOBIGUARD system this would be an explicit STARK.Verify
        // failure. In simulation we infer it from the threshold violation.
        cout << "[S2] ⚠️ SIGNATURE S2 TRIGGERED!"
             << " Hop delay " << hop_delay * 1000.0
             << "ms exceeds Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms"
             << " AND ZKP timing proof would FAIL (π_delay=⊥)"
             << " on safety-critical flow " << flow_id
             << " sender node " << sender_sim_index
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        // Record detection event for variant 1 (Attack 2 DP)
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

    cout << "[S2] No violation: hop_delay " << hop_delay * 1000.0
         << "ms within Δ_max=" << S2_DELTA_MAX * 1000.0 << "ms" << endl;
    return false;
}

// =========================================================================
// s1_reset_state():
// Resets all per-RSU S1 baseline and variance to zero for a fresh run.
// Call from initialise_stub_attack_state() alongside tap_reset_state().
// =========================================================================
inline void s1_reset_state()
{
    for (int r = 0; r < 300; r++)
    {
        s1_delta_bar[r] = 0.0;
        s1_sigma2[r]    = 0.0;
    }
    cout << "[S1] All S1 per-RSU baseline/variance state reset." << endl;
}

// =========================================================================
// s1_write_csv():
// Writes S1 detection metrics to a CSV file, mirroring the write_tap_csv()
// pattern so both baselines (TAP) and proposed method (S1) produce
// comparable output files.
// =========================================================================
inline void s1_write_csv()
{
    double cycle = (data_gathering_cycle_number - 1.0 > 1.0) ?
                   (data_gathering_cycle_number - 1.0) : 1.0;

    // Compute S1 confusion matrix from is_detected_node[0] vs is_malicious_node[0]
    uint32_t s1_TP = 0, s1_FP = 0, s1_TN = 0, s1_FN = 0;
    for (int n = 0; n < total_size; n++)
    {
        bool malicious = is_malicious_node[0][n];
        bool detected  = is_detected_node[0][n];
        if ( malicious &&  detected) s1_TP++;
        if (!malicious &&  detected) s1_FP++;
        if (!malicious && !detected) s1_TN++;
        if ( malicious && !detected) s1_FN++;
    }
    double TP = s1_TP, FP = s1_FP, TN = s1_TN, FN = s1_FN;
    double DR  = (TP + FN > 0.0) ? (TP / (TP + FN)) : 0.0;
    double FPR = (FP + TN > 0.0) ? (FP / (FP + TN)) : 0.0;
    double eps = 1e-6;
    double num = (TP * TN) - (FP * FN);
    double den = std::sqrt((TP + FP + eps)*(TP + FN + eps)*(TN + FP + eps)*(TN + FN + eps));
    double MCC = (den > 0.0) ? (num / den) : 0.0;

    cout << "[S1][SECURITY] Attack1-CP | MCC=" << MCC
         << " DR=" << DR * 100.0 << "% FPR=" << FPR * 100.0
         << "% TP=" << s1_TP << " FP=" << s1_FP
         << " TN=" << s1_TN << " FN=" << s1_FN << endl;

    string filename = "/home/user/ns-allinone-3.35/ns-3.35/results_routing/S1_Attack1_"
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
         << s1_TP << ", " << s1_FP << ", " << s1_TN << ", " << s1_FN << "\n";
    fout.close();
    cout << "[S1] written to file: " << filename << endl;
}

// =========================================================================
// s2_write_csv():
// Writes S2 detection metrics to a CSV file for Attack 2 (DP).
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

#endif // DETECTION_SIGNATURES_H
