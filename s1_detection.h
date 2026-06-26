#ifndef S1_DETECTION_H
#define S1_DETECTION_H

// =========================================================================
// s1_detection.h — MOBIGUARD Signature S1 Detection
//
// Implements Signature S1 (Selective Time Delay, Control Plane) from the
// proposal, as defined in Equations 3.4, 3.11, 3.12, 3.13, 3.14.
//
// S1 (Attack 1 — Selective Time Delay, Control Plane):
//   δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)  ∧  Priority(p) = HIGH
//   Eq. 3.4, §1608–1627
//   Detection uses a per-RSU mobility-adjusted baseline delay (Eq. 3.11)
//   and an EWMA variance estimator (Eq. 3.12/3.13).
//
// DESIGN NOTE:
//   This header is included inside routing.cc AFTER all global variables
//   have been declared, so it reads globals directly without externs (same
//   pattern as tap_detection.h and s2_detection.h). Do not include it
//   before the global declarations.
//
// INDEPENDENCE:
//   S1 uses its own s1_detection_active flag (declared in routing.cc),
//   independent of s2_detection_active. Disabling S2 does not affect S1.
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

// Baseline intercept δ₀ (static propagation baseline, seconds).
// Calibrated from benign (0% attack) SUMO traces via least-squares regression.
// Initial value: 2 ms — typical DSRC propagation + MAC overhead at zero load.
double s1_delta0 = 0.002;

// Density sensitivity coefficient α_ρ (s per vehicle). Eq. 3.11.
// Initial: 0.0001 s/vehicle (0.1 ms per additional vehicle).
double s1_alpha_rho = 0.0001;

// Speed sensitivity coefficient α_v (s²/m). Eq. 3.11.
// Initial: 0.05.
double s1_alpha_v = 0.05;

// Standard-deviation multiplier k for the S1 threshold (Eq. 3.14).
// Initial candidate k=3 (three-sigma rule) per proposal §3485.
double s1_k = 3.0;

// EWMA forgetting factor β ∈ (0,1) for the variance estimator (Eq. 3.12).
// Initial: 0.9.
double s1_beta = 0.9;

// Per-RSU EWMA baseline and variance, indexed by RSU index (0..N_RSUs-1).
double s1_delta_bar[300] = {0.0};   // δ̄_r(t): mobility-adjusted baseline per RSU
double s1_sigma2[300]    = {0.0};   // σ²_r(t): EWMA variance per RSU

// Per-RSU observed-delay accumulators for the EWMA input δ_r(t) (Eq. 3.12).
// Accumulated inside s1_detect_packet() for every valid packet; drained
// and reset at each s1_update_baseline() call site in routing.cc.
double   s1_rsu_obs_sum[300]   = {0.0};
uint32_t s1_rsu_obs_count[300] = {0};

// =========================================================================
// s1_update_baseline():
// Updates the mobility-adjusted baseline for one RSU (Eq. 3.11/3.12/3.13).
//
//   rsu_idx       — RSU index (0..N_RSUs-1), NOT the ns-3 node ID
//   rho_t         — current vehicle density ρ(t) for this RSU
//   v_bar_t       — current mean vehicle speed v̄(t) in m/s
//   observed_delay — δ_r(t): last measured baseline forwarding delay (seconds)
// =========================================================================
inline void s1_update_baseline(uint32_t rsu_idx,
                                double   rho_t,
                                double   v_bar_t,
                                double   observed_delay)
{
    if (rsu_idx >= (uint32_t)N_RSUs) return;

    // Eq. 3.11: δ̄_r(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
    double inv_v = (v_bar_t > 0.1) ? (1.0 / v_bar_t) : 10.0;
    s1_delta_bar[rsu_idx] = s1_delta0 + s1_alpha_rho * rho_t + s1_alpha_v * inv_v;

    // Eq. 3.12/3.13: σ²_r(t) = β·σ²_r(t-1) + (1-β)·(δ_r(t) − δ̄_r(t))²
    double deviation = observed_delay - s1_delta_bar[rsu_idx];
    s1_sigma2[rsu_idx] = s1_beta * s1_sigma2[rsu_idx]
                       + (1.0 - s1_beta) * deviation * deviation;
}

// =========================================================================
// s1_detect_packet():
// Evaluates Signature S1 for one packet at one RSU (Eq. 3.4 / 3.14).
//
// Returns true when BOTH hold:
//   1. δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)   [delay threshold violation]
//   2. Priority(p) = HIGH                   [safety-critical packet only]
//
//   rsu_idx        — RSU index (0..N_RSUs-1)
//   packet_delay_s — t_recv - t_claimed_fwd for this hop (seconds)
//   is_safety_crit — Priority(p) = HIGH
//   current_hop    — receiving RSU node ID (for logging)
//   packet_id      — packet ID (for logging)
//   flow_id        — flow ID (for logging)
// =========================================================================
inline bool s1_detect_packet(uint32_t rsu_idx,
                              double   packet_delay_s,
                              bool     is_safety_crit,
                              uint32_t current_hop,
                              uint32_t packet_id,
                              uint32_t flow_id)
{
    if (!s1_detection_active) return false;
    if (rsu_idx >= (uint32_t)N_RSUs) return false;

    // Accumulate observed hop-delay for δ_r(t) (Eq. 3.12/3.13), before the SC
    // guard so the EWMA baseline tracks all traffic at this RSU, not only SC.
    if (packet_delay_s > 0.0)
    {
        s1_rsu_obs_sum[rsu_idx]   += packet_delay_s;
        s1_rsu_obs_count[rsu_idx] += 1;
    }

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
// s1_reset_state():
// Resets all per-RSU S1 baseline and variance to zero for a fresh run.
// =========================================================================
inline void s1_reset_state()
{
    for (int r = 0; r < 300; r++)
    {
        s1_delta_bar[r]    = 0.0;
        s1_sigma2[r]       = 0.0;
        s1_rsu_obs_sum[r]  = 0.0;
        s1_rsu_obs_count[r] = 0;
    }
    cout << "[S1] All S1 per-RSU baseline/variance state reset." << endl;
}

// =========================================================================
// s1_write_csv():
// Writes S1 detection metrics to CSV (Attack 1 — Control Plane).
// =========================================================================
inline void s1_write_csv()
{
    double cycle = (data_gathering_cycle_number - 1.0 > 1.0) ?
                   (data_gathering_cycle_number - 1.0) : 1.0;

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

#endif // S1_DETECTION_H
