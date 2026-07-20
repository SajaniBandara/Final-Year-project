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
//   S1 has no individual master-enable flag — gated solely by
//   enable_lrad_obu (AB1, lrad.h), matching main.tex's only mode-level
//   ablation for this part of the architecture. No per-signature toggle is
//   specified anywhere in main.tex; removed 2026-07-09.
// =========================================================================

#include <iostream>
#include <cmath>
#include <fstream>
#include <vector>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// =========================================================================
// S1 per-RSU state — mobility-adjusted baseline and EWMA variance
// =========================================================================

// ── S1 parameters — ALL VALUES ARE INITIAL CANDIDATES, NOT VALIDATED FINALS ──
// The thesis marks δ₀, α_ρ, α_v as pending least-squares regression against
// benign SUMO mobility traces, and β, k as pending grid-search validation
// (thesis §3473–3479, §3485). Results produced with these values are
// preliminary. Update each constant once the corresponding calibration or
// grid-search sweep has been completed.

// δ₀ — baseline intercept (seconds). Eq. 3.11.
// Pending: least-squares regression on benign (0% attack) SUMO traces.
// Initial estimate: 2 ms — typical DSRC propagation + MAC overhead at zero load.
// Calibrated 2026-07-05 via OLS on 27,795 benign rows (5 seeds × 148 cycles × 64 RSUs).
// rule_calibrator.py steps: OLS → β sweep {0.7,0.8,0.9,0.95} → k sweep {1,2,3} → robustness ±30%.
// R²=0.0004: α_ρ and α_v are near-zero — delay in NS-3 DSRC is dominated by crypto/routing
// overhead rather than vehicle density/speed; baseline effectively collapses to δ₀.
double s1_delta0    = 0.00197594;   // s  — OLS intercept (≈1.976 ms)
double s1_alpha_rho = 5.2e-07;      // s/vehicle — density term (near-zero, kept for completeness)
double s1_alpha_v   = 1.237e-05;    // s²/m — speed term (near-zero, kept for completeness)
double s1_k         = 3.0;          // sigma multiplier — k sweep: smallest k with FPR ≤ 1%
double s1_beta      = 0.7;          // EWMA factor — β sweep: fastest σ²(t) convergence in 9s window

// Per-RSU EWMA baseline and variance, indexed by RSU index (0..N_RSUs-1).
// Sized dynamically at runtime by s1_init_state(N_RSUs) — no hardcoded ceiling.
std::vector<double>   s1_delta_bar;     // δ̄_r(t): mobility-adjusted baseline per RSU
std::vector<double>   s1_sigma2;        // σ²_r(t): EWMA variance per RSU

// Per-RSU observed-delay accumulators for the EWMA input δ_r(t) (Eq. 3.12).
// Accumulated inside s1_detect_packet() for every valid packet; drained
// and reset at each s1_update_baseline() call site in routing.cc.
std::vector<double>   s1_rsu_obs_sum;
std::vector<uint32_t> s1_rsu_obs_count;

// =========================================================================
// s1_update_baseline():
// Updates the mobility-adjusted baseline δ̄_r(t) for one RSU (Eq. 3.11).
// σ²_r(t) is NOT updated here — see s1_detect_packet() below for why.
//
//   rsu_idx       — RSU index (0..N_RSUs-1), NOT the ns-3 node ID
//   rho_t         — current vehicle density ρ(t) for this RSU
//   v_bar_t       — current mean vehicle speed v̄(t) in m/s
//   observed_delay — δ_r(t): last cycle-averaged forwarding delay (seconds),
//                    used only for the LSTM per-cycle delta_t log column
//                    (see routing.cc call site) — NOT for σ² (see below).
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
    (void)observed_delay;   // no longer feeds sigma2 here — see s1_detect_packet()
}

// =========================================================================
// s1_detect_packet():
// Evaluates Signature S1 for one packet at one RSU (Eq. 3.4 / 3.14).
//
// Returns true when BOTH hold:
//   1. δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)   [delay threshold violation]
//   2. Priority(p) = HIGH                   [safety-critical packet only]
//
//   rsu_idx        — RSU index (0..N_RSUs-1), derived from current_hop
//   packet_delay_s — t_recv - t_claimed_fwd for this hop (seconds)
//   is_safety_crit — Priority(p) = HIGH
//   sender_node_id — sim index of the node that SENT this packet (the RSU
//                    that applied the injected delay — this is the malicious
//                    node to record in the detection event, NOT current_hop)
//   current_hop    — receiving RSU node ID (for EWMA baseline and logging)
//   packet_id      — packet ID (for logging)
//   flow_id        — flow ID (for logging)
// =========================================================================
inline bool s1_detect_packet(uint32_t rsu_idx,
                              double   packet_delay_s,
                              bool     is_safety_crit,
                              uint32_t sender_node_id,
                              uint32_t current_hop,
                              uint32_t packet_id,
                              uint32_t flow_id)
{
    if (rsu_idx >= (uint32_t)N_RSUs) return false;

    // Condition 2: Priority(p) = HIGH — mandatory conjunction (Eq. 3.4)
    if (!is_safety_crit) return false;

    double delta_bar = s1_delta_bar[rsu_idx];
    double sigma     = std::sqrt(s1_sigma2[rsu_idx]);
    double threshold = delta_bar + s1_k * sigma;

    // Accumulate observed hop-delay for the LSTM per-cycle delta_t log column
    // (cycle-averaged; see s1_update_baseline()'s call site in routing.cc).
    // UNCONDITIONAL regardless of training mode — same "no only-if-compliant
    // clause" reasoning as below.
    if (packet_delay_s > 0.0)
    {
        s1_rsu_obs_sum[rsu_idx]   += packet_delay_s;
        s1_rsu_obs_count[rsu_idx] += 1;
    }

    // Eq. 3.12/3.13: σ²_r(t) = β·σ²_r(t-1) + (1-β)·(δ_r(t)-δ̄_r(t))², updated
    // from THIS packet's raw delay δ_p (packet_delay_s), not a cycle-averaged
    // proxy. Eq. 3.14's own comparand is δ_p (per-packet), so σ_r(t) must be
    // estimated from the same per-packet population it is compared against.
    // The previous version fed σ² from the cycle-AVERAGED obs_delay once per
    // cycle (s1_update_baseline()) while s1_detect_packet() compared raw
    // per-packet delays against the resulting threshold — averaging N packets
    // shrinks variance by ~1/N (Var(mean)=Var(x)/N), so the threshold's k·σ
    // margin was calibrated ~sqrt(N) too tight for what it was actually being
    // tested against. Confirmed: 11,193 S1 triggers in a single 38-cycle/40s
    // run (FPR 28-50%, target ≤1%) collapsed to a normal firing rate once σ²
    // was switched to this per-packet estimate.
    // Kept UNCONDITIONAL (updates on every packet, including violations) for
    // the same reason as before: excluding violating packets from the update
    // created a self-reinforcing feedback loop where a shrinking σ excludes
    // more packets, shrinking σ further with no floor — confirmed via FP
    // climbing continuously across an entire benign-only run rather than
    // plateauing after warmup.
    double deviation = packet_delay_s - delta_bar;
    s1_sigma2[rsu_idx] = s1_beta * s1_sigma2[rsu_idx]
                       + (1.0 - s1_beta) * deviation * deviation;

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

        // Record detection against the SENDER (the RSU that applied the delay),
        // not current_hop (the innocent receiver). is_malicious_node[0] is set
        // on the sending RSU under the compromised controller — recording
        // current_hop would produce a FP (benign receiver) and FN (malicious
        // sender missed), corrupting TP/FP/TN/FN counts.
        //
        // Bucket is S1's OWN designated variant (0 = Attack 1, Selective Delay
        // CP), NOT active_attack_variant. main.tex Attack Signature
        // Identification (line ~1722): "We derive one primary signature per
        // variant" — S1 is permanently Attack 1's signature regardless of
        // which attack_number the CLI selected for this run. S1 has no
        // variant gate (evaluates every safety-critical packet unconditionally,
        // matching tcam_detection.h's S3/S4 precedent), so using
        // active_attack_variant here misattributed every S1 firing into
        // whichever OTHER attack's confusion matrix was being measured —
        // confirmed 2026-07-14: S1 contributed 22 of 221 detection events
        // recorded into Attack 6's own bucket during an A6-only run.
        const int S1_HOME_VARIANT = 0;   // Attack 1, per main.tex Signature S1
        if (sender_node_id < (uint32_t)total_size &&
            !is_detected_node[S1_HOME_VARIANT][sender_node_id])
        {
            record_detection_event(S1_HOME_VARIANT, sender_node_id);
            cout << "[S1] record_detection_event fired for sender node "
                 << sender_node_id << " (detected at RSU " << current_hop
                 << ") variant=" << S1_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    cout << "[S1] No violation: delay " << packet_delay_s * 1000.0
         << "ms within threshold " << threshold * 1000.0 << "ms" << endl;
    return false;
}

// =========================================================================
// s1_init_state():
// Allocates and zero-initialises all per-RSU S1 vectors to exactly n_rsus
// entries. Must be called once after N_RSUs is finalised (i.e. from
// initialise_stub_attack_state() in routing.cc), before any detection or
// baseline-update calls.
// =========================================================================
inline void s1_init_state(uint32_t n_rsus)
{
    // Seed delta_bar from eq:mobility_baseline's own intercept (delta_0),
    // NOT 0.0. delta_bar_r(t) = delta_0 + alpha_rho*rho(t) + alpha_v*v_bar(t)^-1
    // is a closed-form formula computable at any t, including t=0 -- it is
    // not a "starts empty, learns over time" accumulator. delta_0 alone is
    // an accurate seed here since alpha_rho/alpha_v are calibrated near-zero
    // (R^2=0.0004, see the calibration note above -- "baseline effectively
    // collapses to delta_0"). Leaving this at 0.0 previously made the very
    // first packets face threshold=delta_bar+k*sigma=0, so any nonzero delay
    // trivially "violated" it -- a confirmed false-positive source (280 of
    // 719 S1 triggers in one 0%-attack run showed baseline=0.000ms). sigma2
    // legitimately starts at 0.0: eq:ewma_variance is a recursive update
    // that needs a seed, and "no prior variance information" is the
    // standard EWMA bootstrap convention, unlike delta_bar which has no
    // such recursion to justify starting from zero.
    s1_delta_bar.assign(n_rsus, s1_delta0);
    s1_sigma2.assign(n_rsus, 0.0);
    s1_rsu_obs_sum.assign(n_rsus, 0.0);
    s1_rsu_obs_count.assign(n_rsus, 0);
    cout << "[S1] S1 per-RSU state initialised for " << n_rsus << " RSUs "
         << "(delta_bar seeded to delta_0=" << s1_delta0 * 1000.0 << "ms)." << endl;
}

// =========================================================================
// s1_reset_state():
// Zeros all per-RSU S1 state without reallocating (for mid-run resets).
// Requires s1_init_state() to have been called first.
// =========================================================================
inline void s1_reset_state()
{
    // See s1_init_state() for why delta_bar is seeded to s1_delta0, not 0.0.
    std::fill(s1_delta_bar.begin(),     s1_delta_bar.end(),     s1_delta0);
    std::fill(s1_sigma2.begin(),        s1_sigma2.end(),        0.0);
    std::fill(s1_rsu_obs_sum.begin(),   s1_rsu_obs_sum.end(),   0.0);
    std::fill(s1_rsu_obs_count.begin(), s1_rsu_obs_count.end(), 0u);
    cout << "[S1] All S1 per-RSU baseline/variance state reset "
         << "(delta_bar seeded to delta_0=" << s1_delta0 * 1000.0 << "ms)." << endl;
}

#endif // S1_DETECTION_H
