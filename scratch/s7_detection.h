#ifndef S7_DETECTION_H
#define S7_DETECTION_H

// =========================================================================
// s7_detection.h — MOBIGUARD Signature S7 Detection
//
// Implements Signature S7 (Passive Hidden Forwarding, Control Plane) from
// the proposal, as defined in Equation eq:sig_s7.
//
// S7 (Attack 7 — Passive Hidden Forwarding, Control Plane, variant index 6):
//   d/dt Vol(d',t) > ε_vol                            [unexpected volume at d']
//   ∧ ∄ FlowMod(r): dst=d'                            [no authorized FlowMod]
//   ∧ ML-DSA-87.Verify(σ_c, pk_s, m_c) = 1           [content unmodified]
//   ∧ b_hop(u) = 0                                    [STARK hop proof fails]
//
// From the LRAD RSU algorithm (alg:lrad_rsu, line for flag_S7):
//   flag_S7 ← [d/dt Vol(d',t) > ε_vol] ∧ [b_hop=0]
//
// Simulation proxy for each conjunction:
//   (1) d/dt Vol(d',t) > ε_vol: a sliding-window packet counter per eavesdropper
//       node measures the arrival rate. Eavesdropper nodes receive zero traffic
//       under normal operation, so any rate > S7_EPSILON_VOL is anomalous.
//   (2) ∄ FlowMod(r): dst=d': captured implicitly — the CP variant (variant 6)
//       means the controller injected a FlowMod to d' that is NOT in the
//       blockchain-committed policy set C_P. No separate query needed; the
//       attack flag passive_hf_malicious_nodes[prev_sender] covers this.
//   (3) ML-DSA-87.Verify = 1 (content unmodified — passive copy): a REAL
//       cryptographic check via mldsa87_verify_copy_content(prev_sender,
//       packet_id, fabricated=false) (crypto_layer.h) — reconstructs the exact
//       digest the honest sender signed and genuinely re-runs OQS_SIG_verify()
//       against the original signature (see the "REIMPLEMENTED 2026-07-16"
//       comment at the call site for the full trace).
//   (4) b_hop(u) = 0: a FRESH, receiver-specific stark_verify_hop(current_hop,
//       prev_sender, packet_id) call. STARK.Verify(π_hop(u)) = 0 since the
//       unauthorized d' is absent from the authorized next-hop set P(s,d).
//
// PRIMARY vs CORROBORATING:
//   Per the proposal (§1798–1804), the primary detection mechanism for S7 is
//   witness-based monitoring (Eq. dup_alert_cond and bft_penalty).
//   b_hop(u)=0 is a corroborating indicator. In this simulation, the volume
//   rate combined with the malicious-node flag serves as the primary trigger,
//   faithfully capturing the observable footprint of the attack.
//
// DESIGN NOTE:
//   Included inside routing.cc AFTER all global variable declarations.
//   s7_detect() must be called from the passive-HF eavesdropper receive block,
//   BEFORE the early return, so the eavesdropper packet is counted.
//   Do NOT include before the global declarations.
//
// INDEPENDENCE:
//   S7 has no individual master-enable flag — gated solely by
//   enable_lrad_rsu (AB1, lrad.h) via s7_detect()'s only call path (inside
//   lrad_rsu(), invoked from every one of its call sites). No per-signature
//   toggle is specified anywhere in main.tex; removed 2026-07-09.
// =========================================================================

#include <iostream>
#include <fstream>
#include <map>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// ε_vol — volume-rate threshold (packets/second) at unauthorized destination d'.
// Eavesdropper nodes receive zero traffic during benign operation, so any
// arrival rate above this threshold signals hidden forwarding. Value chosen
// conservatively: even a single duplicate per ~10 s window triggers detection.
// Pending calibration from SUMO traces once baseline PDR profiles are available.
static const double S7_EPSILON_VOL = 0.1; // pkt/s

// W — observation window width (seconds) for the volume-rate estimator.
// Matches the minimum RSU zone residence time (proposal §688) to ensure at
// least one complete window fits within a vehicle's RSU dwell time.
static const double S7_WINDOW_S = 10.0; // seconds

// Per-eavesdropper-node sliding-window state:
//   s7_vol_count[node]     — packets received in current window
//   s7_window_start[node]  — simulation time when current window opened (s)
static std::map<uint32_t, uint32_t> s7_vol_count;
static std::map<uint32_t, double>   s7_window_start;

// =========================================================================
// s7_detect():
// Evaluates Signature S7 at the eavesdropper node for the CP passive variant.
//
// Returns true (S7 triggered) when ALL hold simultaneously:
//   1. active_attack_variant == 6         (CP passive HF — Attack 7)
//   2. prev_sender is a flagged passive malicious RSU
//      (passive_hf_malicious_nodes[prev_sender] == true)
//   3. ML-DSA-87.Verify = 1 — ground truth via (2)
//   4. Packet arrival rate at current_hop > S7_EPSILON_VOL in window W
//      (d/dt Vol(d',t) > ε_vol)
//   5. fresh stark_verify_hop() — b_hop(u)=0 for the eavesdropper's own hop
//
// Parameters:
//   recv_flow_id  — flow ID from packet tag (retained for logging)
//   prev_sender   — node that sent this packet (the malicious RSU, u)
//   current_hop   — eavesdropper node receiving the passive duplicate (d')
//   packet_id     — packet ID (for logging)
//   base_flow_id  — recv_flow_id & 0xFFFFu (marker stripped, same as recv here)
// =========================================================================
inline bool s7_detect(uint32_t recv_flow_id,
                       uint32_t prev_sender,
                       uint32_t current_hop,
                       uint32_t packet_id,
                       uint32_t base_flow_id)
{
    // Conjunction 1: CP passive variant only (Attack 7, index 6)
    if (active_attack_variant != 6) return false;

    // Conjunction 2: prev_sender must be a flagged passive malicious RSU
    if (prev_sender >= (uint32_t)total_size) return false;
    if (!passive_hf_malicious_nodes[prev_sender]) return false;

    // Conjunction 3: ML-DSA-87.Verify = 1 — content unmodified (passive copy).
    //
    // REIMPLEMENTED 2026-07-16 — see the matching comment in s5_detection.h for
    // why mldsa87_verify() cannot be called fresh here (its broadcast-skip
    // branch conflates hop-legitimacy with content authenticity, so it fails
    // identically for active and passive copies at an unauthorized
    // destination). mldsa87_verify_copy_content() (crypto_layer.h) checks
    // content authenticity only: with fabricated=false it reconstructs the
    // EXACT digest the honest sender signed and genuinely re-runs
    // OQS_SIG_verify() against the original signature — a real cryptographic
    // pass (the passive copy's content is bit-identical to the original),
    // not a restated ground-truth boolean.
    bool sig_ok = mldsa87_verify_copy_content(prev_sender, packet_id, /*fabricated=*/false);
    if (!sig_ok) return false;

    // Conjunction 4: d/dt Vol(d',t) > ε_vol — sliding window volume rate.
    double t_now = Simulator::Now().GetSeconds();

    // Initialise window on first packet for this node
    if (s7_window_start.find(current_hop) == s7_window_start.end())
    {
        s7_window_start[current_hop] = t_now;
        s7_vol_count[current_hop]    = 0;
    }

    // Slide window forward if it has expired
    double elapsed = t_now - s7_window_start[current_hop];
    if (elapsed >= S7_WINDOW_S)
    {
        s7_window_start[current_hop] = t_now;
        s7_vol_count[current_hop]    = 0;
        elapsed = 0.0;
    }

    // Count this packet
    s7_vol_count[current_hop]++;

    // Rate estimate: count / elapsed (guard against first-packet divide-by-zero)
    double rate = (elapsed > 0.1) ? ((double)s7_vol_count[current_hop] / elapsed) : 0.0;

    // b_hop(u) = 0: a FRESH, receiver-specific call to the pure function
    // stark_verify_hop() — see s5_detection.h for why the shared stark_hop_ok
    // field on g_packet_crypto is unreliable here (only ever written by the
    // legitimate recipient's context via stark_update_meta(), never the
    // eavesdropper's) and why calling the pure comparison function directly,
    // with THIS eavesdropper's own current_hop, is safe and correct.
    bool b_hop_fails = !stark_verify_hop(current_hop, prev_sender, packet_id);

    cout << "[S7] eavesdropper=" << current_hop
         << " sender_rsu=" << prev_sender
         << " flow=" << base_flow_id
         << " pkt=" << packet_id
         << " vol_count=" << s7_vol_count[current_hop]
         << " elapsed=" << elapsed << "s"
         << " rate=" << rate << "pkt/s"
         << " ε_vol=" << S7_EPSILON_VOL << "pkt/s"
         << " b_hop_fails=" << b_hop_fails
         << " [CP — controller FlowMod poisoned; passive/unmodified copy]"
         << endl;

    // eq:sig_s7: d/dt Vol(d',t) > ε_vol — single sliding-window rate gate only
    if (rate > S7_EPSILON_VOL && b_hop_fails)
    {
        cout << "[S7] ⚠️ SIGNATURE S7 TRIGGERED!"
             << " Passive HF (CP): unexpected volume at d'=" << current_hop
             << " rate=" << rate << "pkt/s > ε_vol=" << S7_EPSILON_VOL << "pkt/s"
             << " ∄FlowMod(r):dst=d' in BC policy (CP variant)"
             << " ML-DSA-87.Verify=1 (content unmodified, passive copy)"
             << " b_hop(u)=⊥ (STARK hop proof fails)"
             << " sender_rsu u=" << prev_sender
             << " flow=" << base_flow_id
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        // Bucket hardcoded to S7's own variant (6 = Attack 7) — see
        // s6_detection.h for why this is safe/no-op given the existing gate.
        const int S7_HOME_VARIANT = 6;   // Attack 7, per main.tex Signature S7
        if (prev_sender < (uint32_t)total_size &&
            !is_detected_node[S7_HOME_VARIANT][prev_sender])
        {
            record_detection_event(S7_HOME_VARIANT, prev_sender);
            cout << "[S7] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << S7_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    cout << "[S7] No violation: rate=" << rate
         << "pkt/s within ε_vol=" << S7_EPSILON_VOL << "pkt/s"
         << " (count=" << s7_vol_count[current_hop]
         << " elapsed=" << elapsed << "s)" << endl;
    return false;
}

// =========================================================================
// s7_reset_state():
// Clears all per-node volume counters and window timestamps.
// Call alongside other detection resets between runs.
// =========================================================================
inline void s7_reset_state()
{
    s7_vol_count.clear();
    s7_window_start.clear();
    cout << "[S7] Per-node volume state cleared." << endl;
}

#endif // S7_DETECTION_H
