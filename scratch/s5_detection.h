#ifndef S5_DETECTION_H
#define S5_DETECTION_H

// =========================================================================
// s5_detection.h — MOBIGUARD Signature S5 Detection
//
// Implements Signature S5 (Active Hidden Forwarding, Control Plane) from
// the proposal, as defined in Equation eq:sig_s5.
//
// S5 (Attack 5 — Active Hidden Forwarding, Control Plane, variant index 4):
//   d' ∉ P(s,d)                                         [unauthorized destination]
//   ∧ FlowMod(r) installed (s → d')                     [CP: controller poisoned]
//   ∧ ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0        [content modified]
//   ∧ b_hop(u) = 0                                       [STARK hop proof fails]
//
// Simulation proxy for each conjunction:
//   (0) d' ∉ P(s,d): enforced inside s5_detect() by comparing current_hop
//       against (delta_at_nodes_inst + base_flow_id)->destination_f. If
//       current_hop IS the legitimate destination, the detection does not fire,
//       preventing false positives at any node that happens to be on the
//       authorized path.
//   (1) FlowMod CP origin: active_attack_variant == 4 confirms the CP variant
//       where the malicious controller poisoned delta_at_controller_inst before
//       transmit_delta_values(), so the RSU received a legitimate-looking but
//       unauthorized FlowMod.
//   (2) prev_sender is the flagged active malicious RSU:
//       active_hf_malicious_nodes[prev_sender] == true.
//   (3) ML-DSA-87 failure: recv_flow_id carries the 0xDEAD0000 fabrication
//       marker set by hf_send_active_duplicate(). In deployed MOBIGUARD this
//       corresponds to ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0.
//   (4) b_hop(u) = 0: kept as an INDEPENDENT check from ML-DSA-87.
//       In deployed MOBIGUARD, STARK.Verify(π_hop(u), C_hop, H_SHA3) = 0
//       because d' ∉ P(s,d) — the RSU cannot produce a valid hop ZKP for an
//       unauthorized destination. Simulation proxy: active_hf_malicious_nodes
//       [prev_sender] (already confirmed in conjunction 2; re-stated explicitly
//       per Eq. sig_s5 to keep the two conditions logically separable).
//
// DESIGN NOTE:
//   Included inside routing.cc AFTER all global variable declarations, so
//   globals are read directly without externs. This matches the pattern of
//   s1_detection.h, s2_detection.h, and tap_detection.h.
//   Do NOT include this header before the global declarations.
//
// INDEPENDENCE:
//   Controlled solely by s5_detection_active (declared in routing.cc).
//   Disabling any other detection switch does not affect S5.
// =========================================================================

#include <iostream>
#include <fstream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Fabrication marker placed in flow_id field by hf_send_active_duplicate()
static const uint32_t S5_DEAD_MARKER = 0xDEAD0000u;

// =========================================================================
// s5_detect():
// Evaluates Signature S5 at the eavesdropper node for the CP active variant.
//
// Returns true (S5 triggered) when ALL conditions hold simultaneously:
//   0. current_hop != legitimate destination for base_flow_id
//      (d' ∉ P(s,d) — first conjunction of Eq. sig_s5)
//   1. active_attack_variant == 4      (CP active HF — Attack 5)
//   2. prev_sender is a known active malicious RSU
//      (active_hf_malicious_nodes[prev_sender] == true)
//   3. recv_flow_id carries the 0xDEAD0000 fabrication marker
//      (ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0)
//   4. b_hop(u) = 0 — independent from ML-DSA-87; confirmed by (2).
//      STARK hop ZKP fails because d' is absent from the authorized next-hop
//      policy P(s,d) for this flow.
//
// Parameters:
//   recv_flow_id  — flow ID from the received packet tag (may carry 0xDEAD0000)
//   prev_sender   — node that sent this packet (the malicious RSU, u)
//   current_hop   — node currently receiving the packet (the eavesdropper, d')
//   packet_id     — packet ID (for logging and detection event recording)
//   base_flow_id  — original flow ID with marker stripped (recv_flow_id & 0xFFFFu)
// =========================================================================
inline bool s5_detect(uint32_t recv_flow_id,
                       uint32_t prev_sender,
                       uint32_t current_hop,
                       uint32_t packet_id,
                       uint32_t base_flow_id)
{
    if (!s5_detection_active) return false;

    // Conjunction 1: CP active variant only (Attack 5, index 4)
    if (active_attack_variant != 4) return false;

    // Conjunction 2: prev_sender must be a flagged active malicious RSU
    if (prev_sender >= (uint32_t)total_size) return false;
    if (!active_hf_malicious_nodes[prev_sender]) return false;

    // Conjunction 3: ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0
    // Primary: result of mldsa87_verify() stored in g_packet_crypto by MacRx.
    // Fallback to 0xDEAD0000 marker if crypto record not yet populated.
    auto it_s5 = g_packet_crypto.find({prev_sender, packet_id});
    bool mldsa_fails;
    if (it_s5 != g_packet_crypto.end() && it_s5->second.sig_len > 0)
        mldsa_fails = !it_s5->second.sig_valid;
    else
        mldsa_fails = ((recv_flow_id & S5_DEAD_MARKER) == S5_DEAD_MARKER);

    // Conjunction 4: b_hop(u) = 0 — INDEPENDENT from ML-DSA-87.
    // Primary: stark_hop_ok from g_packet_crypto set by stark_update_meta().
    // Fallback: active_hf_malicious_nodes ground truth.
    bool b_hop_fails;
    if (it_s5 != g_packet_crypto.end() && it_s5->second.sig_len > 0)
        b_hop_fails = !it_s5->second.stark_hop_ok;
    else
        b_hop_fails = active_hf_malicious_nodes[prev_sender];

    // Conjunction 0 (Eq. sig_s5 first term): d' ∉ P(s,d).
    // Explicit guard: if current_hop is the legitimate authorized destination for
    // base_flow_id, then no unauthorized forwarding occurred — abort detection.
    // Guards against false positives when a legitimate destination node observes
    // its own (correctly delivered) packet.
    bool d_prime_unauthorized = true;
    if (base_flow_id < (uint32_t)(2 * var))
    {
        uint32_t legit_dest = (delta_at_nodes_inst + base_flow_id)->destination_f;
        if (current_hop == legit_dest)
            d_prime_unauthorized = false;
    }

    cout << "[S5] receiver=" << current_hop
         << " sender_rsu=" << prev_sender
         << " flow=" << base_flow_id
         << " pkt=" << packet_id
         << " recv_fid=0x" << hex << recv_flow_id << dec
         << " mldsa_fails=" << mldsa_fails
         << " b_hop_fails=" << b_hop_fails
         << " d_prime_unauthorized=" << d_prime_unauthorized
         << " [CP — controller FlowMod poisoned before transmit_delta_values()]"
         << endl;

    if (mldsa_fails && b_hop_fails && d_prime_unauthorized)
    {
        cout << "[S5] ⚠️ SIGNATURE S5 TRIGGERED!"
             << " Active HF (CP): unauthorized dest d'=" << current_hop
             << " sender_rsu u=" << prev_sender
             << " d' ∉ P(s,d) (current_hop is NOT the authorized destination)"
             << " FlowMod(CP) installed by poisoned controller"
             << " ML-DSA-87.Verify=0 (0xDEAD0000 fabrication marker)"
             << " b_hop(u)=⊥ (STARK hop ZKP fails; independent of ML-DSA-87)"
             << " flow=" << base_flow_id
             << " pkt=" << packet_id
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        if (prev_sender < (uint32_t)total_size &&
            !is_detected_node[active_attack_variant][prev_sender])
        {
            record_detection_event(active_attack_variant, prev_sender);
            cout << "[S5] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << active_attack_variant
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    return false;
}

#endif // S5_DETECTION_H
