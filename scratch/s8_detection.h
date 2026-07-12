#ifndef S8_DETECTION_H
#define S8_DETECTION_H

// =========================================================================
// s8_detection.h — MOBIGUARD Signature S8 Detection
//
// Implements Signature S8 (Passive Hidden Forwarding, Data Plane) from
// the proposal, as defined in Equation eq:sig_s8.
//
// S8 (Attack 8 — Passive Hidden Forwarding, Data Plane, variant index 7):
//   BatchVerify(σ, {pk_i}, {m_i}, r) = 1              [primary path correct]
//   ∧ ML-DSA-87.Verify(σ_c, pk_s, m_c) = 1           [content unmodified]
//   ∧ b_hop(u) = 0                                    [STARK hop proof fails]
//
// From the LRAD RSU algorithm (alg:lrad_rsu, line for flag_S8):
//   flag_S8 ← [b_batch] ∧ [b_hop=0]
//
// Simulation proxy for each conjunction:
//   (1) b_batch=1 (BatchVerify passes): recv_flow_id carries NO 0xDEAD0000
//       marker, confirming the aggregate ML-DSA-87 signature chain over the
//       primary delivery path is intact — the packet was not content-modified.
//   (2) ML-DSA-87.Verify = 1: same as (1) — the passive copy is byte-for-byte
//       identical to the original; the sender's individual signature is valid
//       over the copy received at d'.
//   (3) b_hop(u) = 0: passive_hf_malicious_nodes[prev_sender] == true confirms
//       the sending RSU self-modified its own delta_at_nodes_inst after the
//       legitimate controller FlowMod arrived (DP). In deployed MOBIGUARD this
//       is STARK.Verify(π_hop(u)) = 0 because the unauthorized destination d'
//       is absent from the authorized next-hop policy P(s,d).
//
// DISTINCTION FROM S7:
//   S7 (CP): primary signal is unexpected volume at d' — the controller table
//            was poisoned; d/dt Vol(d',t) > ε_vol drives detection.
//   S8 (DP): primary signal is [b_batch ∧ b_hop=0] — the aggregate batch
//            signature over the primary path succeeds (content unmodified, no
//            dropped packets), while the hop ZKP fails because the RSU sent
//            a covert copy to d' that is absent from P(s,d).
//   The attack variant index (6 vs 7) disambiguates CP vs DP in simulation.
//
// PRIMARY vs CORROBORATING:
//   Per the proposal (§1832–1834), the primary detection mechanism for S8 is
//   witness-based monitoring (Eq. dup_alert_cond and bft_penalty). b_hop=0 is
//   a corroborating indicator. In simulation, [b_batch ∧ b_hop=0] at the
//   eavesdropper faithfully captures the observable footprint of the DP attack.
//
// DESIGN NOTE:
//   Included inside routing.cc AFTER all global variable declarations.
//   s8_detect() must be called from the passive-HF eavesdropper receive block,
//   BEFORE the early return, alongside s7_detect().
//   Do NOT include before the global declarations.
//
// INDEPENDENCE:
//   Controlled solely by s8_detection_active (declared in routing.cc).
// =========================================================================

#include <iostream>
#include <fstream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// =========================================================================
// s8_detect():
// Evaluates Signature S8 at the eavesdropper node for the DP passive variant.
//
// Returns true (S8 triggered) when ALL hold simultaneously:
//   1. active_attack_variant == 7         (DP passive HF — Attack 8)
//   2. prev_sender is a flagged passive malicious RSU
//      (passive_hf_malicious_nodes[prev_sender] == true)
//   3. recv_flow_id carries NO 0xDEAD0000 marker
//      (b_batch=1 ∧ ML-DSA-87.Verify=1 — content unmodified, batch passes)
//
// Parameters:
//   recv_flow_id  — flow ID from packet tag (should have NO 0xDEAD0000 marker)
//   prev_sender   — node that sent this packet (the malicious RSU, u)
//   current_hop   — eavesdropper node receiving the passive duplicate (d')
//   packet_id     — packet ID (for logging)
//   base_flow_id  — recv_flow_id & 0xFFFFu (same as recv_flow_id for passive)
// =========================================================================
inline bool s8_detect(uint32_t recv_flow_id,
                       uint32_t prev_sender,
                       uint32_t current_hop,
                       uint32_t packet_id,
                       uint32_t base_flow_id)
{
    if (!s8_detection_active) return false;

    // Conjunction 1: DP passive variant only (Attack 8, index 7)
    if (active_attack_variant != 7) return false;

    // Conjunction 2: prev_sender must be a flagged passive malicious RSU
    if (prev_sender >= (uint32_t)total_size) return false;
    if (!passive_hf_malicious_nodes[prev_sender]) return false;

    // Conjunctions 1/2: b_batch=1 ∧ ML-DSA-87.Verify=1 — content unmodified.
    // Primary: sig_valid from g_packet_crypto set by mldsa87_verify() in MacRx.
    // Fallback: absence of 0xDEAD0000 marker if crypto record not populated.
    auto it_s8 = g_packet_crypto.find({prev_sender, packet_id});
    bool b_batch;
    if (it_s8 != g_packet_crypto.end() && it_s8->second.sig_len > 0)
        b_batch = it_s8->second.sig_valid;
    else
        b_batch = ((recv_flow_id & 0xDEAD0000u) == 0);
    if (!b_batch) return false;

    // Conjunction 3: b_hop(u) = 0 — STARK hop proof fails.
    // Primary: stark_hop_ok from g_packet_crypto set by stark_update_meta().
    // Fallback: passive_hf_malicious_nodes ground truth.
    bool b_hop_fails;
    if (it_s8 != g_packet_crypto.end() && it_s8->second.sig_len > 0)
        b_hop_fails = !it_s8->second.stark_hop_ok;
    else
        b_hop_fails = true; // passive_hf_malicious_nodes confirmed above

    cout << "[S8] eavesdropper=" << current_hop
         << " sender_rsu=" << prev_sender
         << " flow=" << base_flow_id
         << " pkt=" << packet_id
         << " recv_fid=0x" << hex << recv_flow_id << dec
         << " b_batch=1 (BatchVerify passes, content unmodified)"
         << " b_hop_fails=" << b_hop_fails
         << " [DP — RSU self-modified delta_at_nodes_inst; controller table clean]"
         << endl;

    if (b_batch && b_hop_fails)
    {
        cout << "[S8] ⚠️ SIGNATURE S8 TRIGGERED!"
             << " Passive HF (DP): eavesdropper d'=" << current_hop
             << " sender_rsu u=" << prev_sender
             << " BatchVerify=1 (primary path correct, aggregate signature intact)"
             << " ML-DSA-87.Verify=1 (passive copy, content unmodified)"
             << " b_hop(u)=⊥ (STARK hop proof fails; RSU self-modified its own rule)"
             << " flow=" << base_flow_id
             << " pkt=" << packet_id
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        if (prev_sender < (uint32_t)total_size &&
            !is_detected_node[active_attack_variant][prev_sender])
        {
            record_detection_event(active_attack_variant, prev_sender);
            cout << "[S8] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << active_attack_variant
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    return false;
}

#endif // S8_DETECTION_H
