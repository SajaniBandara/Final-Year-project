#ifndef S6_DETECTION_H
#define S6_DETECTION_H

// =========================================================================
// s6_detection.h — MOBIGUARD Signature S6 Detection
//
// Implements Signature S6 (Active Hidden Forwarding, Data Plane) from
// the proposal, as defined in Equation eq:sig_s6.
//
// S6 (Attack 6 — Active Hidden Forwarding, Data Plane, variant index 5):
//   ∃ d, d' : d ≠ d'
//   ∧ msg_id ∈ R(d, W)                               [same msg at legit dest]
//   ∧ msg_id ∈ R(d', W)                              [same msg at eavesdropper]
//   ∧ ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0    [content modified]
//   ∧ b_hop(u) = 0                                    [STARK hop proof fails]
//
// Simulation proxy for each conjunction:
//   (1/2) DUP(msg_id, W): s6_msg_recv_log maps (stripped_flow_id, packet_id)
//         to {node → receive_timestamp}. Entries older than S6_WINDOW_S are
//         expired on every s6_log_recv() call, faithfully implementing R(d,W).
//         When ≥2 distinct nodes have live entries, DUP is confirmed.
//   (3) ML-DSA-87.Verify = 0: recv_flow_id & 0xDEAD0000 != 0 (content
//       modified). The active duplicate has flow_id = 0xDEAD0000 | original.
//   (4) b_hop(u) = 0: active_hf_malicious_nodes[prev_sender] — the malicious
//       RSU self-modified its own delta table and cannot produce a valid STARK
//       hop-legitimacy proof. Kept logically separate from (3) per Eq. sig_s6.
//   (5) DP origin: active_attack_variant == 5. No controller FlowMod reached
//       the blockchain policy set, so BC.Query(C_P) would find no endorsement
//       for the forwarding toward d'.
//
// DESIGN NOTE:
//   Included inside routing.cc AFTER all global variable declarations.
//   s6_log_recv() must be called from TWO sites in routing.cc:
//     (a) Inside the active-HF eavesdropper receive block (to log d').
//     (b) Inside the pd_all_inst delivery block for every normal receive
//         (to log d).
//   Both calls strip 0xDEAD0000 so both copies map to the same key.
//
// INDEPENDENCE:
//   Controlled solely by s6_detection_active (declared in routing.cc).
// =========================================================================

#include <iostream>
#include <fstream>
#include <map>
#include <utility>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Fabrication marker placed in flow_id by hf_send_active_duplicate()
static const uint32_t S6_DEAD_MARKER = 0xDEAD0000u;

// Observation window W (seconds) for R(d, W) and R(d', W) — Eq. sig_s6.
// Both the legitimate delivery and the eavesdrop copy arrive within 0.001 s
// of each other (the trampoline offset in hf_send_active_duplicate). A 30 s
// window comfortably spans the maximum RSU zone residence time (§688: 10–30 s)
// while keeping the log from accumulating stale entries across cycles.
// Pending: revisit once SUMO traces provide measured handoff intervals.
static const double S6_WINDOW_S = 30.0;

// Per-(stripped_flow_id, packet_id) receive log.
// Inner map: { node_id → simulation-time of receive (seconds) }
// Entries older than S6_WINDOW_S are expired in s6_log_recv() before insertion.
static std::map<std::pair<uint32_t,uint32_t>,
                std::map<uint32_t,double>> s6_msg_recv_log;

// =========================================================================
// s6_log_recv():
// Records that current_hop received (fid, packet_id) at the current sim time.
// Expires entries older than S6_WINDOW_S before inserting, implementing the
// finite observation window W from Eq. sig_s6 (R(d,W) / R(d',W)).
// Safe to call when s6_detection_active is false — exits immediately.
// =========================================================================
inline void s6_log_recv(uint32_t recv_flow_id, uint32_t packet_id, uint32_t current_hop)
{
    if (!s6_detection_active) return;
    uint32_t base_fid = recv_flow_id & 0xFFFFu;
    double   t_now    = Simulator::Now().GetSeconds();
    auto     key      = std::make_pair(base_fid, packet_id);
    auto&    node_ts  = s6_msg_recv_log[key];

    // Expire entries outside window W (R(d,W) — finite observation window)
    for (auto it = node_ts.begin(); it != node_ts.end(); )
    {
        if (t_now - it->second > S6_WINDOW_S)
            it = node_ts.erase(it);
        else
            ++it;
    }

    // Insert / refresh this node's timestamp
    node_ts[current_hop] = t_now;
}

// =========================================================================
// s6_detect():
// Evaluates Signature S6 at the eavesdropper node for the DP active variant.
//
// Returns true (S6 triggered) when ALL hold simultaneously:
//   1. active_attack_variant == 5           (DP active HF — Attack 6)
//   2. active_hf_malicious_nodes[prev_sender] — b_hop(u)=0 proxy
//   3. recv_flow_id carries 0xDEAD0000      — ML-DSA-87.Verify=0 proxy
//   4. (base_flow_id, packet_id) has ≥2 distinct live nodes in window W
//      — DUP(msg_id, W) confirmed (R(d,W) ∧ R(d',W))
//
// Parameters:
//   recv_flow_id — flow ID from packet tag at eavesdropper (has 0xDEAD0000)
//   prev_sender  — node that sent this packet (the malicious RSU, u)
//   current_hop  — eavesdropper node (d')
//   packet_id    — packet ID
//   base_flow_id — recv_flow_id & 0xFFFFu (marker stripped)
// =========================================================================
inline bool s6_detect(uint32_t recv_flow_id,
                       uint32_t prev_sender,
                       uint32_t current_hop,
                       uint32_t packet_id,
                       uint32_t base_flow_id)
{
    if (!s6_detection_active) return false;

    // Conjunction 5: DP variant only (Attack 6, index 5)
    if (active_attack_variant != 5) return false;

    // Conjunction 2 / b_hop(u)=0: prev_sender must be a flagged active
    // malicious RSU. In deployed MOBIGUARD this is STARK.Verify(π_hop)=0
    // because d' ∉ P(s,d). Kept as an independent check from ML-DSA-87.
    if (prev_sender >= (uint32_t)total_size) return false;
    if (!active_hf_malicious_nodes[prev_sender]) return false;

    // Lookup crypto record once — used for both mldsa_fails and b_hop_fails.
    auto it_s6 = g_packet_crypto.find({prev_sender, packet_id});

    // Conjunction 3: ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0
    // Primary: result of mldsa87_verify() stored in g_packet_crypto by MacRx.
    // Fallback to 0xDEAD0000 marker if crypto record not yet populated.
    // ¬b_batch = individual verify failed OR batch challenge failed (eq:batch_challenge)
    bool mldsa_fails;
    if (it_s6 != g_packet_crypto.end() && it_s6->second.sig_len > 0)
        mldsa_fails = !it_s6->second.sig_valid || !g_batch_passed;
    else
        mldsa_fails = ((recv_flow_id & S6_DEAD_MARKER) == S6_DEAD_MARKER);

    // b_hop(u) = 0: primary from stark_hop_ok, fallback to ground truth.
    bool b_hop_fails;
    if (it_s6 != g_packet_crypto.end() && it_s6->second.sig_len > 0)
        b_hop_fails = !it_s6->second.stark_hop_ok;
    else
        b_hop_fails = true; // active_hf_malicious_nodes confirmed above

    // Conjunctions 1/2: DUP(msg_id, W) — R(d,W) ∧ R(d',W)
    // Count only live entries within window W (expiry already done in s6_log_recv).
    auto key = std::make_pair(base_flow_id, packet_id);
    const auto& node_ts = s6_msg_recv_log[key];
    bool dup_detected = (node_ts.size() >= 2);

    cout << "[S6] eavesdropper=" << current_hop
         << " sender_rsu=" << prev_sender
         << " flow=" << base_flow_id
         << " pkt=" << packet_id
         << " recv_fid=0x" << hex << recv_flow_id << dec
         << " live_recv_count=" << node_ts.size()
         << " W=" << S6_WINDOW_S << "s"
         << " mldsa_fails=" << mldsa_fails
         << " b_hop_fails=" << b_hop_fails
         << " dup_detected=" << dup_detected
         << " [DP — RSU self-modified delta_at_nodes_inst; controller clean]"
         << endl;

    if (mldsa_fails && b_hop_fails && dup_detected)
    {
        cout << "[S6] ⚠️ SIGNATURE S6 TRIGGERED!"
             << " Active HF (DP): msg_id=(" << base_flow_id << "," << packet_id << ")"
             << " seen at " << node_ts.size() << " nodes within W=" << S6_WINDOW_S << "s"
             << " — DUP(msg_id,W) confirmed"
             << " ML-DSA-87.Verify=0 (0xDEAD0000 fabrication marker)"
             << " b_hop(u)=⊥ (STARK hop proof fails; independent of ML-DSA-87)"
             << " eavesdropper d'=" << current_hop
             << " sender_rsu u=" << prev_sender
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        if (prev_sender < (uint32_t)total_size &&
            !is_detected_node[active_attack_variant][prev_sender])
        {
            record_detection_event(active_attack_variant, prev_sender);
            cout << "[S6] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << active_attack_variant
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    return false;
}

// =========================================================================
// s6_reset_state():
// Clears the duplication log and all window timestamps between runs.
// =========================================================================
inline void s6_reset_state()
{
    s6_msg_recv_log.clear();
    if (s6_detection_active)
        cout << "[S6] Duplication log cleared (window W=" << S6_WINDOW_S << "s)." << endl;
}

#endif // S6_DETECTION_H
