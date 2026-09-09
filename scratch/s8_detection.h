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
//   (1) BatchVerify=1: read directly from g_batch_passed, a genuine system-wide
//       signal (not per-packet) set by the 50ms batch_verify_mldsa87() tick.
//   (2) ML-DSA-87.Verify = 1 (content unmodified): a REAL cryptographic check
//       via mldsa87_verify_copy_content(prev_sender, packet_id,
//       fabricated=false) (crypto_layer.h) — reconstructs the exact digest the
//       honest sender signed and genuinely re-runs OQS_SIG_verify() against
//       the original signature (see the "REIMPLEMENTED 2026-07-16" comment at
//       the call site for the full trace).
//   (3) b_hop(u) = 0: a FRESH, receiver-specific stark_verify_hop(current_hop,
//       prev_sender, packet_id) call. In deployed MOBIGUARD this is
//       STARK.Verify(π_hop(u)) = 0 because the unauthorized destination d'
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
//   S8 has no individual master-enable flag — gated solely by
//   enable_lrad_rsu (AB1, lrad.h) via s8_detect()'s only call path (inside
//   lrad_rsu(), invoked from every one of its call sites). No per-signature
//   toggle is specified anywhere in main.tex; removed 2026-07-09.
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
//   3. g_batch_passed (BatchVerify=1) ∧ ground truth via (2) (ML-DSA-87.Verify=1)
//   4. fresh stark_verify_hop() — b_hop(u)=0 for the eavesdropper's own hop
//
// Parameters:
//   recv_flow_id  — flow ID from packet tag (retained for logging)
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
    // Conjunction 1: DP passive variant only (Attack 8, index 7)
    // Round 10: variant_active() replaces the bare == test so joint/NEXUS runs
    // (all eight variants armed at once) do not silence this signature.
    if (hf_variant_guard && !variant_active(7)) return false;

    // Round 10: the addressing conjunct that fixed S5, applied here too --
    // confirmed necessary, not precautionary. Broadcast media deliver every
    // frame to every neighbour, so b_hop_fails holds for all of them and a
    // passive overhearer could accuse the sender. Measured before this fix:
    // up to 27 distinct nodes accusing one (sender, message, timestamp) event,
    // and 11.6-22.3% of window-level firings landing on nodes never declared
    // attackers. UINT32_MAX means the tag carried no value -- treat as "cannot
    // tell" and fall through rather than inventing a fire.
    if (hf_require_addressed
        && g_s5_rx_intended_recipient != UINT32_MAX
        && g_s5_rx_intended_recipient != current_hop) return false;

    // Round 10 (option b, approved): stop asserting on a contained node.
    if (hf_detector_suppressed(prev_sender)) return false;

    // Conjunction: b_hop(u) = 0 (eq:sig_s5). ORACLE GATE REMOVED 2026-09-06,
    // supervisor Q5 -- see hf_oracle_gate (crypto_layer.h) for the full
    // rationale. This previously read passive_hf_malicious_nodes[prev_sender],
    // the attack injector's own assignment array, which made this signature
    // structurally incapable of accusing an innocent node and so made its
    // precision an identity rather than a measurement. eq:sig_s5 lists no
    // such conjunct. stark_verify_hop() evaluates the hop-legitimacy proof
    // the gate stood in for: it compares the receiving hop against the
    // signed_next_hop embedded at sign time and consults no ground truth,
    // so a benign packet on its intended path passes here and a duplicate
    // diverted to an eavesdropper does not.
    if (prev_sender >= (uint32_t)total_size) return false;
    if (hf_oracle_gate) {
        if (!passive_hf_malicious_nodes[prev_sender]) return false;  // legacy, A/B only
    } else {
        if (stark_verify_hop(current_hop, prev_sender, packet_id, base_flow_id))
            return false;   // b_hop(u) = 1 -> packet is on its signed path
    }

    // Conjunction 1: BatchVerify(σ, {pk_i}, {m_i}, r) = 1 — primary-path delivery
    // correct across all hops. g_batch_passed is a genuine system-wide signal
    // (not per-packet, not receiver-specific — set by the 50ms
    // batch_verify_mldsa87() tick), so it is read directly and is unaffected by
    // the per-packet shared-record issue described below.
    //
    // FIXED 2026-07-10 — this conjunction was previously MISSING entirely: the
    // old code folded "BatchVerify=1" and "ML-DSA-87.Verify=1" into a single
    // b_batch variable sourced only from g_packet_crypto's sig_valid, so S8
    // never actually checked g_batch_passed despite Eq. sig_s8 requiring it as
    // an independent conjunction (matching S6's ¬b_batch term, which DID
    // reference g_batch_passed — S8 was inconsistent with its sibling signature).
    bool batch_verify_ok = g_batch_passed;

    // Conjunction 2: ML-DSA-87.Verify(σ_c, pk_s, m_c) = 1 — content unmodified.
    //
    // REIMPLEMENTED 2026-07-16 — see the matching comment in s5_detection.h for
    // why mldsa87_verify() cannot be called fresh here (broadcast-skip
    // conflates hop-legitimacy with content authenticity).
    // mldsa87_verify_copy_content() (crypto_layer.h) with fabricated=false
    // reconstructs the exact digest the honest sender signed and genuinely
    // re-runs OQS_SIG_verify() against the original signature — a real
    // cryptographic pass, not a restated ground-truth boolean.
    bool mldsa_verify_ok = mldsa87_verify_copy_content(prev_sender, packet_id, base_flow_id, /*fabricated=*/false);

    bool b_batch = batch_verify_ok && mldsa_verify_ok;
    if (!b_batch) return false;

    // Conjunction 3: b_hop(u) = 0 — a FRESH, receiver-specific call to the pure
    // function stark_verify_hop() — see s5_detection.h for why the shared
    // stark_hop_ok field on g_packet_crypto is unreliable here (only ever
    // written by the legitimate recipient's context, never the eavesdropper's).
    bool b_hop_fails = !stark_verify_hop(current_hop, prev_sender, packet_id, base_flow_id);

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

        // Bucket hardcoded to S8's own variant (7 = Attack 8) — see
        // s6_detection.h for why this is safe/no-op given the existing gate.
        const int S8_HOME_VARIANT = 7;   // Attack 8, per main.tex Signature S8
        if (!g_disable_s7_s8 &&
            prev_sender < (uint32_t)total_size &&
            !is_detected_node[S8_HOME_VARIANT][prev_sender])
        {
            record_detection_event(S8_HOME_VARIANT, prev_sender, DSRC_RULE_S8);
            cout << "[S8] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << S8_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    return false;
}

#endif // S8_DETECTION_H
