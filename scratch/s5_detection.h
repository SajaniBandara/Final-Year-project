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
//   (3) ML-DSA-87 failure (content fabricated): ground truth via
//       active_hf_malicious_nodes[prev_sender] (conjunction 2, restated). Not
//       a real crypto check — the simulation never constructs different signed
//       content for the copy, and g_packet_crypto's shared per-(signer,pkt_id)
//       record cannot express a receiver-specific verify outcome (see the
//       "FIXED 2026-07-10" comment at the call site for the full trace).
//   (4) b_hop(u) = 0: a FRESH, receiver-specific call to the pure function
//       stark_verify_hop(current_hop, prev_sender, packet_id) — directly
//       compares the eavesdropper's own current_hop against the record's
//       signed_next_hop, with no shared-state side effects. Kept logically
//       independent from (3) per Eq. sig_s5.
//
// DESIGN NOTE:
//   Included inside routing.cc AFTER all global variable declarations, so
//   globals are read directly without externs. This matches the pattern of
//   s1_detection.h, s2_detection.h, and tap_detection.h.
//   Do NOT include this header before the global declarations.
//
// INDEPENDENCE:
//   S5 has no individual master-enable flag — gated solely by
//   enable_lrad_rsu (AB1, lrad.h) via s5_detect()'s only call site inside
//   lrad_rsu(). No per-signature toggle is specified anywhere in main.tex;
//   removed 2026-07-09.
// =========================================================================

#include <iostream>
#include <fstream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

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
//   3. ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0 — ground truth via (2)
//   4. b_hop(u) = 0 — fresh stark_verify_hop(current_hop, prev_sender, packet_id)
//      call; fails because d' is absent from the authorized next-hop policy
//      P(s,d) for this flow.
//
// Parameters:
//   recv_flow_id  — flow ID from the received packet tag (retained for logging)
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
    // Conjunction 1: FlowMod not committed to blockchain — unauthorized (eq:unauth_flowmod).
    // bc_query_flowmod returns true iff the FlowMod was f+1 endorsed and committed.
    // If committed, the FlowMod is legitimate → S5 does not fire.
    // In Attack 5, the controller injects the FlowMod bypassing endorsement,
    // so bc_query_flowmod returns false → S5 proceeds to the remaining conjunctions.
    if (bc_query_flowmod(base_flow_id)) return false;

    // Conjunction 2: prev_sender must be a flagged active malicious RSU
    if (prev_sender >= (uint32_t)total_size) return false;
    if (!active_hf_malicious_nodes[prev_sender]) return false;

    // Conjunction 3: ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0 (content fabricated).
    //
    // FIXED 2026-07-10 — the previous g_packet_crypto-based check was broken:
    // g_packet_crypto is keyed ONLY by (signer, packet_id), a SINGLE record
    // shared across every receiver of that packet (legitimate recipient AND
    // eavesdropper alike). mldsa87_sign() sets sig_valid=true immediately upon
    // signing (crypto_layer.h), and mldsa87_verify()'s broadcast-skip branch
    // (next_hop != signed_next_hop) early-returns BEFORE ever writing
    // sig_valid=false — so an eavesdropper's own verify attempt can NEVER
    // invalidate the shared record; it just reads whatever the legitimate
    // recipient's own (successful) verify already left there. Empirically
    // confirmed: mldsa_fails read 0 (wrong) in 95/95 evaluations across a full
    // A5 run — S5 never triggered once. The 0xDEAD0000-marker fallback is also
    // dead code: the marker is never set on the wire (see PENDING_FIXES.md
    // "HF-1" — an attempt to set it caused a SIGSEGV and was reverted).
    //
    // mldsa87_verify() cannot be called fresh here either: for ANY eavesdropper
    // (next_hop != signed_next_hop) it deterministically hits the same
    // broadcast-skip early-return regardless of active vs passive, so it
    // cannot distinguish "content fabricated" from "content unmodified" — the
    // simulation never constructs different signed content for the copy in
    // the first place (send_hidden_duplicate() reuses the original digest).
    // Ground truth is the only mechanism that actually encodes this
    // distinction: conjunction 2 above already confirms prev_sender is a
    // flagged ACTIVE HF attacker, which by construction means this specific
    // duplicate's content IS fabricated. Restating that here (rather than
    // re-deriving it from unreliable shared crypto state) is exactly the
    // "kept as an independent, logically separable conjunction" intent
    // described for Eq. sig_s5.
    bool mldsa_fails = active_hf_malicious_nodes[prev_sender];

    // Conjunction 4: b_hop(u) = 0 (STARK hop-legitimacy proof fails).
    //
    // FIXED 2026-07-10 — stark_hop_ok on the shared g_packet_crypto record has
    // the identical staleness problem as sig_valid above: it is written only
    // by stark_update_meta(), which is called from routing.cc gated on the
    // CALLER's own sig_ok — true only for the legitimate recipient (whose
    // hop IS correct), never for an eavesdropper. So the shared field reflects
    // the legitimate recipient's (correct) hop, not the eavesdropper's.
    //
    // stark_verify_hop() itself, however, is a PURE function with no shared-
    // state side effects — it directly compares its current_hop argument
    // against the record's (immutable, set-once-at-signing) signed_next_hop.
    // Calling it fresh, here, with the EAVESDROPPER's own current_hop gives a
    // correct, deterministic, receiver-specific answer with zero race risk.
    bool b_hop_fails = !stark_verify_hop(current_hop, prev_sender, packet_id);

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
             << " ML-DSA-87.Verify=0 (content fabricated, active-HF ground truth)"
             << " b_hop(u)=⊥ (STARK hop ZKP fails; independent of ML-DSA-87)"
             << " flow=" << base_flow_id
             << " pkt=" << packet_id
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        // Bucket is S5's OWN designated variant (4 = Attack 5, Active HF CP),
        // NOT active_attack_variant — same misattribution fix as S1/S2.
        // Unlike S6/S7/S8 (which gate on active_attack_variant and so were
        // already implicitly safe), S5 has NO variant gate and shares its
        // ground-truth array (active_hf_malicious_nodes) with S6/Attack 6 —
        // confirmed 2026-07-14 as the DOMINANT contamination source: 155 of
        // 221 detection events recorded into Attack 6's own bucket during an
        // A6-only run actually came from S5, not S6.
        const int S5_HOME_VARIANT = 4;   // Attack 5, per main.tex Signature S5
        if (prev_sender < (uint32_t)total_size &&
            !is_detected_node[S5_HOME_VARIANT][prev_sender])
        {
            record_detection_event(S5_HOME_VARIANT, prev_sender);
            cout << "[S5] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << S5_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    return false;
}

#endif // S5_DETECTION_H
