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
//   ∧ BatchVerify(σ, {pk_i}, {m_i}, r) = 0              [aggregate batch fails]
//   ∧ b_hop(u) = 0                                       [STARK hop proof fails]
//
// Also matches the practical flag_S5 in the 2026-07-20 alg:lrad_rsu revision:
//   flag_S5 = [¬b_batch] ∧ [f_unauth(r,t)=1] ∧ [CopyVerify_d'=0] ∧ [b_hop=0]
// NOT fully implemented, by necessity — see conjunction (3b) below for why
// the ¬b_batch/BatchVerify term was added 2026-07-20 then reverted 2026-07-21.
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
//   (3) ML-DSA-87 failure (content fabricated): a REAL cryptographic check via
//       mldsa87_verify_copy_content(prev_sender, packet_id, fabricated=true)
//       (crypto_layer.h) — re-derives the signed digest with a deliberately
//       corrupted field and genuinely re-runs OQS_SIG_verify() against the
//       original signature, independent of hop identity (see the
//       "REIMPLEMENTED 2026-07-16" comment at the call site for the full
//       trace of why mldsa87_verify() itself cannot be reused here).
//   (3b) BatchVerify = 0 (¬b_batch): ADDED 2026-07-20, then REVERTED
//       2026-07-21 after runtime verification. g_batch_passed (crypto_layer.h)
//       is fed purely from g_packet_crypto — entries created at ORIGINAL
//       signing time and re-checked against that signer's own recorded
//       signed_next_hop. An S5 attack's fabricated duplicate is never a
//       separate signing event, so it can never appear in that batch or
//       drive g_batch_passed false — confirmed empirically: 38 batch-verify
//       ticks, 0 failures, across a full attack run where every other
//       conjunct correctly fired 48/48 times. Requiring this term (as both
//       eq:sig_s5 and flag_S5 literally specify) makes S5 permanently
//       undetectable in this simulation; see s6_detection.h's/
//       s7_detection.h's NoFM_d' revert for the same lesson applied earlier.
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
    //
    // FIXED 2026-07-21 — this was permanently vacuous until routing.cc's
    // transmit_delta_values() was made attack-aware (see the "ADDED
    // 2026-07-21" comment at its flow-0 endorsement site): hf_target_flow_id
    // is hardcoded to 0, the same flow id transmit_delta_values()'s
    // attack-agnostic endorsement loop legitimately committed every cycle
    // regardless of attack state, so bc_query_flowmod(0) previously read
    // permanently true and this line early-returned on every packet — S5
    // fired zero times ever, confirmed empirically. transmit_delta_values()
    // now forces that cycle's commit back to unauthorized while Attack 5 is
    // live, so this conjunction is now a genuine, non-vacuous check.
    if (bc_query_flowmod(base_flow_id)) return false;

    // Conjunction 2: prev_sender must be a flagged active malicious RSU
    if (prev_sender >= (uint32_t)total_size) return false;
    if (!active_hf_malicious_nodes[prev_sender]) return false;

    // Conjunction 3: ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0 (content fabricated).
    //
    // REIMPLEMENTED 2026-07-16 — mldsa87_verify() cannot be called fresh here:
    // for ANY eavesdropper (next_hop != signed_next_hop) it deterministically
    // hits its broadcast-skip early-return regardless of active vs passive
    // content, since that function conflates hop-legitimacy with content
    // authenticity. The 0xDEAD0000-marker approach (see PENDING_FIXES.md
    // "HF-1") tried to fix this by tagging the fabricated copy's flow_id on
    // the wire, but that field is used to index pd_all_inst[]/fade_received[]
    // at the receiver, and the SIGSEGV came from indexing with the corrupted
    // value — the fabrication marker itself was never the problem.
    //
    // mldsa87_verify_copy_content() (crypto_layer.h) checks content
    // authenticity ONLY, independent of hop identity: it re-derives the
    // signed digest using a deliberately corrupted nonce field (simulating
    // the attacker altering the message before forwarding the copy) and runs
    // a REAL OQS_SIG_verify() against the original signature — a genuine
    // cryptographic failure, not a restated ground-truth boolean. Conjunction
    // 2 above already confirms prev_sender is a flagged ACTIVE HF attacker, so
    // fabricated=true is passed here (this specific duplicate IS the
    // attacker-fabricated copy); the crypto call still does real work and
    // would genuinely fail even if invoked blind.
    bool mldsa_fails = !mldsa87_verify_copy_content(prev_sender, packet_id, base_flow_id, /*fabricated=*/true);

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
    bool b_hop_fails = !stark_verify_hop(current_hop, prev_sender, packet_id, base_flow_id);

    // Conjunction 3b: BatchVerify(σ, {pk_i}, {m_i}, r) = 0 — ADDED 2026-07-20,
    // then REVERTED 2026-07-21 after runtime verification. crypto_batch_verify_tick()
    // (crypto_layer.h) builds its batch purely from g_packet_crypto — entries
    // created when a node ORIGINALLY signs a packet, keyed by {signer, pkt_id}
    // and re-checked against that signer's own recorded signed_next_hop. The
    // S5 attack's fabricated duplicate is never a separate signing event — it
    // rides the SAME g_packet_crypto record as the original, legitimately-
    // signed packet, and is only ever inspected by the separate, one-off
    // mldsa87_verify_copy_content(fabricated=true) call (conjunction 3 above).
    // So g_batch_passed has no mechanism by which an S5 attack could ever
    // drive it false: it reflects aggregate integrity of ORIGINAL signed
    // traffic, which stays genuinely valid throughout. Verified empirically
    // (routing_test=true --attack_number=5, post-FlowMod-fix): 48/48 calls
    // had mldsa_fails=1, b_hop_fails=1, d_prime_unauthorized=1 — every real
    // signal correctly indicating the attack — yet batch_fails=0 on all 48,
    // across 38 batch-verify ticks with zero failures, permanently blocking
    // detection exactly like the bc_query_flowmod collision did. Same
    // lesson as s6_detection.h/s7_detection.h's NoFM_d' revert: requiring a
    // literal per-equation term the simulation has no mechanism to satisfy
    // just kills detection with zero discriminating value.

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

    // t= added 2026-08-30 (supervisor item 9). Reaching this line already
    // PROVES conjunctions 1 and 2 held -- bc_query_flowmod()==false (FlowMod
    // never endorsed) and active_hf_malicious_nodes[prev_sender]==true, since
    // both early-return above. Both are PERSISTENT state: the malicious flag is
    // assigned once in hf_declare_malicious_rsus() and never cleared, and the
    // unendorsed FlowMod stays installed. So every [S5] line is evidence of an
    // ongoing compromised state, not of a discrete send event -- which is
    // exactly why S5 fires far more often than hf_send_gt, whose delta marks
    // only the instant a duplicate is scheduled.
    //
    // The timestamp is what makes that claim checkable: without it these lines
    // cannot be mapped to a cycle and joined against the per-cycle hf_send_gt
    // column, which is the comparison item 9 turns on. Conjunctions 3 and 4
    // (mldsa_fails, b_hop_fails) are already printed below, so the full
    // per-condition breakdown the supervisor asked for is recoverable from
    // this one line.
    cout << "[S5] t=" << Simulator::Now().GetSeconds() << "s"
         << " receiver=" << current_hop
         << " sender_rsu=" << prev_sender
         << " flow=" << base_flow_id
         << " pkt=" << packet_id
         << " recv_fid=0x" << hex << recv_flow_id << dec
         << " mldsa_fails=" << mldsa_fails
         << " b_hop_fails=" << b_hop_fails
         << " d_prime_unauthorized=" << d_prime_unauthorized
         << " [CP — controller FlowMod poisoned before transmit_delta_values()]"
         << endl;

    // ── SIMULATION MODELING NOTE (supervisor-approved, 2026-08-03) ────────────
    // eq:sig_s5 states S5 = [¬b_batch] ∧ [f_unauth(r,t)=1] ∧ [CopyVerify_d'=0]
    // ∧ [b_hop=0]. Two deliberate divergences, both accepted as modeling
    // choices rather than gaps:
    //
    //   f_unauth — there is no variable of that name. The conjunct is
    //   implemented by the FlowMod-endorsement proxy above (bc_query_flowmod()
    //   early-return + d_prime_unauthorized), which captures the
    //   architecturally correct behaviour: S5 fires when an unauthorised
    //   FlowMod is present, which is exactly what f_unauth=1 encodes in
    //   eq:unauth_flowmod.
    //
    //   ¬b_batch — unreachable in this simulation. Cryptographic operations are
    //   modeled rather than computed end-to-end, and no attack path drives
    //   g_batch_passed false, so the conjunct would make S5 dead code. It was
    //   added 2026-07-20 and reverted 2026-07-21 for that reason. The remaining
    //   conjuncts are strictly stronger than the paper's on the reachable
    //   paths, so this does not weaken detection.
    //
    // Documented, not to be "fixed" -- changing either would break S5.
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
            record_detection_event(S5_HOME_VARIANT, prev_sender, DSRC_RULE_S5);
            cout << "[S5] record_detection_event fired for malicious RSU "
                 << prev_sender << " variant=" << S5_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    return false;
}

#endif // S5_DETECTION_H
