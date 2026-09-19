#ifndef SELECTIVE_TIME_DELAY_H
#define SELECTIVE_TIME_DELAY_H

#include <iostream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Forward declarations of functions implemented in routing.cc
extern std::string attack_tag();
extern bool GetBooleanWithProbability(double probabilityPercent, int nodeID);

// P4 / Experiment 4 (attack observable evidence): the fraction of eligible
// HIGH-priority (safety-critical) packets the selective-delay attacker actually
// targets. Default 1.0 = every safety-critical packet (original behaviour,
// AOEI=1.0). Set < 1.0 to subsample; the paper's AOEI {0.25,0.5,0.75,1.0} maps
// to targeting ratios {0.10,0.25,0.75,1.00}. Targeting is a deterministic
// function of (flow_id, packet_id) so the SAME packets are hit across arms and
// seeds -- a clean A/B knob with no coupling to the ns-3 RNG stream.
// CLI: --selective_target_ratio  (see routing.cc cmd.AddValue).
inline double g_selective_target_ratio = 1.0;

inline bool selective_packet_targeted(uint32_t flow_id, uint32_t packet_id)
{
    if (g_selective_target_ratio >= 1.0) return true;
    if (g_selective_target_ratio <= 0.0) return false;
    uint64_t h = (uint64_t)flow_id * 2654435761ull + (uint64_t)packet_id * 40503ull + 0x9E3779B9ull;
    h ^= h >> 13; h *= 0x9E3779B97F4A7C15ull; h ^= h >> 16;
    double u = (double)(h & 0xFFFFFFull) / (double)0x1000000ull;   // uniform in [0,1)
    return u < g_selective_target_ratio;
}

// sample_attack_injection_delay() (mobility amplification fix §4.3):
// Returns the per-packet attack delay in seconds. In the default banded
// mode (attack_delay_pseudo_random=true, attack_variables.h), draws from a
// +/-10% band around attack_delay_ms (the active intensity level's anchor —
// ATTACK_DELAY_ANCHOR_{LOW,MED,HIGH}_MS) using a seeded ns-3
// UniformRandomVariable, reproducible per sim_seed/sim_run. In deterministic
// mode (attack_delay_pseudo_random=false), returns attack_delay_ms unchanged
// -- for standalone testing that needs an exact value (e.g. the S2-threshold
// sweep, routing.cc ~L141781).
//
// Band bounds are captured once on first call (lazily, after cmd.Parse() has
// already resolved attack_delay_ms from the CLI) since attack_delay_ms is
// fixed for the remainder of the run.
inline double sample_attack_injection_delay()
{
    if (!attack_delay_pseudo_random)
        return attack_delay_ms / 1000.0;

    static Ptr<UniformRandomVariable> rng = nullptr;
    if (!rng) {
        double lo = attack_delay_ms * (1.0 - ATTACK_DELAY_BAND_FRAC);
        double hi = attack_delay_ms * (1.0 + ATTACK_DELAY_BAND_FRAC);
        rng = CreateObject<UniformRandomVariable>();
        rng->SetAttribute("Min", DoubleValue(lo));
        rng->SetAttribute("Max", DoubleValue(hi));
    }
    return rng->GetValue() / 1000.0;
}

// eq:quarantine enforcement for Selective Time Delay (A1/A2), 2026-09-05.
//
// A1 and A2 were the last two variants with NO enforcement guard of any kind --
// not an inert guard, an absent one. A3/A4 have theirs at
// tcam_attack_helper.h:784, A5-A8 at routing.cc:121655/:121751; this closes the
// remaining two. eq:quarantine describes quarantine as instructing the network
// to drop flows from a compromised node, with no RSU-only restriction, so this
// is finishing the spec rather than adding a design decision.
//
// BOTH tests are required, exactly as the HF guard does it. A2's malicious-node
// pool spans the full node space (declare_attackers(), attack_declaration.h:
// n_candidates = N_Vehicles + N_RSUs), so its injector CAN be a vehicle relay.
// Vehicles never cross the RSU trust threshold, so testing the injector alone
// would let every vehicle-attacker injection through while
// g_lstm_std_sendgt_count still attributes it to the covering RSU -- which IS
// quarantined. That is the same leak measured on A6/A8 (2026-08-30) and closed
// there the same way. hf_gt_attribution_node() maps an RSU to itself, so A1
// (whose injector is always the RSU holding the poisoned FlowMod) is covered by
// the same expression with no special case.
//
// Caveat, stated because it is a real modelling choice and not self-evident:
// blocking the INJECTION lets the packet forward normally rather than dropping
// it, i.e. a quarantined node is denied the malicious action but still relays
// legitimate traffic. That matches the convention every other guard in this
// codebase already uses, and it is open question 2.3 ("should legitimate
// forwarding by a quarantined RSU also be blocked?"), not a new deviation.
//
// UINT32_MAX (no RSU currently covers the injecting vehicle) is safe:
// quarantine_blocks() bounds-checks and returns false.
//
// Requires crypto_layer.h (quarantine_blocks) and routing.cc's
// hf_gt_attribution_node definition to precede this header -- both do
// (routing.cc:115177 and :115218 vs :115506).
//
// No-op while --enable_quarantine_enforcement is off: quarantine_blocks()
// returns false unconditionally in that state, so every result produced before
// 2026-09-05 reproduces bit-identically.
inline bool std_delay_quarantine_blocks(uint32_t injector)
{
    // Fix 3 (N3): count a genuine block (this guard is reached only when the
    // injecting node was about to apply the attack, so a true here is an aborted
    // action). Covers the four A1/A2 call sites that route through this helper.
    if (quarantine_blocks_action(injector)) return true;
    return quarantine_blocks_action(hf_gt_attribution_node(injector));
}

// Unified Receiver Delay Calculator
//
// attack_delay_ms (global, CLI: --attack_delay_ms) — anchor delay (ms) used by
//   both CP and DP attacks; actual_delay is drawn from a band around it via
//   sample_attack_injection_delay() (§4.3) unless attack_delay_pseudo_random
//   is disabled. Default anchor 100 ms (2x Delta_max).
// is_safety_critical — both attacks only delay HIGH-priority safety-critical
//   packets per S1 (Eq. 3.4) and S2 (Eq. 3.5). Best-effort falls through.
inline double calculate_unified_selective_delay(
    bool present_selective_delay_dp,
    bool is_malicious_dp,
    bool is_first_attempt,
    double attack_percentage,
    bool present_selective_delay_cp,
    double injected_delay_cp,
    uint32_t current_hop,
    uint32_t packet_id,
    uint32_t flow_id,
    bool is_safety_critical)
{
    // Attack 2: Data Plane Delay (Malicious node intentionally delays)
    // Guard: is_safety_critical enforces Signature S2 / Equation 3.5 conjunction
    // "Priority(p) = HIGH" — best-effort packets are passed through immediately.
    if (present_selective_delay_dp && is_malicious_dp && is_first_attempt
        && is_safety_critical && selective_packet_targeted(flow_id, packet_id))
    {
        // eq:quarantine -- see std_delay_quarantine_blocks() above. Tested here
        // rather than at function entry so the covering-RSU lookup is paid only
        // on packets an attack would actually fire on.
        if (std_delay_quarantine_blocks(current_hop)) return 0.0;

        double actual_delay = sample_attack_injection_delay();

        cout << attack_tag() << " ③ "
             << (current_hop < (uint32_t)N_Vehicles ? "Malicious Vehicle" : "Malicious RSU")
             << " (node " << current_hop
             << ") intercepting packet ID " << packet_id
             << " for flow " << flow_id
             << " [SAFETY-CRITICAL] at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        cout << attack_tag() << " ④ Buffering — injecting fixed delay of "
             << actual_delay * 1000.0 << "ms" << endl;
        cout << attack_tag() << " ⑤ Delayed forward scheduled at t="
             << Simulator::Now().GetSeconds() + actual_delay
             << "s (delay=" << actual_delay * 1000.0 << "ms)" << endl;
        return actual_delay;
    }

    // Attack 1: Control Plane Delay (Benign node obeying poisoned FlowMod)
    // Mutually exclusive: only runs if DP attack did not trigger.
    // Guard: is_safety_critical enforces Signature S1 / Equation 3.4 conjunction
    // "Priority(p) = HIGH" — best-effort packets receive no injected delay.
    if (present_selective_delay_cp && injected_delay_cp > 0.0
        && is_safety_critical && selective_packet_targeted(flow_id, packet_id))
    {
        // eq:quarantine -- the A1 injector is always the RSU holding the
        // poisoned FlowMod, so this is the RSU-attacker case A3 already proves
        // the mechanism on.
        if (std_delay_quarantine_blocks(current_hop)) return 0.0;

        cout << attack_tag() << " RSU (node " << current_hop
             << ", UNAWARE it is compromised) obeying poisoned flowMod for packet ID "
             << packet_id << ", flow " << flow_id
             << " [SAFETY-CRITICAL]"
             << " — forwarding with " << injected_delay_cp * 1000.0 << "ms delay"
             << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        return injected_delay_cp;
    }

    return 0.0;
}

// Unified Scheduler for routing loops
template <typename Func, typename... Args>
inline bool schedule_unified_selective_delay_attack(
    bool present_selective_delay_dp,
    bool is_malicious_dp,
    bool is_first_attempt,
    double attack_percentage,
    bool present_selective_delay_cp,
    double injected_delay_cp,
    uint32_t source,
    uint32_t packet_ID,
    uint32_t fid,
    bool is_safety_critical,
    Func func,
    Args... args)
{
    // Attack 2: Data Plane Delay
    // Guard: is_safety_critical enforces Signature S2 / Equation 3.5.
    if (present_selective_delay_dp && is_malicious_dp && is_first_attempt
        && is_safety_critical && selective_packet_targeted(fid, packet_ID))
    {
        // eq:quarantine -- see std_delay_quarantine_blocks(). Returning false
        // (not scheduling a delayed forward) drops the caller through to its
        // own `if (!attacked)` immediate-send path, which is exactly the
        // "attack denied, traffic unaffected" semantics the other guards use.
        if (std_delay_quarantine_blocks(source)) return false;

        double actual_delay = sample_attack_injection_delay();

        cout << attack_tag() << " ③ "
             << (source < (uint32_t)N_Vehicles ? "Malicious Vehicle" : "Malicious RSU")
             << " (node " << source
             << ") intercepting packet ID " << packet_ID
             << " for flow " << fid
             << " [SAFETY-CRITICAL] at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        cout << attack_tag() << " ④ Buffering — injecting fixed delay of "
             << actual_delay * 1000.0 << "ms" << endl;
        cout << attack_tag() << " ⑤ Delayed forward scheduled at t="
             << Simulator::Now().GetSeconds() + actual_delay
             << "s (delay=" << actual_delay * 1000.0 << "ms)" << endl;

        Simulator::Schedule(Seconds(actual_delay), func, args...);
        return true;
    }

    // Attack 1: Control Plane Delay
    // Mutually exclusive: only runs if DP attack did not trigger.
    // Guard: is_safety_critical enforces Signature S1 / Equation 3.4.
    if (present_selective_delay_cp && injected_delay_cp > 0.0
        && is_safety_critical && selective_packet_targeted(fid, packet_ID))
    {
        // eq:quarantine -- A1 injector is always the poisoned-FlowMod RSU.
        if (std_delay_quarantine_blocks(source)) return false;

        cout << attack_tag() << " RSU (node " << source
             << ", UNAWARE it is compromised) obeying poisoned flowMod for packet ID "
             << packet_ID << ", flow " << fid
             << " [SAFETY-CRITICAL]"
             << " — forwarding with " << injected_delay_cp * 1000.0 << "ms delay"
             << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;

        Simulator::Schedule(Seconds(injected_delay_cp), func, args...);
        return true;
    }

    return false;
}

#endif // SELECTIVE_TIME_DELAY_H
