#ifndef SELECTIVE_TIME_DELAY_H
#define SELECTIVE_TIME_DELAY_H

#include <iostream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Forward declarations of functions implemented in routing.cc
extern std::string attack_tag();
extern bool GetBooleanWithProbability(double probabilityPercent, int nodeID);

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
        && is_safety_critical)
    {
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
        && is_safety_critical)
    {
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
        && is_safety_critical)
    {
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
        && is_safety_critical)
    {
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
