#ifndef SELECTIVE_TIME_DELAY_H
#define SELECTIVE_TIME_DELAY_H

#include <iostream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Forward declarations of functions implemented in routing.cc
extern std::string attack_tag();
extern bool GetBooleanWithProbability(double probabilityPercent, int nodeID);

// Unified Receiver Delay Calculator
inline double calculate_unified_selective_delay(
    bool present_selective_delay_dp,
    bool is_malicious_dp,
    bool is_first_attempt,
    double attack_percentage,
    double attack2_delay,
    bool present_selective_delay_cp,
    double injected_delay_cp,
    uint32_t current_hop,
    uint32_t packet_id,
    uint32_t flow_id)
{
    // Attack 2: Data Plane Delay (Malicious node intentionally delays)
    if (present_selective_delay_dp && is_malicious_dp && is_first_attempt)
    {
        // bool atk = GetBooleanWithProbability(attack_percentage, current_hop);
        // if (atk)
        // {
            cout << attack_tag() << " ③ Malicious RSU (node " << current_hop
                 << ") intercepting packet ID " << packet_id
                 << " for flow " << flow_id
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
            cout << attack_tag() << " ④ Buffering - injecting delay of "
                 << attack2_delay * 1000.0 << "ms" << endl;
            cout << attack_tag() << " ⑤ Delayed forward scheduled at t="
                 << Simulator::Now().GetSeconds() + attack2_delay
                 << "s (delay=" << attack2_delay * 1000.0
                 << "ms)" << endl;
            return attack2_delay;
        // }
    }
    
    // Attack 1: Control Plane Delay (Benign node obeying poisoned FlowMod)
    // Mutually exclusive: only runs if DP attack did not trigger
    if (present_selective_delay_cp && injected_delay_cp > 0.0)
    {
        cout << attack_tag() << " [ATTACK1] RSU (node " << current_hop
             << ", UNAWARE it is compromised) obeying poisoned flowMod for packet ID "
             << packet_id << ", flow " << flow_id
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
    double attack2_delay,
    bool present_selective_delay_cp,
    double injected_delay_cp,
    uint32_t source,
    uint32_t packet_ID,
    uint32_t fid,
    Func func,
    Args... args)
{
    std::cout << "[DEBUG] schedule_unified_selective_delay_attack called on node " << source
              << " for packet " << packet_ID << ". Params: "
              << "present_dp=" << present_selective_delay_dp
              << ", is_malicious_dp=" << is_malicious_dp
              << ", is_first_attempt=" << is_first_attempt
              << ", attack_percentage=" << attack_percentage 
              << ", present_cp=" << present_selective_delay_cp
              << ", injected_delay_cp=" << injected_delay_cp << std::endl;

    // Attack 2: Data Plane Delay
    if (present_selective_delay_dp && is_malicious_dp && is_first_attempt)
    {
        // bool atk = GetBooleanWithProbability(attack_percentage, source);
        // if (atk)
        // {
            cout << attack_tag() << " ③ Malicious RSU (node " << source
                 << ") intercepting packet ID " << packet_ID
                 << " for flow " << fid << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
            cout << attack_tag() << " ④ Buffering — injecting delay of "
                 << attack2_delay * 1000.0 << "ms" << endl;
            cout << attack_tag() << " ⑤ Delayed forward scheduled at t="
                 << Simulator::Now().GetSeconds() + attack2_delay
                 << "s (delay=" << attack2_delay*1000.0 << "ms)" << endl;
            
            Simulator::Schedule(Seconds(attack2_delay), func, args...);
            return true;
        // }
    }

    // Attack 1: Control Plane Delay
    // Mutually exclusive: only runs if DP attack did not trigger
    if (present_selective_delay_cp && injected_delay_cp > 0.0)
    {
        cout << attack_tag() << " [ATTACK1] RSU (node " << source
             << ", UNAWARE it is compromised) obeying poisoned flowMod for packet ID "
             << packet_ID << ", flow " << fid
             << " — forwarding with " << injected_delay_cp * 1000.0 << "ms delay"
             << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;

        Simulator::Schedule(Seconds(injected_delay_cp), func, args...);
        return true;
    }

    return false;
}

#endif // SELECTIVE_TIME_DELAY_H
