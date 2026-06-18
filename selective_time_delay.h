#ifndef SELECTIVE_TIME_DELAY_H
#define SELECTIVE_TIME_DELAY_H

#include <iostream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Forward declarations of functions implemented in routing.cc
extern std::string attack_tag();
extern bool GetBooleanWithProbability(double probabilityPercent, int nodeID);

// Main receiver delay calculator
inline double calculate_selective_delay(
    bool present_selective_delay,
    bool is_malicious,
    bool is_first_attempt,
    double attack_percentage,
    uint32_t current_hop,
    uint32_t packet_id,
    uint32_t flow_id,
    double attack2_delay)
{
    double tx_delay = 0.0;
    if (present_selective_delay && is_malicious && is_first_attempt)
    {
        bool atk = GetBooleanWithProbability(attack_percentage, current_hop);
        if (atk)
        {
            tx_delay = attack2_delay;
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
        }
    }
    return tx_delay;
}

// Scheduler for routing loops
template <typename AppClass>
inline bool schedule_selective_delay_attack(
    AppClass* app,
    Ptr<Packet> packet_i,
    uint32_t source,
    uint32_t next_hop_id,
    Mac48Address dest_address,
    uint32_t fid,
    uint32_t packet_ID,
    bool present_selective_delay,
    bool is_malicious,
    bool is_first_attempt,
    double attack_percentage,
    double attack2_delay)
{
    if (is_malicious && present_selective_delay && is_first_attempt)
    {
        bool atk = GetBooleanWithProbability(attack_percentage, source);
        if (atk)
        {
            cout << attack_tag() << " ③ Malicious RSU (node " << source
                 << ") intercepting packet ID " << packet_ID
                 << " for flow " << fid << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
            cout << attack_tag() << " ④ Buffering — injecting delay of "
                 << attack2_delay * 1000.0 << "ms" << endl;
            cout << attack_tag() << " ⑤ Delayed forward scheduled at t="
                 << Simulator::Now().GetSeconds() + attack2_delay
                 << "s (delay=" << attack2_delay*1000.0 << "ms)" << endl;
            
            Simulator::Schedule(Seconds(attack2_delay), 
                                &AppClass::send_dsrc_routing_packet, 
                                app, packet_i, source, next_hop_id, dest_address, fid, packet_ID);
            return true;
        }
    }
    return false;
}

#endif // SELECTIVE_TIME_DELAY_H
