#ifndef HF_ATTACK_HELPER_H
#define HF_ATTACK_HELPER_H

// =============================================================================
// hf_attack_helper.h — Hidden Forwarding Attack Variants 5–8
// =============================================================================
//
// Implements four Hidden Forwarding attack variants:
//
//   Attack 5 (active_attack_variant == 4): Active  Hidden Forwarding, Control Plane
//   Attack 6 (active_attack_variant == 5): Active  Hidden Forwarding, Data Plane
//   Attack 7 (active_attack_variant == 6): Passive Hidden Forwarding, Control Plane
//   Attack 8 (active_attack_variant == 7): Passive Hidden Forwarding, Data Plane
//
// ── CP vs DP distinction ─────────────────────────────────────────────────────
//
//   The delta table is the FlowMod equivalent in this simulation.
//
//     delta_at_controller_inst[fid].delta_fi_inst[node].delta_values[next_hop]
//       → Routing weights computed by the controller.
//         > 0.0 means "node should forward flow fid toward next_hop".
//
//     delta_at_nodes_inst[fid].delta_fi_inst[node].delta_values[next_hop]
//       → Local copy installed at each node after transmit_delta_values()
//         delivers the controller's decision downlink.
//
//   CONTROL PLANE (Variants 5, 7):
//     The malicious CONTROLLER corrupts delta_at_controller_inst before
//     transmit_delta_values() fires. The RSU is honest — it simply installs
//     and obeys the poisoned rule it received from the controller.
//
//   DATA PLANE (Variants 6, 8):
//     The malicious RSU directly overwrites its own delta_at_nodes_inst
//     after the legitimate rule arrives from the (clean) controller.
//     The controller is not involved. The attacker is the RSU itself.
//
// ── Active vs Passive distinction ────────────────────────────────────────────
//
//   ACTIVE (Variants 5, 6):  Duplicate packet has flow_id set to
//     (0xDEAD0000 | original_flow_id) — a fabrication marker that causes
//     EdDSA verification failure, feeding 𝟙[π_hop=⊥] = 1 into the LSTM.
//
//   PASSIVE (Variants 7, 8):  Exact copy, no content change.
//     Undetectable by volume/conservation methods (FADE MCC = 0).
//
// ── Multi-RSU scaling (SUMO networks) ────────────────────────────────────────
//
//   In test network mode (routing_test=true):
//     Hardcoded node indices are used (e.g. RSU=6, eavesdropper=2).
//
//   In SUMO mode (routing_test=false, 80+ vehicles, 20+ RSUs):
//     hf_declare_malicious_rsus() uses attack_percentage to determine how
//     many RSUs to compromise. It scans proposed_routing_tables to find RSUs
//     that are actually on active flow paths, so the attack is realistic
//     rather than targeting random nodes.
//
//     attack_percentage meaning for HF variants:
//       0%  → no RSUs attacked (baseline)
//      20%  → ~20% of on-path RSUs are malicious
//      ...
//     100%  → all on-path RSUs are malicious
//
//     This mirrors the pattern already used for Attack 4 (DP TCAM exhaustion)
//     where num_attackers scales the number of compromised nodes.
//
// ── Globals defined in routing.cc, used here ─────────────────────────────────
//   extern int      active_attack_variant;
//   extern double   simTime;
//   extern double   attack_start_time;
//   extern bool     routing_test;
//   extern uint32_t N_Vehicles;
//   extern uint32_t N_RSUs;
//   extern int      attack_percentage;
//   extern bool     present_active_hf_attack;
//   extern bool     present_passive_hf_attack;
//   extern bool     active_hf_malicious_nodes[];
//   extern bool     passive_hf_malicious_nodes[];
//   extern uint32_t active_hf_eavesdropper_index;
//   extern uint32_t passive_hf_eavesdropper_index;
//   extern std::map<uint32_t, uint32_t> passive_hf_rsu_to_eavesdropper;
//   extern uint32_t g_hdup_rsu, g_hdup_eaves, g_hdup_flow_id;
//   extern uint32_t g_hdup_packet_id, g_hdup_channel, g_hdup_p_size;
//   extern Time     g_hdup_timestamp;
//   extern bool     g_hdup_intentional;
//   extern uint64_t g_total_copies_scheduled;
//   extern uint32_t hf_target_flow_id;
//   struct delta_f  delta_at_controller_inst[];
//   struct delta_f  delta_at_nodes_inst[];
//   struct proposed_routing_table proposed_routing_tables[];
//
// =============================================================================

#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

// Staging globals — must be declared before any function that references them
static uint32_t g_declare_flow_id = 0;
static bool     g_declare_is_cp   = false;
static bool     g_declare_active  = false;

// =============================================================================
// HF EVENT LOG
// =============================================================================

struct HfDuplicateEvent {
    double   event_time;        // sim time when duplicate was scheduled
    uint32_t flow_id;           // flow being duplicated
    uint32_t packet_id;         // packet within that flow
    uint32_t malicious_node;    // RSU/node that sent the duplicate
    uint32_t eavesdropper;      // unauthorized recipient
    bool     is_active;         // true = content modified (Attacks 5,6)
    bool     is_cp;             // true = control-plane origin (Attacks 5,7)
};

std::vector<HfDuplicateEvent> g_hf_event_log;

// Export at end of simulation — mirrors export_tcam_snapshot_baseline()
inline void export_hf_event_log()
{
    static const std::map<int, std::string> variant_to_label = {
        {4, "attack5"}, {5, "attack6"}, {6, "attack7"}, {7, "attack8"}
    };
    std::string mode = "baseline";
    auto it = variant_to_label.find(active_attack_variant);
    if (it != variant_to_label.end()) mode = it->second;

    const std::string base_dir =
        "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";
    std::string path = base_dir + "hf_events_" + mode + "_" +
                       std::to_string(attack_percentage) + ".csv";

    std::ofstream fout(path, std::ios::trunc);
    fout << "t,flow_id,packet_id,malicious_node,eavesdropper,is_active,is_cp\n";
    for (const auto& e : g_hf_event_log)
    {
        fout << e.event_time     << ","
             << e.flow_id        << ","
             << e.packet_id      << ","
             << e.malicious_node << ","
             << e.eavesdropper   << ","
             << (e.is_active ? 1 : 0) << ","
             << (e.is_cp    ? 1 : 0)  << "\n";
    }
    fout.close();
    std::cout << "[HF] Event log exported: " << g_hf_event_log.size()
              << " events -> " << path << std::endl;
}

// =============================================================================
// DELTA TABLE INJECTION — the CP/DP distinction
// =============================================================================

// Delayed raw-state verification — fires ~1s after injection so we can see
// whether the controller's poisoned delta actually propagated down to the
// node's table (CP should now show both nonzero), or whether DP's injection
// stayed isolated to the node table only (controller should still read 0).
// Declared here, before hf_cp_inject_delta / hf_dp_inject_delta, since both
// reference it directly.
static uint32_t g_verify_flow_id = 0;
static uint32_t g_verify_rsu_node = 0;
static uint32_t g_verify_eaves_node = 0;

inline void hf_verify_state_trampoline()
{
    double ctrl_val = (delta_at_controller_inst + g_verify_flow_id)
        ->delta_fi_inst[g_verify_rsu_node].delta_values[g_verify_eaves_node];
    double node_val = (delta_at_nodes_inst + g_verify_flow_id)
        ->delta_fi_inst[g_verify_rsu_node].delta_values[g_verify_eaves_node];
    std::cout << "[RAW STATE CHECK - AFTER 1s] t=" << Simulator::Now().GetSeconds()
              << "s  delta_at_CONTROLLER[" << g_verify_rsu_node << "][" << g_verify_eaves_node << "]=" << ctrl_val
              << "  delta_at_NODES[" << g_verify_rsu_node << "][" << g_verify_eaves_node << "]=" << node_val
              << std::endl;
}

// ── CP: corrupts the CONTROLLER's delta table ─────────────────────────────────
// Called BEFORE transmit_delta_values() so the poisoned weight propagates to
// the RSU via the normal downlink path. The RSU is honest but manipulated.
//
inline void hf_cp_inject_delta(uint32_t flow_id,
                                uint32_t rsu_node,
                                uint32_t eavesdropper_node,
                                double   weight = 0.5)
{
    (delta_at_controller_inst + flow_id)
        ->delta_fi_inst[rsu_node].delta_values[eavesdropper_node] = weight;

    std::cout << "[HF CP INJECT] Controller delta poisoned:"
              << " flow=" << flow_id
              << " rsu=" << rsu_node
              << " -> eavesdropper=" << eavesdropper_node
              << " weight=" << weight
              << " t=" << Simulator::Now().GetSeconds() << "s"
              << " [Malicious FlowMod delivered to RSU via transmit_delta_values()]"
              << std::endl;

    // RAW STATE VERIFICATION — read back actual stored values, not narration
    double ctrl_val = (delta_at_controller_inst + flow_id)->delta_fi_inst[rsu_node].delta_values[eavesdropper_node];
    double node_val = (delta_at_nodes_inst + flow_id)->delta_fi_inst[rsu_node].delta_values[eavesdropper_node];
    std::cout << "[RAW STATE CHECK] after CP inject: "
              << "delta_at_CONTROLLER[" << rsu_node << "][" << eavesdropper_node << "]=" << ctrl_val
              << "  delta_at_NODES[" << rsu_node << "][" << eavesdropper_node << "]=" << node_val
              << std::endl;

    g_verify_flow_id = flow_id;
    g_verify_rsu_node = rsu_node;
    g_verify_eaves_node = eavesdropper_node;
    Simulator::Schedule(Seconds(1.0), &hf_verify_state_trampoline);      
}

// ── DP: corrupts the RSU's OWN local delta table ─────────────────────────────
// Called AFTER transmit_delta_values() has delivered the legitimate rule.
// The RSU overwrites its own installed entry. Controller table stays clean.
//
inline void hf_dp_inject_delta(uint32_t flow_id,
                                uint32_t rsu_node,
                                uint32_t eavesdropper_node,
                                double   weight = 0.5)
{
    (delta_at_nodes_inst + flow_id)
        ->delta_fi_inst[rsu_node].delta_values[eavesdropper_node] = weight;

    std::cout << "[HF DP INJECT] Node delta self-poisoned:"
              << " flow=" << flow_id
              << " rsu=" << rsu_node
              << " -> eavesdropper=" << eavesdropper_node
              << " weight=" << weight
              << " t=" << Simulator::Now().GetSeconds() << "s"
              << " [Controller table untouched — RSU modified its own installed rule]"
              << std::endl;

    // RAW STATE VERIFICATION — read back actual stored values, not narration
    double ctrl_val = (delta_at_controller_inst + flow_id)->delta_fi_inst[rsu_node].delta_values[eavesdropper_node];
    double node_val = (delta_at_nodes_inst + flow_id)->delta_fi_inst[rsu_node].delta_values[eavesdropper_node];
    std::cout << "[RAW STATE CHECK] after DP inject: "
              << "delta_at_CONTROLLER[" << rsu_node << "][" << eavesdropper_node << "]=" << ctrl_val
              << "  delta_at_NODES[" << rsu_node << "][" << eavesdropper_node << "]=" << node_val
              << std::endl;

    g_verify_flow_id = flow_id;
    g_verify_rsu_node = rsu_node;
    g_verify_eaves_node = eavesdropper_node;
    Simulator::Schedule(Seconds(1.0), &hf_verify_state_trampoline);
}

// Re-applies DP poisoning for all currently-compromised RSUs. Called twice per
// cycle: once immediately after clear_delta_at_nodes() (which runs at the very
// start of each cycle, before initialize_flow_counters()'s own internal clear),
// and again from inside initialize_flow_counters() itself. Two calls are needed
// because there are two separate clearing mechanisms in routing.cc that both
// wipe delta_at_nodes_inst at different points in the same cycle; without both
// re-applies, the DP attack's poisoned entry is briefly (but genuinely) absent
// for part of every cycle.
inline void hf_reapply_dp_after_clear()
{
    if (active_attack_variant != 5 && active_attack_variant != 7) return;
    for (auto const& kv : passive_hf_rsu_to_eavesdropper)
    {
        uint32_t rsu_node = kv.first;
        (void)kv.second;
        if (active_hf_malicious_nodes[rsu_node] || passive_hf_malicious_nodes[rsu_node])
        {
            // DP trigger uses malicious-node flag — no delta write needed here.
            // Writing to nodes_inst would corrupt routing decisions
            // (original rerouted to eavesdropper instead of legitimate hop).
        }
    }
}

// Re-applies CP poisoning (both tables) for all currently-compromised RSUs.
// Called immediately after clear_delta_at_nodes(), for the same reason
// hf_reapply_dp_after_clear() exists: clear_delta_at_nodes() wipes
// delta_at_nodes_inst at the start of every cycle, before
// initialize_flow_counters()'s own re-apply gets a chance to run.
inline void hf_reapply_cp_after_clear()
{
    if (active_attack_variant != 4 && active_attack_variant != 6) return;
    std::cout << "[CP REAPPLY] t=" << Simulator::Now().GetSeconds()
              << "s map_size=" << passive_hf_rsu_to_eavesdropper.size()
              << " flow=" << g_declare_flow_id << std::endl;
    for (auto const& kv : passive_hf_rsu_to_eavesdropper)
    {
        uint32_t rsu_node   = kv.first;
        uint32_t eaves_node = kv.second;
        if (active_hf_malicious_nodes[rsu_node] || passive_hf_malicious_nodes[rsu_node])
        {
            for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
            {
                // CP: poison controller table only. nodes_inst must stay clean
                // so routing decisions (initiate_all_flows) send the original
                // packet to the legitimate next hop, not the eavesdropper.
                (delta_at_controller_inst+fid)->delta_fi_inst[rsu_node].delta_values[eaves_node] = 0.5;
            }
            std::cout << "[CP REAPPLY] wrote CTRL[" << rsu_node << "][" << eaves_node << "]=0.5 (all flows)" << std::endl;
        }
    }
}
// ── Check if a poisoned delta entry exists for this RSU/eavesdropper pair ─────
// Used in check_delivery_and_retransmit as the forwarding trigger condition.
//
inline bool hf_delta_entry_active(uint32_t flow_id,
                                   uint32_t rsu_node,
                                   uint32_t eavesdropper_node)
{
    // Use the malicious-node flag as the HF trigger instead of reading
    // delta tables. Writing to nodes_inst would corrupt routing decisions
    // in initiate_all_flows (routing the original to the eavesdropper
    // instead of the legitimate hop, dropping PDR). Writing to
    // controller_inst for DP attacks would erase the CP/DP forensic
    // distinction. The malicious flag is set by hf_declare_malicious_rsus
    // at attack_start_time and stays set for the rest of the simulation.
    return active_hf_malicious_nodes[rsu_node] ||
           passive_hf_malicious_nodes[rsu_node];
}

// ── Resolve the eavesdropper index for a given RSU ────────────────────────────
// Reads passive_hf_rsu_to_eavesdropper map first; falls back to legacy index.
//
inline uint32_t hf_resolve_eavesdropper(uint32_t rsu_node)
{
    auto it = passive_hf_rsu_to_eavesdropper.find(rsu_node);
    if (it != passive_hf_rsu_to_eavesdropper.end())
        return it->second;
    return present_active_hf_attack
               ? active_hf_eavesdropper_index
               : passive_hf_eavesdropper_index;
}

// =============================================================================
// DP INJECTION TRAMPOLINES
// NS-3 3.35 Simulator::Schedule does not support lambdas.
// We use the same staging-global + zero-arg trampoline pattern as
// send_hidden_duplicate_trampoline() in routing.cc.
// =============================================================================

// Staging globals for scheduled DP injections
static uint32_t g_dp_inject_flow_id   = 0;
static uint32_t g_dp_inject_rsu_node  = 0;
static uint32_t g_dp_inject_eaves     = 0;

inline void hf_dp_inject_trampoline()
{
    hf_dp_inject_delta(g_dp_inject_flow_id,
                       g_dp_inject_rsu_node,
                       g_dp_inject_eaves);
}

// Staging globals moved to top of file (after #include block) for forward visibility

// Forward declaration — hf_declare_malicious_rsus is defined below the trampolines
inline void hf_declare_malicious_rsus(uint32_t flow_id_to_attack, bool is_cp, bool is_active);

inline void hf_declare_malicious_rsus_trampoline()
{
    hf_declare_malicious_rsus(g_declare_flow_id,
                               g_declare_is_cp,
                               g_declare_active);
}

// =============================================================================
// MULTI-RSU SCALING — for SUMO networks with attack_percentage
// =============================================================================
//
// How it works:
//
//   1. Walk proposed_routing_tables for every active flow to collect the list
//      of RSU nodes (index >= N_Vehicles) that appear on any flow path.
//      These are "on-path RSUs" — nodes that actually relay traffic.
//      Attacking off-path RSUs would have no effect.
//
//   2. Calculate num_to_compromise = ceil(on_path_rsus.size() * attack_percentage / 100).
//
//   3. Mark the first num_to_compromise RSUs from that list as malicious,
//      inject the delta entry for each one, and register their eavesdropper
//      in passive_hf_rsu_to_eavesdropper.
//
//   The eavesdropper for each RSU is chosen as the nearest vehicle that is
//   NOT the legitimate destination — specifically the vehicle that appears
//   as the PREVIOUS hop before this RSU in proposed_routing_tables (the sender),
//   since that vehicle is within range and the RSU already has a delta entry
//   pointing to it. This is a realistic eavesdrop target.
//
// Arguments:
//   flow_id_to_attack — which flow to target (0 for single-flow test networks)
//   is_cp             — true = inject into controller table; false = into node table
//   is_active         — true = active variant (content modified); false = passive
//
inline void hf_declare_malicious_rsus(uint32_t flow_id_to_attack,
                                       bool     is_cp,
                                       bool     is_active)
{
    if (attack_percentage <= 0)
    {
        std::cout << "[HF SCALE] attack_percentage=0 — no RSUs compromised." << std::endl;
        return;
    }

    // ── Step 1: collect on-path forwarder nodes ──────────────────────────────────
    // Combined pool for CP variants  : RSUs only
    // Combined pool for DP variants  : RSUs + intermediate vehicle relays
    //
    // Source selection by mode:
    //   routing_test=true  → proposed_routing_tables (hardcoded test-network paths)
    //   routing_test=false → delta_at_controller_inst (real optimizer output;
    //                        proposed_routing_tables is never populated in SUMO mode
    //                        since run_stable_path_finding writes only to
    //                        proposed_algo2_output_inst, not update_proposed_route)
    std::vector<uint32_t> on_path_nodes;
    std::map<uint32_t, uint32_t> node_to_eaves;

    if (routing_test)
    {
        // Test-network mode: walk proposed_routing_tables path arrays (RSUs only —
        // the test topology has no V2V relay hops).
        for (uint32_t src = 0; src < (uint32_t)total_size; src++)
        {
            for (uint32_t dst = 0; dst < (uint32_t)total_size; dst++)
            {
                if (src == dst) continue;
                uint32_t prev = 50000;
                for (uint32_t step = 0; step < (uint32_t)total_size; step++)
                {
                    uint32_t node = proposed_routing_tables[src].rows[dst].path[step];
                    if (node >= 50000) break;
                    if (node >= N_Vehicles && node < N_Vehicles + N_RSUs)
                    {
                        bool already_added = false;
                        for (auto r : on_path_nodes)
                            if (r == node) { already_added = true; break; }
                        if (!already_added)
                        {
                            on_path_nodes.push_back(node);
                            if (prev < N_Vehicles)
                                node_to_eaves[node] = prev;
                        }
                    }
                    prev = node;
                }
            }
        }
    }
    else
    {
        // SUMO mode — scan delta_at_controller_inst (not nodes_inst) because
        // clear_delta_at_nodes() fires at t=attack_start_time and wipes
        // delta_at_nodes_inst to zero; delta_at_controller_inst is written by
        // run_proposed_RL and never cleared, so it always holds valid weights here.

        // ── RSUs ──────────────────────────────────────────────────────────────
        for (uint32_t rsu = N_Vehicles; rsu < N_Vehicles + N_RSUs; rsu++)
        {
            on_path_nodes.push_back(rsu);

            // Eavesdropper = vehicle with highest delta weight pointing TO this RSU
            uint32_t best_eaves = rsu - N_Vehicles; // fallback: same-index vehicle
            double   best_w     = 0.0;
            for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
            {
                for (uint32_t v = 0; v < N_Vehicles; v++)
                {
                    double w = (delta_at_controller_inst + fid)
                                   ->delta_fi_inst[v].delta_values[rsu];
                    if (w > best_w) { best_w = w; best_eaves = v; }
                }
            }
            node_to_eaves[rsu] = best_eaves;

            // Legitimate hop = highest outgoing delta weight FROM this RSU
            // (excluding the eavesdropper vehicle)
            uint32_t legit_hop = (rsu + 1 < N_Vehicles + N_RSUs)
                                 ? rsu + 1 : N_Vehicles; // fallback: next RSU
            double   legit_w   = 0.0;
            for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
            {
                for (uint32_t n = 0; n < (uint32_t)total_size; n++)
                {
                    if (n == best_eaves) continue;
                    double w = (delta_at_controller_inst + fid)
                                   ->delta_fi_inst[rsu].delta_values[n];
                    if (w > legit_w) { legit_w = w; legit_hop = n; }
                }
            }
            passive_hf_rsu_to_legitimate_hop[rsu] = legit_hop;

            std::cout << "[HF SCALE] RSU " << rsu
                      << " eavesdropper=" << best_eaves
                      << " legit_hop=" << legit_hop << std::endl;
        }

        // ── Vehicle relay nodes (DP variants only) ────────────────────────────
        // A vehicle is a malicious intermediate forwarder if it has BOTH incoming
        // AND outgoing delta weights — it is relayed-through rather than an
        // endpoint. This matches the thesis V2V path:
        //   Vehicle A → Attacker Vehicle → RSU → Vehicle B
        // where the attacker vehicle self-modifies its own FlowMod (DP injection).
        if (!is_cp)
        {
            for (uint32_t v = 0; v < N_Vehicles; v++)
            {
                bool has_incoming = false;
                bool has_outgoing = false;
                for (uint32_t fid = 0;
                     fid < 2 * (uint32_t)flows && (!has_incoming || !has_outgoing);
                     fid++)
                {
                    for (uint32_t n = 0; n < (uint32_t)total_size; n++)
                    {
                        if (n == v) continue;
                        if (!has_incoming &&
                            (delta_at_controller_inst + fid)->delta_fi_inst[n].delta_values[v] > 0.0)
                            has_incoming = true;
                        if (!has_outgoing &&
                            (delta_at_controller_inst + fid)->delta_fi_inst[v].delta_values[n] > 0.0)
                            has_outgoing = true;
                    }
                }
                if (!has_incoming || !has_outgoing) continue;

                on_path_nodes.push_back(v);

                // Legitimate next hop: highest outgoing delta FROM this vehicle
                uint32_t legit_hop_v = (v + 1) % N_Vehicles; // fallback
                double   legit_w_v   = 0.0;
                for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
                {
                    for (uint32_t n = 0; n < (uint32_t)total_size; n++)
                    {
                        if (n == v) continue;
                        double w = (delta_at_controller_inst + fid)
                                       ->delta_fi_inst[v].delta_values[n];
                        if (w > legit_w_v) { legit_w_v = w; legit_hop_v = n; }
                    }
                }
                passive_hf_rsu_to_legitimate_hop[v] = legit_hop_v;

                // Eavesdropper: another vehicle (not the legit next hop) with the
                // highest outgoing delta weight FROM this relay vehicle — it
                // receives the covert duplicate copy.
                uint32_t best_eaves_v = (v + 1) % N_Vehicles; // fallback
                double   best_ew_v    = 0.0;
                for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
                {
                    for (uint32_t ev = 0; ev < N_Vehicles; ev++)
                    {
                        if (ev == v || ev == legit_hop_v) continue;
                        double w = (delta_at_controller_inst + fid)
                                       ->delta_fi_inst[v].delta_values[ev];
                        if (w > best_ew_v) { best_ew_v = w; best_eaves_v = ev; }
                    }
                }
                node_to_eaves[v] = best_eaves_v;

                std::cout << "[HF SCALE] VehicleRelay " << v
                          << " eavesdropper=" << best_eaves_v
                          << " legit_hop=" << legit_hop_v << std::endl;
            }
        }
    }

    std::cout << "[HF SCALE] Found " << on_path_nodes.size()
              << " on-path forwarder node(s) (mode=" << (routing_test ? "test" : "SUMO")
              << " CP=" << (is_cp ? "yes" : "no") << ")" << std::endl;

    if (on_path_nodes.empty())
    {
        std::cout << "[HF SCALE] WARNING: No on-path forwarder nodes found."
                  << " Has run_optimization / run_proposed_RL fired yet?" << std::endl;
        return;
    }

    // Sort combined list by total incoming traffic load (descending) so
    // num_to_compromise selects the MOST ACTIVE nodes, not lowest-indexed ones.
    if (!routing_test)
    {
        std::sort(on_path_nodes.begin(), on_path_nodes.end(),
            [](uint32_t a, uint32_t b)
            {
                double load_a = 0.0, load_b = 0.0;
                for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
                {
                    for (uint32_t n = 0; n < (uint32_t)total_size; n++)
                    {
                        if (n != a)
                            load_a += (delta_at_controller_inst + fid)
                                          ->delta_fi_inst[n].delta_values[a];
                        if (n != b)
                            load_b += (delta_at_controller_inst + fid)
                                          ->delta_fi_inst[n].delta_values[b];
                    }
                }
                return load_a > load_b; // descending: highest load first
            });
    }

    // ── Step 2: calculate how many to compromise from the combined pool ───────
    uint32_t total_on_path     = (uint32_t)on_path_nodes.size();
    uint32_t num_to_compromise = (uint32_t)std::ceil(
        total_on_path * attack_percentage / 100.0);
    if (num_to_compromise > total_on_path)
        num_to_compromise = total_on_path;

    std::cout << "[HF SCALE] " << total_on_path << " on-path node(s) found."
              << " attack_percentage=" << attack_percentage << "%"
              << " -> compromising " << num_to_compromise << " node(s)."
              << " CP=" << (is_cp ? "yes" : "no")
              << " Active=" << (is_active ? "yes" : "no")
              << std::endl;

    // ── Step 3: mark and inject ───────────────────────────────────────────────
    for (uint32_t i = 0; i < num_to_compromise; i++)
    {
        uint32_t mal_node = on_path_nodes[i];

        // Choose eavesdropper; fall back to vehicle 0 if nothing was recorded.
        uint32_t eaves_node = 0;
        auto eit = node_to_eaves.find(mal_node);
        if (eit != node_to_eaves.end())
            eaves_node = eit->second;

        // Register in the eavesdropper map so hf_resolve_eavesdropper() works
        passive_hf_rsu_to_eavesdropper[mal_node] = eaves_node;

        // Flag as malicious
        if (is_active)
        {
            active_hf_malicious_nodes[mal_node] = true;
            present_active_hf_attack = true;
        }
        else
        {
            passive_hf_malicious_nodes[mal_node] = true;
            present_passive_hf_attack = true;
        }

        record_attack_onset(active_attack_variant, mal_node);
        is_malicious_node[active_attack_variant][mal_node] = true;
        t_onset[mal_node] = attack_start_time;

        // Inject the delta entry
        if (is_cp)
        {
            hf_cp_inject_delta(flow_id_to_attack, mal_node, eaves_node);
        }
        else
        {
            // DP: call hf_dp_inject_delta directly — we are already executing
            // inside hf_declare_malicious_rsus_trampoline (a Simulator::Schedule
            // callback), so no lambda/trampoline is needed here.
            //
            // IMPORTANT: The single-slot g_dp_inject_* staging globals CANNOT
            // handle multiple nodes in a loop — each iteration overwrites the
            // globals before the previous Simulator::Schedule fires. Calling
            // directly avoids this race entirely.
            hf_dp_inject_delta(flow_id_to_attack, mal_node, eaves_node);
        }

        bool is_vehicle_relay = (mal_node < N_Vehicles);
        std::cout << "[HF SCALE] " << (is_vehicle_relay ? "VehicleRelay" : "RSU")
                  << " " << mal_node
                  << " marked malicious -> eavesdropper=" << eaves_node
                  << std::endl;
    }
}

// =============================================================================
// INIT FUNCTIONS — called from initialise_stub_attack_state() case blocks
// =============================================================================
//
// routing_test=true  → use the hardcoded test topology indices passed in
// routing_test=false → call hf_declare_malicious_rsus() to scale with
//                       attack_percentage across the SUMO network

// ── Attack 5: Active Hidden Forwarding, Control Plane ─────────────────────────
inline void hf_init_attack5_cp(uint32_t flow_id,
                                uint32_t test_rsu_node,
                                uint32_t test_eavesdropper)
{
    if (routing_test)
    {
        // Test network: single hardcoded RSU
        active_hf_malicious_nodes[test_rsu_node] = true;
        present_active_hf_attack = true;
        active_hf_eavesdropper_index = test_eavesdropper;
        hf_cp_inject_delta(flow_id, test_rsu_node, test_eavesdropper);
        std::cout << "[HF ATTACK5 CP] Test network: RSU=" << test_rsu_node
                  << " eavesdropper=" << test_eavesdropper
                  << " [CP — controller table poisoned]" << std::endl;
    }
    else
    {
        // SUMO network: scale with attack_percentage
        // hf_declare_malicious_rsus is scheduled at attack_start_time so
        // proposed_routing_tables is already populated by run_proposed_RL
        g_declare_flow_id = flow_id;
        g_declare_is_cp   = true;
        g_declare_active  = true;
        Simulator::Schedule(
            Seconds(attack_start_time),
            &hf_declare_malicious_rsus_trampoline);
        std::cout << "[HF ATTACK5 CP] SUMO: will compromise "
                  << attack_percentage << "% of on-path RSUs at t="
                  << attack_start_time << "s [CP — controller tables]" << std::endl;
    }
}

// ── Attack 6: Active Hidden Forwarding, Data Plane ────────────────────────────
inline void hf_init_attack6_dp(uint32_t flow_id,
                                uint32_t test_rsu_node,
                                uint32_t test_eavesdropper)
{
    if (routing_test)
    {
        // Test network: single hardcoded RSU
        // DP: schedule injection 10ms after attack_start_time so transmit_delta_values
        // has already delivered the legitimate rule first
        active_hf_malicious_nodes[test_rsu_node] = true;
        present_active_hf_attack = true;
        active_hf_eavesdropper_index = test_eavesdropper;
        g_dp_inject_flow_id  = flow_id;
        g_dp_inject_rsu_node = test_rsu_node;
        g_dp_inject_eaves    = test_eavesdropper;
        Simulator::Schedule(
            Seconds(attack_start_time + 0.010),
            &hf_dp_inject_trampoline);
        std::cout << "[HF ATTACK6 DP] Test network: RSU=" << test_rsu_node
                  << " eavesdropper=" << test_eavesdropper
                  << " [DP — RSU self-modifies at t=" << (attack_start_time + 0.010)
                  << "s; controller clean]" << std::endl;
    }
    else
    {
        // SUMO network: scale with attack_percentage
        // hf_declare_malicious_rsus handles the 10ms DP offset internally
        g_declare_flow_id = flow_id;
        g_declare_is_cp   = false;
        g_declare_active  = true;
        Simulator::Schedule(
            Seconds(attack_start_time),
            &hf_declare_malicious_rsus_trampoline);
        std::cout << "[HF ATTACK6 DP] SUMO: will compromise "
                  << attack_percentage << "% of on-path RSUs + relay vehicles at t="
                  << attack_start_time << "s [DP — node local tables]" << std::endl;
    }
}

// ── Attack 7: Passive Hidden Forwarding, Control Plane ────────────────────────
inline void hf_init_attack7_cp(uint32_t flow_id,
                                uint32_t test_rsu_node,
                                uint32_t test_eavesdropper)
{
    if (routing_test)
    {
        passive_hf_malicious_nodes[test_rsu_node] = true;
        present_passive_hf_attack = true;
        passive_hf_eavesdropper_index = test_eavesdropper;
        hf_cp_inject_delta(flow_id, test_rsu_node, test_eavesdropper);
        std::cout << "[HF ATTACK7 CP] Test network: RSU=" << test_rsu_node
                  << " eavesdropper=" << test_eavesdropper
                  << " [CP — controller table poisoned; duplicate UNMODIFIED]" << std::endl;
    }
    else
    {
        g_declare_flow_id = flow_id;
        g_declare_is_cp   = true;
        g_declare_active  = false;
        Simulator::Schedule(
            Seconds(attack_start_time),
            &hf_declare_malicious_rsus_trampoline);
        std::cout << "[HF ATTACK7 CP] SUMO: will compromise "
                  << attack_percentage << "% of on-path RSUs at t="
                  << attack_start_time << "s [CP — controller tables; passive copy]" << std::endl;
    }
}

// ── Attack 8: Passive Hidden Forwarding, Data Plane ───────────────────────────
inline void hf_init_attack8_dp(uint32_t flow_id,
                                uint32_t test_rsu_node,
                                uint32_t test_eavesdropper)
{
    if (routing_test)
    {
        passive_hf_malicious_nodes[test_rsu_node] = true;
        present_passive_hf_attack = true;
        passive_hf_eavesdropper_index = test_eavesdropper;
        g_dp_inject_flow_id  = flow_id;
        g_dp_inject_rsu_node = test_rsu_node;
        g_dp_inject_eaves    = test_eavesdropper;
        Simulator::Schedule(
            Seconds(attack_start_time + 0.010),
            &hf_dp_inject_trampoline);
        std::cout << "[HF ATTACK8 DP] Test network: RSU=" << test_rsu_node
                  << " eavesdropper=" << test_eavesdropper
                  << " [DP — RSU self-modifies at t=" << (attack_start_time + 0.010)
                  << "s; duplicate UNMODIFIED]" << std::endl;
    }
    else
    {
        g_declare_flow_id = flow_id;
        g_declare_is_cp   = false;
        g_declare_active  = false;
        Simulator::Schedule(
            Seconds(attack_start_time),
            &hf_declare_malicious_rsus_trampoline);
        std::cout << "[HF ATTACK8 DP] SUMO: will compromise "
                  << attack_percentage << "% of on-path RSUs + relay vehicles at t="
                  << attack_start_time << "s [DP — node local tables; passive copy]" << std::endl;
    }
}

// =============================================================================
// DUPLICATE SENDERS — called from check_delivery_and_retransmit
// =============================================================================

// Forward-declare the trampoline (defined in routing.cc)
void send_hidden_duplicate_trampoline();

// ── Passive duplicate (Variants 7, 8) — exact unmodified copy ────────────────
inline void hf_send_passive_duplicate(uint32_t rsu_node,
                                       uint32_t eavesdropper_node,
                                       uint32_t flow_id,
                                       uint32_t packet_id,
                                       uint32_t channel,
                                       uint32_t p_size,
                                       Time     original_timestamp)
{
    g_hdup_rsu         = rsu_node;
    g_hdup_eaves       = eavesdropper_node;
    g_hdup_flow_id     = flow_id;           // unmodified
    g_hdup_packet_id   = packet_id;
    g_hdup_channel     = channel;
    g_hdup_p_size      = p_size;
    g_hdup_timestamp   = original_timestamp;
    g_hdup_intentional = true;
    g_total_copies_scheduled++;

    HfDuplicateEvent ev;
    ev.event_time     = Simulator::Now().GetSeconds();
    ev.flow_id        = flow_id;
    ev.packet_id      = packet_id;
    ev.malicious_node = rsu_node;
    ev.eavesdropper   = eavesdropper_node;
    ev.is_active      = false;
    ev.is_cp          = (active_attack_variant == 6); // variant 6 = Attack 7 CP
    g_hf_event_log.push_back(ev);

    std::cout << "[HF PASSIVE] RSU(" << rsu_node << ")"
              << " -> eavesdropper(" << eavesdropper_node << ")"
              << " pkt=" << packet_id << " flow=" << flow_id
              << " [" << (ev.is_cp ? "CP" : "DP") << "] UNMODIFIED copy"
              << " t=" << ev.event_time << "s" << std::endl;

    Simulator::Schedule(Seconds(0.001), send_hidden_duplicate_trampoline);
}

// ── Active duplicate (Variants 5, 6) — content-fabricated copy ───────────────
// Sets g_hdup_flow_id to (0xDEAD0000 | flow_id) so the tag in the duplicate
// packet contains a tampered flow ID. This causes EdDSA verification failure
// at the receiver, which MOBIGUARD detects as π_hop = ⊥.
//
inline void hf_send_active_duplicate(uint32_t rsu_node,
                                      uint32_t eavesdropper_node,
                                      uint32_t flow_id,
                                      uint32_t packet_id,
                                      uint32_t channel,
                                      uint32_t p_size,
                                      Time     original_timestamp)
{
    g_hdup_rsu         = rsu_node;
    g_hdup_eaves       = eavesdropper_node;
    g_hdup_flow_id     = 0xDEAD0000u | flow_id;   // fabrication marker
    g_hdup_packet_id   = packet_id;
    g_hdup_channel     = channel;
    g_hdup_p_size      = p_size;
    g_hdup_timestamp   = original_timestamp;
    g_hdup_intentional = true;
    g_total_copies_scheduled++;

    HfDuplicateEvent ev;
    ev.event_time     = Simulator::Now().GetSeconds();
    ev.flow_id        = flow_id;
    ev.packet_id      = packet_id;
    ev.malicious_node = rsu_node;
    ev.eavesdropper   = eavesdropper_node;
    ev.is_active      = true;
    ev.is_cp          = (active_attack_variant == 4); // variant 4 = Attack 5 CP
    g_hf_event_log.push_back(ev);

    std::cout << "[HF ACTIVE] RSU(" << rsu_node << ")"
              << " -> eavesdropper(" << eavesdropper_node << ")"
              << " pkt=" << packet_id << " flow=" << flow_id
              << " fabricated_flow_id=0x" << std::hex << (0xDEAD0000u | flow_id) << std::dec
              << " [" << (ev.is_cp ? "CP" : "DP") << "] CONTENT MODIFIED — EdDSA FAIL"
              << " t=" << ev.event_time << "s" << std::endl;

    Simulator::Schedule(Seconds(0.001), send_hidden_duplicate_trampoline);
}

#endif // HF_ATTACK_HELPER_H
