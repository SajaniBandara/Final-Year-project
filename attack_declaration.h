#ifndef ATTACK_DECLARATION_H
#define ATTACK_DECLARATION_H

// =========================================================================
// Attack declaration scaffold — Selective Time Delay (Attack 1: Control
// Plane, Attack 2: Data Plane).
//
// This header owns the "who is malicious, derived from attack_percentage"
// logic for both attacks, kept deliberately separate from routing.cc so
// future edits to the (very large) routing.cc file cannot accidentally
// delete or silently break this scaffold. routing.cc retains the "now
// arm the attack" logic (initialise_stub_attack_state()), which calls
// into the present_*/controller_compromised[]/selective_delay_malicious_nodes[]
// state this header produces.
//
// Governing threat-model assumption (must hold throughout):
// "The threat model assumes that an adversary couldn't exist in both data
// plane and control plane at once." declare_attack_states() below resets
// and re-derives both attacks' master switches every call specifically to
// enforce this — do not remove that reset, and do not add a code path
// where present_selective_delay_cp_attack and
// present_selective_delay_attack_nodes can both be true at once.
//
// attack_number mapping (extend this table as future attacks are added —
// see routing.cc's existing active_attack_variant switch for the
// corresponding arming-side cases):
//   attack_number == 1  ->  Selective Time Delay, Control Plane (Attack 1)
//                            -> active_attack_variant == 0
//   attack_number == 2  ->  Selective Time Delay, Data Plane    (Attack 2)
//                            -> active_attack_variant == 1
//   attack_number == 3..8 -> reserved for future attacks.
// =========================================================================

#include <iostream>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// Forward declarations of symbols defined in routing.cc that this header
// depends on but does not own. Do not redefine any of these here — if the
// build reports any of these as missing, it means routing.cc's actual
// declaration changed and this list needs updating to match, not that a
// definition should be added in this header.
extern std::string attack_tag();
extern bool GetBooleanWithProbability(double probabilityPercent, int nodeID);
extern void update_route_malicious(uint32_t source, uint32_t destination, uint32_t next_hop, double delay);
extern void record_attack_onset(int v, int n);

// Ground truth metrics arrays defined in routing.cc
extern bool is_malicious_node[NUM_ATTACK_VARIANTS][total_size];
extern double t_onset[total_size];
extern double attack_start_time;

// declare_attack_states():
// Top-level dispatcher. Translates attack_number into the existing
// active_attack_variant value plus the correct present_* master-switch
// flags. Does NOT perform any attack arming itself (no routing-table
// writes, no Simulator::Schedule calls) — that remains
// initialise_stub_attack_state()'s job in routing.cc.
inline void declare_attack_states()
{
    // IMPORTANT: when attack_number_explicitly_set is false (legacy path where
    // --active_attack_variant is passed directly without --attack_number),
    // declare_attack_states() returns early and active_attack_variant is used
    // as-is. The declare_attackers() fallback below re-derives present_* flags
    // from active_attack_variant for this case. This path exists for backward
    // compatibility with scripts that predate the attack_number CLI parameter.
    // New experiment runs should always pass --attack_number; direct use of
    // --active_attack_variant without --attack_number bypasses the mutual-
    // exclusion reset and is not recommended.
    if (!attack_number_explicitly_set)
    {
        cout << "[declare_attack_states] attack_number not explicitly set — "
             << "skipping dispatcher, leaving active_attack_variant="
             << active_attack_variant << " as set directly by CLI/test harness."
             << endl;
        return; // do not touch active_attack_variant or any present_* flag
    }

    present_selective_delay_cp_attack    = false;
    present_selective_delay_attack_nodes = false;

    switch (attack_number)
    {
        case (1): // Selective Time Delay — Control Plane (Attack 1)
            present_selective_delay_cp_attack = true;
            active_attack_variant = 0;
            break;

        case (2): // Selective Time Delay — Data Plane (Attack 2)
            present_selective_delay_attack_nodes = true;
            active_attack_variant = 1;
            break;

        // case (3) through case (8): reserved. Add a new case here when
        // each attack's present_* flag(s) exist, mirroring this pattern.

        default:
            cout << "[declare_attack_states] WARNING: unrecognized attack_number="
                 << attack_number << " — no attack armed." << endl;
            break;
    }

    cout << "[declare_attack_states] attack_number=" << attack_number
         << " -> active_attack_variant=" << active_attack_variant
         << ", present_selective_delay_cp_attack=" << present_selective_delay_cp_attack
         << ", present_selective_delay_attack_nodes=" << present_selective_delay_attack_nodes
         << endl;
}

// declare_attackers():
// Per-run "who is malicious" derivation for both attacks, driven entirely
// by attack_percentage. Attack 2: independent stochastic draw per node.
// Attack 1: deterministic threshold ladder over N_Controllers, always
// leaving at least one controller honest.
inline void declare_attackers()
{
    // If the attack_number dispatcher didn't run, infer the present_*
    // flags directly from active_attack_variant so legacy
    // --active_attack_variant-only invocations still behave correctly.
    if (!attack_number_explicitly_set)
    {
        present_selective_delay_cp_attack    = (active_attack_variant == 0);
        present_selective_delay_attack_nodes = (active_attack_variant == 1);
    }

    for (uint32_t i = 0; i < (uint32_t)var; i++)
    {
        bool attacking_state = GetBooleanWithProbability(attack_percentage, i);
        if (present_selective_delay_attack_nodes == true)
        {
            selective_delay_malicious_nodes[i] = attacking_state;
            
            // Sync ground-truth for TAP Detection (Attack 2 is variant index 1)
            is_malicious_node[1][i] = attacking_state;
            if (attacking_state) {
                t_onset[i] = attack_start_time;
            }
        }
        else
        {
            selective_delay_malicious_nodes[i] = false;
        }
    }

    cout << attack_tag() << " declare_attackers() completed" << endl;
    for (uint32_t i = 0; i < (uint32_t)var; i++)
    {
        cout << attack_tag() << " Node " << i << " selective_delay_malicious = "
             << selective_delay_malicious_nodes[i] << endl;
    }

    // --- Attack 1 (Selective Time Delay, Control Plane): deterministic
    // controller-compromise threshold ladder, generalized to
    // N_Controllers. Always leaves at least one controller honest.
    for (uint32_t c = 0; c < N_Controllers; c++)
    {
        controller_compromised[c] = false; // reset every run
    }

    if (present_selective_delay_cp_attack == true)
    {
        // At p=100% the thesis (§3503) specifies all controllers are compromised.
        // Below 100%, always leave at least one controller honest.
        uint32_t max_compromisable = (attack_percentage == 100) ? N_Controllers
                                                                 : N_Controllers - 1;
        uint32_t step;
        if (attack_percentage < 10)       step = 0;
        else if (attack_percentage < 33)  step = 1;
        else if (attack_percentage < 66)  step = 2;
        else                              step = 3;

        uint32_t num_to_compromise = (step * max_compromisable) / 3;
        if (num_to_compromise > max_compromisable) num_to_compromise = max_compromisable;

        for (uint32_t c = 0; c < num_to_compromise; c++)
        {
            controller_compromised[c] = true;
        }

        if (active_attack_variant == 0) {
            cout << attack_tag() << " [ATTACK1] declare_attackers(): attack_percentage="
                 << attack_percentage << "% -> " << num_to_compromise << " of "
                 << N_Controllers << " controllers compromised." << endl;
        }
    }

    // Ground truth: mark all RSUs whose owning controller is compromised as
    // Attack 1 (variant index 0) malicious actors, and record onset at
    // attack_start_time. This is the SINGLE authoritative write for variant 0 —
    // do NOT call record_attack_onset() again elsewhere for variant 0, as doing
    // so would overwrite t_onset[] with a later timestamp and break the
    // mitigation-latency metric Lmit = t_quarantine - t_onset (proposal metrics
    // section). Fixes deviation D6 (is_malicious_node[0] ground truth not set
    // in SUMO path) and deviation D2 (t_onset[] overwritten every second).
    if (present_selective_delay_cp_attack) {
        for (uint32_t r = 0; r < RSU_Nodes.GetN(); r++) {
            uint32_t ctrl = rsu_controller_assignment[r];
            if (controller_compromised[ctrl]) {
                uint32_t rsu_node_id = N_Vehicles + r;
                is_malicious_node[0][rsu_node_id] = true;
                t_onset[rsu_node_id] = attack_start_time;
                cout << attack_tag()
                     << " [ATTACK1] Ground truth: RSU node " << rsu_node_id
                     << " (rsu index " << r << ") marked malicious via compromised controller "
                     << ctrl << ", onset=" << attack_start_time << "s" << endl;
            }
        }
    }
}

// reapply_cp_selective_delay():
// Recurring task (re-scheduled every 1s) that poisons the routing table
// for every RSU whose assigned controller is compromised. Runs only for
// Attack 1 (active_attack_variant == 0). Re-derives next_hop fresh each
// tick so it only ever poisons routes that have already converged.
inline void reapply_cp_selective_delay()
{
    if (active_attack_variant != 0) return;
    double now = Simulator::Now().GetSeconds();
    if (now >= simTime) return;

    for (uint32_t r = 0; r < RSU_Nodes.GetN(); r++)
    {
        uint32_t owning_controller = rsu_controller_assignment[r];
        if (!controller_compromised[owning_controller]) continue;
        // already used in routing.cc's own rsu_controller_assignment[]
        // call sites (e.g. RSU_dataunicast_alone,
        // RSU_metadata_downlink_unicast). Do not assume r == node ID.
        uint32_t rsu_node_id = N_Vehicles + r;

        for (uint32_t f = 0; f < flows; f++)
        {
            uint32_t src = (delta_at_nodes_inst + f)->source_f;
            uint32_t dst = (delta_at_nodes_inst + f)->destination_f;
            if (src >= total_size || dst >= total_size) continue;
            uint32_t current_next_hop = find_next_hop(src, dst, rsu_node_id);
            if (current_next_hop == large) continue;

            // Phase 3 / D3: replace rand()-based draw with a reproducible ns-3
            // UniformRandomVariable so results are fully determined by sim_seed
            // + sim_run (set via RngSeedManager in main()). The static pointer
            // is initialised once; ns-3's single-threaded model makes this safe.
            static Ptr<UniformRandomVariable> cp_delay_rng = nullptr;
            if (!cp_delay_rng) {
                cp_delay_rng = CreateObject<UniformRandomVariable>();
            }
            double variable_delay = cp_delay_rng->GetValue(attack1_min_delay_seconds,
                                                           attack1_max_delay_seconds);

            update_route_malicious(rsu_node_id, dst, current_next_hop, variable_delay);
            // NOTE: record_attack_onset(0, rsu_node_id) is intentionally NOT called
            // here. Ground-truth onset recording for variant 0 is performed once in
            // declare_attackers() at attack_start_time. Calling it here would
            // overwrite t_onset[] on every 1-second tick, breaking the mitigation-
            // latency metric Lmit = t_quarantine - t_onset (deviation D2 fix).
        }
    }

    Simulator::Schedule(Seconds(1.0), &reapply_cp_selective_delay);
}

#endif // ATTACK_DECLARATION_H
