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
#include <vector>
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
extern void ShuffleNodeIndices(std::vector<uint32_t>& indices);
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

    // S1/S2/S3/S4/S5-S8 signature detectors are NOT gated per attack_number.
    // main.tex's only mode-level ablation for this part of the architecture
    // is AB1 (enable_lrad_obu / enable_lrad_rsu, main.tex:4141-4170), which
    // gates the entire OBU/RSU detection stage; within that stage, all
    // applicable signatures are evaluated continuously (alg:lrad_obu's
    // D_OBU = flag_S1 v flag_S2p v flag_S3 v flag_S4 and alg:lrad_rsu's
    // D_RSU = flag_S2f v flag_S5 v ... v flag_S8 are both ORs across every
    // signature, with no "only check the one matching the current attack"
    // clause) — matching main.tex:4621's "all eight attack variants operate
    // simultaneously in every experiment." Each sX_detect() function already
    // gates on its own attack-specific ground truth internally (e.g.
    // s5_detect() checks active_hf_malicious_nodes[prev_sender]), so leaving
    // every signature always-on is safe: a detector with no matching
    // attacker present in this run simply never fires. Removed the previous
    // per-attack_number reset-and-arm-one-signature logic 2026-07-09.
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

        case (3): // TCAM Exhaustion — Control Plane (Attack 3)
            active_attack_variant = 2;
            break;

        case (4): // TCAM Exhaustion — Data Plane (Attack 4)
            active_attack_variant = 3;
            break;

        case (5): // Active Hidden Forwarding — Control Plane (Attack 5)
            active_attack_variant = 4;
            break;

        case (6): // Active Hidden Forwarding — Data Plane (Attack 6)
            active_attack_variant = 5;
            break;

        case (7): // Passive Hidden Forwarding — Control Plane (Attack 7)
            active_attack_variant = 6;
            break;

        case (8): // Passive Hidden Forwarding — Data Plane (Attack 8)
            active_attack_variant = 7;
            break;

        default:
            cout << "[declare_attack_states] WARNING: unrecognized attack_number="
                 << attack_number << " — no attack armed." << endl;
            break;
    }

    // Round 10: register the armed variant in the set variant_active() reads.
    // Single-variant runs register exactly one; a future joint/NEXUS mode
    // registers all eight by calling this dispatcher per variant.
    if (active_attack_variant >= 0 && active_attack_variant < 32)
        g_active_variant_mask |= (1u << active_attack_variant);

    cout << "[declare_attack_states] attack_number=" << attack_number
         << " -> active_attack_variant=" << active_attack_variant
         << ", present_selective_delay_cp_attack=" << present_selective_delay_cp_attack
         << ", present_selective_delay_attack_nodes=" << present_selective_delay_attack_nodes
         << endl;
}

// declare_attackers():
// Per-run "who is malicious" derivation for both attacks, driven entirely
// by attack_percentage. Attack 2: deterministic count floor(0.01*p*var)
// (main.tex simulation_table: attacker allocation = floor(0.01*p*264) nodes),
// with only WHICH nodes are attackers randomized per seed via a seeded
// Fisher-Yates shuffle (ShuffleNodeIndices) — NOT the count itself. An
// earlier version drew an independent Bernoulli(p) coin per node, which
// gives the right count only in expectation (binomial variance of ~+-8
// nodes at p=40%), confounding attack_percentage sweeps across the "5 fixed
// pseudorandom seeds" the proposal specifies per configuration.
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
        selective_delay_malicious_nodes[i] = false;
        is_malicious_node[1][i]            = false;
    }

    if (present_selective_delay_attack_nodes == true)
    {
        uint32_t n_candidates = (uint32_t)var;
        // +1e-9 epsilon guards the truncating cast against floating-point
        // rounding landing infinitesimally below an exact integer boundary
        // (e.g. 0.01*100.0*264.0 should equal exactly 264.0, but is not
        // guaranteed to under all compilers/optimization levels/FMA
        // behavior) — without it, a boundary case could silently truncate
        // to one fewer attacker than main.tex's floor(0.01p*264) specifies,
        // at exactly the sweep points {0,20,40,60,80,100} main.tex tests
        // (main.tex:5041, code review finding, 2026-07-08).
        uint32_t n_atk = (uint32_t)(0.01 * attack_percentage * (double)n_candidates + 1e-9);
        if (n_atk > n_candidates) n_atk = n_candidates; // guard p=100 rounding

        std::vector<uint32_t> candidates(n_candidates);
        for (uint32_t i = 0; i < n_candidates; i++) candidates[i] = i;
        if (n_atk > 0) ShuffleNodeIndices(candidates);

        for (uint32_t k = 0; k < n_atk; k++)
        {
            uint32_t idx = candidates[k];
            selective_delay_malicious_nodes[idx] = true;

            // Sync ground-truth for TAP Detection (Attack 2 is variant index 1)
            is_malicious_node[1][idx] = true;
            t_onset[idx] = attack_start_time;
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
        // main.tex simulation_table: "<33%:1; 33-66%:2; >=66%:3; 100%:4" — three
        // bands only. p==0 (no attack) is the sole zero-compromise case; an
        // earlier "<10% -> step 0" band left attack_percentage in [1,10) with
        // zero controllers compromised, contradicting the table's "<33% -> 1".
        uint32_t step;
        if (attack_percentage == 0)       step = 0;
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
            cout << attack_tag() << " declare_attackers(): attack_percentage="
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
// Recurring task (re-scheduled every 1s) that installs the malicious controller's
// poisoned flowMod on every RSU whose assigned controller is compromised. Runs only
// for Attack 1 (active_attack_variant == 0).
//
// main.tex §1387: the malicious controller "transmits manipulated flowMod packets to
// the RSU", and when a legitimate packet arrives the RSU, "processed according to these
// compromised instructions", forwards it "with an intentional, variable delay".
//
// The poisoned rule's MATCH is the priority class, NOT the destination. Signature S1
// (eq:sig_s1, main.tex:1730-1737): "only high-priority packets are delayed, while
// best-effort traffic from the same RSU remains within baseline" — i.e. the same RSU
// delays HIGH and passes best-effort, which a destination-keyed rule cannot express.
// So the rule is installed once per compromised RSU into cp_poisoned_flowmod_delay[]
// (routing.cc), and the Priority(p)=HIGH half of the match is applied at the forwarding
// sites via is_safety_critical_flow[] (see calculate_unified_selective_delay() /
// schedule_unified_selective_delay_attack() below).
//
// This replaces the previous per-(RSU,destination) routing_tables poison, which could
// only fire when a poisoned (RSU,dst) pair happened to coincide with the traffic's
// actual (forwarding-node,dst) pair — see cp_poisoned_flowmod_delay's declaration for
// the measured effect (80 rules installed, delay applied 0 times in 447 forwards).
//
// sample_attack_injection_delay() is defined in selective_time_delay.h (§4.3),
// included later in routing.cc — forward-declared here (same pattern as
// routing.cc's own ad-hoc `extern void ufcr_attempt_unauthorized_flowmod();`)
// so this recurring reinstall can draw from the same banded pseudo-random
// delay as Attack 2's DP path, instead of Attack 1 staying on the raw
// deterministic attack_delay_ms while DP alone got the §4.3 fix.
double sample_attack_injection_delay();

inline void reapply_cp_selective_delay()
{
    if (active_attack_variant != 0) return;
    double now = Simulator::Now().GetSeconds();
    if (now >= simTime) return;

    // §4.3: banded pseudo-random draw around the attack_delay_ms anchor
    // (or the raw deterministic value in --attack_delay_pseudo_random=0
    // mode) — see sample_attack_injection_delay() in selective_time_delay.h.
    // Re-drawn every 1s reinstall cycle (this function's own cadence), so
    // each refresh independently samples the band rather than freezing on
    // whatever the first install happened to draw.
    double variable_delay = sample_attack_injection_delay();

    for (uint32_t r = 0; r < RSU_Nodes.GetN(); r++)
    {
        uint32_t owning_controller = rsu_controller_assignment[r];
        if (!controller_compromised[owning_controller]) continue;
        // already used in routing.cc's own rsu_controller_assignment[]
        // call sites (e.g. RSU_dataunicast_alone,
        // RSU_metadata_downlink_unicast). Do not assume r == node ID.
        uint32_t rsu_node_id = N_Vehicles + r;
        if (rsu_node_id >= (uint32_t)total_size) continue;

        // Install (or refresh) the poisoned flowMod on this RSU.
        bool first_install = (cp_poisoned_flowmod_delay[rsu_node_id] == 0.0);
        cp_poisoned_flowmod_delay[rsu_node_id] = variable_delay;

        // Log the install once per RSU: this task re-fires every 1s and would
        // otherwise emit an identical line per compromised RSU per second.
        // (The rule's match — Priority(p)=HIGH — is documented in this function's
        // header and applied at the forwarding sites via is_safety_critical_flow[];
        // it is not restated here, since only real state should be logged.)
        if (first_install)
            cout << attack_tag() << " Malicious controller " << owning_controller
                 << " installed poisoned flowMod on RSU node " << rsu_node_id
                 << " (rsu index " << r << "): delay=" << variable_delay * 1000.0 << "ms"
                 << ", at t=" << now << "s" << endl;

        // NOTE: record_attack_onset(0, rsu_node_id) is intentionally NOT called
        // here. Ground-truth onset recording for variant 0 is performed once in
        // declare_attackers() at attack_start_time. Calling it here would
        // overwrite t_onset[] on every 1-second tick, breaking the mitigation-
        // latency metric Lmit = t_quarantine - t_onset (deviation D2 fix).
    }

    Simulator::Schedule(Seconds(1.0), &reapply_cp_selective_delay);
}

#endif // ATTACK_DECLARATION_H
