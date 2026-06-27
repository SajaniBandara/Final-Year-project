#ifndef ATTACK_VARIABLES_H
#define ATTACK_VARIABLES_H

/* =========================================================================
   Governing threat-model assumption (must hold throughout)
   =========================================================================
   The thesis's threat model states: "The threat model assumes that an
   adversary couldn't exist in both data plane and control plane at once."

   This means Attack 1 (control plane) and Attack 2 (data plane) must remain
   mutually exclusive in every simulation run. Concretely:

   1. selective_delay_malicious_nodes[] (the runtime DP attack flag) must
      NEVER be set true for an RSU in Attack 1. The RSU is not an attacker —
      it is a benign node obeying a poisoned FlowMod installed by a
      compromised controller.

   2. is_malicious_node[0][rsu_node_id] (the ground-truth metrics array) IS
      intentionally set true for RSUs whose assigned controller is compromised
      (in declare_attackers()). This is correct — those RSUs are the affected
      nodes that detectors must identify, even though the RSU itself is unaware.
      Do NOT confuse this with selective_delay_malicious_nodes[].

   3. Attack 1's and Attack 2's master switches (present_selective_delay_cp_attack
      and present_selective_delay_attack_nodes) must never both be true at once.
   ========================================================================= */

// Selective Time Delay Attack Variables (Attack 2)
// Placed in a separate header for modularity.

// Array that maps whether each node is currently acting as a selective delay attacker
bool selective_delay_malicious_nodes[total_size];

bool present_selective_delay_attack_nodes = false;

// Selective Time Delay Attack Variables (Attack 1 — Control Plane)
// The RSU itself is never marked malicious for this attack; only the
// controller-installed routing_table_row.injected_delay field carries the
// malicious behaviour. present_selective_delay_cp_attack is the master
// switch: forwarding code must check this before ever reading
// injected_delay, so a stale nonzero injected_delay value can never fire
// unless this attack is genuinely active for the current run.
// Per the threat model, this flag and Attack 2's
// present_selective_delay_attack_nodes must never both be true at once.
bool present_selective_delay_cp_attack = false;

// Single deterministic attack delay used by both CP (Attack 1) and DP (Attack 2).
// Pass via --attack_delay_ms=<value> at runtime to treat delay as an independent
// variable in threshold-validation experiments.
//
// Both attacks use the same range per the proposal (§1319–1327): legitimate handoff
// latencies in the SDVN are 50–300 ms (handoff jitter window at 80–120 km/h).
// An adversary injects delays within this window so the attack is statistically
// indistinguishable from legitimate jitter. The original implementation drew from
// Uniform(50–300 ms) for both CP and DP. The thesis specifically uses 80 ms as the
// DP example delay (§3817). This default (80 ms) is above S2_DELTA_MAX=50 ms, so
// Signature S2 (Eq. 3.5) fires. Set via --attack_delay_ms at runtime.
double attack_delay_ms = 80.0; // default 80 ms (thesis example value); set via --attack_delay_ms

// Top-level attack-type selector, mirroring the supervisor's reference
// numbering convention (attack_number 1, 2, 3, ...). This is DISTINCT from
// active_attack_variant, which remains the variable the rest of routing.cc
// actually switches on for attack-specific setup. attack_number exists
// purely as the entry point for declare_attack_states(), which translates
// it into the existing active_attack_variant value plus the right
// present_*_attack_* flags.
//
// Current mapping (extend this table as new attacks are added):
//   attack_number == 1  ->  Selective Time Delay, Control Plane (Attack 1)
//                            -> active_attack_variant == 0
//   attack_number == 2  ->  Selective Time Delay, Data Plane    (Attack 2)
//                            -> active_attack_variant == 1
//   attack_number == 3..8 -> reserved for future attacks; add a new case
//                            to declare_attack_states() and a new
//                            present_*_attack_nodes/controllers pair here
//                            when each is implemented, following the same
//                            pattern as attacks 1 and 2 below.
int attack_number = 1; // default to Attack 1 (CP) — change via CLI/test harness
bool attack_number_explicitly_set = false;

// Per-controller compromise state for Attack 1 (Selective Time Delay, CP).
// Indexed by controller ID (0 .. N_Controllers-1). Populated by
// declare_attackers() using the same attack_percentage threshold-ladder
// pattern as the supervisor reference, generalized to N_Controllers
// instead of a hardcoded 4. controller_compromised[c] == true means
// controller c is the malicious controller for this run.
bool controller_compromised[total_size]; // sized to total_size, matches
                                    // rsu_controller_assignment[300]'s sizing
                                    // convention already used in routing.cc
#endif // ATTACK_VARIABLES_H
