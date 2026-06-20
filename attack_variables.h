#ifndef ATTACK_VARIABLES_H
#define ATTACK_VARIABLES_H

/* =========================================================================
   Governing threat-model assumption (must hold throughout)
   =========================================================================
   The thesis's threat model states: "The threat model assumes that an
   adversary couldn't exist in both data plane and control plane at once."

   This means Attack 1 (control plane) and Attack 2 (data plane) must remain
   mutually exclusive in every simulation run. Concretely:
   1. RSU must never be marked malicious for Attack 1 (only the controller is compromised).
   2. Attack 1's and Attack 2's master switches must never both be true at once.
   3. Hard stop: if you find yourself needing to mark an RSU malicious for Attack 1,
      that is a sign you are violating the assumption!
   ========================================================================= */

// Selective Time Delay Attack Variables (Attack 2)
// Placed in a separate header for modularity.

// Array that maps whether each node is currently acting as a selective delay attacker
bool selective_delay_malicious_nodes[total_size]; 

bool present_selective_delay_attack_nodes = false;
double attack2_delay_seconds = 0.080; // 80ms injected delay

// Selective Time Delay Attack Variables (Attack 1 — Control Plane)
// The RSU itself is never marked malicious for this attack; only the
// controller-installed routing_table_row.injected_delay field carries the
// malicious behaviour. present_selective_delay_cp_attack is the master
// switch: forwarding code must check this before ever reading
// injected_delay, so a stale nonzero injected_delay value can never fire
// unless this attack is genuinely active for the current run.
// Per the threat model, this flag and Attack 2's
// present_selective_delay_attack_nodes must never both be true at once.
bool   present_selective_delay_cp_attack = false;
double attack1_min_delay_seconds = 0.060;
double attack1_max_delay_seconds = 0.120;
uint32_t selective_delay_cp_target_rsu = 2; // which RSU's table the controller poisons

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
bool controller_compromised[300]; // sized >= max N_Controllers, matches
                                    // rsu_controller_assignment[300]'s sizing
                                    // convention already used in routing.cc
#endif // ATTACK_VARIABLES_H
