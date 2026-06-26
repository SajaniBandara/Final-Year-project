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
// attack2_delay_seconds: nominal mean kept for test-network logging and backward
// compatibility with the single-scenario verification result (80 ms, MCC=1.0).
// The actual per-packet delay is drawn uniformly from [attack2_min, attack2_max].
double attack2_delay_seconds     = 0.080; // nominal mean (used for logging only)
// Variable delay bounds for Attack 2 (Data Plane).
// Range spans the handoff jitter window defined in §1319–1327 (50–300 ms).
// Lower bound 0.060 s sits 10 ms above S2_DELTA_MAX (50 ms) so every attack
// packet strictly exceeds the detection threshold under the thesis's Eq. 3.5
// strict '>' comparison — fixes deviation B2 (min_delay = Δ_max boundary case).
// Thesis §1255: "intentional, variable lags" — fixes deviation D4.
double attack2_min_delay_seconds = 0.060; // 60 ms — 10 ms above S2_DELTA_MAX
double attack2_max_delay_seconds = 0.300; // 300 ms — full handoff jitter window per §1319–1327

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
// Variable delay range spanning the handoff jitter window (§1319–1327:
// legitimate handoff latencies of 50–300 ms).
// Fixed 80 ms constant replaced with variable range per thesis §1255
// ("intentional, variable lags") — fixes deviation D3.
// Note: selective_delay_cp_target_rsu removed (was dead code — reapply_cp_selective_delay
// iterates ALL RSUs under compromised controllers, not a single hardcoded one).
double attack1_min_delay_seconds = 0.060; // 60 ms — above S1 baseline (~2 ms + 3σ) ensuring detection
double attack1_max_delay_seconds = 0.300; // 300 ms — full handoff jitter window per §1319–1327

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
