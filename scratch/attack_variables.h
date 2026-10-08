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

// Attack delay used by both CP (Attack 1) and DP (Attack 2) — mobility
// amplification fix §4.3 (docs/MOBILITY_AMPLIFICATION_FIX_PLAN.md).
//
// Both attacks use the same range per the proposal (§1319–1327): legitimate handoff
// latencies in the SDVN are 50–300 ms (handoff jitter window at 80–120 km/h).
// An adversary injects delays within this window so the attack is statistically
// indistinguishable from legitimate jitter. The original implementation drew from
// Uniform(50–300 ms) for both CP and DP; that was later replaced with a single
// fixed 80 ms value (never matching any of eq:intensity_td's three levels) so
// delay could be an explicit independent variable in threshold-validation
// experiments — that 80 ms default is what's being replaced here.
//
// eq:intensity_td (main.tex ~L5199) defines three discrete intensity levels as
// multiples of Delta_max (50 ms): 1.1x (stealth, ~55ms), 2x (moderate, 100ms),
// 4x (aggressive, 200ms). Supervisor guidance (2026-07-25): "You can make it
// pseudo-random (you can control the randomness with defined bounds and
// behavior). Not totally random." -> each level is now the ANCHOR of a bounded
// band (default +/-10%) instead of a single deterministic value; see
// sample_attack_injection_delay() in selective_time_delay.h, which draws from
// [anchor*(1-ATTACK_DELAY_BAND_FRAC), anchor*(1+ATTACK_DELAY_BAND_FRAC)] using
// a seeded ns-3 UniformRandomVariable (reproducible per sim_seed/sim_run, same
// convention as GetBooleanWithProbability()/ShuffleNodeIndices() in routing.cc).
//
// attack_delay_ms is still set via --attack_delay_ms at runtime and still acts
// as the band's anchor/center -- pass any of the three levels below, or a
// custom value for other threshold-validation sweeps. Bands are non-overlapping
// by construction at the three canonical anchors, so Experiment 1's three lines
// stay distinguishable.
const double ATTACK_DELAY_ANCHOR_LOW_MS  = 55.0;   // 1.1x Delta_max -- sub-threshold stealth
const double ATTACK_DELAY_ANCHOR_MED_MS  = 100.0;  // 2x   Delta_max -- moderate injection
const double ATTACK_DELAY_ANCHOR_HIGH_MS = 200.0;  // 4x   Delta_max -- aggressive injection
const double ATTACK_DELAY_BAND_FRAC      = 0.10;   // +/-10% around the active anchor

double attack_delay_ms = ATTACK_DELAY_ANCHOR_MED_MS; // default anchor (2x Delta_max); set via --attack_delay_ms

// Selects deterministic vs. banded pseudo-random injection (§4.3). Default
// true: the attack-percentage sweep path (Experiments 1/2) draws each
// packet's delay from the band around attack_delay_ms. Set to false via
// --attack_delay_pseudo_random=0 for standalone/deterministic testing that
// needs an EXACT delay value -- e.g. the S2-threshold sweep (routing.cc
// ~L141781) that probes whether a specific ms value crosses S2_DELTA_MAX.
bool attack_delay_pseudo_random = true; // CLI: --attack_delay_pseudo_random

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
// PHANTOM AB9/AB10/AB12 compromise model (supervisor-approved 2026-10-05). All default OFF,
// so every existing run is unchanged. Exactly three capabilities, each active ONLY at
// attack_percentage >= 33 and ONLY on a controller marked compromised below:
//   ab9_no_isolation : a compromised controller cannot be revoked / failed over (AB9 substitute)
//   ab10_false_keys  : controller-issued proving/verification keys -> proofs verified at RSUs
//                      owned by a compromised controller are accepted (AB10 substitute)
//   ab12_legitimize  : rejected unauthorized FlowMods are retroactively legitimised and the
//                      compromised controller's trust penalties are cancelled (AB12 substitute)
// ab_compromise_model only extends the existing controller-compromise ladder to attacks
// that lack one (A2/A4) so the three capabilities have a compromised controller to act on;
// it changes no attack behaviour.
bool ab_compromise_model = false;
bool ab9_no_isolation    = false;
bool ab10_false_keys     = false;
bool ab12_legitimize     = false;
// AB8 substitute (plan: "single roadside unit, immediate commitment"): FlowMod commit quorum of 1 instead of f+1.
bool ab8_single_rsu      = false;
// AB4 substitute (plan: "direct wall clock comparison"): the timing check is a plain comparison of the
// raw timestamps against the bound -- same accept/reject decision as the proof, but the prover reveals
// its raw timestamps to the verifier (privacy cost M10) and no proof/commitment is produced.
bool ab4_direct_compare  = false;
// AB11 probe: each cycle every revoked RSU replays a proof under its pre-revocation key; the proof is
// accepted iff key rotation did not retire that key. Records acceptance by whole cycles since revocation.
bool ab11_reuse_probe    = false;
bool controller_compromised[total_size]; // sized to total_size, matches
                                    // rsu_controller_assignment[300]'s sizing
                                    // convention already used in routing.cc
#endif // ATTACK_VARIABLES_H
