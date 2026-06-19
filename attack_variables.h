#ifndef ATTACK_VARIABLES_H
#define ATTACK_VARIABLES_H

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

#endif // ATTACK_VARIABLES_H
