#ifndef ATTACK_VARIABLES_H
#define ATTACK_VARIABLES_H

// Selective Time Delay Attack Variables (Attack 2)
// Placed in a separate header for modularity.

// Array that maps whether each node is currently acting as a selective delay attacker
bool selective_delay_malicious_nodes[total_size]; 

bool present_selective_delay_attack_nodes = false;
double attack2_delay_seconds = 0.080; // 80ms injected delay

#endif // ATTACK_VARIABLES_H
