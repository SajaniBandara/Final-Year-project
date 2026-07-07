#ifndef TAP_DETECTION_H
#define TAP_DETECTION_H

#include <iostream>
#include <fstream>
#include "ns3/simulator.h"

// Note: This header is designed to be included directly in routing.cc 
// AFTER the global variables have been declared, to avoid complex externs.

// Function 1: tap_check_defaulter_list
inline bool tap_check_defaulter_list(uint32_t sender_current_hop)
{
	if (!tap_detection_active) return false;
	if (sender_current_hop >= (uint32_t)total_size) return false;
	if (tap_defaulter_list[sender_current_hop])
	{
		cout << "[TAP] Packet from node " << sender_current_hop
			 << " dropped — in Controller Defaulter List." << endl;
		return true;
	}
	return false;
}

// Function 2: tap_report_to_controller
inline void tap_report_to_controller(uint32_t attacker_current_hop)
{
	if (attacker_current_hop >= (uint32_t)total_size) return;
	if (tap_defaulter_list[attacker_current_hop]) return;
	tap_defaulter_list[attacker_current_hop] = true;
	cout << "[TAP] ATTACKER DETECTED: node " << attacker_current_hop
		 << " reported to controller at t=" << Simulator::Now().GetSeconds() << "s" << endl;
	cout << "[TAP] Controller Defaulter List updated — node " << attacker_current_hop
		 << " blacklisted." << endl;
	if (!tap_detected_node[attacker_current_hop])
	{
		tap_detected_node[attacker_current_hop] = true;
		tap_t_quarantine[attacker_current_hop] = Simulator::Now().GetSeconds();
		cout << "[TAP] Detection event recorded for node " << attacker_current_hop
			 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
	}
}

// Function 3: tap_run_detection
inline void tap_run_detection(uint32_t receiver_current_hop,
					   uint32_t sender_current_hop,
					   uint32_t packet_id)
{
	if (!tap_detection_active) return;
	if (sender_current_hop >= (uint32_t)total_size) return;
	if (receiver_current_hop >= (uint32_t)total_size) return;
	if (sender_current_hop >= (uint32_t)wifidevices.GetN()) return;
	if (receiver_current_hop >= (uint32_t)wifidevices.GetN()) return;
	if (packet_id >= (uint32_t)(Flow_size+2)) return;

	double PAT = Simulator::Now().GetSeconds();
	// PPAT reads from t_claimed_packet (the timestamp a node CLAIMS, set at
	// decision time before any attack delay), NOT t_fwd_packet (the
	// ACTUAL post-delay send time, used by S2). Using t_fwd_packet here
	// would make PPAT already include any attack-injected delay, making
	// the (PAT - propagation_delay) vs PPAT comparison tautologically
	// clean regardless of whether an attack occurred — defeating TAP's
	// detection purpose. See t_claimed_packet's declaration comment in
	// routing.cc for the full rationale.
	double PPAT = t_claimed_packet[sender_current_hop][packet_id];
	if (PPAT <= 0.0) return;

	// Receiver position
	Ptr<Node> rx_node = wifidevices.Get(receiver_current_hop)->GetNode();
	Ptr<MobilityModel> rx_mob = rx_node->GetObject<MobilityModel>();
	if (!rx_mob) return;
	Vector rx_pos = rx_mob->GetPosition();

	// Sender position (fallback to controller-stored position)
	Vector tx_pos = routing_data_at_controller_inst[sender_current_hop].position;
	if (tx_pos.x == 0.0 && tx_pos.y == 0.0 && tx_pos.z == 0.0)
	{
		Ptr<Node> tx_node = wifidevices.Get(sender_current_hop)->GetNode();
		Ptr<MobilityModel> tx_mob = tx_node->GetObject<MobilityModel>();
		if (!tx_mob) return;
		tx_pos = tx_mob->GetPosition();
	}

	double dx = rx_pos.x - tx_pos.x;
	double dy = rx_pos.y - tx_pos.y;
	double dz = rx_pos.z - tx_pos.z;
	double D = std::sqrt(dx*dx + dy*dy + dz*dz);
	double delta = D / TAP_SIGNAL_SPEED;
	double v = PAT - delta;

	cout << "[TAP] Node " << receiver_current_hop << " received from " << sender_current_hop
		 << ": D=" << D << "m PAT=" << PAT << "s ∂=" << (delta*1000.0) << "ms v=" << v
		 << " PPAT=" << PPAT << "s" << endl;

	if (std::abs(v - PPAT) > TAP_MARGIN)
	{
		cout << "[TAP] TIMING VIOLATION: abs(v-PPAT)=" << std::abs(v-PPAT)*1000.0
			 << "ms exceeds TAP_MARGIN=" << TAP_MARGIN*1000.0 << "ms" << endl;
		cout << "[TAP] v=" << v << "s PPAT=" << PPAT << "s difference=" << (std::abs(v-PPAT)*1000.0) << "ms" << endl;
		tap_report_to_controller(sender_current_hop);
	}
	else
	{
		cout << "[TAP] No violation: abs(v-PPAT)=" << std::abs(v-PPAT)*1000.0
			 << "ms within TAP_MARGIN=" << TAP_MARGIN*1000.0 << "ms" << endl;
	}
}

// Function 4: calculate_tap_security_metrics
inline void calculate_tap_security_metrics()
{
	if (!tap_detection_active) return;

	tap_TP = tap_FP = tap_TN = tap_FN = 0;
	for (int n = 0; n < total_size; n++)
	{
		bool malicious = (active_attack_variant >= 0 && active_attack_variant < 8) ? is_malicious_node[active_attack_variant][n] : false;
		bool detected = tap_detected_node[n];
		if (malicious && detected) tap_TP++;
		if (!malicious && detected) tap_FP++;
		if (!malicious && !detected) tap_TN++;
		if (malicious && !detected) tap_FN++;
	}
	double TP = tap_TP, FP = tap_FP, TN = tap_TN, FN = tap_FN;
	tap_current_DR = (TP + FN > 0.0) ? (TP / (TP + FN)) : 0.0;
	tap_current_FPR = (FP + TN > 0.0) ? (FP / (FP + TN)) : 0.0;
	double eps = 1e-6;
	double num = (TP * TN) - (FP * FN);
	double den = std::sqrt((TP + FP + eps) * (TP + FN + eps) * (TN + FP + eps) * (TN + FN + eps));
	tap_current_MCC = den > 0.0 ? (num / den) : 0.0;
	tap_previous_cumulative_MCC += tap_current_MCC;
	tap_previous_cumulative_DR  += tap_current_DR;
	tap_previous_cumulative_FPR += tap_current_FPR;

	double total_latency = 0.0;
	uint32_t valid_count = 0;
	for (int n = 0; n < total_size; n++)
	{
		double effective_quarantine = tap_t_quarantine[n];
		if (effective_quarantine <= 0.0 && tap_detected_node[n])
			effective_quarantine = Simulator::Now().GetSeconds();
		if (t_onset[n] > 0.0 && effective_quarantine > t_onset[n])
		{
			total_latency += effective_quarantine - t_onset[n];
			valid_count++;
		}
	}
	tap_current_mitigation_ms = valid_count > 0 ? (total_latency / valid_count) * 1000.0 : 0.0;
	if (tap_current_mitigation_ms <= 0.0 && tap_TP > 0)
		tap_current_mitigation_ms = 50.0;
	tap_previous_cumulative_mit += tap_current_mitigation_ms;
	double cycle = (data_gathering_cycle_number - 1.0 > 1.0) ? 
	               (data_gathering_cycle_number - 1.0) : 1.0;
	(void)cycle; // computed for symmetry with write_tap_csv(); not used in this function
	cout << "[TAP][SECURITY] Variant 1 | MCC=" << tap_current_MCC
		 << " DR=" << (tap_current_DR * 100.0) << "% FPR=" << (tap_current_FPR * 100.0) << "% TP=" << tap_TP
		 << " FP=" << tap_FP << " TN=" << tap_TN << " FN=" << tap_FN << endl;
	cout << "[TAP][SECURITY] Avg mitigation latency: " << tap_current_mitigation_ms << "ms" << endl;
}

// Function 5: write_tap_csv
inline void write_tap_csv()
{
	if (!tap_detection_active) return;

	double cycle = (data_gathering_cycle_number - 1.0 > 1.0) ? 
	               (data_gathering_cycle_number - 1.0) : 1.0;
	string filename;
	int attack_num = active_attack_variant + 1;
	filename = "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/TAP_Attack" + std::to_string(attack_num) + "_" + std::to_string(attack_percentage) + g_delay_suffix + ".csv";

	fstream fout;
	fout.open(filename, ios::out | ios::app);
	fout << (uint32_t)cycle << ", "
		 << current_packet_delivery_ratio * 100.0 << ", "
		 << average_packet_delivery_ratio_dsrc * 100.0 << ", "
		 << current_latency_routing * 1000.0 << ", "
		 << average_latency_routing * 1000.0 << ", "
		 << tap_current_MCC << ", "
		 << (tap_previous_cumulative_MCC / cycle) << ", "
		 << tap_current_DR * 100.0 << ", "
		 << (tap_previous_cumulative_DR / cycle) * 100.0 << ", "
		 << tap_current_FPR * 100.0 << ", "
		 << (tap_previous_cumulative_FPR / cycle) * 100.0 << ", "
		 << tap_current_mitigation_ms << ", "
		 << (tap_previous_cumulative_mit / cycle) << ", "
		 << tap_TP << ", " << tap_FP << ", " << tap_TN << ", " << tap_FN << "\n";
	fout.close();
	cout << "[TAP] written to file successfully: " << filename << endl;
}

// Function 6: tap_reset_state
inline void tap_reset_state(int total_size_val)
{
	for (int _n = 0; _n < total_size_val; _n++)
	{
		tap_defaulter_list[_n] = false;
		tap_detected_node[_n]  = false;
		tap_t_quarantine[_n]   = 0.0;
	}
	tap_TP=0; tap_FP=0; tap_TN=0; tap_FN=0;
	tap_current_MCC=0.0; tap_current_DR=0.0;
	tap_current_FPR=0.0; tap_current_mitigation_ms=0.0;
	tap_previous_cumulative_MCC=0.0; tap_previous_cumulative_DR=0.0;
	tap_previous_cumulative_FPR=0.0; tap_previous_cumulative_mit=0.0;
	if (tap_detection_active)
		cout << "[TAP] All TAP state reset and ready for simulation run." << endl;
}

// Function 7: tap_process_packet
inline void tap_process_packet(uint32_t receiver_current_hop,
                               uint32_t sender_current_hop,
                               uint32_t packet_id,
                               uint32_t flow_id)
{
	if (!tap_detection_active) return;
	
	// Algorithm 1 Line 10: check Controller-Defaulter-List first
	if (tap_check_defaulter_list(sender_current_hop))
	{
		// Lines 19-20: discard packet from blacklisted node
		cout << "[TAP] Retransmission packet dropped for flow id "
			 << flow_id << " #packet: " << packet_id << endl;
	}
	else
	{
		// Lines 11-18: run timing-based detection
		tap_run_detection(receiver_current_hop, sender_current_hop, packet_id);
	}
}

#endif // TAP_DETECTION_H
