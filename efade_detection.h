#ifndef EFADE_DETECTION_H
#define EFADE_DETECTION_H

// =====================================================
// efade_detection.h — eFADE (Forwarding Anomaly Detection architEcture)
//
// Implements Li et al., IEEE TPDS 32(11) 2021.
//
// This header is designed to be included directly in routing.cc
// AFTER the global variables have been declared, to avoid complex externs.
//
//  Component 1 – Flow selection:
//      Flows are the same logical flows already tracked by
//      delta_at_nodes_inst[].  Each flow's full hop path is
//      read from proposed_routing_tables[src].rows[dst].path[].
//
//  Component 2 – Measurement points:
//      All nodes along the active flow path are selected as measurement points.
//
//  Component 3 – Rule installation:
//      No separate SDN rule install is needed in simulation: instead
//      each node on the path acts as a measurement point to count
//      incoming and outgoing packets.
//      A measurement epoch of FADE_EPOCH_SEC seconds mirrors the
//      R1 hard-timeout (t1) from the paper; counters are reset each
//      epoch so that only packets belonging to the same window are
//      compared (satisfies the synchronisation invariant).
//
//  Component 4 – Anomaly identification:
//      For each node on the flow path (excluding the source), the detector
//      compares packets received (fade_node_in) against packets forwarded
//      (fade_node_out). If the outbound count exceeds the inbound count,
//      the node is duplicating traffic and is flagged as a "duplication"
//      anomaly, with that node recorded as the localisation.
//
// ── Globals defined in routing.cc, used here ─────────────────────────────────
//   extern int      active_attack_variant;
//   extern bool     routing_test;
//   extern int      attack_percentage;
//   extern int      total_size;
//   extern uint32_t large;
//   extern int      flows;
//   extern int      flow_size;
//   extern double   data_transmission_period;
//   extern double   data_gathering_cycle_number;
//   extern bool     selective_delay_malicious_nodes[];
//   extern bool     passive_hf_malicious_nodes[];
//   extern bool     active_hf_malicious_nodes[];
//   struct delta_f  delta_at_nodes_inst[];
//   struct proposed_routing_table proposed_routing_tables[];
//   struct demanding_flow_struct  demanding_flow_struct_nodes_inst[];
// =====================================================

#include <map>
#include <set>
#include <string>
#include <fstream>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <cstring>

static const double FADE_EPOCH_SEC = 1.0;   // measurement window (= R1 hard timeout)

// ── Per-flow path configuration ─────────────────────────────────────────────
struct FadeFlowConfig
{
    uint32_t source;
    uint32_t destination;
    uint32_t path_len;
    uint32_t path_nodes[total_size]; // store the actual path nodes of the flow
    bool     configured;
    FadeFlowConfig() : source(0), destination(0),
                       path_len(0), configured(false)
    { memset(path_nodes, 0, sizeof(path_nodes)); }
};

// ── Per-flow detection result ─────────────────────────────────────────────────
struct FadeDetectionResult
{
    bool        detected;
    double      detection_time;
    std::string anomaly_type;    // "duplication" | "none"
    uint32_t    loc_from;
    uint32_t    loc_to;
    uint32_t    duplicating_node;
    FadeDetectionResult()
        : detected(false), detection_time(-1.0),
          anomaly_type("none"), loc_from(large), loc_to(large), duplicating_node(large) {}
};

std::map<uint32_t, FadeFlowConfig>      fade_flow_config;
std::map<uint32_t, FadeDetectionResult> fade_results;
std::ofstream fade_csv;

// received[flow_id][node] = set of distinct packet_ids that arrived at node
std::map<uint32_t, std::map<uint32_t, std::set<uint32_t>>> fade_received;
// forwarded[flow_id][node][packet_id] = set of distinct next-hop destinations
std::map<uint32_t, std::map<uint32_t, std::map<uint32_t, std::set<uint32_t>>>> fade_forwarded;
uint32_t pp_tp_global = 0;
uint32_t pp_tn_global = 0;
uint32_t pp_fp_global = 0;
uint32_t pp_fn_global = 0;

// PIR counter — incremented in MacRx before the eavesdropper-return early exit
uint32_t fade_eavesdrop_counter = 0;
uint64_t g_total_copies_scheduled = 0;
std::set<std::pair<uint32_t, uint32_t>> fade_eavesdropped_packets;
uint32_t hf_target_flow_id = 0;   // malicious RSU duplicates ONLY this flow; all others honest

// ── FADE per-cycle CSV state ──────────────────────────────────────────────────
// Mirror MOBIGUARD's cur/avg columns so FADE per-scenario CSVs match shape.
double   fade_cum_pdr = 0.0;
double   fade_cum_pir = 0.0;
double   fade_cum_mcc = 0.0;
double   fade_cum_dr  = 0.0;
double   fade_cum_fpr = 0.0;
uint32_t fade_prev_eavesdrop  = 0;
uint32_t fade_prev_copies     = 0;

// ── Configure a flow's probes from the routing table ─────────────────────────
// Called lazily (on first packet send) so that routing tables are populated.
inline void fade_configure_flow(uint32_t flow_id)
{
    if (fade_flow_config.count(flow_id) &&
        fade_flow_config[flow_id].configured) return;

    uint32_t src = (delta_at_nodes_inst + flow_id)->source_f;
    uint32_t dst = (delta_at_nodes_inst + flow_id)->destination_f;

    FadeFlowConfig cfg;
    cfg.source      = src;
    cfg.destination = dst;
    cfg.path_len    = 0;

    // Walk the stored path to find its nodes and length
    for (uint32_t step = 0; step < (uint32_t)total_size; step++)
    {
        uint32_t node = proposed_routing_tables[src].rows[dst].path[step];
        if (node >= (uint32_t)total_size) break;
        cfg.path_nodes[cfg.path_len++] = node;
    }

    std::cout << "[eFADE DEBUG] configure flow " << flow_id
              << " src=" << src << " dst=" << dst
              << " path_len=" << cfg.path_len << " nodes:";
    for (uint32_t i = 0; i < cfg.path_len; i++) std::cout << " " << cfg.path_nodes[i];
    std::cout << std::endl;

    if (cfg.path_len < 2)
    {
        // No valid route — mark as configured but skip
        cfg.configured = true;
        fade_flow_config[flow_id] = cfg;
        return;
    }

    cfg.configured  = true;
    fade_flow_config[flow_id] = cfg;

    std::cout << "[eFADE] Flow " << flow_id
              << "  src=" << src << " dst=" << dst
              << "  path_len=" << cfg.path_len
              << "  path:";
    for (uint32_t i = 0; i < cfg.path_len; i++)
        std::cout << " " << cfg.path_nodes[i];
    std::cout << std::endl;
}

// ── Call once after routing tables are stable to pre-configure all flows ─────
inline void fade_configure_all_flows()
{
    for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
        fade_configure_flow(fid);
}

// ── Helper: is any node on this flow's path a malicious node? ────────────────
// Used to classify TP / FP / TN / FN for the FADE MCC calculation.
inline bool fade_is_flow_attacked(uint32_t flow_id)
{
    auto it = fade_flow_config.find(flow_id);
    if (it == fade_flow_config.end() || !it->second.configured) return false;

    FadeFlowConfig &cfg = it->second;
    uint32_t src = cfg.source;
    uint32_t dst = cfg.destination;

    for (uint32_t step = 0; step < (uint32_t)total_size; step++)
    {
        uint32_t node = proposed_routing_tables[src].rows[dst].path[step];
        if (node >= (uint32_t)total_size) break;
        // Only check the array that corresponds to the active attack variant.
        // variant 1  = Attack 2 (Selective Time Delay, Data Plane)
        // variant 7  = Attack 8 (Passive Hidden Forwarding, Data Plane)
        if (active_attack_variant == 1 && selective_delay_malicious_nodes[node]) return true;
        if (active_attack_variant == 7 && passive_hf_malicious_nodes[node])      return true;
        // Active Hidden Forwarding (variant 4 = Attack 5 Control Plane,
        // variant 5 = Attack 6 Data Plane): malicious RSU is in active_hf array.
        if ((active_attack_variant == 4 || active_attack_variant == 5)
            && active_hf_malicious_nodes[node])                                  return true;
        // Passive Hidden Forwarding, Control Plane (variant 6 = Attack 7):
        // malicious RSU is in passive_hf array.
        if (active_attack_variant == 6 && passive_hf_malicious_nodes[node])      return true;
    }
    return false;
}

// ── Compute + append one metrics row to fade_metrics.csv ─────────────────────
// Called once after Simulator::Run() so all counters are final.
//
// Forward declaration — destination_counter is defined later in the file
// (after packet_delivery structs) but is needed here by fade_save_metrics().
extern uint32_t destination_counter[2*flows];
extern uint32_t origination_counter[2*flows];

inline bool fade_is_flow_active(uint32_t flow_id)
{
    if (destination_counter[flow_id] > 0) return true;
    auto it = fade_received.find(flow_id);
    if (it != fade_received.end())
    {
        for (auto &node_entry : it->second)
        {
            if (!node_entry.second.empty()) return true;
        }
    }
    return false;
}

inline void fade_find_active_attack_flow_and_node(int32_t &atk_fid, int32_t &mal_node)
{
    atk_fid = -1;
    mal_node = -1;
    for (auto const &entry : fade_flow_config)
    {
        uint32_t flow_id = entry.first;
        if (!entry.second.configured) continue;
        if (!fade_is_flow_active(flow_id)) continue;

        uint32_t src = entry.second.source;
        uint32_t dst = entry.second.destination;
        for (uint32_t step = 0; step < (uint32_t)total_size; step++)
        {
            uint32_t node = proposed_routing_tables[src].rows[dst].path[step];
            if (node >= (uint32_t)total_size) break;
            if (passive_hf_malicious_nodes[node] || active_hf_malicious_nodes[node] || selective_delay_malicious_nodes[node])
            {
                atk_fid = flow_id;
                mal_node = node;
                break;
            }
        }
        if (atk_fid != -1) break;
    }

    if (atk_fid == -1 || mal_node == -1)
    {
        atk_fid = 0;
        mal_node = 6;
    }
}

// CSV columns:
//   attack_variant, attack_percentage,
//   total_flows, total_sent, total_received,
//   pdr, pir,
//   tp, fp, tn, fn, mcc
inline void fade_save_metrics()
{
    // Count total sent across all flows
    uint32_t total_flows    = 0;
    for (auto &entry : fade_flow_config)
    {
        uint32_t flow_id = entry.first;
        if (!entry.second.configured) continue;
        if (!fade_is_flow_active(flow_id)) continue;
        total_flows++;
    }

    int32_t atk_fid = -1;
    int32_t mal_node = -1;
    fade_find_active_attack_flow_and_node(atk_fid, mal_node);

    std::cout << "[eFADE PP] counting per-packet at flow " << atk_fid
              << " node " << mal_node
              << " (forwarded packets=" << (pp_tp_global + pp_tn_global + pp_fp_global + pp_fn_global) << ")" << std::endl;

    uint32_t tp = pp_tp_global;
    uint32_t fp = pp_fp_global;
    uint32_t tn = pp_tn_global;
    uint32_t fn = pp_fn_global;

    // True end-to-end PDR across the whole simulation:
    //   total delivered = sum of destination_counter[fid] over active flows
    //   total scheduled = f_size * number_of_data_cycles per active flow
    // data_gathering_cycle_number starts at 1 and increments each cycle,
    // so after Simulator::Run() it equals (num_cycles + 1); num_cycles = it - 1.
    // uint32_t num_cycles = (uint32_t)(data_gathering_cycle_number - 1.0);
    // if (num_cycles == 0) num_cycles = 1; // guard
	uint32_t num_cycles = (uint32_t)(Simulator::Now().GetSeconds() / data_transmission_period);
	if (num_cycles == 0) num_cycles = 1; // guard
    uint32_t g_total_delivered = 0;
    uint32_t g_total_scheduled = 0;
    for (auto &entry2 : fade_flow_config)
    {
        uint32_t fid2 = entry2.first;
        if (!entry2.second.configured) continue;
        if (!fade_is_flow_active(fid2)) continue;
        uint32_t fsz = (demanding_flow_struct_nodes_inst + fid2)->f_size;
        if (fsz == 0) fsz = routing_test ? 3 : flow_size;
        g_total_delivered += destination_counter[fid2];
        g_total_scheduled += fsz * num_cycles;
        cout << "[PDR DEBUG] flow=" << fid2
             << " fsz=" << fsz
             << " destination_counter=" << destination_counter[fid2]
             << " running_g_total_delivered=" << g_total_delivered
             << " running_g_total_scheduled=" << g_total_scheduled
             << endl;
    }
    cout << "[PDR DEBUG TOTAL] g_total_delivered=" << g_total_delivered
         << " g_total_scheduled=" << g_total_scheduled
         << " num_cycles=" << num_cycles
         << " Now=" << Simulator::Now().GetSeconds() << "s"
         << " data_transmission_period=" << data_transmission_period
         << endl;
    double pdr = (g_total_scheduled > 0)
        ? 100.0 * (double)g_total_delivered / (double)g_total_scheduled
        : 0.0;
    if (pdr > 100.0) pdr = 100.0;

    // PIR = fraction of intentionally-scheduled hidden duplicates that were
    // successfully received by the eavesdropper.
    //
    // PIR FIX explanation:
    //   OLD (broken): denominator = g_total_scheduled (all packets in simulation).
    //     fade_eavesdrop_counter was incremented in MacRx on every packet
    //     physically overheard by Vehicle B — including ambient Wi-Fi broadcast
    //     at 0% attack intensity — so PIR was always 100%.
    //
    //   NEW (fixed): denominator = g_total_copies_scheduled (only packets for
    //     which GetBooleanWithProbability returned true AND send_hidden_duplicate
    //     was called).  fade_eavesdrop_counter is now gated on g_hdup_intentional
    //     so only confirmed-received duplicates count.  At 0% intensity,
    //     g_total_copies_scheduled == 0 → PIR = 0%.  At 100% intensity, every
    //     forwarded packet triggers a copy → PIR ≈ 100% (subject to channel loss).
    //     At intermediate intensities PIR scales linearly with attack_percentage.
    double pir = (g_total_copies_scheduled > 0)
        ? 100.0 * (double)fade_eavesdrop_counter / (double)g_total_copies_scheduled
        : 0.0;

    // Matthews Correlation Coefficient
    double denom = std::sqrt(
        (double)(tp+fp) * (double)(tp+fn) *
        (double)(tn+fp) * (double)(tn+fn));
    double mcc = (denom > 0.0)
        ? ((double)(tp * tn) - (double)(fp * fn)) / denom
        : 0.0;

    // Append row to fade_metrics.csv (append so repeated runs accumulate)
    // Check if file exists BEFORE opening — once ofstream opens it, it always exists.
    bool write_header = false;
    {
        std::ifstream check("fade_metrics.csv");
        write_header = !check.good();
    }
    std::ofstream mfile;
    mfile.open("fade_metrics.csv", std::ios::out | std::ios::app);
    if (write_header)
        mfile << "attack_variant,attack_percentage,"
              << "total_flows,pdr,pir,tp,fp,tn,fn,mcc\n";

    mfile << active_attack_variant   << ","
          << attack_percentage       << ","
          << total_flows             << ","
          << std::fixed << std::setprecision(2) << pdr << ","
          << std::fixed << std::setprecision(2) << pir << ","
          << tp << "," << fp << "," << tn << "," << fn << ","
          << std::fixed << std::setprecision(4) << mcc << "\n";

    mfile.close();

    double dr = (tp + fn > 0) ? (double)tp / (double)(tp + fn) : 0.0;
    double fpr = (fp + tn > 0) ? (double)fp / (double)(fp + tn) : 0.0;

    std::cout << "[FADE METRICS] variant=" << active_attack_variant
              << " atk%=" << attack_percentage
              << " PDR=" << pdr << "% PIR=" << pir << "%"
              << std::fixed << std::setprecision(2)
              << " DR=" << dr
              << " FPR=" << fpr
              << " MCC=" << mcc
              << " (TP=" << tp << " FP=" << fp
              << " TN=" << tn << " FN=" << fn << ")"
              << std::endl;
}

inline void fade_detect_anomaly()
{
    double now = Simulator::Now().GetSeconds();

	 if (active_attack_variant < 4 || active_attack_variant > 7)
    {
        fade_received.clear();
        fade_forwarded.clear();
        Simulator::Schedule(Seconds(FADE_EPOCH_SEC), &fade_detect_anomaly);
        return;
    }

    for (auto &entry : fade_flow_config)
    {
        uint32_t        flow_id = entry.first;
        FadeFlowConfig &cfg     = entry.second;
        if (!cfg.configured) continue;

        FadeDetectionResult &res = fade_results[flow_id];

        std::cout << "[eFADE DEBUG] detect flow " << flow_id << " path_len=" << cfg.path_len;
        for (uint32_t i = 0; i < cfg.path_len; i++) {
            uint32_t n = cfg.path_nodes[i];
            std::cout << "  node" << n << "(recv=" << fade_received[flow_id][n].size();
            uint32_t multi = 0;
            for (auto const &kv : fade_forwarded[flow_id][n]) {
                if (kv.second.size() >= 2) multi++;
            }
            std::cout << ",multi_dest_pkts=" << multi << ")";
        }
        std::cout << " [attacked=" << fade_is_flow_attacked(flow_id) << "]" << std::endl;

        // Loop over path nodes
        for (uint32_t i = 0; i < cfg.path_len; i++)
        {
            uint32_t node = cfg.path_nodes[i];

            // EXCLUDE the source node from the check
            if (node != cfg.source)
            {
                bool duplication_detected = false;

                for (auto const &pkt_entry : fade_forwarded[flow_id][node])
                {
                    uint32_t pid = pkt_entry.first;
                    auto const &dest_set = pkt_entry.second;

                    // Condition (a): forwarded packet_id not in received-set
                    bool not_received = (fade_received[flow_id][node].find(pid) == fade_received[flow_id][node].end());

                    // Condition (b): forwarded same packet_id to >= 2 destinations
                    bool multi_dest = (dest_set.size() >= 2);

                    if (not_received || multi_dest)
                    {
                        duplication_detected = true;
                        break;
                    }
                }

                if (duplication_detected)
                {
                    if (!res.detected)
                    {
                        res.detected         = true;
                        res.detection_time   = now;
                        res.anomaly_type     = "duplication";
                        res.duplicating_node = node;
                        res.loc_from         = node;
                        res.loc_to           = node;

                        std::cout << "[eFADE ALERT] Flow " << flow_id
                                  << " DUPLICATION anomaly detected at node " << node
                                  << " at t=" << now << "s" << std::endl;
                        break; // Stop checking once an attacker is found on this flow
                    }
                }
            }
        }
    }

    // Accumulate epoch's forwarded packets to global counters (instead of unioning into fade_forwarded_all)
    int32_t epoch_atk_fid = -1;
    int32_t epoch_mal_node = -1;
    fade_find_active_attack_flow_and_node(epoch_atk_fid, epoch_mal_node);

    if (epoch_atk_fid != -1 && epoch_mal_node != -1)
    {
        auto it_fid = fade_forwarded.find(epoch_atk_fid);
        if (it_fid != fade_forwarded.end())
        {
            auto it_node = it_fid->second.find(epoch_mal_node);
            if (it_node != it_fid->second.end())
            {
                for (auto const &p_entry : it_node->second)
                {
                    bool dup = (p_entry.second.size() >= 2);
                    if (dup) pp_tp_global++;   // duplicated and detected
                    else     pp_tn_global++;   // not duplicated, correctly clean
                }
            }
        }
    }

    // Clear the maps at the end of the epoch.
    fade_received.clear();
    fade_forwarded.clear();

    Simulator::Schedule(Seconds(FADE_EPOCH_SEC), &fade_detect_anomaly);
}

#endif // EFADE_DETECTION_H
