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
//      compares the COUNT of packets received (p_in) against the COUNT of
//      packets forwarded (p_out) during the epoch — mirroring Li et al.'s
//      Algorithm 2, which compares raw packet counts reported by R1/R2
//      rules (p1 vs p_i), not individual packet identities (real FADE's R1/R2
//      rules count matched packets; they cannot see packet IDs). If
//      p_out > p_in, the node is duplicating traffic and is flagged as a
//      "duplication" anomaly, with that node recorded as the localisation.
//      (An earlier version tracked exact packet IDs and destination sets,
//      which is strictly more precise than what real FADE can observe and
//      understated the flow-statistics-accuracy limitation main.tex's B3
//      comparison is meant to expose — see docs/PENDING_FIXES.md Fix 7.)
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

// received_count[flow_id][node] = number of packet-receive events at node this epoch
// (count-based, mirrors R1/R2's packet counters in Li et al. — real FADE rules
// count matches, they cannot record individual packet identities).
std::map<uint32_t, std::map<uint32_t, uint32_t>> fade_received_count;
// forwarded_count[flow_id][node] = number of packet-forward events (send
// events) at node this epoch; a node that sends the same packet to two
// destinations increments this twice, so forwarded_count > received_count
// signals duplication exactly as p_i != p1 does in the paper's Algorithm 2.
std::map<uint32_t, std::map<uint32_t, uint32_t>> fade_forwarded_count;
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

    // Walk the stored path to find its nodes and length.
    // Test mode:  proposed_routing_tables is populated by run_stable_path_finding.
    // SUMO mode:  proposed_routing_tables is never populated; reconstruct path by
    //             greedily following the highest-weight delta hop from delta_at_nodes_inst.
    if (routing_test)
    {
        for (uint32_t step = 0; step < (uint32_t)total_size; step++)
        {
            uint32_t node = proposed_routing_tables[src].rows[dst].path[step];
            if (node >= (uint32_t)total_size) break;
            cfg.path_nodes[cfg.path_len++] = node;
        }
    }
    else
    {
        bool visited[total_size];
        memset(visited, 0, sizeof(visited));
        uint32_t cur = src;
        for (uint32_t step = 0; step < (uint32_t)total_size; step++)
        {
            if (cur >= (uint32_t)total_size) break;
            cfg.path_nodes[cfg.path_len++] = cur;
            if (cur == dst) break;
            visited[cur] = true;
            uint32_t best_next = (uint32_t)total_size;
            double   best_w    = 0.0;
            for (uint32_t n = 0; n < (uint32_t)total_size; n++)
            {
                if (visited[n]) continue;
                double w = (delta_at_nodes_inst + flow_id)->delta_fi_inst[cur].delta_values[n];
                if (w > best_w) { best_w = w; best_next = n; }
            }
            if (best_next >= (uint32_t)total_size || best_w <= 0.0) break;
            cur = best_next;
        }
    }

    std::cout << "[eFADE DEBUG] configure flow " << flow_id
              << " src=" << src << " dst=" << dst
              << " path_len=" << cfg.path_len << " nodes:";
    for (uint32_t i = 0; i < cfg.path_len; i++) std::cout << " " << cfg.path_nodes[i];
    std::cout << std::endl;

    // In test mode the full path (vehicle→RSU→vehicle) is available via
    // proposed_routing_tables, so require it to reach dst.
    // In SUMO mode delta_at_nodes_inst only stores vehicle→RSU forwarding
    // weights; RSU→RSU or RSU→vehicle hops are controlled via the controller
    // and are not reflected in the node-side delta table.  Accept any path
    // that reaches at least one RSU — that RSU is the anomalous forwarder
    // eFADE needs to monitor; the destination vehicle leg is irrelevant.
    if (routing_test)
    {
        bool reached_dst = (cfg.path_len > 0 && cfg.path_nodes[cfg.path_len - 1] == dst);
        if (cfg.path_len < 2 || !reached_dst)
        {
            fade_flow_config[flow_id] = cfg;
            return;
        }
    }
    else
    {
        bool has_rsu = false;
        for (uint32_t i = 0; i < cfg.path_len; i++)
        {
            if (cfg.path_nodes[i] >= (uint32_t)N_Vehicles &&
                cfg.path_nodes[i] <  (uint32_t)(N_Vehicles + N_RSUs))
            {
                has_rsu = true;
                break;
            }
        }
        if (cfg.path_len < 2 || !has_rsu)
        {
            fade_flow_config[flow_id] = cfg;
            return;
        }
    }

    if (cfg.path_len > 0 && cfg.path_nodes[cfg.path_len - 1] != dst)
        cfg.path_nodes[cfg.path_len++] = dst;
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

// Forces a fresh delta walk regardless of prior configuration state.
// Used at attack_start_time - 0.5s so the path reflects current vehicle
// positions rather than the stale t=1.08s snapshot.
inline void fade_reconfigure_all_flows()
{
    for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
    {
        if (fade_flow_config.count(fid))
            fade_flow_config[fid].configured = false;
        fade_configure_flow(fid);
    }
}

// ── Helper: is any node on this flow's path a malicious node? ────────────────
// Used to classify TP / FP / TN / FN for the FADE MCC calculation.
inline bool fade_is_flow_attacked(uint32_t flow_id)
{
    auto it = fade_flow_config.find(flow_id);
    if (it == fade_flow_config.end() || !it->second.configured) return false;

    FadeFlowConfig const &cfg = it->second;
    // eFADE covers Hidden Forwarding attacks only (variants 4–7).
    // Use the pre-built cfg.path_nodes — proposed_routing_tables is empty in SUMO mode.
    for (uint32_t i = 0; i < cfg.path_len; i++)
    {
        uint32_t node = cfg.path_nodes[i];
        if ((active_attack_variant == 4 || active_attack_variant == 5)
            && active_hf_malicious_nodes[node])  return true;
        if ((active_attack_variant == 6 || active_attack_variant == 7)
            && passive_hf_malicious_nodes[node]) return true;
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
    auto it = fade_received_count.find(flow_id);
    if (it != fade_received_count.end())
    {
        for (auto &node_entry : it->second)
        {
            if (node_entry.second > 0) return true;
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

        // Use the pre-configured path (works for both test and SUMO mode,
        // since fade_configure_flow already resolved the correct path nodes).
        FadeFlowConfig const &cfg = entry.second;
        for (uint32_t i = 0; i < cfg.path_len; i++)
        {
            uint32_t node = cfg.path_nodes[i];
            if (passive_hf_malicious_nodes[node] || active_hf_malicious_nodes[node])
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

    // PDR: use the same globals as TAP (computed each cycle by
    // calculate_average_packet_delivery_ratio_routing in routing.cc).
    double pdr = average_packet_delivery_ratio_dsrc * 100.0;

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
    std::system("mkdir -p results_routing");
    std::string fade_metrics_path = "results_routing/fade_metrics" + g_sim_tag + ".csv";
    bool write_header = false;
    {
        std::ifstream check(fade_metrics_path);
        write_header = !check.good();
    }
    std::ofstream mfile;
    mfile.open(fade_metrics_path, std::ios::out | std::ios::app);
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

    // Retry path configuration for any flow not yet fully configured.
    // Paths built at t=1.080 may be incomplete if delta tables weren't
    // fully propagated yet; this ensures they get completed once routing
    // has stabilised (typically by the second or third epoch).
    for (uint32_t fid = 0; fid < 2 * (uint32_t)flows; fid++)
        fade_configure_flow(fid);

    if (!fade_detection_active)
    {
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
            std::cout << "  node" << n << "(recv=" << fade_received_count[flow_id][n]
                       << ",fwd=" << fade_forwarded_count[flow_id][n] << ")";
        }
        std::cout << " [attacked=" << fade_is_flow_attacked(flow_id) << "]" << std::endl;

        // Loop over path nodes
        for (uint32_t i = 0; i < cfg.path_len; i++)
        {
            uint32_t node = cfg.path_nodes[i];

            // EXCLUDE the source node from the check
            if (node != cfg.source)
            {
                // Count-based conservation check (Algorithm 2, Li et al.):
                // p_in = packets received at this node this epoch (~ p1 at
                // the reference rule); p_out = packets forwarded (~ p_i at
                // this node's R2 rule). p_out > p_in means this node sent
                // out more copies than it took in — duplication.
                uint32_t p_in  = fade_received_count[flow_id][node];
                uint32_t p_out = fade_forwarded_count[flow_id][node];
                bool duplication_detected = (p_out > p_in);

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

    // Node-epoch TP/FP/TN/FN accumulation across all configured flows.
    // For each node on each flow path (excluding source) that saw any
    // traffic this epoch, classify the node's count-conservation verdict
    // (p_out > p_in) as TP/FP/TN/FN against ground truth. This mirrors
    // Algorithm 2's own decision granularity — one verdict per node per
    // detection round, not per packet identity (see the count-based
    // rewrite note at the top of this file / PENDING_FIXES.md Fix 7).
    // In practice this rarely changes sample count vs the old per-packet
    // version: flows send at 1 Hz into 1 s epochs, so almost every epoch
    // has at most one packet in flight per node anyway.
    for (auto const &flow_entry : fade_flow_config)
    {
        uint32_t fid2 = flow_entry.first;
        if (!flow_entry.second.configured) continue;
        FadeFlowConfig const &cfg2 = flow_entry.second;
        for (uint32_t i = 0; i < cfg2.path_len; i++)
        {
            uint32_t node = cfg2.path_nodes[i];
            if (node == cfg2.source) continue;
            bool node_malicious = active_hf_malicious_nodes[node] || passive_hf_malicious_nodes[node];

            auto it_fid = fade_forwarded_count.find(fid2);
            if (it_fid == fade_forwarded_count.end()) continue;
            auto it_node = it_fid->second.find(node);
            if (it_node == it_fid->second.end()) continue;

            uint32_t p_out = it_node->second;
            uint32_t p_in  = fade_received_count[fid2][node];
            if (p_out == 0 && p_in == 0) continue; // no traffic at this node this epoch

            bool dup = (p_out > p_in);
            if ( node_malicious &&  dup) pp_tp_global++;
            if (!node_malicious &&  dup) pp_fp_global++;
            if (!node_malicious && !dup) pp_tn_global++;
            if ( node_malicious && !dup) pp_fn_global++;
        }
    }

    // Clear the maps at the end of the epoch.
    fade_received_count.clear();
    fade_forwarded_count.clear();

    Simulator::Schedule(Seconds(FADE_EPOCH_SEC), &fade_detect_anomaly);
}

#endif // EFADE_DETECTION_H
