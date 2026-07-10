#ifndef TCAM_ATTACK_HELPER_H
#define TCAM_ATTACK_HELPER_H

// MobiGuard blockchain event writer — S3/S4 anomaly detection + CSV output.
// Included here so every TCAM install/snapshot automatically logs blockchain events.
#include "bc_blockchain_helper.h"

// The following globals are defined in routing.cc and used here:
extern double   simTime;
extern int      active_attack_variant;
extern uint32_t N_RSUs;
extern uint32_t N_Vehicles;
extern int      num_attackers;
extern double   attack_rate_pps;
extern double   cp_attack_pct;         // % of RSUs targeted per CP tick (0-100)



// ---------- Change 8: TCAM snapshot exporter — 5-tuple stamped at install ----------

struct TcamEntry {
    uint32_t flow_id;
    uint32_t node_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    double   install_time;
    double   last_seen_time; // sim time of most recent packet hit
    uint64_t packet_count;   // packets forwarded through this entry
    uint64_t byte_count;     // bytes  forwarded through this entry
    bool     is_malicious;   // true when injected by attacker (Change 5–7)
};

std::vector<TcamEntry> g_tcam_table;
std::set<std::pair<uint32_t,uint32_t>> g_tcam_installed; // (flow_id, node_id) dedup

// Per-node installed rule count — updated by tcam_install() and
// tcam_install_malicious().  Declared here so routing.cc can forward-declare
// it with `extern` before check_delivery_and_retransmit is defined.
int g_tcam_rule_count[300] = {0}; // indexed by node_id, sized >= total_size

// Returns the first non-loopback IPv4 address of a node given its sim index (0-based).
// NodeList IDs in this simulation are offset by 2 (management + controller nodes occupy 0,1).
inline static uint32_t get_node_ipv4(uint32_t sim_node_index)
{
    Ptr<Node> nd = NodeList::GetNode(sim_node_index + 2);
    if (!nd) return 0;
    Ptr<Ipv4> ipv4 = nd->GetObject<Ipv4>();
    if (!ipv4) return 0;
    for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
    {
        Ipv4Address addr = ipv4->GetAddress(i, 0).GetLocal();
        if (addr != Ipv4Address::GetLoopback() && addr.Get() != 0)
            return addr.Get();
    }
    return 0;
}

// Deterministic port derivation from flow identity (Option B).
// Different (fid, src, dst, salt) combinations produce scattered 16-bit ports.
inline static uint16_t derive_port(uint32_t fid, uint32_t src, uint32_t dst, uint32_t salt)
{
    std::size_t h = std::hash<uint64_t>{}(
        (uint64_t(fid) << 32) ^ (uint64_t(src) << 16) ^ (uint64_t(dst) << 8) ^ salt);
    return static_cast<uint16_t>(1024 + (h % 60000));
}

// Forward-declare so tcam_hit() can call tcam_install() before it is defined.
inline void tcam_install(uint32_t node_id, uint32_t fid);
// Forward-declare the per-second dump so tcam_install can schedule it.
inline void tcam_snapshot_dump();

// Helper to generate a unique flow ID because the simulator reuses fid=0/1.
inline static uint32_t get_actual_flow_id(uint32_t fid) {
    if (fid >= 1000000) return fid; // malicious fake_fid
    
    uint32_t src_node = (delta_at_nodes_inst + fid)->source_f;
    uint32_t dst_node = (delta_at_nodes_inst + fid)->destination_f;
    auto key = std::make_pair(src_node, dst_node);
    
    static std::map<std::pair<uint32_t, uint32_t>, uint32_t> g_benign_flow_map;
    static uint32_t g_next_benign_flow_id = 1;
    
    if (g_benign_flow_map.find(key) == g_benign_flow_map.end()) {
        g_benign_flow_map[key] = g_next_benign_flow_id++;
    }
    return g_benign_flow_map[key];
}

// Helper to generate deterministic flow_id for an IP 5-tuple
inline static uint32_t get_or_create_ip_flow_id(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    std::string key = std::to_string(src_ip) + "-" + std::to_string(dst_ip) + "-" + std::to_string(src_port) + "-" + std::to_string(dst_port) + "-" + std::to_string(proto);
    static std::map<std::string, uint32_t> g_ip_flow_map;
    static uint32_t g_next_ip_flow_id = 1000; // Start at 1000 to avoid conflicts
    if (g_ip_flow_map.find(key) == g_ip_flow_map.end()) {
        g_ip_flow_map[key] = g_next_ip_flow_id++;
    }
    return g_ip_flow_map[key];
}

// ── IP-based Per-packet hit updater ────────────────────────────────────────
// Called by MacTx for standard NS-3 routed packets (e.g., background UDP traffic)
inline void tcam_hit_ip(uint32_t node_id, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto, uint32_t pkt_bytes)
{
    uint32_t actual_fid = get_or_create_ip_flow_id(src_ip, dst_ip, src_port, dst_port, proto);

    for (auto& e : g_tcam_table)
    {
        if (e.flow_id == actual_fid && e.node_id == node_id)
        {
            e.packet_count++;
            e.byte_count   += pkt_bytes;
            e.last_seen_time = Simulator::Now().GetSeconds();
            return;
        }
    }

    bool first_ever = (g_tcam_table.empty());

    TcamEntry e;
    e.flow_id        = actual_fid;
    e.node_id        = node_id;
    e.src_ip         = src_ip;
    e.dst_ip         = dst_ip;
    e.src_port       = src_port;
    e.dst_port       = dst_port;
    e.proto          = proto;
    e.install_time   = Simulator::Now().GetSeconds();
    e.last_seen_time = e.install_time;
    e.packet_count   = 1;
    e.byte_count     = pkt_bytes;
    e.is_malicious   = false;
    g_tcam_table.push_back(e);

    if (first_ever)
        Simulator::Schedule(Seconds(1.0), &tcam_snapshot_dump);
}

// ── Per-packet hit updater ─────────────────────────────────────────────────
// Called at every relay/source forward for (node_id, fid). Increments the
// matching entry's packet and byte counters; updates last_seen_time.
inline void tcam_hit(uint32_t node_id, uint32_t original_fid, uint32_t pkt_bytes)
{
    uint32_t actual_fid = get_actual_flow_id(original_fid);

    for (auto& e : g_tcam_table)
    {
        if (e.flow_id == actual_fid && e.node_id == node_id)
        {
            e.packet_count++;
            e.byte_count   += pkt_bytes;
            e.last_seen_time = Simulator::Now().GetSeconds();
            return;
        }
    }
    // Entry not yet installed — install first, then record the hit.
    tcam_install(node_id, original_fid);
    tcam_hit(node_id, original_fid, pkt_bytes);
}

// Install a TCAM rule for (flow_id, node_id) once.  Subsequent calls for the
// same pair are silently ignored — dedup via g_tcam_installed.
// On the very first install ever, also kicks off the per-second snapshot loop.
inline void tcam_install(uint32_t node_id, uint32_t original_fid)
{
    uint32_t actual_fid = get_actual_flow_id(original_fid);
    auto key = std::make_pair(actual_fid, node_id);
    if (g_tcam_installed.count(key)) return;
    g_tcam_installed.insert(key);

    bool first_ever = (g_tcam_table.empty());  // schedule timer only once

    uint32_t src_node = (delta_at_nodes_inst + original_fid)->source_f;
    uint32_t dst_node = (delta_at_nodes_inst + original_fid)->destination_f;

    uint32_t src_ip = get_node_ipv4(src_node);
    uint32_t dst_ip = get_node_ipv4(dst_node);

    // Per-flow deterministic ports — vary across flows so PSE is meaningful
    uint16_t src_port = derive_port(actual_fid, src_node, dst_node, 0x1234u);
    uint16_t dst_port = derive_port(actual_fid, dst_node, src_node, 0x5678u);

    TcamEntry e;
    e.flow_id        = actual_fid;
    e.node_id        = node_id;
    e.src_ip         = src_ip;
    e.dst_ip         = dst_ip;
    e.src_port       = src_port;
    e.dst_port       = dst_port;
    e.proto          = 17;   // UDP
    e.install_time   = Simulator::Now().GetSeconds();
    e.last_seen_time = e.install_time;
    e.packet_count   = 0;
    e.byte_count     = 0;
    e.is_malicious   = false;
    g_tcam_table.push_back(e);
    g_tcam_rule_count[node_id]++;

    Ipv4Address sip, dip;
    sip.Set(src_ip);
    dip.Set(dst_ip);
    std::cout << "[TCAM INSTALL] flow=" << actual_fid
              << " node=" << node_id
              << " " << sip << ":" << src_port
              << " -> " << dip << ":" << dst_port
              << " t=" << e.install_time << "s" << std::endl;

    // MobiGuard: log FlowMod event to bc_flowmod_log.csv + emit [BC-FLOWMOD] line.
    // Bridge tails this CSV and calls LogFlowMod() on-chain in real time.
    bc_log_flowmod(node_id, actual_fid, src_ip, dst_ip, src_port, dst_port, false);

    // Kick off the per-second snapshot loop the very first time any entry is installed.
    if (first_ever)
        Simulator::Schedule(Seconds(1.0), &tcam_snapshot_dump);
}

// ── Per-second snapshot exporter (Change 8) ────────────────────────────────
// Fires at t=first_install+1s then every 1s until simTime.
// Writes two CSVs into results_routing/:
//   tcam_snapshots_<mode>.csv  — one row per (node, flow) per second
//   tcam_occupancy_<mode>.csv  — one row per node per second (rule count)
inline void tcam_snapshot_dump()
{
    double now = Simulator::Now().GetSeconds();
    int    t   = static_cast<int>(std::round(now));

    // Derive mode tag — maps internal enum values to the paper's attack numbers
    // (attack_id = active_attack_variant + 1), matching the scheme
    // write_security_metrics_csv() uses for MOBIGUARD_Attack*.csv. Previously
    // variant 0/1 stayed as "attack0"/"attack1" while variant 2/3 were bumped
    // to "attack3"/"attack4" — an inconsistent, off-by-one labeling that made
    // e.g. Attack 2 (variant=1) data land in a file named "tcam_snapshots_attack1*",
    // indistinguishable from actual Attack 1 output.
    std::string mode;
    if (active_attack_variant == -1) {
        mode = "baseline";
    } else {
        mode = "attack" + std::to_string(active_attack_variant + 1);
        // For Attack 4 multi-attacker sweeps append _nN so each run
        // produces a distinct file: attack4_n1.csv, attack4_n8.csv, …
        if (active_attack_variant == 3 && num_attackers > 1)
            mode += "_n" + std::to_string(num_attackers);
    }

    const std::string base_dir =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
    std::string snap_path = base_dir + "tcam_snapshots_" + mode + ".csv";
    std::string occ_path  = base_dir + "tcam_occupancy_"  + mode + ".csv";

    // Open in append mode; write header only when file is new/empty.
    std::ofstream snap_f(snap_path, std::ios::app);
    if (snap_f.is_open() && snap_f.tellp() == 0)
        snap_f << "t,rsu_id,flow_id,src_ip,dst_ip,src_port,dst_port,proto,"
               << "install_time,duration,packets,bytes,is_malicious\n";

    std::ofstream occ_f(occ_path, std::ios::app);
    if (occ_f.is_open() && occ_f.tellp() == 0)
        occ_f << "t,rsu_id,total_rule_count\n";

    // Walk every installed entry; build per-node rule count as we go.
    std::map<uint32_t,int> rule_count;
    for (const auto& e : g_tcam_table)
    {
        rule_count[e.node_id]++;
        if (snap_f.is_open())
        {
            double duration = now - e.install_time;
            Ipv4Address sip, dip;
            sip.Set(e.src_ip);
            dip.Set(e.dst_ip);
            snap_f << t
                   << ',' << e.node_id
                   << ',' << e.flow_id
                   << ',' << sip
                   << ',' << dip
                   << ',' << e.src_port
                   << ',' << e.dst_port
                   << ',' << (int)e.proto
                   << ',' << std::fixed << std::setprecision(6)
                   << e.install_time
                   << ',' << duration
                   << ',' << e.packet_count
                   << ',' << e.byte_count
                   << ',' << (e.is_malicious ? 1 : 0)
                   << '\n';
        }
    }
    if (occ_f.is_open())
    {
        for (const auto& kv : rule_count)
            occ_f << t << ',' << kv.first << ',' << kv.second << '\n';
    }
    snap_f.close();
    occ_f.close();

    // MobiGuard: check S4 (TCAM exhaustion) for all RSUs once per second.
    // Writes penalty rows to bc_trust_updates.csv when rule count > 80% capacity.
    bc_check_s4();

    if (now + 1.0 <= simTime)
        Simulator::Schedule(Seconds(1.0), &tcam_snapshot_dump);
}

// ── End-of-sim backup export ────────────────────────────────────────────────
// Writes a final static snapshot with total lifetime counters per entry.
inline void export_tcam_snapshot_baseline()
{
    // Same paper-numbering scheme as tcam_snapshot_dump(): attack_id = variant+1.
    std::string mode;
    if (active_attack_variant == -1) {
        mode = "baseline";
    } else {
        mode = "attack" + std::to_string(active_attack_variant + 1);
        // Mirror the _nN suffix logic from tcam_snapshot_dump().
        if (active_attack_variant == 3 && num_attackers > 1)
            mode += "_n" + std::to_string(num_attackers);
    }
    std::string path =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/tcam_snapshots_" + mode + "_final.csv";
    std::ofstream fout(path, std::ios::trunc);
    fout << "flow_id,node_id,src_ip,dst_ip,src_port,dst_port,proto,install_time,packets,bytes\n";
    for (const auto& e : g_tcam_table)
    {
        Ipv4Address sip, dip;
        sip.Set(e.src_ip);
        dip.Set(e.dst_ip);
        fout << e.flow_id      << ","
             << e.node_id      << ","
             << sip            << ","
             << dip            << ","
             << e.src_port     << ","
             << e.dst_port     << ","
             << (int)e.proto   << ","
             << e.install_time << ","
             << e.packet_count << ","
             << e.byte_count   << "\n";
    }
    fout.close();
    std::cout << "[TCAM SNAPSHOT] Final export: " << g_tcam_table.size()
              << " entries -> " << path << std::endl;
}

// ---------- TCAM exhaustion helpers ----------

// ── Change 5: malicious-flow installer ────────────────────────────────────
// Like tcam_install() but:
//   • skips g_tcam_installed dedup (each fake_fid is intentionally unique)
//   • sets is_malicious = true
//   • derives 5-tuple from fake_fid alone (no delta_at_nodes_inst needed)
//
// flow_id stored in the TCAM entry (and CSV) is derived from the 5-tuple via
// get_or_create_ip_flow_id(), placing it in the same [1000, N] range as
// legitimate traffic.  The raw fake_fid (1M+ / 2M+) is only used internally
// as a seed to produce a unique 5-tuple and is never written to any output.
// Without this, an LSTM or similar model can trivially classify entries as
// malicious purely from the flow_id magnitude.
inline void tcam_install_malicious(uint32_t node_id, uint32_t target_rsu_node_id, uint32_t fake_fid)
{
    // node_id            = attacker's own node (source of the packet; used for src_ip).
    // target_rsu_node_id = the RSU whose TCAM this malicious FlowMod actually lands on.
    // For Attack 3 (CP), attacker and victim RSU are the same node, so that call
    // site passes the same value for both -- no behavior change there.
    //
    // Build a synthetic 5-tuple unique to this fake_fid.
    // src IP = attacker node's real IP; dst IP sampled from the same server
    // range used by benign traffic (10.1.1.65–68) so the dst_ip column does
    // not leak attack membership to an ML classifier.
    uint32_t src_ip  = get_node_ipv4(node_id);
    uint32_t encoded = fake_fid & 0xFFFF;
    // Cycle through the four real RSU server addresses (.65 .66 .67 .68)
    uint32_t dst_last = 65u + (encoded % 4u);
    uint32_t dst_ip   = ((uint32_t)10 << 24) | ((uint32_t)1 << 16)
                      | ((uint32_t)1 << 8)   | dst_last;

    uint16_t src_port = derive_port(fake_fid, node_id, 0xDEAD, 0x1111u);
    uint16_t dst_port = derive_port(fake_fid, 0xDEAD, node_id, 0x2222u);

    // Derive the visible flow_id from the 5-tuple using the same lookup used
    // for benign flows — result lands in [1000, N], indistinguishable from
    // legitimate entries by flow_id alone.
    uint32_t visible_fid = get_or_create_ip_flow_id(src_ip, dst_ip, src_port, dst_port, 17);

    TcamEntry e;
    e.flow_id        = visible_fid;
    e.node_id        = target_rsu_node_id;
    e.src_ip         = src_ip;
    e.dst_ip         = dst_ip;
    e.src_port       = src_port;
    e.dst_port       = dst_port;
    e.proto          = 17;   // UDP
    e.install_time   = Simulator::Now().GetSeconds();
    e.last_seen_time = e.install_time;
    e.packet_count   = 1;    // counts as one "packet miss" that triggered install
    e.byte_count     = 750;  // nominal packet size consistent with benign traffic
    e.is_malicious   = true;
    g_tcam_table.push_back(e);
    g_tcam_rule_count[target_rsu_node_id]++;
    // NOTE: intentionally NOT inserted into g_tcam_installed so repeated calls
    // with the same fake_fid could be used for refresh; but dp_attack_tick always
    // increments g_dp_attack_fid_counter so each call is truly unique.

    Ipv4Address sip, dip;
    sip.Set(src_ip);
    dip.Set(dst_ip);
    std::cout << "[TCAM INSTALL MAL] visible_fid=" << visible_fid
              << " (seed=" << fake_fid << ")"
              << " attacker=" << node_id
              << " target_rsu=" << target_rsu_node_id
              << " " << sip << ":" << src_port
              << " -> " << dip << ":" << dst_port
              << " t=" << e.install_time << "s" << std::endl;

    // MobiGuard: log malicious FlowMod to bc_flowmod_log.csv (is_malicious=1).
    // Bridge calls MarkFlowModUnauthorized() + triggers S3 rate counter.
    bc_log_flowmod(target_rsu_node_id, visible_fid, src_ip, dst_ip, src_port, dst_port, true);
}

// Forward-declared here (defined in lrad.h, included later in routing.cc) so
// dp_attack_tick_for can reuse the same vehicle->RSU association used by real
// per-vehicle escalation routing -- not a new/invented notion of "nearest RSU."
inline uint32_t lookup_vehicle_associated_rsu_local_idx(uint32_t vehicle);

// ── Change 5+7: self-rescheduling DP attacker tick (per-node) ─────────────
// dp_attack_tick_for(node): fires every (1/attack_rate_pps) seconds for the
// given attacker node while active_attack_variant==3 and sim time < simTime.
// Each call installs one new unique malicious TCAM rule targeting the RSU
// this attacker vehicle is currently associated with.
inline void dp_attack_tick_for(uint32_t attacker_node)
{
    if (active_attack_variant != 3) return;
    double now = Simulator::Now().GetSeconds();
    if (now >= simTime) return;

    // Target the RSU this attacker vehicle is actually associated with right
    // now (same lookup real packet forwarding/escalation uses), instead of
    // stuffing the entry into the attacker's own TCAM slot.
    uint32_t rsu_local_idx = lookup_vehicle_associated_rsu_local_idx(attacker_node);
    if (rsu_local_idx < N_RSUs)
    {
        uint32_t target_rsu_node_id = N_Vehicles + rsu_local_idx;
        uint32_t fake_fid = g_dp_attack_fid_counter++;
        tcam_install_malicious(attacker_node, target_rsu_node_id, fake_fid);
    }
    // else: vehicle currently out of DSRC range of any RSU -- skip this tick,
    // same "silently drop, not an error" handling as escalate_to_rsu().

    double interval = 1.0 / attack_rate_pps;
    Simulator::Schedule(Seconds(interval),
                        &dp_attack_tick_for, attacker_node);
}

// Legacy single-attacker entry point (node 0) — kept for backward compat.
inline void dp_attack_tick()
{
    dp_attack_tick_for(0);
}

// ── Change 6: self-rescheduling CP (controller) attacker tick ─────────────
// Fires every (1/attack_rate_pps) seconds while active_attack_variant==2.
// Each call installs one new malicious rule on a configurable fraction of
// RSUs (cp_attack_pct %, default 100%), simulating a compromised controller
// broadcasting a junk FlowMod to part or all of the network.
// RSUs are selected by index (0..num_targeted-1) for determinism.
inline void cp_attack_tick()
{
    if (active_attack_variant != 2) return;
    double now = Simulator::Now().GetSeconds();
    if (now >= simTime) return;

    // Compute how many RSUs to target this tick based on cp_attack_pct.
    uint32_t num_targeted = static_cast<uint32_t>(
        std::ceil(N_RSUs * (cp_attack_pct / 100.0)));
    if (num_targeted < 1)       num_targeted = 1;
    if (num_targeted > N_RSUs)  num_targeted = N_RSUs;

    for (uint32_t r = 0; r < num_targeted; r++)
    {
        uint32_t rsu_idx  = N_Vehicles + r;        // sim node index of RSU r
        uint32_t fake_fid = g_cp_attack_fid_counter++;
        tcam_install_malicious(rsu_idx, rsu_idx, fake_fid); // attacker == victim RSU, same as before
    }

    double interval = 1.0 / attack_rate_pps;
    Simulator::Schedule(Seconds(interval), &cp_attack_tick);
}

#endif // TCAM_ATTACK_HELPER_H
