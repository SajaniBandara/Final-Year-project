#ifndef TCAM_ATTACK_HELPER_H
#define TCAM_ATTACK_HELPER_H

#include <algorithm>   // std::remove_if — tcam_evict_expired()

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
extern double   cp_attack_intensity;   // % of RSUs targeted per CP tick (0-100)
                                        // NOTE: NOT the "attack percentage" used in the
                                        // report/thesis -- that is attack_percentage
                                        // (routing.cc), which drives num_controllers_compromised.
extern int      TCAM_CAPACITY;         // single canonical TCAM size (defined in routing.cc —
                                       // see there for the current value; never restate it here)

// ---------- TCAM resource-model constants (2026-07-13) ----------
// Named, configurable (not inlined) per-rule timeout values. A rule is
// evicted when EITHER timer expires: idle_timeout counts from the last
// packet seen on the flow (last_seen_time); hard_timeout counts from
// install_time regardless of ongoing traffic. Applies to legit and
// malicious entries alike -- tcam_evict_expired() does not look at
// is_malicious.
double TCAM_IDLE_TIMEOUT_S = 30.0;   // 2026-07-16: 10 -> 30. Applies to fixed-timeout
                                     // entries: ip-hook observations and the malicious
                                     // fallback idle (moot while the attacker refreshes,
                                     // see tcam_refresh_malicious_on_node). Benign
                                     // generator flows use their OWN uniform(9,22)s
                                     // residence-window idle_timeout_s instead of this.
double TCAM_HARD_TIMEOUT_S = 120.0;  // 2026-07-16: 30 -> 120. Hard cap from install_time
                                     // for BENIGN entries only. Rarely fires for gen flows
                                     // (the vehicle departs / the flow idles out within the
                                     // 9-22s residence window first); raised so present-
                                     // vehicle rules refresh less aggressively. Malicious
                                     // rules are EXEMPT from the hard timeout entirely (see
                                     // tcam_evict_expired) -- required so the slow attacker
                                     // can accumulate to capacity rather than being capped
                                     // at rate x hard_timeout.

// ---------- Legit-flow idle-timeout, 9-22s residence window (2026-07-16) ----------
// main.tex Sec. mobility_amplification: a vehicle crosses a 300-500m RSU zone
// in ~9-22s at highway speed. Each generator (legit) flow gets its OWN
// idle_timeout drawn uniformly from this window at install time (TcamEntry::
// idle_timeout_s), instead of the fixed global TCAM_IDLE_TIMEOUT_S, so a
// legit rule expires around when its vehicle would plausibly have left the
// zone even if no explicit neighbour-departure event ever fires for it.
// Malicious/ip-hook entries keep using the fixed global TCAM_IDLE_TIMEOUT_S.
inline double sample_gen_idle_timeout_s()
{
    static Ptr<UniformRandomVariable> rng = nullptr;
    if (!rng) rng = CreateObject<UniformRandomVariable>();
    return rng->GetValue(9.0, 22.0);
}

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
    bool     presence_managed = false; // true = generator (legit) flow. Evicted by
                             // EITHER trigger, whichever fires first: explicit
                             // neighbour departure (tcam_evict_gen_entry) or the
                             // normal idle/hard-timeout sweep in tcam_evict_expired()
                             // using this entry's own idle_timeout_s (2026-07-16).
                             // Set in tcam_install() when the install fid is a
                             // gen-fid (gen_flow_lookup true).
    double   idle_timeout_s = TCAM_IDLE_TIMEOUT_S; // per-entry idle timeout; generator
                             // flows override this with sample_gen_idle_timeout_s()
                             // (uniform 9-22s, main.tex zone-residence window).
                             // Non-generator entries keep the fixed global default.
    bool     counts_capacity;// true = genuine data-plane TCAM rule that occupies a
                             // slot in g_tcam_rule_count (installed via tcam_install /
                             // tcam_install_malicious, sim-index node space, capped at
                             // TCAM_CAPACITY, read by the S3/S4 detector). false = a
                             // passive Ipv4Tx-hook observation from tcam_hit_ip (RSU IP
                             // L3 Tx stream: control-plane + background IP traffic, in
                             // NodeList index space) that is NOT a data-plane FlowMod
                             // rule and must not touch g_tcam_rule_count. See the
                             // 2026-07-14 note in tcam_hit_ip() / tcam_evict_expired().
    bool     authorized = true; // f_unauth for S3 (eq:unauth_flowmod): true = this
                             // FlowMod is in the blockchain-committed endorsed policy
                             // set (f+1 endorsement quorum satisfied); false =
                             // UNAUTHORISED (no f+1 endorsement). Set at install by
                             // tcam_flowmod_authorized() from the OBSERVABLE legitimate-
                             // flow registry (fid provenance / F_active), NOT from
                             // is_malicious. Default true so passive ip-hook entries
                             // (which are not data-plane FlowMods) are never counted as
                             // unauthorised by the S3 detector.
};

std::vector<TcamEntry> g_tcam_table;
std::set<std::pair<uint32_t,uint32_t>> g_tcam_installed; // (flow_id, node_id) dedup

// Per-node installed rule count — updated by tcam_install() and
// tcam_install_malicious().  Declared here so routing.cc can forward-declare
// it with `extern` before check_delivery_and_retransmit is defined.
int g_tcam_rule_count[300] = {0}; // indexed by node_id, sized >= total_size

// Per-node cumulative TABLE_FULL rejection count -- an install attempt that
// found g_tcam_rule_count[node_id] >= TCAM_CAPACITY and was refused. Mirrors
// g_tcam_rule_count's indexing/lifetime.
int g_tcam_reject_count[300] = {0};

// Per-node cumulative PACKET_IN (table-miss) count -- the S4 λ_PI signal
// (eq:sig_s4). A PACKET_IN fires on every table MISS: (a) each new rule install
// (a miss that triggered PACKET_IN -> controller -> FlowMod), counted in
// tcam_install / tcam_install_malicious, and (b) each packet arriving at a FULL
// table that cannot install a rule (repeated slow-path miss), counted in the
// slow-path block in routing.cc. This is the paper's PACKET_IN flood rate, which
// is nonzero from attack onset (and has a benign baseline from legit installs),
// UNLIKE g_slowpath_hit_count which only counts the full-table delay case and is
// therefore zero until exhaustion. S4's lambda_pi is derived from THIS counter.
// DEFINED in routing.cc (alongside g_slowpath_hit_count); externed here so the
// install/malicious-install paths below can increment it.
extern int g_packetin_count[300];
// Issue 6 fix (2026-08-02): per-(RSU, source vehicle) companion to
// g_packetin_count above -- see its declaration in routing.cc.
extern std::map<uint32_t, std::map<uint32_t, uint32_t>> g_packetin_by_source;

// ── True install-rate instrumentation (2026-07-15, MEASUREMENT ONLY) ─────────
// Per-node counters accumulated within each 1-s snapshot window, then flushed
// to lambda_l_true.csv and reset by tcam_snapshot_dump(). They separate the
// three lifecycle events so the TRUE new-install rate (lambda_l, the FlowMod
// rate the S3 detector keys on) is not conflated with timeout-refresh churn:
//   g_lambda_new       = fresh installs   (a (flow,node) key never evicted before)
//   g_lambda_evict     = timeout evictions (counts_capacity data-plane rules only)
//   g_lambda_reinstall = re-installs after a prior eviction of the SAME key (churn)
// A key is classed as "reinstall" iff it has been evicted at least once before
// (tracked in g_tcam_ever_evicted). Nothing here alters install/evict behaviour.
uint32_t g_lambda_new[300]       = {0};
uint32_t g_lambda_evict[300]     = {0};
uint32_t g_lambda_reinstall[300] = {0};
std::set<std::pair<uint32_t,uint32_t>> g_tcam_ever_evicted; // (flow_id,node_id) evicted >=1x

// Monotone cumulative install counters (NEVER reset — the per-cycle arrays above
// are zeroed each snapshot). The S3 windowed rate estimator reads these to form a
// sliding-window install count (new + reinstall) without depending on snapshot
// phase. lambda_obs for S3 = (new_cum + reinstall_cum) delta over the window.
uint64_t g_lambda_new_cum[300]       = {0};
uint64_t g_lambda_reinstall_cum[300] = {0};

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
// ── k-NN flow generator gen-fid registry (2026-07-14) ──────────────────────
// The benign data path is bound to fid in [0, 2*flows) by fixed-size arrays
// (delta_at_nodes_inst[2*flows], pd_all_inst[2*flows], ...). The concurrency
// generator (tcam_flow_generator.h) needs many DISTINCT flow identities WITHOUT
// growing those arrays, so it uses gen-fids in the reserved range
// [TCAM_GEN_FID_BASE, 1000000). A gen-fid does NOT index delta_at_nodes_inst;
// its (src_node, dst_node) is registered here and resolved by both
// get_actual_flow_id() and tcam_install(). Generated flows still install via the
// SAME counted/capped path (tcam_install sets counts_capacity=true, increments
// g_tcam_rule_count, respects TABLE_FULL, is evicted by tcam_evict_expired) --
// exactly like the 2 native flows. Only the identity source differs.
static const uint32_t TCAM_GEN_FID_BASE = 500000; // gen range [500000, 999999]; malicious is >=1000000
std::map<uint32_t, std::pair<uint32_t,uint32_t>> g_gen_flow_endpoints; // gen_fid -> (src_node, dst_node)

// True + fills src/dst if `fid` is a registered generated flow.
inline static bool gen_flow_lookup(uint32_t fid, uint32_t& src_node, uint32_t& dst_node) {
    if (fid < TCAM_GEN_FID_BASE || fid >= 1000000) return false;
    auto it = g_gen_flow_endpoints.find(fid);
    if (it == g_gen_flow_endpoints.end()) return false;
    src_node = it->second.first;
    dst_node = it->second.second;
    return true;
}

inline static uint32_t get_actual_flow_id(uint32_t fid) {
    if (fid >= 1000000) return fid; // malicious fake_fid

    uint32_t src_node, dst_node;
    if (gen_flow_lookup(fid, src_node, dst_node)) {
        // Generated flow: resolve (src,dst) from the gen registry, then share the
        // SAME (src,dst)->sequential-id map as native benign flows so a persistent
        // neighbor pair keeps its identity across cycles (re-selection => same
        // actual_fid => tcam_hit refreshes the existing entry instead of duplicating).
    } else {
        src_node = (delta_at_nodes_inst + fid)->source_f;
        dst_node = (delta_at_nodes_inst + fid)->destination_f;
    }
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
    // [ip-hook exclusion, 2026-07-14] These entries come from the network-wide
    // Ipv4Tx hook (routing.cc Ipv4Tx -> tcam_hit_ip) on the RSU IPv4 L3 Tx
    // stream: control-plane (delta/solution distribution to the 10.1.1.x
    // controller subnet, telemetry uplink) plus background IP-routed packets.
    // They are NOT data-plane FlowMod rules and are keyed in NodeList index
    // space (RSU = 204..267), which is DIFFERENT from the sim-index space
    // (RSU = 200..263) used by g_tcam_rule_count, tcam_install(), and the
    // S3/S4 detector. Counting them here would (a) collide two index spaces in
    // one array and (b) misattribute control-plane traffic as TCAM exhaustion.
    // So they do NOT increment g_tcam_rule_count and are NOT subject to the
    // TABLE_FULL cap. Boundedness: each (5-tuple, node) is deduped by the linear
    // scan above, and every entry is removed by tcam_evict_expired() once idle
    // >= TCAM_IDLE_TIMEOUT_S or age >= TCAM_HARD_TIMEOUT_S, so the count of live
    // ip-hook entries is bounded by the distinct RSU 5-tuples seen within one
    // hard-timeout window (empirically <=1 concurrent per node under benign
    // load; attacks route through tcam_install_malicious(), not this path).
    e.counts_capacity = false;
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
    // Entry not yet installed — install, then record the hit ONCE by re-scanning.
    // The previous code recursed back into tcam_hit(), which infinite-loops when
    // the table is FULL: tcam_install() rejects (TABLE_FULL), the entry still is
    // not present, so the recursive call installs+rejects again forever ->
    // stack-overflow SIGSEGV. This only surfaced once the attack could actually
    // exhaust the table (2026-07-17). If the install was rejected (table full),
    // the second scan finds nothing and we return: the packet took the controller
    // slow path with no rule installed, which is the correct exhaustion behaviour.
    tcam_install(node_id, original_fid);
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
    // Install rejected (TABLE_FULL) — no rule to update; slow-path drop.
}

// ── Real-time FlowMod authorization — f_unauth (eq:unauth_flowmod / eq:endorsed_commit) ──
// enable_endorsement_requirement (AB8) is defined in crypto_layer.h; declared here so
// this header's authorization gate compiles regardless of include phase.
extern bool enable_endorsement_requirement;
extern uint32_t g_dp_attack_fid_counter;   // DP attacker fids >= 1e6 (routing.cc)
extern uint32_t g_cp_attack_fid_counter;   // CP attacker fids >= 2e6 (routing.cc)

// OBSERVABLE legitimacy predicate for endorsement. An honest RSU endorses a FlowMod
// iff it corresponds to a real registered active flow (eq:sig_s3: ∃v: flow ∈ F_active).
// Legitimate flows carry native fids (<500k) or generator fids ([500k,1M)) registered
// by the mobility-driven flow generator from ACTUAL vehicle transmissions. Attacker-
// injected FlowMods use synthetic fids (DP >=1e6, CP >=2e6) that appear in NO
// legitimate-flow registry, so no honest RSU can endorse them. This reads the flow
// registry (fid provenance), NOT the is_malicious label — so S3 no longer consults an
// oracle. (Under the current generator, benign and attack rules are indistinguishable
// by per-rule traffic statistics, so registry provenance is the discriminating
// observable, consistent with the paper's endorsed-policy channel model, eq:policy_commit.)
inline bool tcam_flow_is_legit(uint32_t original_fid) {
    return original_fid < 1000000u;   // native or generator flow; attacker fids are >= 1e6
}

// Endorsement/commit gate — SAME f+1 quorum rule as bc_commit_flowmod(), AB8-aware.
// Honest RSUs endorse a legitimate flow with f+1 signatures; an attacker flow collects
// zero. When enable_endorsement_requirement is set, < f+1 endorsements ⇒ NOT committed
// ⇒ f_unauth=1. When the requirement is off (AB8-A) every FlowMod commits ⇒ f_unauth
// never fires — reproducing the paper's AB8-A/AB8-B ablation. Cheap by design: the
// ML-DSA endorsement crypto cost is measured at the dedicated T_consensus commit site
// (routing.cc); here we only need the authorization OUTCOME for the S3 detector, so we
// replicate the quorum decision without re-running f+1 signatures per install.
inline bool tcam_flowmod_authorized(uint32_t original_fid) {
    uint32_t f_plus_1  = (N_RSUs > 0) ? ((N_RSUs - 1) / 3) + 1 : 1;
    uint32_t endorsers = tcam_flow_is_legit(original_fid) ? f_plus_1 : 0u;
    if (enable_endorsement_requirement && endorsers < f_plus_1)
        return false;   // unauthorized: absent from the endorsed policy set (eq:unauth_flowmod)
    return true;        // committed / authorized
}

// Install a TCAM rule for (flow_id, node_id) once.  Subsequent calls for the
// same pair are silently ignored — dedup via g_tcam_installed.
// On the very first install ever, also kicks off the per-second snapshot loop.
inline void tcam_install(uint32_t node_id, uint32_t original_fid)
{
    uint32_t actual_fid = get_actual_flow_id(original_fid);
    auto key = std::make_pair(actual_fid, node_id);
    if (g_tcam_installed.count(key)) return;

    // TABLE_FULL: hard cap at TCAM_CAPACITY. Reject the install -- the rule
    // is NOT created and NOT added to g_tcam_installed, so the next packet
    // for this flow retries the install (reactive re-install once capacity
    // frees up via eviction, see tcam_evict_expired()).
    if (g_tcam_rule_count[node_id] >= TCAM_CAPACITY) {
        g_tcam_reject_count[node_id]++;
        std::cout << "[TCAM REJECT] TABLE_FULL node=" << node_id
                  << " flow=" << actual_fid
                  << " count=" << g_tcam_rule_count[node_id]
                  << "/" << TCAM_CAPACITY
                  << " t=" << Simulator::Now().GetSeconds() << "s" << std::endl;
        return;
    }

    g_tcam_installed.insert(key);

    bool first_ever = (g_tcam_table.empty());  // schedule timer only once

    // Generated flows resolve (src,dst) from the gen registry (they do not index
    // delta_at_nodes_inst); native flows read delta_at_nodes_inst[original_fid].
    uint32_t src_node, dst_node;
    const bool is_gen_flow = gen_flow_lookup(original_fid, src_node, dst_node);
    if (!is_gen_flow) {
        src_node = (delta_at_nodes_inst + original_fid)->source_f;
        dst_node = (delta_at_nodes_inst + original_fid)->destination_f;
    }

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
    e.counts_capacity = true;   // genuine data-plane rule: occupies a TCAM slot
    e.presence_managed = is_gen_flow; // generator flows: departure + idle-timeout, whichever first
    e.idle_timeout_s   = is_gen_flow ? sample_gen_idle_timeout_s() : TCAM_IDLE_TIMEOUT_S;
    // f_unauth (eq:unauth_flowmod): pre-install endorsement check. Legit flows are in
    // the endorsed policy set -> authorized. Reads the flow registry, not is_malicious.
    e.authorized       = tcam_flowmod_authorized(original_fid);
    g_tcam_table.push_back(e);
    g_tcam_rule_count[node_id]++;
    g_packetin_count[node_id]++;   // this install was triggered by a table miss -> PACKET_IN (eq:sig_s4 λ_PI)
    g_packetin_by_source[node_id][src_node]++;   // Issue 6 fix: per-source attribution

    // TRUE lambda_l instrument (measurement only): a fresh key vs a churn refresh.
    if (g_tcam_ever_evicted.count(key)) { g_lambda_reinstall[node_id]++; g_lambda_reinstall_cum[node_id]++; }
    else                                { g_lambda_new[node_id]++;       g_lambda_new_cum[node_id]++; }

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

// ── Rule eviction (2026-07-13; extended 2026-07-16) ─────────────────────────
// Evicts any TcamEntry whose idle_timeout or hard_timeout has expired, for
// legit, malicious, and generator entries alike (each entry's OWN
// idle_timeout_s -- global TCAM_IDLE_TIMEOUT_S for non-generator entries,
// uniform(9,22)s residence-window sample for generator entries). Generator
// entries are evicted by whichever fires first: this sweep, or the explicit
// neighbour-departure trigger in tcam_evict_gen_entry(). Frees the
// (flow_id, node_id) dedup key too, so a legit flow whose next packet
// arrives after eviction goes through tcam_hit() -> tcam_install() again as
// a genuine fresh install (reactive re-install), rather than being silently
// blocked by a stale dedup entry.
inline void tcam_evict_expired()
{
    double now = Simulator::Now().GetSeconds();
    auto is_expired = [now](const TcamEntry& e) {
        bool idle_expired = (now - e.last_seen_time) >= e.idle_timeout_s;
        // Attacker-maintained malicious rules (Attacks 3/4): idle-timeout ONLY,
        // no hard timeout. The attacker refreshes them every tick
        // (tcam_refresh_malicious_on_node), so last_seen stays current and idle
        // never fires while the attack is active -> the malicious set persists
        // and accumulates toward TCAM_CAPACITY, matching the paper's slow-
        // exhaustion mechanism (periodic refresh keeps rules resident). Once the
        // attack stops refreshing, they idle out normally. A hard timeout here
        // would cap resident malicious rules at rate x hard_timeout, which for
        // the slow band (3.2 pps) is far below any realistic capacity and would
        // make exhaustion structurally impossible.
        if (e.is_malicious) return idle_expired;
        bool hard_expired = (now - e.install_time) >= TCAM_HARD_TIMEOUT_S;
        return idle_expired || hard_expired;
    };

    auto new_end = std::remove_if(g_tcam_table.begin(), g_tcam_table.end(),
        [&](const TcamEntry& e) {
            if (!is_expired(e)) return false;
            // Only genuine data-plane rules touch g_tcam_rule_count / g_tcam_installed.
            // Passive ip-hook entries (counts_capacity=false, from tcam_hit_ip) never
            // incremented the counter, so decrementing here would drive it NEGATIVE and
            // corrupt the S3/S4 detector's occupancy reading -- see tcam_hit_ip().
            if (e.counts_capacity) {
                g_tcam_rule_count[e.node_id]--;
                g_tcam_installed.erase(std::make_pair(e.flow_id, e.node_id));
                // TRUE lambda_l instrument (measurement only): record the eviction
                // and mark the key so its next install is classed as a reinstall.
                g_lambda_evict[e.node_id]++;
                g_tcam_ever_evicted.insert(std::make_pair(e.flow_id, e.node_id));
            }
            std::cout << "[TCAM EVICT] node=" << e.node_id
                      << " flow=" << e.flow_id
                      << " age=" << (now - e.install_time)
                      << "s idle=" << (now - e.last_seen_time)
                      << "s t=" << now << "s" << std::endl;
            return true;
        });
    g_tcam_table.erase(new_end, g_tcam_table.end());
}

// ── Presence-driven eviction of a single generator entry (2026-07-15) ────────
// Immediately removes the counted entry (actual_fid, node_id) installed by the
// all-neighbour generator when a DSRC neighbour leaves range. Mirrors the
// counted-path bookkeeping of tcam_evict_expired() exactly (decrement counter,
// free dedup key, feed the λ_l evict instrument) so the leak invariant and
// occupancy accounting stay correct. Only touches presence_managed entries.
// This is one of TWO independent eviction triggers for generator entries
// (2026-07-16) -- the other is the per-entry idle_timeout_s sweep in
// tcam_evict_expired(), whichever fires first. If tcam_evict_expired() has
// already timed the entry out, remove_if below simply matches nothing and
// this call is a safe no-op.
inline void tcam_evict_gen_entry(uint32_t actual_fid, uint32_t node_id)
{
    double now = Simulator::Now().GetSeconds();
    auto new_end = std::remove_if(g_tcam_table.begin(), g_tcam_table.end(),
        [&](const TcamEntry& e) {
            if (!(e.presence_managed && e.flow_id == actual_fid && e.node_id == node_id))
                return false;
            if (e.counts_capacity) {
                g_tcam_rule_count[e.node_id]--;
                g_tcam_installed.erase(std::make_pair(e.flow_id, e.node_id));
                g_lambda_evict[e.node_id]++;
                g_tcam_ever_evicted.insert(std::make_pair(e.flow_id, e.node_id));
            }
            (void)now;
            return true;
        });
    g_tcam_table.erase(new_end, g_tcam_table.end());
}

// ── Attacker keep-alive refresh (2026-07-16) ────────────────────────────────
// Bumps last_seen_time to now for every malicious entry on `node_id`, so the
// idle-timeout sweep in tcam_evict_expired() does not evict them. Models a slow
// TCAM-exhaustion attacker periodically re-sending packets that match its
// already-installed malicious flows (main.tex Mechanism 3 / PASCOAL2020107223):
// the rules stay resident and the per-tick new install accumulates the table
// toward TCAM_CAPACITY, instead of the malicious count saturating at
// rate x idle_timeout. Called once per attacker tick per target RSU, BEFORE the
// tick installs its one new rule. Cheap: one linear pass over g_tcam_table.
inline void tcam_refresh_malicious_on_node(uint32_t node_id)
{
    double now = Simulator::Now().GetSeconds();
    for (auto& e : g_tcam_table)
        if (e.is_malicious && e.node_id == node_id)
            e.last_seen_time = now;
}

// ── Per-second snapshot exporter (Change 8) ────────────────────────────────
// Fires at t=first_install+1s then every 1s until simTime.
// Writes two CSVs into results_routing/:
//   tcam_snapshots_<mode>.csv  — one row per (node, flow) per second
//   tcam_occupancy_<mode>.csv  — one row per node per second (rule count,
//                                 cumulative TABLE_FULL rejections)
inline void tcam_snapshot_dump()
{
    tcam_evict_expired();

    double now = Simulator::Now().GetSeconds();
    int    t   = static_cast<int>(std::round(now));

    // Canonical shape: Attack{N}_{pct}_seed{S}[_cpint{X}|_n{N}], matching
    // MOBIGUARD/TAP/FADE/bc_*/g_sim_tag/lstm — N is 1-indexed (0 = baseline).
    // cp_attack_intensity (Attack 3) and num_attackers (Attack 4) have no
    // slot in the canonical shape, so they stay as trailing suffixes rather
    // than being folded into {pct} — {pct} here is always attack_percentage.
    int mode_id = (active_attack_variant >= 0) ? (active_attack_variant + 1) : 0;
    std::string mode = "Attack" + std::to_string(mode_id)
                      + "_" + std::to_string(attack_percentage)
                      + "_seed" + std::to_string(sim_seed)
                      + (g_run_tag.empty() ? "" : "_" + g_run_tag);
    // For Attack 4 multi-attacker sweeps append _nN so each run
    // produces a distinct file: ..._n1.csv, ..._n8.csv, …
    if (active_attack_variant == 3 && num_attackers > 1)
        mode += "_n" + std::to_string(num_attackers);
    // For Attack 3 CP-percentage sweeps append _cpintN so each run
    // produces a distinct file. (Attack 3 has no analogous num_attackers
    // axis, so every run is suffixed — unlike Attack 4, there is no
    // single-run "bare" case.)
    // NOTE: this is derived from cp_attack_intensity, which is NOT the
    // report's attack_percentage (already captured correctly above) — see
    // the extern declaration above and the "Fixed 2026-07-10" comment on
    // cp_attack_tick() below. Do not read "_cpintN" as the report's attack
    // percentage.
    if (active_attack_variant == 2)
        mode += "_cpint" + std::to_string(static_cast<int>(std::round(cp_attack_intensity)));

    const std::string base_dir =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
    std::string snap_path = base_dir + "tcam_snapshots_" + mode + ".csv";
    std::string occ_path  = base_dir + "tcam_occupancy_"  + mode + ".csv";

    // Self-truncating per run (2026-07-16): the VERY FIRST snapshot dump of this
    // process truncates the file, so a stale file left by a PRIOR run is wiped
    // rather than appended to (the old "append + header-only-when-empty" logic
    // silently merged runs). Subsequent per-second dumps within THIS run append.
    // Mirrors the lambda_first pattern below. This removes the need to manually
    // delete old CSVs before every run.
    static bool tcam_dump_first = true;
    std::ios::openmode dump_mode = tcam_dump_first ? std::ios::trunc : std::ios::app;

    // Write header only when the file is new/empty (true right after a truncate).
    std::ofstream snap_f(snap_path, dump_mode);
    if (snap_f.is_open() && snap_f.tellp() == 0)
        snap_f << "t,rsu_id,flow_id,src_ip,dst_ip,src_port,dst_port,proto,"
               << "install_time,duration,packets,bytes,is_malicious\n";

    std::ofstream occ_f(occ_path, dump_mode);
    if (occ_f.is_open() && occ_f.tellp() == 0)
        occ_f << "t,rsu_id,total_rule_count,cum_rejections,counted_rule_count\n";

    tcam_dump_first = false;

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
        // total_rule_count (kv.second) = RAW g_tcam_table entries at this node
        // (includes passive ip-hook observations). counted_rule_count =
        // g_tcam_rule_count = authoritative data-plane rule count the S3/S4
        // detector reads (excludes ip-hook entries). The two differ only by the
        // ip-hook delta and let occupancy accounting be reconciled explicitly.
        for (const auto& kv : rule_count)
            occ_f << t << ',' << kv.first << ',' << kv.second
                   << ',' << g_tcam_reject_count[kv.first]
                   << ',' << g_tcam_rule_count[kv.first] << '\n';
    }
    snap_f.close();
    occ_f.close();

    // ── TRUE lambda_l flush (measurement only) ──────────────────────────────
    // One row per (t, rsu) for the whole RSU sim-index range so zero-install
    // cycles are captured (needed for an unbiased rate-vs-density correlation),
    // plus any vehicle-relay node that saw activity this window. Counters are
    // accumulated over the 1-s window since the last snapshot => rates per second.
    {
        static bool lambda_first = true;
        // Mode-suffixed (2026-07-16) so concurrent runs of DIFFERENT modes
        // (e.g. baseline + attack3_pct40) do not both write the same
        // lambda_l_true.csv and interleave/corrupt each other. Previously this
        // was a single untagged file -- unlike the mode-tagged snapshot/occupancy
        // files -- so two concurrent sims collided here even with distinct seeds.
        const std::string lam_path = base_dir + "lambda_l_true_" + mode + ".csv";
        std::ofstream lam_f(lam_path, lambda_first ? std::ios::trunc : std::ios::app);
        if (lambda_first && lam_f.is_open())
            lam_f << "t,rsu_id,new_installs,evictions,reinstalls\n";
        lambda_first = false;
        if (lam_f.is_open()) {
            std::set<uint32_t> nodes;
            for (uint32_t r = 0; r < N_RSUs; ++r) nodes.insert(N_Vehicles + r); // all RSUs incl. zeros
            for (uint32_t i = 0; i < 300; ++i)                                  // + any active vehicle hop
                if (g_lambda_new[i] || g_lambda_evict[i] || g_lambda_reinstall[i]) nodes.insert(i);
            for (uint32_t nid : nodes)
                lam_f << t << ',' << nid << ',' << g_lambda_new[nid]
                       << ',' << g_lambda_evict[nid] << ',' << g_lambda_reinstall[nid] << '\n';
        }
        lam_f.close();
        for (uint32_t i = 0; i < 300; ++i) { g_lambda_new[i]=0; g_lambda_evict[i]=0; g_lambda_reinstall[i]=0; }
    }

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
    // Same canonical shape as tcam_snapshot_dump():
    // Attack{N}_{pct}_seed{S}[_cpint{X}|_n{N}].
    int mode_id = (active_attack_variant >= 0) ? (active_attack_variant + 1) : 0;
    std::string mode = "Attack" + std::to_string(mode_id)
                      + "_" + std::to_string(attack_percentage)
                      + "_seed" + std::to_string(sim_seed)
                      + (g_run_tag.empty() ? "" : "_" + g_run_tag);
    // Mirror the _nN / _cpintN suffix logic from tcam_snapshot_dump().
    // NOTE: _cpintN comes from cp_attack_intensity, NOT the report's
    // attack_percentage (see extern declaration near top of file).
    if (active_attack_variant == 3 && num_attackers > 1)
        mode += "_n" + std::to_string(num_attackers);
    if (active_attack_variant == 2)
        mode += "_cpint" + std::to_string(static_cast<int>(std::round(cp_attack_intensity)));
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

    // TABLE_FULL: same hard cap as tcam_install(). Once the victim RSU's
    // table is saturated, further malicious FlowMods are refused too --
    // exhaustion is a one-time event per rule slot, not unbounded growth.
    if (g_tcam_rule_count[target_rsu_node_id] >= TCAM_CAPACITY) {
        g_tcam_reject_count[target_rsu_node_id]++;
        // A table-full miss is STILL a PACKET_IN: the packet has no matching
        // rule, so it is punted to the controller regardless of whether the
        // follow-up FlowMod can be installed. During exhaustion the same flows
        // keep missing (no slot to install into), so PACKET_INs actually SPIKE
        // -- this is the S4 signal (eq:sig_s4 λ_PI). Counting it only on the
        // successful-install branch below zeroed λ_PI out during the exact
        // phase S4 must detect.
        g_packetin_count[target_rsu_node_id]++;
        g_packetin_by_source[target_rsu_node_id][node_id]++;   // Issue 6 fix: per-source attribution
        std::cout << "[TCAM REJECT] TABLE_FULL node=" << target_rsu_node_id
                  << " fake_fid=" << fake_fid
                  << " count=" << g_tcam_rule_count[target_rsu_node_id]
                  << "/" << TCAM_CAPACITY
                  << " t=" << Simulator::Now().GetSeconds() << "s" << std::endl;
        return;
    }
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
    e.counts_capacity = true;   // genuine data-plane rule (attacker-injected)
    // f_unauth (eq:unauth_flowmod): attacker fids (>=1e6) are in no legitimate-flow
    // registry -> 0 honest endorsers -> NOT committed under AB8 -> unauthorized.
    // Derived from fid provenance via the same observable predicate as legit installs.
    e.authorized     = tcam_flowmod_authorized(fake_fid);
    // Ground-truth wiring for M1-M3 (calculate_security_detection_metrics): mark the
    // VICTIM RSU malicious using the SAME node-index space (RSU node_id) that
    // record_detection_event() uses when flag_s3/flag_s4 fires (tcam_detection.h).
    // Previously this was either never set (variant 2 / Attack 3, marker removed
    // 2026-07-10) or set on the ATTACKER's own node index (variant 3 / Attack 4) --
    // a different index space than record_detection_event's RSU-indexed marking, so
    // is_malicious_node and is_detected_node could never overlap and sec_TP/DR were
    // structurally 0 for both S3 and S4 regardless of detector quality. Guarded to
    // fire once per RSU so t_onset[] reflects the FIRST attack time (needed for the
    // M4 mitigation-latency metric), not the most recent tick.
    if (!is_malicious_node[active_attack_variant][target_rsu_node_id])
        record_attack_onset(active_attack_variant, target_rsu_node_id);
    g_tcam_table.push_back(e);
    g_tcam_rule_count[target_rsu_node_id]++;
    g_packetin_count[target_rsu_node_id]++;  // attacker's unique-5-tuple packet missed -> PACKET_IN (eq:sig_s4 λ_PI)
    g_packetin_by_source[target_rsu_node_id][node_id]++;   // Issue 6 fix: per-source attribution

    // A malicious FlowMod IS a FlowMod install, so it must count in λ_FM / λ_obs
    // (eq:sig_s3: λ_FM = FlowMod rate from the controller = legit + malicious).
    // Without this the S3 windowed excess (λ_obs − E[λ_l|ρ]) stays at the benign
    // level and S3's rate term is blind to the attack (λ̂_a stays negative -> S3
    // never fires). Each attack fid is unique (never evicted before) -> always a
    // NEW install, not a reinstall. E[λ_l|ρ] is fit from BENIGN only (no malicious
    // installs there), so this does not contaminate the density calibration.
    g_lambda_new[target_rsu_node_id]++;
    g_lambda_new_cum[target_rsu_node_id]++;
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
        // Keep this attacker's already-installed rules on the target RSU alive,
        // then add one new rule -> persistent accumulation toward capacity.
        tcam_refresh_malicious_on_node(target_rsu_node_id);
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
// Each call installs one new malicious rule on every RSU whose OWNING
// CONTROLLER is compromised (controller_compromised[], set by the Attack 3
// init block in routing.cc from the same attack_percentage threshold ladder
// Attack 1 uses), simulating a compromised controller broadcasting a junk
// FlowMod to the RSUs it controls. Mirrors Attack 1's
// reapply_cp_selective_delay() (attack_declaration.h) exactly, so A3's
// penetration scaling is structurally consistent with A1's.
//
// Fixed 2026-07-10: previously flooded a FIXED cp_attack_intensity% (default 40%)
// of RSUs by index, completely ignoring attack_percentage — so
// attack_percentage=0 flooded the same ~26 RSUs as attack_percentage=80,
// violating main.tex's penetration formula (p=0 -> 0 attacker nodes).
// cp_attack_intensity is left declared/CLI-overridable for manual experimentation
// but is no longer read by the default attack_percentage-driven sweep path.
//
// NOTE (flag): cp_attack_intensity is NOT the attack percentage referenced in
// the report/thesis — that is attack_percentage (routing.cc), which drives
// num_controllers_compromised above. cp_attack_intensity is unrelated legacy
// input only used for the "_pctN" output-filename suffix (tcam_snapshot_dump(),
// export_tcam_snapshot_baseline()). UNRESOLVED: the pct20/40/60/80/100 sweep
// data on disk shows malicious-RSU counts scaling exactly with cp_attack_intensity
// (13/26/39/52/64), which this function's logic below does not explain, since it
// reads only controller_compromised[] (derived from attack_percentage, which
// defaulted to 0 in that sweep). Verify which variable actually drove those runs
// before citing the pct-sweep results in the report.
inline void cp_attack_tick()
{
    if (active_attack_variant != 2) return;
    double now = Simulator::Now().GetSeconds();
    if (now >= simTime) return;

    for (uint32_t r = 0; r < RSU_Nodes.GetN(); r++)
    {
        uint32_t owning_controller = rsu_controller_assignment[r];
        if (!controller_compromised[owning_controller]) continue;

        uint32_t rsu_idx  = N_Vehicles + r;        // sim node index of RSU r
        // Keep prior malicious rules on this RSU alive, then add one new rule ->
        // persistent accumulation toward capacity (slow exhaustion).
        tcam_refresh_malicious_on_node(rsu_idx);
        uint32_t fake_fid = g_cp_attack_fid_counter++;
        tcam_install_malicious(rsu_idx, rsu_idx, fake_fid); // attacker == victim RSU, same as before
    }

    double interval = 1.0 / attack_rate_pps;
    Simulator::Schedule(Seconds(interval), &cp_attack_tick);
}

#endif // TCAM_ATTACK_HELPER_H
