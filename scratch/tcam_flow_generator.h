#ifndef TCAM_FLOW_GENERATOR_H
#define TCAM_FLOW_GENERATOR_H

// ===========================================================================
// tcam_flow_generator.h — all-neighbour, presence-driven concurrency generator
// 2026-07-15 (supervisor redesign; replaces the k=2 / timeout-churn version)
//
// Purpose: make per-RSU TCAM occupancy track REAL vehicle density by having each
// active in-zone vehicle hold a live unicast flow to EVERY one-hop DSRC neighbour,
// for exactly as long as that neighbour stays in range.
//
// REDESIGN vs the old k=2 version:
//   * 100 ms poll/diff period (was 1 s).
//   * ALL one-hop neighbours (linklifetimeMatrix_dsrc[v][w] > 0) — the k-nearest
//     cap is GONE.
//   * PRESENCE-DRIVEN eviction: when a neighbour leaves range the flow is evicted
//     IMMEDIATELY (tcam_evict_gen_entry). These flows are EXEMPT from the idle/hard
//     timeout (TcamEntry.presence_managed=true; tcam_evict_expired skips them).
//   * Install stays REACTIVE on neighbour appearance, via the SAME counted/capped
//     path as all traffic: tcam_hit() -> tcam_install() (counts_capacity=true,
//     increments g_tcam_rule_count, respects TABLE_FULL). No entry is pushed into
//     g_tcam_table by any other route, so the per-node
//     (total_rule_count - counted_rule_count) <= 1 leak invariant holds.
//
// Mechanism each 100 ms tick: for every vehicle v, build its CURRENT one-hop
// neighbour set from linklifetimeMatrix_dsrc[v] and diff it against v's set from
// the previous tick:
//     appeared (cur \ prev)  -> install flow (v -> w)
//     departed (prev \ cur)  -> evict   flow (v -> w)   [immediate]
//     unchanged              -> no action
// A vehicle that goes inactive (speed < MIN_SPEED) has an empty current set, so
// all of its flows are evicted — presence falls out of the same diff.
//
// NOTE on data granularity: linklifetimeMatrix_dsrc is refreshed once per SIM
// CYCLE (~1 s), so although we POLL every 100 ms the neighbour membership is
// piecewise-constant per second; appear/depart events therefore land at cycle
// boundaries. The 100 ms period is honoured as instructed; effective event
// granularity is bounded by the 1 s matrix refresh, not the poll.
//
// TWO DELIBERATE DEVIATIONS (preserved from the prior design, both required):
//   (D1) find_next_hop() returns a FIXED relay RSU for every V2V flow, which would
//        pile all occupancy on one RSU. The relay is instead each vehicle's REAL
//        associated RSU via lookup_vehicle_associated_rsu_local_idx() (lrad.h),
//        preserving arch-3 (vehicle -> its RSU -> neighbour) and per-RSU density.
//   (D2) S1/S2 sampling lives in the fid-indexed forward path this lighter path
//        avoids; we call the REAL s1_detect_packet() directly for the relay hop
//        with a benign delay so S1/S2 still get a real population.
//
// STATE-STRUCTURE NOTE (Task 4): maintaining a per-vehicle previous-neighbour set
// at 100 ms x 200 vehicles is cheap with a FULL diff each tick — the neighbour
// scan is O(N_Vehicles^2) = 200*200 = 40k matrix reads/tick x 10 ticks/s = 400k
// reads/s, plus small std::set ops on ~tens of entries. That is negligible beside
// the per-packet ML-DSA-87 crypto that dominates runtime, so NO incremental
// adjacency structure is needed; a full rebuild+diff is used for clarity.
// ===========================================================================

#include <algorithm>
#include <vector>
#include <set>
#include <map>
#include <cmath>
#include <functional>
#include <utility>

// ── externs from routing.cc / other headers (all defined before this include) ─
extern std::vector<std::vector<double>> linklifetimeMatrix_dsrc;
extern uint32_t N_Vehicles;
extern uint32_t N_RSUs;
extern double   simTime;
struct routing_data_at_nodes;                 // fwd (full def in routing.cc)
extern struct routing_data_at_nodes routing_data_at_nodes_inst[];
// tcam_hit(), get_actual_flow_id(), tcam_evict_gen_entry(), g_gen_flow_endpoints,
// TCAM_GEN_FID_BASE  -> tcam_attack_helper.h
// lookup_vehicle_associated_rsu_local_idx()  -> lrad.h
// s1_detect_packet()                          -> s1_detection.h

// ── tunable config ───────────────────────────────────────────────────────────
static double   TCAM_GEN_PERIOD_S          = 0.100; // 100 ms poll/diff period
static double   TCAM_GEN_SAFETY_FRACTION   = 0.30;  // seeded fraction tagged safety-critical
static double   TCAM_GEN_MIN_SPEED         = 0.10;  // m/s; active/entered gate
static double   TCAM_GEN_WARMUP_S          = 30.0;  // no flows before all 200 present+moving
static uint32_t TCAM_GEN_PKT_BYTES         = 750;   // nominal packet size
static double   TCAM_GEN_BENIGN_HOP_DELAY  = 0.0015;// ~1.5 ms benign relay hop delay for S1

// ── generator state ──────────────────────────────────────────────────────────
// Previous-tick one-hop neighbour set per vehicle (the diff baseline).
static std::vector<std::set<uint32_t>> g_gen_prev_neigh;
// Live flows: (src_vehicle, neighbour) -> (actual_fid, relay_rsu_node) so a
// departure can evict exactly the entries that were installed.
static std::map<std::pair<uint32_t,uint32_t>, std::pair<uint32_t,uint32_t>> g_gen_active;

// Deterministic, seeded safety-critical decision per (src,dst).
inline static bool tcam_gen_is_safety_critical(uint32_t s, uint32_t d) {
    std::size_t h = std::hash<uint64_t>{}(((uint64_t)s << 20) ^ (uint64_t)d);
    return ((double)(h % 1000) / 1000.0) < TCAM_GEN_SAFETY_FRACTION;
}

// Install a counted/capped, presence-managed flow (v -> nb) along v -> its RSU -> nb.
inline void tcam_gen_install_flow(uint32_t v, uint32_t nb, uint32_t gen_fid, bool sc)
{
    uint32_t rsu_local = lookup_vehicle_associated_rsu_local_idx(v);
    if (rsu_local >= N_RSUs) return; // v out of range of any RSU -> cannot relay; skip
    uint32_t rsu_node = N_Vehicles + rsu_local;

    // Register (src,dst) so get_actual_flow_id()/tcam_install() resolve identity.
    g_gen_flow_endpoints[gen_fid] = std::make_pair(v, nb);
    uint32_t actual_fid = get_actual_flow_id(gen_fid); // stable per (v,nb)

    // Same counted/capped path as all traffic: tcam_hit -> tcam_install.
    tcam_hit(v,        gen_fid, TCAM_GEN_PKT_BYTES); // source vehicle forwards
    tcam_hit(rsu_node, gen_fid, TCAM_GEN_PKT_BYTES); // RSU relay forwards (density-tracking)

    // (D2) real S1 sample for the relay RSU hop.
    s1_detect_packet(rsu_local, TCAM_GEN_BENIGN_HOP_DELAY, sc,
                     /*sender*/ v, /*current_hop*/ rsu_node,
                     /*packet_id*/ 0, /*flow_id*/ gen_fid & 0xFFFFu);

    // Remember install locations for presence-driven eviction on departure.
    g_gen_active[std::make_pair(v, nb)] = std::make_pair(actual_fid, rsu_node);
}

// Presence-driven eviction: neighbour nb left v's range -> remove its two entries.
inline void tcam_gen_evict_flow(uint32_t v, uint32_t nb)
{
    auto it = g_gen_active.find(std::make_pair(v, nb));
    if (it == g_gen_active.end()) return;
    uint32_t actual_fid = it->second.first;
    uint32_t rsu_node   = it->second.second;
    tcam_evict_gen_entry(actual_fid, v);        // source-vehicle hop
    tcam_evict_gen_entry(actual_fid, rsu_node); // relay-RSU hop (the density-tracking one)
    g_gen_active.erase(it);
}

// Per-100 ms tick: diff each vehicle's current one-hop neighbour set vs previous.
inline void tcam_flow_generator_tick()
{
    double now = ns3::Simulator::Now().GetSeconds();

    // Keep the 100 ms chain alive across warmup and for the whole run.
    if (now + TCAM_GEN_PERIOD_S <= simTime + 1e-9)
        ns3::Simulator::Schedule(ns3::Seconds(TCAM_GEN_PERIOD_S), &tcam_flow_generator_tick);

    if (now < TCAM_GEN_WARMUP_S) return; // respect warmup

    if (g_gen_prev_neigh.size() < N_Vehicles) g_gen_prev_neigh.resize(N_Vehicles);

    // gen-fids are transient per tick — only APPEARED neighbours install this tick,
    // so a fresh disposable id per appearance is enough (identity of a persistent
    // pair is carried by the stable actual_fid + g_gen_active, not by the gen-fid).
    g_gen_flow_endpoints.clear();
    uint32_t gen_fid = TCAM_GEN_FID_BASE;

    uint32_t n_active = 0, n_appeared = 0, n_departed = 0, n_sc = 0;

    for (uint32_t v = 0; v < N_Vehicles; ++v)
    {
        // Build v's CURRENT one-hop neighbour set (empty if inactive/out of range).
        std::set<uint32_t> cur;
        ns3::Vector vel = (routing_data_at_nodes_inst + v)->velocity;
        double speed = std::sqrt(vel.x * vel.x + vel.y * vel.y);
        bool active = (speed >= TCAM_GEN_MIN_SPEED) && (v < linklifetimeMatrix_dsrc.size());
        if (active)
        {
            const std::vector<double>& row = linklifetimeMatrix_dsrc[v];
            for (uint32_t w = 0; w < N_Vehicles; ++w)
                if (w != v && w < row.size() && row[w] > 0.0)
                    cur.insert(w);
            if (!cur.empty()) ++n_active;
        }

        std::set<uint32_t>& prev = g_gen_prev_neigh[v];

        // appeared = cur \ prev  -> install
        for (uint32_t w : cur)
            if (prev.find(w) == prev.end())
            {
                bool sc = tcam_gen_is_safety_critical(v, w);
                tcam_gen_install_flow(v, w, gen_fid++, sc);
                ++n_appeared; if (sc) ++n_sc;
            }
        // departed = prev \ cur  -> evict immediately
        for (uint32_t w : prev)
            if (cur.find(w) == cur.end())
            {
                tcam_gen_evict_flow(v, w);
                ++n_departed;
            }

        prev = std::move(cur);
    }

    // Log every tick past warmup so the 100 ms event rate is measurable.
    std::cout << "[GEN] t=" << now << "s active_veh=" << n_active
              << " appeared=" << n_appeared << " departed=" << n_departed
              << " live_flows=" << g_gen_active.size()
              << " sc=" << n_sc << " (all-neigh,100ms)" << std::endl;
}

#endif // TCAM_FLOW_GENERATOR_H
