#ifndef TCAM_FLOW_GENERATOR_H
#define TCAM_FLOW_GENERATOR_H

// ===========================================================================
// tcam_flow_generator.h — k-nearest-neighbour concurrency flow generator (1b)
// 2026-07-14
//
// Purpose: the benign data plane sustains only ~2 concurrent flows (flows=1),
// so per-RSU TCAM occupancy is ~2/256 despite real vehicle density. This
// generator makes each active in-zone vehicle open short-lived unicast data
// flows to its k nearest DSRC neighbours, so per-RSU CONCURRENT occupancy rises
// and TRACKS vehicle density.
//
// Design (the "lighter path", option 1b — agreed after finding the full
// check_and_transmit path is bound to ~25 fid-indexed fixed arrays):
//   * Reuses the SAME counted/capped install as all other traffic:
//     tcam_hit() -> tcam_install() (counts_capacity=true, increments
//     g_tcam_rule_count, respects TABLE_FULL, evicted by tcam_evict_expired).
//     Generated flows get distinct identities via the gen-fid registry in
//     tcam_attack_helper.h WITHOUT growing the `flows` constant or any wire
//     format. Nothing is pushed into g_tcam_table by any other route, so the
//     per-node (total_rule_count - counted_rule_count) <= 1 leak invariant holds.
//   * Neighbour set comes DIRECTLY from linklifetimeMatrix_dsrc[v] (vehicles
//     within 270 m of vehicle v), NOT per-RSU-cell membership.
//   * Short-lived + re-selected every cycle against that cycle's fresh
//     linklifetimeMatrix_dsrc, so flows churn with mobility (existing idle/hard
//     timeout evicts stale ones).
//
// TWO DELIBERATE DEVIATIONS from a literal "route through find_next_hop" (both
// required for the density-tracking goal; documented for review):
//   (D1) find_next_hop() returns a FIXED relay RSU (node N_Vehicles, i.e. RSU 0)
//        for EVERY vehicle->vehicle flow (routing.cc ~94601). Using it literally
//        would pile ALL generated occupancy on one RSU and NOT track per-RSU
//        density. So the relay is each vehicle's REAL associated RSU via
//        lookup_vehicle_associated_rsu_local_idx() (lrad.h) — the same
//        association real per-vehicle escalation / DP-attack routing use. The
//        arch-3 semantics (vehicle -> its RSU -> neighbour) are preserved; only
//        the "which RSU" simplification in find_next_hop is corrected.
//   (D2) S1/S2 sampling lives inside the fid-indexed forward path, which this
//        lighter generator intentionally avoids. To still give S1/S2 a real
//        population we call the REAL s1_detect_packet() directly for the relay
//        RSU hop with a benign hop-delay, tagged safety-critical for a seeded
//        fraction of generated flows.
//
// Invoked once per cycle from routing.cc via a single Simulator::Schedule line.
// ===========================================================================

#include <algorithm>
#include <vector>
#include <cmath>
#include <functional>

// ── externs from routing.cc / other headers (all defined before this include) ─
extern std::vector<std::vector<double>> linklifetimeMatrix_dsrc;
extern uint32_t N_Vehicles;
extern uint32_t N_RSUs;
struct routing_data_at_nodes;                 // fwd (full def in routing.cc)
extern struct routing_data_at_nodes routing_data_at_nodes_inst[];
// tcam_hit(), g_gen_flow_endpoints, TCAM_GEN_FID_BASE  -> tcam_attack_helper.h
// lookup_vehicle_associated_rsu_local_idx()            -> lrad.h
// s1_detect_packet()                                   -> s1_detection.h

// ── tunable config (compile-time; CLI hooks are a one-liner each if wanted) ──
static uint32_t TCAM_GEN_K                 = 2;    // k nearest DSRC neighbours (default low on purpose)
static double   TCAM_GEN_SAFETY_FRACTION   = 0.30; // fraction of generated flows tagged safety-critical (S1/S2)
static double   TCAM_GEN_MIN_SPEED         = 0.10; // m/s; "active/entered" gate (excludes stationary pre-entry nodes)
static double   TCAM_GEN_WARMUP_S          = 30.0; // no generated flows before all 200 vehicles are present+moving
static uint32_t TCAM_GEN_PKT_BYTES         = 750;  // nominal packet size, consistent with benign traffic
static double   TCAM_GEN_BENIGN_HOP_DELAY  = 0.0015; // ~1.5 ms benign relay hop delay fed to S1 (< S1 threshold)

// Deterministic, seeded safety-critical decision per (src,dst) — reproducible
// across runs, independent of iteration order.
inline static bool tcam_gen_is_safety_critical(uint32_t s, uint32_t d) {
    std::size_t h = std::hash<uint64_t>{}(((uint64_t)s << 20) ^ (uint64_t)d);
    return ((double)(h % 1000) / 1000.0) < TCAM_GEN_SAFETY_FRACTION;
}

// Install a counted/capped rule for flow (v -> nb) along the arch-3 relay path
// v -> associated RSU -> nb. Installs at the two FORWARDING hops (source vehicle
// and relay RSU) exactly like existing traffic; the RSU install is the
// density-tracking one. Feeds S1 for the relay-RSU hop.
inline void tcam_gen_install_flow(uint32_t v, uint32_t nb,
                                  uint32_t gen_fid, bool safety_crit)
{
    uint32_t rsu_local = lookup_vehicle_associated_rsu_local_idx(v);
    if (rsu_local >= N_RSUs) return; // v currently out of DSRC range of any RSU -> skip (same as escalate_to_rsu)
    uint32_t rsu_node = N_Vehicles + rsu_local;

    // Register (src,dst) so get_actual_flow_id()/tcam_install() resolve identity
    // for this gen-fid (it does NOT index delta_at_nodes_inst).
    g_gen_flow_endpoints[gen_fid] = std::make_pair(v, nb);

    // Same counted/capped path as all traffic: tcam_hit -> tcam_install.
    tcam_hit(v,        gen_fid, TCAM_GEN_PKT_BYTES); // source vehicle forwards
    tcam_hit(rsu_node, gen_fid, TCAM_GEN_PKT_BYTES); // RSU relay forwards (density-tracking install)

    // (D2) feed the REAL S1 detector for the relay RSU hop so S1/S2 get a real
    // population; benign delay stays under threshold (no false fire expected).
    s1_detect_packet(rsu_local, TCAM_GEN_BENIGN_HOP_DELAY, safety_crit,
                     /*sender*/ v, /*current_hop*/ rsu_node,
                     /*packet_id*/ 0, /*flow_id*/ gen_fid & 0xFFFFu);
}

// Per-cycle tick: for every active vehicle, open flows to its k nearest DSRC
// neighbours. Called from routing.cc after linklifetimeMatrix_dsrc is refreshed.
inline void tcam_flow_generator_tick()
{
    double now = ns3::Simulator::Now().GetSeconds();
    if (now < TCAM_GEN_WARMUP_S) return; // respect warmup

    // gen-fids are transient per tick; identity persists across cycles via the
    // (src,dst)->sequential-id map inside get_actual_flow_id (so a stable
    // neighbour pair refreshes its existing TCAM entry instead of duplicating).
    g_gen_flow_endpoints.clear();
    uint32_t gen_fid = TCAM_GEN_FID_BASE;

    uint32_t n_active = 0, n_flows = 0, n_sc = 0;

    for (uint32_t v = 0; v < N_Vehicles; ++v)
    {
        // active/entered gate: a stationary pre-entry node has ~0 velocity.
        ns3::Vector vel = (routing_data_at_nodes_inst + v)->velocity;
        double speed = std::sqrt(vel.x * vel.x + vel.y * vel.y);
        if (speed < TCAM_GEN_MIN_SPEED) continue;
        if (v >= linklifetimeMatrix_dsrc.size()) continue;

        // neighbours = other VEHICLES within 270 m (linklifetimeMatrix_dsrc[v][w] > 0).
        // k nearest ~ k highest link-lifetime (closer/more-stable proxy, same
        // ordering lookup_vehicle_associated_rsu_local_idx uses).
        std::vector<std::pair<double,uint32_t>> neigh;
        for (uint32_t w = 0; w < N_Vehicles; ++w)
        {
            if (w == v) continue;
            if (w < linklifetimeMatrix_dsrc[v].size() &&
                linklifetimeMatrix_dsrc[v][w] > 0.0)
                neigh.push_back(std::make_pair(linklifetimeMatrix_dsrc[v][w], w));
        }
        if (neigh.empty()) continue;
        ++n_active;

        uint32_t kk = std::min((size_t)TCAM_GEN_K, neigh.size());
        std::partial_sort(neigh.begin(), neigh.begin() + kk, neigh.end(),
                          std::greater<std::pair<double,uint32_t>>());
        for (uint32_t i = 0; i < kk; ++i)
        {
            uint32_t nb = neigh[i].second;
            bool sc = tcam_gen_is_safety_critical(v, nb);
            tcam_gen_install_flow(v, nb, gen_fid++, sc);
            ++n_flows; if (sc) ++n_sc;
        }
    }

    std::cout << "[GEN] t=" << now << "s active_vehicles=" << n_active
              << " flows=" << n_flows << " safety_critical=" << n_sc
              << " (k=" << TCAM_GEN_K << ")" << std::endl;
}

#endif // TCAM_FLOW_GENERATOR_H
