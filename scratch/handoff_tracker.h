#ifndef HANDOFF_TRACKER_H
#define HANDOFF_TRACKER_H

// =========================================================================
// handoff_tracker.h — Per-vehicle serving-RSU handoff detection
//
// Mobility Amplification Fix Plan §4.1
// (docs/MOBILITY_AMPLIFICATION_FIX_PLAN.md). Tracks which RSU each vehicle
// was associated with on the previous cycle and flags a "handoff" whenever
// that association changes -- the missing executable counterpart to the
// "handoff"/"zone-cross" concept that, before this file, existed only in
// comments (main.tex Mechanism 1, ~L1524: "legitimate handoff latencies of
// 50-300 ms during flow-rule recomputation and reinstallation").
//
// This header does NOT decide which RSU is "nearest" -- that is already
// computed elsewhere (lookup_vehicle_associated_rsu_local_idx() in lrad.h
// selects the RSU with the strongest current DSRC link).
// handoff_tracker_update() just takes whatever RSU index the caller
// currently considers a vehicle associated with, and reports whether it
// changed since the last call for that vehicle. Keeping this header
// decoupled from linklifetimeMatrix_dsrc/lrad.h means it only depends on
// N_Vehicles, so it can be included early -- same position as
// s1_detection.h/s2_detection.h -- regardless of where the RSU-association
// logic feeding it happens to live in the file.
//
// DESIGN NOTE:
//   Reads N_Vehicles directly (no extern), same convention as
//   s1_detection.h/s2_detection.h: this header must be included after
//   N_Vehicles is declared in routing.cc (declared near the top of the
//   file, long before any detection header is included).
// =========================================================================

#include <cstdint>
#include <vector>

// Sentinel meaning "no cycle observed yet for this vehicle" -- distinct
// from any real RSU index (0..N_RSUs-1) and from whatever "no RSU in
// range" sentinel a caller's association logic uses (e.g. lrad.h's
// lookup_vehicle_associated_rsu_local_idx() returns N_RSUs for that case).
// Using UINT32_MAX here means a vehicle's very first observed cycle is
// never spuriously reported as a handoff.
const uint32_t HANDOFF_TRACKER_UNSEEN = UINT32_MAX;

// Per-vehicle state, indexed by vehicle_id (0..N_Vehicles-1). Sized by
// handoff_tracker_init_state(); NOT resized lazily inside
// handoff_tracker_update() so a caller passing an out-of-range vehicle_id
// is a no-op instead of silently growing state.
std::vector<uint32_t> g_handoff_prev_rsu;      // serving RSU as of the last update
std::vector<bool>     g_handoff_just_occurred; // true only for the cycle the change was detected
std::vector<uint32_t> g_handoff_cycles_since;  // cycles elapsed since this vehicle's last handoff

// =========================================================================
// handoff_tracker_init_state():
// Allocates and initialises per-vehicle handoff state to exactly
// n_vehicles entries. Must be called once (from
// initialise_stub_attack_state() in routing.cc, alongside s1_init_state())
// before any handoff_tracker_update() call. All vehicles start at
// HANDOFF_TRACKER_UNSEEN so the first cycle each vehicle is observed never
// counts as a handoff.
// =========================================================================
inline void handoff_tracker_init_state(uint32_t n_vehicles)
{
    g_handoff_prev_rsu.assign(n_vehicles, HANDOFF_TRACKER_UNSEEN);
    g_handoff_just_occurred.assign(n_vehicles, false);
    g_handoff_cycles_since.assign(n_vehicles, 0);
}

// =========================================================================
// handoff_tracker_update():
// Call once per vehicle per simulation cycle with that vehicle's current
// serving-RSU index (whatever the caller's association logic returns --
// e.g. lookup_vehicle_associated_rsu_local_idx(vehicle_id) from lrad.h).
// Diffs against the value stored from the previous cycle: a change flags
// a handoff event for this cycle and resets the cycles-since counter.
// =========================================================================
inline void handoff_tracker_update(uint32_t vehicle_id, uint32_t current_rsu_local_idx)
{
    if (vehicle_id >= g_handoff_prev_rsu.size()) return;

    uint32_t prev = g_handoff_prev_rsu[vehicle_id];
    bool handed_off = (prev != HANDOFF_TRACKER_UNSEEN) && (prev != current_rsu_local_idx);

    g_handoff_just_occurred[vehicle_id] = handed_off;
    g_handoff_cycles_since[vehicle_id] = handed_off ? 0 : (g_handoff_cycles_since[vehicle_id] + 1);
    g_handoff_prev_rsu[vehicle_id] = current_rsu_local_idx;
}

// Returns true if `vehicle_id` handed off to a different serving RSU on
// the cycle covered by the most recent handoff_tracker_update() call.
inline bool handoff_just_occurred(uint32_t vehicle_id)
{
    if (vehicle_id >= g_handoff_just_occurred.size()) return false;
    return g_handoff_just_occurred[vehicle_id];
}

// Returns the number of cycles elapsed since `vehicle_id`'s last handoff
// (0 on the handoff's own cycle).
inline uint32_t handoff_cycles_since(uint32_t vehicle_id)
{
    if (vehicle_id >= g_handoff_cycles_since.size()) return 0;
    return g_handoff_cycles_since[vehicle_id];
}

#endif // HANDOFF_TRACKER_H
