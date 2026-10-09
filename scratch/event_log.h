// event_log.h -- raw per-cycle EVENT log for event-based scoring (supervisor 2026-10-08).
//
// WHY: the old confusion matrix (calculate_security_detection_metrics, and the node-level label
// behind detector_windows / M1) is a snapshot of LATCHED node state (is_malicious_node stays true,
// is_detected_node stays true), so a working defence cannot raise MCC. This log records only what
// HAPPENED in each routing cycle; scripts/event_scorer.py turns it into TP/FP/FN/TN.
//
// Unit: scored node = RSU, routing cycle = floor(sim seconds) (data_transmission_frequency is fixed at
// 1.0). Vehicle attackers/alarms are attributed to their covering RSU (hf_gt_attribution_node), the
// same attribution the LSTM labels already use. Nothing here reads any latched flag.
//
// File: results_routing/events_<run>.csv, rows `cycle,node,kind,value`:
//   ACT   value = attack actions performed by/at this node in the cycle that reached an honest node
//         (counted AFTER the quarantine-enforcement check: an aborted action is not an action)
//   ALM1  value = DetectionSource bit mask of per-packet rule alarms raised on node (window = 1 cycle)
//   ALM10 value = bit mask of windowed alarms (LSTM, window = 10 cycles ending at this cycle)
//   QUA   node entered SC.Quarantine in this cycle (value 1); scorer stops scoring it from cycle+1
//   FIRE  node = -1, value = "bitindex:count" firings of that DetectionSource flag this cycle
//   WIT   witness alert raised on node, value = type (0 duplication, 1 non-forwarding)
//   FALSEQ is derived by the scorer (QUA on a node that never attacked before that cycle)
#ifndef EVENT_LOG_H
#define EVENT_LOG_H

#include <map>
#include <vector>
#include <array>
#include <sstream>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include "ns3/simulator.h"
#include "build_tag.h"

struct EvCell { uint32_t state = 0; uint32_t act = 0; uint32_t alm1 = 0; uint32_t alm10 = 0; uint32_t qua = 0; uint32_t wit0 = 0; uint32_t wit1 = 0; };

static std::map<std::pair<uint32_t,int32_t>, EvCell> g_ev_cells;     // (cycle,node)
static std::map<uint32_t, std::map<int,uint32_t>>     g_ev_fire;     // cycle -> bitindex -> count
static std::string g_ev_path;
static std::ofstream g_ev_out;
static int g_ev_variant = -1;
static std::map<uint32_t, std::map<int,uint32_t>> g_ev_dec;   // cycle -> source bit -> decisions taken
static bool g_ev_enabled = true;
// --aux_logs=0 suppresses the four large auxiliary logs that dominated disk use (tcam_snapshots 170 GB, bc_detection_log 53 GB,
// crypto_timing_log 16.5 GB, bc_flowmod_log 5 GB over earlier sweeps; about 0.6 GB per 180 s run) -- only the file writes, never the logic
// around them. Default 1 keeps every older workflow unchanged; all final runs pass 0.
static bool g_aux_logs = true;
static std::string g_ev_cfg;                                          // one "# cfg ..." header line: the run configuration
static std::map<uint32_t, std::vector<std::array<std::string,3>>> g_ev_misc;   // cycle -> (node, kind, value) rows (QUAX, REV, TD, CTRLC)
// Calibration series (--ev_log_util=1): per RSU-cycle TCAM occupancy (S4), SFTO predicted occupancy (-1 = table not growing),
// and TAP's largest |v - PPAT| (s) seen on packets from that RSU (or a vehicle it covers). They let U_thresh, SFTO's theta and
// TAP's margin be swept OFFLINE from one benign and one attack run.
static bool g_ev_log_util = false;
struct EvUV { double util = -1.0, sfto = -2.0, tapdev = -1.0; };
static std::map<std::pair<uint32_t,int32_t>, EvUV> g_ev_uv;
static bool g_ev_trust_qua = true;   // false in TAP / FADE-only runs: MOBIGUARD trust machinery is not the baseline's mitigation
static uint32_t g_ev_flushed_upto = 0;     // cycles < this are on disk

// Alarm sources of the baselines (bits above the DetectionSource enum in routing.cc, which uses 0..13).
static const uint32_t EV_SRC_TAP  = 1u << 14;
static const uint32_t EV_SRC_SFTO = 1u << 15;
static const uint32_t EV_SRC_FADE = 1u << 16;
// Defined in routing.cc after hf_gt_attribution_node(): maps a vehicle to its covering RSU, then ev_alarm().
inline void ev_alarm_attributed(uint32_t raw_node, uint32_t src_bit, int window_cycles);

inline uint32_t ev_cycle() { return (uint32_t)ns3::Simulator::Now().GetSeconds(); }

inline void ev_open_if_needed()
{
    if (g_ev_out.is_open() || g_ev_path.empty()) return;
    g_ev_out.open(g_ev_path, std::ios::out | std::ios::trunc);   // trunc: a reused tag can never append
    g_ev_out << "# commit=" << SDVN_BUILD_TAG << "\n";
    g_ev_out << "# variant=" << g_ev_variant << "\n";
    if (!g_ev_cfg.empty()) g_ev_out << "# cfg " << g_ev_cfg << "\n";
    g_ev_out << "cycle,node,kind,value\n";
}

inline void ev_flush_before(uint32_t cyc)
{
    if (g_ev_path.empty() || cyc <= g_ev_flushed_upto) return;
    ev_open_if_needed();
    for (auto it = g_ev_cells.begin(); it != g_ev_cells.end() && it->first.first < cyc; )
    {
        uint32_t c = it->first.first; int32_t n = it->first.second; const EvCell& e = it->second;
        if (e.state) g_ev_out << c << "," << n << ",STATE," << e.state << "\n";
        if (e.act)   g_ev_out << c << "," << n << ",ACT,"   << e.act   << "\n";
        if (e.alm1)  g_ev_out << c << "," << n << ",ALM1,"  << e.alm1  << "\n";
        if (e.alm10) g_ev_out << c << "," << n << ",ALM10," << e.alm10 << "\n";
        if (e.qua)   g_ev_out << c << "," << n << ",QUA,1\n";
        if (e.wit0)  g_ev_out << c << "," << n << ",WIT,0:" << e.wit0 << "\n";
        if (e.wit1)  g_ev_out << c << "," << n << ",WIT,1:" << e.wit1 << "\n";
        it = g_ev_cells.erase(it);
    }
    for (auto it = g_ev_fire.begin(); it != g_ev_fire.end() && it->first < cyc; )
    {
        for (auto& kv : it->second) g_ev_out << it->first << ",-1,FIRE," << kv.first << ":" << kv.second << "\n";
        it = g_ev_fire.erase(it);
    }
    for (auto it = g_ev_misc.begin(); it != g_ev_misc.end() && it->first < cyc; )
    {
        for (auto& r : it->second) g_ev_out << it->first << "," << r[0] << "," << r[1] << "," << r[2] << "\n";
        it = g_ev_misc.erase(it);
    }
    for (auto it = g_ev_uv.begin(); it != g_ev_uv.end() && it->first.first < cyc; )
    {
        g_ev_out << it->first.first << "," << it->first.second << ",UTIL," << it->second.util << ":" << it->second.sfto << ":" << it->second.tapdev << "\n";
        it = g_ev_uv.erase(it);
    }
    for (auto it = g_ev_dec.begin(); it != g_ev_dec.end() && it->first < cyc; )
    {
        for (auto& kv : it->second) g_ev_out << it->first << ",-1,DEC," << kv.first << ":" << kv.second << "\n";
        it = g_ev_dec.erase(it);
    }
    g_ev_out.flush();
    g_ev_flushed_upto = cyc;
}

inline void ev_flush_all() { ev_flush_before(0xFFFFFFFFu); }

inline void ev_init(const std::string& path, int variant = -1)
{
    g_ev_path = path; g_ev_variant = variant;
    std::atexit(ev_flush_all);
}

// Called on every event; flushes completed cycles so memory stays bounded.
inline void ev_tick() { ev_flush_before(ev_cycle()); }

// An attack action reached an honest node. `node` is the scored node (victim / covering RSU).
inline void ev_act(uint32_t node)
{
    if (!g_ev_enabled) return;
    ev_tick(); g_ev_cells[{ev_cycle(), (int32_t)node}].act++;
}

// A detector raised an alarm on `node` (scored node). bitmask = DetectionSource bit.
inline void ev_alarm(uint32_t node, uint32_t src_bit, int window_cycles)
{
    if (!g_ev_enabled) return;
    ev_tick();
    EvCell& e = g_ev_cells[{ev_cycle(), (int32_t)node}];
    if (window_cycles > 1) e.alm10 |= src_bit; else e.alm1 |= src_bit;
}

// Raw flag firing (counted before any ablation gate where the call site allows it).
inline void ev_fire(uint32_t src_bit)
{
    if (!g_ev_enabled) return;
    ev_tick();
    int b = 0; while (b < 31 && !((src_bit >> b) & 1u)) ++b;
    g_ev_fire[ev_cycle()][b]++;
}

// A decision a detector took (alarm or not): the denominator of a per-decision false-alarm rate.
inline void ev_decision(uint32_t src_bit)
{
    if (!g_ev_enabled) return;
    ev_tick();
    int b = 0; while (b < 31 && !((src_bit >> b) & 1u)) ++b;
    g_ev_dec[ev_cycle()][b]++;
}

// A3/A4 state label: number of attacker-injected (ground-truth is_malicious) TCAM entries held by `node` at cycle end.
inline void ev_state(uint32_t node, uint32_t n_entries)
{
    if (!g_ev_enabled || n_entries == 0) return;
    ev_tick(); g_ev_cells[{ev_cycle(), (int32_t)node}].state = n_entries;
}

inline void ev_misc(uint32_t node, const char* kind, const std::string& value)
{
    if (!g_ev_enabled) return;
    ev_tick();
    g_ev_misc[ev_cycle()].push_back({std::to_string(node), kind, value});
}
inline void ev_set_cfg(const std::string& cfg) { g_ev_cfg = cfg; }

inline void ev_util(uint32_t node, double util)
{
    if (!g_ev_enabled || !g_ev_log_util) return;
    ev_tick(); g_ev_uv[{ev_cycle(), (int32_t)node}].util = util;
}
inline void ev_sfto_pred(uint32_t node, double pred)
{
    if (!g_ev_enabled || !g_ev_log_util) return;
    ev_tick(); g_ev_uv[{ev_cycle(), (int32_t)node}].sfto = pred;
}
// Defined in routing.cc (needs the covering-RSU attribution): keeps the maximum deviation per scored RSU and cycle.
inline void ev_tap_dev_attributed(uint32_t raw_sender, double dev);

inline void ev_quarantine(uint32_t node)
{
    if (!g_ev_enabled) return;
    ev_tick(); g_ev_cells[{ev_cycle(), (int32_t)node}].qua = 1;
}

// M4 per attacker (per-event series): first attack action, quarantine event and controller-revocation times [s, 0 = never].
inline void ev_m4(uint32_t node, double t_first, double t_quar, double t_rev)
{
    ev_open_if_needed();
    g_ev_out << "0," << node << ",M4," << t_first << ":" << t_quar << ":" << t_rev << "\n";
}

inline void ev_attacker(uint32_t node)
{
    ev_open_if_needed();
    g_ev_out << "0," << node << ",ATK,1\n";
}

inline void ev_witness(uint32_t node, int type)
{
    if (!g_ev_enabled) return;
    ev_tick();
    EvCell& e = g_ev_cells[{ev_cycle(), (int32_t)node}];
    if (type == 0) e.wit0++; else e.wit1++;
}

#endif // EVENT_LOG_H
