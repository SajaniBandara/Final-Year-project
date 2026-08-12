#ifndef DETECTOR_WINDOWS_H
#define DETECTOR_WINDOWS_H

// =========================================================================
// detector_windows.h — emits detector_windows.csv, the input for M1
// (eq:mcc / eq:mcc_variant / eq:mcc_mobility).
//
// WHY THIS EXISTS
// ---------------
// The thesis defines M1 over DETECTION WINDOWS stratified by mode (OBU/RSU)
// and variant. metrics/README.md states the gap plainly:
//
//   | M1 | node-level MCC exists inline in routing.cc; window-level needs
//        | detector_windows.csv: node, mode, variant, w_start, w_end, score
//          [, truth, density, speed] |
//
// Until now the simulator emitted no such file (grep routing.cc:
// 0 references), so every reported MCC came from the inline PER-NODE
// confusion matrix in calculate_security_detection_metrics() — 268 nodes,
// sticky latches, whole-run. That is a different statistic from the paper's
// per-window MCC and the two are not comparable: measured 2026-08-06, the
// same Q6 configuration scores 0.264 per-node against ~0.895 per-window on
// the LSTM pipeline's own evaluator. Neither number is wrong; they answer
// different questions, and only the window one is M1.
//
// CONTRACT (metrics/io/detector_output.py)
//   REQUIRED = {node, mode, variant, w_start, w_end, score}
//   optional  truth (bool), density_bin/speed_bin (view 3)
//   m01 thresholds `score` at config.decision_threshold (default 0.5) and
//   enforces an FPR <= 1 % gate PER MODE.
//
// WINDOWING: W = 10 s, stride = 5 s (metrics/config.py detection_window_s /
// detection_stride_s). Windows overlap 50 %, exactly as the offline
// evaluator's do — deduplication is the consumer's job (evaluator.py applies
// non-maximum suppression), not ours. We emit the raw window grid.
//
// SCORE SEMANTICS: the RSU/OBU composite decisions (D_RSU, D_OBU) are
// BOOLEAN, not continuous, so `score` is emitted as 0.0 / 1.0 — a window
// scores 1.0 if the composite fired on any cycle inside it. With the default
// threshold of 0.5 this reproduces the composite decision exactly. It is NOT
// the LSTM anomaly score; mixing a continuous reconstruction error with
// binary rule flags on one scale would make the threshold meaningless.
// =========================================================================

#include <fstream>
#include <string>
#include <vector>
#include "ns3/simulator.h"

// Off by default: the emitter costs one bit per node per cycle and one file
// write at teardown, but it is diagnostic output, not part of a normal run.
bool     enable_detector_windows = false;
double   DW_WINDOW_S = 10.0;   // must match metrics/config.py detection_window_s
double   DW_STRIDE_S = 5.0;    // must match metrics/config.py detection_stride_s

// Per-cycle latches, reset by dw_end_cycle().
static std::vector<uint8_t> g_dw_obu_fired;   // [vehicle]
static std::vector<uint8_t> g_dw_rsu_fired;   // [rsu local idx]
// Per-cycle history, appended by dw_end_cycle().
static std::vector<std::vector<uint8_t>> g_dw_obu_hist;   // [cycle][vehicle]
static std::vector<std::vector<uint8_t>> g_dw_rsu_hist;   // [cycle][rsu]
static std::vector<std::vector<uint8_t>> g_dw_obu_truth;  // [cycle][vehicle]
static std::vector<std::vector<uint8_t>> g_dw_rsu_truth;  // [cycle][rsu]
static std::vector<double>               g_dw_cycle_t;    // [cycle] sim time

inline void dw_init()
{
    if (!enable_detector_windows) return;
    g_dw_obu_fired.assign((size_t)N_Vehicles, 0);
    g_dw_rsu_fired.assign((size_t)N_RSUs, 0);
    g_dw_obu_hist.clear(); g_dw_rsu_hist.clear();
    g_dw_obu_truth.clear(); g_dw_rsu_truth.clear();
    g_dw_cycle_t.clear();
}

// Called from lrad_obu() when D_OBU fires.
inline void dw_mark_obu(uint32_t vehicle)
{
    if (!enable_detector_windows) return;
    if (vehicle < g_dw_obu_fired.size()) g_dw_obu_fired[vehicle] = 1;
}

// Called from lrad_rsu() when D_RSU fires. rsu is the GLOBAL node index.
inline void dw_mark_rsu(uint32_t rsu)
{
    if (!enable_detector_windows) return;
    if (rsu < (uint32_t)N_Vehicles) return;
    uint32_t r = rsu - (uint32_t)N_Vehicles;
    if (r < g_dw_rsu_fired.size()) g_dw_rsu_fired[r] = 1;
}

// Called once per simulation cycle, after the per-RSU logging pass.
// Snapshots this cycle's decisions AND ground truth, then clears the latches.
inline void dw_end_cycle()
{
    if (!enable_detector_windows) return;

    // OBU ground truth: the attacker-identity flag, with the SAME event gate
    // calculate_security_detection_metrics() applies for A1/A2 — otherwise a
    // node counts as malicious before its delay has actually manifested and
    // every pre-onset window becomes a false negative.
    std::vector<uint8_t> ot((size_t)N_Vehicles, 0);
    if (active_attack_variant >= 0 && active_attack_variant < NUM_ATTACK_VARIANTS)
    {
        for (uint32_t v = 0; v < (uint32_t)N_Vehicles; ++v)
        {
            bool mal = is_malicious_node[active_attack_variant][v];
            if (active_attack_variant == 0) mal = mal && g_s1_gt_delay_exceeded[v];
            else if (active_attack_variant == 1) mal = mal && g_s2_gt_delay_exceeded[v];
            ot[v] = mal ? 1 : 0;
        }
    }

    // RSU ground truth: reuse lstm_rsu_ground_truth_label() rather than
    // reimplementing it — it carries the A3/A4 victim-RSU, A2 covering-RSU and
    // A6/A8 covering-RSU fallbacks, and a second copy would drift from it.
    std::vector<uint8_t> rt((size_t)N_RSUs, 0);
    for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r)
        rt[r] = (uint8_t)lstm_rsu_ground_truth_label((uint32_t)N_Vehicles + r);

    // S3/S4 fold-in — REQUIRED for M1 to see the TCAM family at all.
    // dw_mark_rsu() is only ever called from lrad_rsu() when D_RSU fires, and
    // D_RSU deliberately excludes flag_S3/flag_S4 (see LRADRSUFlags, lrad.h:72-79:
    // the TCAM signatures are evaluated independently by ComputeTcamDetection()).
    // main.tex:2544-2546 defines D_RSU *with* S3/S4, so the window grid was
    // structurally blind to every TCAM detection: measured on Q1/2026-08-08,
    // A3 scored MCC 1.000 per-node against 0.103 per-window, and A4 0.891
    // against 0.360 — the per-window figure was reading S2f alone on a TCAM
    // attack. Fold the published per-RSU flags in here rather than changing
    // D_RSU itself, because D_RSU also gates BC.Write, the BTMM trust penalty
    // and quarantine; widening it would change simulation behaviour, not just
    // the measurement.
    //
    // Gated by g_disable_s3_s4 so Q1-Q6 ablation isolation still holds (a
    // config with S3/S4 "off" must not gain TCAM detections in M1). This is
    // the confusion-matrix gating semantics, NOT the LSTM gate's — that one
    // reads the RAW flags on purpose (runbook §3), so the two must not be
    // collapsed into one decision.
    if (!g_disable_s3_s4)
    {
        for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r)
        {
            uint32_t nid = (uint32_t)N_Vehicles + r;
            if (nid < 300 && (g_tcam_flag_s3_last[nid] || g_tcam_flag_s4_last[nid])
                && r < g_dw_rsu_fired.size())
                g_dw_rsu_fired[r] = 1;
        }
    }

    g_dw_obu_hist.push_back(g_dw_obu_fired);
    g_dw_rsu_hist.push_back(g_dw_rsu_fired);
    g_dw_obu_truth.push_back(ot);
    g_dw_rsu_truth.push_back(rt);
    g_dw_cycle_t.push_back(ns3::Simulator::Now().GetSeconds());

    std::fill(g_dw_obu_fired.begin(), g_dw_obu_fired.end(), 0);
    std::fill(g_dw_rsu_fired.begin(), g_dw_rsu_fired.end(), 0);
}

// Slides the W/stride grid over the cycle history and writes one row per
// (node, mode, window). Call once at end of simulation.
inline void dw_write_csv(const std::string& path)
{
    if (!enable_detector_windows) return;
    const size_t n_cycles = g_dw_cycle_t.size();
    if (n_cycles == 0) return;

    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open())
    {
        std::cerr << "[DETECTOR-WINDOWS] WARNING: cannot open " << path << std::endl;
        return;
    }
    f << "node,mode,variant,w_start,w_end,score,truth\n";

    // variant: the proposal's attack number (0 = benign, 1-8), matching the
    // convention lstm_logger.h uses for its file names.
    const int variant = (active_attack_variant < 0) ? 0 : (active_attack_variant + 1);

    const double t0 = g_dw_cycle_t.front();
    const double t_end = g_dw_cycle_t.back();
    uint64_t rows = 0;

    for (double ws = t0; ws + DW_WINDOW_S <= t_end + 1e-9; ws += DW_STRIDE_S)
    {
        const double we = ws + DW_WINDOW_S;
        // Cycle indices inside [ws, we)
        size_t c0 = 0, c1 = 0;
        while (c0 < n_cycles && g_dw_cycle_t[c0] <  ws) ++c0;
        c1 = c0;
        while (c1 < n_cycles && g_dw_cycle_t[c1] <  we) ++c1;
        if (c1 <= c0) continue;   // empty window

        for (uint32_t v = 0; v < (uint32_t)N_Vehicles; ++v)
        {
            uint8_t fired = 0, truth = 0;
            for (size_t c = c0; c < c1; ++c)
            {
                if (g_dw_obu_hist[c][v])  fired = 1;
                if (g_dw_obu_truth[c][v]) truth = 1;
            }
            f << v << ",OBU," << variant << "," << ws << "," << we << ","
              << (fired ? "1.0" : "0.0") << "," << (truth ? "1" : "0") << "\n";
            ++rows;
        }
        for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r)
        {
            uint8_t fired = 0, truth = 0;
            for (size_t c = c0; c < c1; ++c)
            {
                if (g_dw_rsu_hist[c][r])  fired = 1;
                if (g_dw_rsu_truth[c][r]) truth = 1;
            }
            f << ((uint32_t)N_Vehicles + r) << ",RSU," << variant << ","
              << ws << "," << we << "," << (fired ? "1.0" : "0.0") << ","
              << (truth ? "1" : "0") << "\n";
            ++rows;
        }
    }
    f.close();
    std::cout << "[DETECTOR-WINDOWS] wrote " << rows << " rows over "
              << n_cycles << " cycles -> " << path << std::endl;
}

#endif // DETECTOR_WINDOWS_H
