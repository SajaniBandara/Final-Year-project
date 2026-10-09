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
// Supervisor's primary-detector requirement (2026-08-21): "each variant is
// scored against its PRIMARY detector's per-window output, not the
// OR-combination". dw_mark_rsu() is driven by D_RSU, which is that
// OR-combination, so this grid could not express it.
//
// Measured consequence: S2 fires 1,572-3,313 times during A5-A8 runs and
// records into variant 1's bucket, so it is invisible in those variants'
// node-level matrices (where S5-S8 all show FP=0) while still setting D_RSU
// and polluting every one of their window scores. That is what holds A5-A8's
// window MCC at 0.26-0.35 despite node-level FP=0.
//
// Separate latch carrying ONLY the primary detector for the variant under
// test, so the table can score what the supervisor actually asked for.
static std::vector<uint8_t> g_dw_rsu_primary;      // [rsu local idx]
static std::vector<std::vector<uint8_t>> g_dw_rsu_primary_hist;
// Per-cycle history, appended by dw_end_cycle().
static std::vector<std::vector<uint8_t>> g_dw_obu_hist;   // [cycle][vehicle]
static std::vector<std::vector<uint8_t>> g_dw_rsu_hist;   // [cycle][rsu]
static std::vector<std::vector<uint8_t>> g_dw_obu_truth;  // [cycle][vehicle]
static std::vector<std::vector<uint8_t>> g_dw_rsu_truth;  // [cycle][rsu]
// Supervisor item 2 (2026-08-27): the DECLARED-attacker truth, i.e. the same
// node-level label WITHOUT the per-cycle activity gate that g_dw_rsu_truth
// applies. Recall must be reported both ways -- against every declared
// attacker, and against the acted set (those that actually attacked) -- and
// the acted-only number cannot be inverted back to the declared one from the
// gated column alone, because a declared node that never acted is
// indistinguishable there from a benign node. Emitted as its own column.
static std::vector<std::vector<uint8_t>> g_dw_rsu_truth_declared;  // [cycle][rsu]
static std::vector<double>               g_dw_cycle_t;    // [cycle] sim time

inline void dw_init()
{
    if (!enable_detector_windows) return;
    g_dw_obu_fired.assign((size_t)N_Vehicles, 0);
    g_dw_rsu_fired.assign((size_t)N_RSUs, 0);
    g_dw_rsu_primary.assign((size_t)N_RSUs, 0);
    g_dw_rsu_primary_hist.clear();
    g_dw_obu_hist.clear(); g_dw_rsu_hist.clear();
    g_dw_obu_truth.clear(); g_dw_rsu_truth.clear(); g_dw_rsu_truth_declared.clear();
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

// Called from lrad_rsu() with the PRIMARY detector's own flag for the variant
// under test -- not D_RSU. Assignment follows the supervisor's 2026-08-21
// table: A1/A2 -> S1/S2, A3/A4 -> S3/S4 (recorded separately by
// tcam_detection.h), A5/A6 -> crypto/S5/S6, A7/A8 -> R_anom rule + witness
// + S7/S8.
inline void dw_mark_rsu_primary(uint32_t rsu, bool primary_fired)
{
    if (!enable_detector_windows || !primary_fired) return;
    if (rsu < (uint32_t)N_Vehicles) return;
    uint32_t r = rsu - (uint32_t)N_Vehicles;
    if (r < g_dw_rsu_primary.size()) g_dw_rsu_primary[r] = 1;
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
    // Supervisor Decision 4 (2026-08-21): window-level truth. The node-level
    // label alone is constant for the whole run, so a genuine attacker's
    // DORMANT windows counted as positives no detector could ever catch --
    // measured at 40.7% of node-level positives (30,730 of 75,578), capping a
    // perfect zero-FP detector at DR ~59.3%. AND it with this cycle's activity
    // latch so a window is positive only when the node is malicious AND the
    // attack actually fired in it.
    //
    // g_dw_activity_last defaults to 1 for variants with no per-cycle gate
    // (A3/A4, benign), so those keep exactly their previous behaviour.
    std::vector<uint8_t> rt((size_t)N_RSUs, 0);
    std::vector<uint8_t> rtd((size_t)N_RSUs, 0);   // item 2: declared, ungated
    for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r)
    {
        uint8_t node_lvl = (uint8_t)lstm_rsu_ground_truth_label((uint32_t)N_Vehicles + r);
        uint8_t active   = (r < g_dw_activity_last.size()) ? g_dw_activity_last[r] : 1;
        rt[r]  = (node_lvl && active) ? 1 : 0;
        rtd[r] = node_lvl ? 1 : 0;
    }

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
            if (nid < (uint32_t)total_size && (g_tcam_flag_s3_last[nid] || g_tcam_flag_s4_last[nid])
                && r < g_dw_rsu_fired.size())
                g_dw_rsu_fired[r] = 1;
        }
    }

    // PRIMARY-column fold-in for the TCAM family (2026-08-27).
    //
    // score_primary carries "only the detector this variant is actually scored
    // by" (supervisor's 2026-08-21 assignment). Every other variant's primary
    // flag is set in lrad_rsu() via dw_mark_rsu_primary(), but A3/A4 cannot be
    // done there: that call marks prev_sender, whereas S3/S4 fire at -- and
    // A3/A4 ground truth labels -- the VICTIM RSU holding the malicious TCAM
    // entries (lstm_rsu_ground_truth_label(), lstm_logger.h). See the no-op
    // `case 2: case 3:` in lrad.h for the full reasoning.
    //
    // So mirror the score fold-in directly above, which already indexes r
    // correctly and is already proven against the score column, into
    // g_dw_rsu_primary. Scoped to variants 2/3 only: for any other variant the
    // TCAM signatures are not that variant's primary detector, and folding them
    // in would reintroduce exactly the cross-detector pollution score_primary
    // exists to prevent.
    //
    // Gated by g_disable_s3_s4 through the same branch, so Q2/Q3/Q4 (which set
    // it to isolate the crypto/LSTM/witness layers) correctly score zero here.
    if (!g_disable_s3_s4 &&
        (active_attack_variant == 2 || active_attack_variant == 3))
    {
        for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r)
        {
            uint32_t nid = (uint32_t)N_Vehicles + r;
            if (nid < (uint32_t)total_size && (g_tcam_flag_s3_last[nid] || g_tcam_flag_s4_last[nid])
                && r < g_dw_rsu_primary.size())
                g_dw_rsu_primary[r] = 1;
        }
    }

    g_dw_obu_hist.push_back(g_dw_obu_fired);
    g_dw_rsu_hist.push_back(g_dw_rsu_fired);
    g_dw_rsu_primary_hist.push_back(g_dw_rsu_primary);
    g_dw_obu_truth.push_back(ot);
    g_dw_rsu_truth.push_back(rt);
    g_dw_rsu_truth_declared.push_back(rtd);
    g_dw_cycle_t.push_back(ns3::Simulator::Now().GetSeconds());

    std::fill(g_dw_obu_fired.begin(), g_dw_obu_fired.end(), 0);
    std::fill(g_dw_rsu_fired.begin(), g_dw_rsu_fired.end(), 0);
    std::fill(g_dw_rsu_primary.begin(), g_dw_rsu_primary.end(), 0);
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
    // score_cycles / score_primary_cycles (item 7 persistence, 2026-08-30):
    // how many DISTINCT CYCLES inside the window the detector fired in, not
    // just whether any did. The existing score/score_primary columns keep
    // their exact OR semantics, so every prior reader and every prior number
    // is unaffected -- these are additive.
    //
    // Why counts rather than a built-in M-of-N threshold: emitting the count
    // lets the persistence threshold M be swept offline from a SINGLE run per
    // configuration, instead of one 90-minute run per candidate M. Window is
    // positive under persistence-M iff the corresponding *_cycles column >= M
    // (M=1 reproduces the current OR behaviour exactly).
    f << "node,mode,variant,w_start,w_end,score,truth,score_primary,truth_declared,"
         "score_cycles,score_primary_cycles\n";

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
            uint32_t fired_cycles = 0;            // item 7 persistence
            for (size_t c = c0; c < c1; ++c)
            {
                if (g_dw_obu_hist[c][v])  { fired = 1; ++fired_cycles; }
                if (g_dw_obu_truth[c][v]) truth = 1;
            }
            // OBU rows carry no score_primary and no declared-truth column;
            // pad both so every row has the same field count (readers index
            // positionally -- see scripts/run_q1q6_ablation.py's COL_* note).
            f << v << ",OBU," << variant << "," << ws << "," << we << ","
              << (fired ? "1.0" : "0.0") << "," << (truth ? "1" : "0")
              << ",,," << fired_cycles << ",\n";
            ++rows;
        }
        for (uint32_t r = 0; r < (uint32_t)N_RSUs; ++r)
        {
            uint8_t fired = 0, truth = 0, prim = 0, truth_d = 0;
            uint32_t fired_cycles = 0, prim_cycles = 0;   // item 7 persistence
            for (size_t c = c0; c < c1; ++c)
            {
                if (g_dw_rsu_hist[c][r])  { fired = 1; ++fired_cycles; }
                if (g_dw_rsu_truth[c][r]) truth = 1;
                if (c < g_dw_rsu_truth_declared.size() && g_dw_rsu_truth_declared[c][r]) truth_d = 1;
                if (c < g_dw_rsu_primary_hist.size() && g_dw_rsu_primary_hist[c][r]) { prim = 1; ++prim_cycles; }
            }
            f << ((uint32_t)N_Vehicles + r) << ",RSU," << variant << ","
              << ws << "," << we << "," << (fired ? "1.0" : "0.0") << ","
              << (truth ? "1" : "0") << "," << (prim ? "1.0" : "0.0") << ","
              << (truth_d ? "1" : "0") << "," << fired_cycles << ","
              << prim_cycles << "\n";
            ++rows;
        }
    }
    f.close();
    std::cout << "[DETECTOR-WINDOWS] wrote " << rows << " rows over "
              << n_cycles << " cycles -> " << path << std::endl;
}

#endif // DETECTOR_WINDOWS_H
