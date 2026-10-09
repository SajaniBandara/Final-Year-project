#ifndef SFTO_DETECTION_H
#define SFTO_DETECTION_H

// ============================================================================
// sfto_detection.h — SFTO-Guard (Tang et al., 2023) IN-SIM baseline detector.
//
// Design B (2026-09-19): the paper's actual real-time mechanism —
//   rule-count prediction + a STATIC flow-table occupancy threshold — run live
//   in the ns-3 loop, instead of the offline LightGBM reproduction under
//   sfto_pipeline/. Scored per-RSU against TCAM ground truth and written to
//   results_routing/SFTO_Attack<N>_<pct>[...]<tag>.csv, exactly like the TAP
//   and eFADE in-sim baselines.
//
// SFTO-Guard detects slow-rate flow-table overflow: each RSU predicts its
// flow-table occupancy a short horizon ahead from the recent install rate and
// raises an alarm when that prediction crosses a fixed capacity fraction. The
// STATIC threshold is deliberate — it is the paper's design, and its known
// weakness (false-positives at high legitimate density, where benign flows
// also grow the table) is exactly the contrast our density-adaptive detector
// is meant to show.
//
// Signals (all live, already tracked for S3/S4):
//   g_tcam_rule_count[node]  — current flow-table occupancy at an RSU
//   TCAM_CAPACITY            — table size
// Ground truth (injection-side, detector-independent):
//   is_malicious_node[variant][rsu_node]  — RSU-attacker variants (Attack 3)
//   sfto_attacked_rsu[rsu_node]            — victim RSUs of a malicious install
//                                            (Attack 4, marked in tcam_install_malicious)
//
// enable_sfto is OFF by default. A clean SFTO baseline run pairs it with
// --enable_lrad_obu=0 --enable_lrad_rsu=0 (MOBIGUARD's own detectors off), the
// same isolation used for TAP/FADE.
// ============================================================================

#include <map>
#include <cmath>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>

// Forward declarations of globals defined in routing.cc / tcam headers.
extern int          g_tcam_rule_count[];
extern int          active_attack_variant;
extern uint32_t     N_Vehicles;
extern uint32_t     N_RSUs;
extern std::string  g_sim_tag;

// Master enable (CLI --enable_sfto), default off. Defined here; declared extern
// where routing.cc's cmd.AddValue needs it.
bool   enable_sfto = false;

// ── SFTO-Guard parameters (paper mechanism) ─────────────────────────────────
double SFTO_THETA      = 0.90;  // static occupancy threshold (fraction of capacity).
// CLI-settable (--sfto_theta) for the SOTA "recalibrated" baseline line: refit to a
// benign occupancy percentile, same method as U_thresh/S1/ε_vol. Default 0.90 (the
// paper value, confirmed correct on this network) — "SFTO (default)" line unchanged.
static const double SFTO_GROWTH_BETA = 0.70; // EWMA smoothing of per-cycle install rate
static const int    SFTO_HORIZON    = 10;    // cycles ahead to predict occupancy
// TCAM_CAPACITY is defined in routing.cc (~line 117445); declared extern there.
extern int TCAM_CAPACITY;

// ── Per-RSU state ───────────────────────────────────────────────────────────
static std::map<uint32_t,int>    sfto_prev_rule_count;   // occupancy last cycle
static std::map<uint32_t,double> sfto_growth_ewma;       // smoothed install rate (rules/cycle)
static std::map<uint32_t,bool>   sfto_detected;          // latched alarm per RSU node
static std::map<uint32_t,bool>   sfto_attacked_rsu;      // ground truth: victim RSUs (Attack 4)

// Confusion-matrix accumulators (computed once at save time).
static uint32_t sfto_TP = 0, sfto_FP = 0, sfto_TN = 0, sfto_FN = 0;
static double   sfto_current_MCC = 0.0, sfto_current_DR = 0.0, sfto_current_FPR = 0.0;

inline void sfto_reset_state()
{
    sfto_prev_rule_count.clear();
    sfto_growth_ewma.clear();
    sfto_detected.clear();
    sfto_attacked_rsu.clear();
    sfto_TP = sfto_FP = sfto_TN = sfto_FN = 0;
}

// Called from tcam_install_malicious() (Attack 4, DP): the malicious vehicle
// targets target_rsu, whose table SFTO would legitimately see filling.
inline void sfto_mark_attacked_rsu(uint32_t target_rsu_node)
{
    if (!enable_sfto) return;
    sfto_attacked_rsu[target_rsu_node] = true;
}

// ── Per-cycle detection: predict occupancy, latch alarm ─────────────────────
// Call once per routing cycle (right after ComputeTcamDetection).
inline void sfto_run_cycle()
{
    if (!enable_sfto) return;
    if (TCAM_CAPACITY <= 0) return;

    for (uint32_t r = 0; r < N_RSUs; ++r)
    {
        const uint32_t node = N_Vehicles + r;               // RSU node id
        const int cur = g_tcam_rule_count[node];

        int prev = cur;
        auto it = sfto_prev_rule_count.find(node);
        if (it != sfto_prev_rule_count.end()) prev = it->second;
        const double growth = (double)(cur - prev);          // rules installed this cycle
        sfto_prev_rule_count[node] = cur;

        double g_ewma = sfto_growth_ewma.count(node) ? sfto_growth_ewma[node] : 0.0;
        g_ewma = SFTO_GROWTH_BETA * g_ewma + (1.0 - SFTO_GROWTH_BETA) * (growth > 0.0 ? growth : 0.0);
        sfto_growth_ewma[node] = g_ewma;

        // Rule-count prediction: occupancy SFTO_HORIZON cycles ahead.
        const double occ      = (double)cur / (double)TCAM_CAPACITY;
        const double occ_pred = occ + (double)SFTO_HORIZON * g_ewma / (double)TCAM_CAPACITY;
        ev_sfto_pred(node, g_ewma > 0.0 ? occ_pred : -1.0);   // calibration series (--ev_log_util)

        // Static-threshold alarm (latched): predicted occupancy crosses SFTO_THETA
        // while the table is actively growing.
        if (g_ewma > 0.0 && occ_pred >= SFTO_THETA)
        {
            ev_alarm_attributed(node, EV_SRC_SFTO, 1);   // raw per-cycle decision, not the latch below
            if (!sfto_detected[node])
            {
                sfto_detected[node] = true;
                std::cout << "[SFTO] RSU node " << node
                          << " overflow-trajectory alarm: occ=" << occ
                          << " pred=" << occ_pred
                          << " (theta=" << SFTO_THETA << ")" << std::endl;
            }
        }
    }
}

// ── End-of-run: per-RSU confusion matrix + MCC → SFTO_*.csv ─────────────────
// is_malicious_node[variant][node] (attack_declaration.h) is in scope: this
// header is included after it in routing.cc.
inline void sfto_save_metrics()
{
    if (!enable_sfto) return;

    // SFTO-Guard addresses the slow-rate TCAM-exhaustion variants only
    // (Attack 3 = variant 2, Attack 4 = variant 3). Outside those it is out of
    // scope; the row is still written (all-negative) so the baseline column is
    // explicit rather than missing.
    const bool tcam_variant = (active_attack_variant == 2 || active_attack_variant == 3);

    sfto_TP = sfto_FP = sfto_TN = sfto_FN = 0;
    for (uint32_t r = 0; r < N_RSUs; ++r)
    {
        const uint32_t node = N_Vehicles + r;
        // Truth: RSU is malicious for this variant (A3, RSU-attacker) OR is a
        // victim RSU of a malicious install (A4, vehicle-attacker) — SFTO detects
        // at the table owner in both cases.
        bool truth = false;
        if (tcam_variant)
        {
            if (active_attack_variant >= 0 && node < (uint32_t)total_size)
                truth = is_malicious_node[active_attack_variant][node];
            if (sfto_attacked_rsu.count(node) && sfto_attacked_rsu[node]) truth = true;
        }
        const bool pred = (sfto_detected.count(node) && sfto_detected[node]);

        if      ( pred &&  truth) ++sfto_TP;
        else if ( pred && !truth) ++sfto_FP;
        else if (!pred &&  truth) ++sfto_FN;
        else                      ++sfto_TN;
    }

    const double tp = sfto_TP, fp = sfto_FP, tn = sfto_TN, fn = sfto_FN;
    const double denom = std::sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
    sfto_current_MCC = (denom > 0.0) ? ((tp*tn - fp*fn) / denom) : 0.0;
    sfto_current_DR  = (tp+fn > 0.0) ? (100.0 * tp / (tp+fn)) : 0.0;
    sfto_current_FPR = (fp+tn > 0.0) ? (100.0 * fp / (fp+tn)) : 0.0;

    std::system("mkdir -p results_routing");
    const std::string path = "results_routing/SFTO_metrics" + g_sim_tag + ".csv";
    bool exists = false;
    { std::ifstream chk(path); exists = chk.good(); }
    std::ofstream f(path, std::ios::out | std::ios::app);
    if (!exists)
        f << "attack_variant,mcc,dr,fpr,tp,fp,tn,fn\n";
    f << active_attack_variant << ","
      << std::fixed << std::setprecision(4)
      << sfto_current_MCC << "," << sfto_current_DR << "," << sfto_current_FPR << ","
      << sfto_TP << "," << sfto_FP << "," << sfto_TN << "," << sfto_FN << "\n";
    f.close();

    std::cout << "[SFTO] variant=" << active_attack_variant
              << " MCC=" << sfto_current_MCC
              << " DR=" << sfto_current_DR << "% FPR=" << sfto_current_FPR << "%"
              << " (TP=" << sfto_TP << " FP=" << sfto_FP
              << " TN=" << sfto_TN << " FN=" << sfto_FN << ")" << std::endl;
}

#endif // SFTO_DETECTION_H
