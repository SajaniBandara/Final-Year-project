#pragma once

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "tcam_attack_helper.h"

// Definitions live in tcam_attack_helper.h (g_tcam_rule_count, g_tcam_table)
// and routing.cc (g_slowpath_hit_count — added in Task 2).
extern int                    g_tcam_rule_count[300];
extern std::vector<TcamEntry> g_tcam_table;
extern int                    g_slowpath_hit_count[300];

// Monotone cumulative install counters (defined in tcam_attack_helper.h, never
// reset). S3 windows over (new + reinstall) — a slow-TCAM attacker refreshes
// rules to keep them alive, which registers as reinstalls, so new-only is blind
// to the attack's persistence mechanic.
extern uint64_t g_lambda_new_cum[300];
extern uint64_t g_lambda_reinstall_cum[300];

// ── Empirical E[λ_l | ρ] (installs/s) ──────────────────────────────────────────
// Sourced from the MEASURED new+reinstall install-rate curve (lambda_l_true.csv,
// 90 s benign, t>40, 3136 RSU-cycles). NOT an invented linear fit. Bin means:
//   ρ 0-3 → 0.02, 3-6 → 0.18, 6-10 → 0.44, 10-15 → 0.61, 15-25 → 0.75, 25+ → 0.89
// Piecewise-linear interpolation across bin centres; clamped flat outside the
// measured range (monotone, saturating).
inline double EmpiricalExpectedLambdaL(double rho)
{
    static const double x[] = { 1.5, 4.5, 8.0, 12.5, 20.0, 30.0 };
    static const double y[] = { 0.02, 0.18, 0.44, 0.61, 0.75, 0.89 };
    const int n = 6;
    if (rho <= x[0])     return y[0];
    if (rho >= x[n - 1]) return y[n - 1];
    for (int i = 1; i < n; ++i) {
        if (rho <= x[i]) {
            const double f = (rho - x[i - 1]) / (x[i] - x[i - 1]);
            return y[i - 1] + f * (y[i] - y[i - 1]);
        }
    }
    return y[n - 1];
}

// ── S3 sliding-window rate estimator (Fix 3) ───────────────────────────────────
// Per-second λ_l is sparse/quantised (benign median 0, mean 0.33), so a per-cycle
// threshold cannot separate benign from attack. Accumulate installs over a sliding
// window and compare the windowed count against the window-scaled E[λ_l|ρ].
// S3_LAMBDA_WINDOW_S is a tunable parameter left for later calibration.
static const uint32_t S3_LAMBDA_WINDOW_S = 10;   // sliding-window length (s)
static const uint32_t S3_HIST_MAX        = 128;  // ring capacity (>= window)
static uint64_t g_s3_cum_hist[300][S3_HIST_MAX] = {{0}}; // per-node cum(new+reinstall) history
static uint32_t g_s3_hist_count = 0;             // cycles recorded so far (shared clock)
static bool     g_tcam_dbg_trace = true;         // print per-RSU (ρ,E,λ) validation tuples

// ── Structs ───────────────────────────────────────────────────────────────────

struct TcamDetectionState {
    uint32_t rsu_node_id;
    double   tcam_util;       // g_tcam_rule_count[rsu_node_id] / TCAM_CAPACITY
    double   lambda_fm;       // FlowMod install rate (rules/s this cycle)
    double   lambda_pi;       // PACKET_IN rate (slow-path hits/s this cycle)
    int      malicious_count; // is_malicious entries in g_tcam_table for this RSU
    int      total_count;     // g_tcam_rule_count[rsu_node_id]
    bool     flag_s3;
    bool     flag_s4;
};

struct TcamCycleMetrics {
    double max_tcam_util;
    double avg_tcam_util;
    double total_lambda_fm;
    double total_lambda_pi;
    int    total_malicious;
    int    s3_fired_count;
    int    s4_fired_count;
    bool   any_s3;
    bool   any_s4;
};

// ── Persistent per-cycle state ────────────────────────────────────────────────

static int g_prev_rule_count[300]    = {0};
static int g_prev_slowpath_hits[300] = {0};

// ── Detection logic ───────────────────────────────────────────────────────────

inline TcamCycleMetrics ComputeTcamDetection(
    uint32_t N_Vehicles,
    uint32_t N_RSUs,
    double   lambda_fm_thresh,  // S3: anomalous FlowMod rate threshold (rules/s)
    double   lambda_pi_thresh,  // S4: PACKET_IN rate threshold (hits/s)
    double   tcam_util_thresh,  // shared utilisation threshold (e.g. 0.80)
    const std::vector<double>& rho_per_rsu) // ρ_r(t): REAL per-RSU zone density (Fix 2)
{
    TcamCycleMetrics metrics{};
    metrics.max_tcam_util   = 0.0;
    metrics.avg_tcam_util   = 0.0;
    metrics.total_lambda_fm = 0.0;
    metrics.total_lambda_pi = 0.0;
    metrics.total_malicious = 0;
    metrics.s3_fired_count  = 0;
    metrics.s4_fired_count  = 0;
    metrics.any_s3          = false;
    metrics.any_s4          = false;

    double util_sum = 0.0;

    for (uint32_t r = 0; r < N_RSUs; ++r) {
        const uint32_t node_id = N_Vehicles + r;

        // 1. TCAM utilisation, clamped to [0, 1]
        double tcam_util = g_tcam_rule_count[node_id] / (double)TCAM_CAPACITY;
        tcam_util = (tcam_util < 0.0 ? 0.0 : (tcam_util > 1.0 ? 1.0 : tcam_util));

        // 2. FlowMod install rate (rules installed this cycle / 1 s)
        const int rules_this_cycle = g_tcam_rule_count[node_id] - g_prev_rule_count[node_id];
        const double lambda_fm = (rules_this_cycle > 0) ? (double)rules_this_cycle : 0.0;

        // 3. PACKET_IN (slow-path) rate (hits this cycle / 1 s)
        const int hits_this_cycle = g_slowpath_hit_count[node_id] - g_prev_slowpath_hits[node_id];
        const double lambda_pi = (hits_this_cycle > 0) ? (double)hits_this_cycle : 0.0;

        // 4. Count malicious TCAM entries belonging to this RSU
        int malicious_count = 0;
        for (const auto& entry : g_tcam_table) {
            if (entry.node_id == node_id && entry.is_malicious) {
                ++malicious_count;
            }
        }

        // 5. Windowed install count (new + reinstall) over the sliding window, and
        //    density-normalised anomalous excess (Eq. 3.3) using the EMPIRICAL
        //    E[λ_l|ρ] curve with the REAL per-RSU density ρ_r(t) (Fix 2 + Fix 3).
        const double rho_r      = (r < rho_per_rsu.size()) ? rho_per_rsu[r] : 0.0;
        const uint64_t cum_now  = g_lambda_new_cum[node_id] + g_lambda_reinstall_cum[node_id];
        const uint32_t pos      = g_s3_hist_count % S3_HIST_MAX;
        const uint32_t w_eff    = (g_s3_hist_count < S3_LAMBDA_WINDOW_S)
                                  ? g_s3_hist_count : S3_LAMBDA_WINDOW_S;
        const uint32_t past_pos = (g_s3_hist_count - w_eff) % S3_HIST_MAX;
        const uint64_t cum_past = g_s3_cum_hist[node_id][past_pos];
        g_s3_cum_hist[node_id][pos] = cum_now;         // record this cycle's cumulative

        const double lambda_obs_win = (double)(cum_now - cum_past); // installs over window
        const double E_lambda_l     = EmpiricalExpectedLambdaL(rho_r);      // installs/s
        const double E_lambda_win   = E_lambda_l * (double)w_eff;           // window-scaled
        const double lambda_hat_a   = lambda_obs_win - E_lambda_win;        // anomalous excess

        // 6. S3: windowed excess FlowMod rate AND high TCAM utilisation (Fix 1: the
        //    oracle `malicious_count > 0` is replaced by the intended U_TCAM > U_thresh).
        const bool flag_s3 = (lambda_hat_a > lambda_fm_thresh) && (tcam_util > tcam_util_thresh);

        // Validation trace: prove E_λ_l varies per RSU/cycle and λ̂_a is centred near 0.
        if (g_tcam_dbg_trace && rho_r > 0.0)
            std::cout << "[S3-DBG] t=" << (int)std::round(Simulator::Now().GetSeconds())
                      << " rsu=" << node_id << " rho=" << rho_r
                      << " E_lam=" << E_lambda_l << " E_win=" << E_lambda_win
                      << " lam_obs=" << lambda_obs_win << " lam_hat_a=" << lambda_hat_a
                      << " util=" << tcam_util << std::endl;

        // 7. S4: high PACKET_IN rate AND high TCAM utilisation (both required)
        const bool flag_s4 = (lambda_pi > lambda_pi_thresh) && (tcam_util > tcam_util_thresh);

        // 8. Advance per-RSU baseline counters for the next cycle
        g_prev_rule_count[node_id]    = g_tcam_rule_count[node_id];
        g_prev_slowpath_hits[node_id] = g_slowpath_hit_count[node_id];

        // Accumulate into cycle-level aggregate
        util_sum                += tcam_util;
        if (tcam_util > metrics.max_tcam_util) metrics.max_tcam_util = tcam_util;
        metrics.total_lambda_fm += lambda_fm;
        metrics.total_lambda_pi += lambda_pi;
        metrics.total_malicious += malicious_count;
        if (flag_s3) { ++metrics.s3_fired_count; record_detection_event(2, node_id); }
        if (flag_s4) { ++metrics.s4_fired_count; record_detection_event(3, node_id); }
    }

    ++g_s3_hist_count;   // advance the shared per-cycle window clock (Fix 3)

    metrics.avg_tcam_util = (N_RSUs > 0) ? (util_sum / N_RSUs) : 0.0;
    metrics.any_s3        = (metrics.s3_fired_count > 0);
    metrics.any_s4        = (metrics.s4_fired_count > 0);

    return metrics;
}

// ── CSV helper ────────────────────────────────────────────────────────────────

// Returns 9 comma-prefixed column values; append directly before the row newline.
// Format: ", max_util(4dp), avg_util(4dp), total_fm(2dp), total_pi(2dp),
//           total_mal, s3_count, s4_count, any_s3(0/1), any_s4(0/1)"
inline std::string TcamDetectionCsvColumns(const TcamCycleMetrics& m)
{
    std::ostringstream oss;
    oss << std::fixed
        << ", " << std::setprecision(4) << m.max_tcam_util
        << ", " << std::setprecision(4) << m.avg_tcam_util
        << ", " << std::setprecision(2) << m.total_lambda_fm
        << ", " << std::setprecision(2) << m.total_lambda_pi
        << ", " << m.total_malicious
        << ", " << m.s3_fired_count
        << ", " << m.s4_fired_count
        << ", " << (m.any_s3 ? 1 : 0)
        << ", " << (m.any_s4 ? 1 : 0);
    return oss.str();
}
