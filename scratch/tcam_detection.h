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

// ── Structs ───────────────────────────────────────────────────────────────────

struct TcamDetectionState {
    uint32_t rsu_node_id;
    double   tcam_util;       // g_tcam_rule_count[rsu_node_id] / TCAM_HW_SIZE
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
    double   vehicle_density)   // ρ(t): vehicles currently active
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
        double tcam_util = g_tcam_rule_count[node_id] / (double)TCAM_HW_SIZE;
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

        // 5. Density-normalised expected FlowMod rate and anomalous excess (Eq. 3.3)
        const double E_lambda_l   = 0.8 + 1.2 * (vehicle_density / (double)N_Vehicles);
        const double lambda_hat_a = lambda_fm - E_lambda_l;

        // 6. S3: excess FlowMod rate AND unauthorised entries present (eq:sig_s3)
        const bool flag_s3 = (lambda_hat_a > lambda_fm_thresh) && (malicious_count > 0);

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
