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
extern int                    g_packetin_count[300];   // PACKET_IN (table-miss) rate source for S4 λ_PI
// Issue 6 fix (2026-08-02): per-(RSU, source vehicle) companion to
// g_packetin_count -- see its declaration in routing.cc. Consumed below by
// s4_attribute_attacker() to compute v_atk = argmax_v λ_PI(v,r,t)
// (eq:s4_attribution), replacing the RSU-only aggregate this file previously
// had no way to disaggregate.
extern std::map<uint32_t, std::map<uint32_t, uint32_t>> g_packetin_by_source;
// Previous-cycle cumulative snapshot per (rsu, vehicle), mirroring
// g_prev_packetin's per-RSU delta pattern below.
static std::map<uint32_t, std::map<uint32_t, uint32_t>> g_prev_packetin_by_source;

// s4_attribute_attacker(): v_atk = argmax_v λ_PI(v,r,t) -- the source vehicle
// with the highest windowed (this-cycle) PACKET_IN rate at RSU r. Advances
// g_prev_packetin_by_source[r] as a side effect (call at most once per RSU
// per cycle, matching every other per-RSU counter's advance-once discipline
// in calculate_security_detection_metrics() below). Returns UINT32_MAX if
// no PACKET_IN activity from any source this cycle (nothing to attribute).
inline uint32_t s4_attribute_attacker(uint32_t rsu_node_id)
{
    uint32_t best_v = UINT32_MAX;
    int      best_delta = 0;
    auto&    cur_by_src  = g_packetin_by_source[rsu_node_id];
    auto&    prev_by_src = g_prev_packetin_by_source[rsu_node_id];
    for (const auto& kv : cur_by_src)
    {
        uint32_t src   = kv.first;
        uint32_t cur   = kv.second;
        uint32_t prev  = prev_by_src.count(src) ? prev_by_src[src] : 0;
        int      delta = (cur >= prev) ? (int)(cur - prev) : 0;
        if (delta > best_delta) { best_delta = delta; best_v = src; }
    }
    prev_by_src = cur_by_src;   // advance snapshot for next cycle
    return best_v;
}

// Monotone cumulative install counters (defined in tcam_attack_helper.h, never
// reset). S3 windows over (new + reinstall) — a slow-TCAM attacker refreshes
// rules to keep them alive, which registers as reinstalls, so new-only is blind
// to the attack's persistence mechanic.
extern uint64_t g_lambda_new_cum[300];
extern uint64_t g_lambda_reinstall_cum[300];

// ── Empirical E[λ_l | ρ] (installs/s) ──────────────────────────────────────────
// eq:density_normalized_rate — E[λ_l|ρ] estimated from RSU vehicle density.
// RE-FIT 2026-07-17 from the clean benign run (variant=-1, cap=1500, seed=1,
// t>30, ~2176 RSU-cycles with ρ>0). The PREVIOUS curve (0.02→0.89) was fit
// against an earlier k=2 generator and became ~20× too low after the switch to
// the all-neighbour presence-driven generator, which would make λ̂_a hugely
// positive for benign traffic and fire S3 constantly. New bin means (new+reinstall
// installs/s), from lambda_l_true_baseline.csv joined with per-RSU ρ:
//   ρ~1.5 → 0.65, ρ~4.5 → 1.26, ρ~8 → 4.83, ρ~12.5 → 5.26, ρ~20 → 8.43, ρ~30 → 18.30
// Piecewise-linear interpolation across bin centres; clamped flat outside the
// measured range (monotone, saturating).
inline double EmpiricalExpectedLambdaL(double rho)
{
    static const double x[] = { 1.5,  4.5,  8.0,  12.5, 20.0, 30.0  };
    static const double y[] = { 0.65, 1.26, 4.83, 5.26, 8.43, 18.30 };
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

// Latest per-RSU S3/S4 detection state, indexed by sim node_id (same space
// as g_tcam_rule_count[]) -- populated once per cycle by ComputeTcamDetection()
// below. Read by lrad_rsu() (lrad.h) to gate flag_LSTM: per the supervisor's
// LSTM/S3/S4 diagnosis, when S3 or S4 fires at an RSU the rule-based layer is
// already the definitive detector there, so the LSTM's contribution to D_RSU
// is suppressed for that RSU this cycle to avoid stacking a structurally
// noisy signal (residual TCAM occupancy) on top of an already-covered event.
static bool g_tcam_flag_s3_last[300] = {false};
static bool g_tcam_flag_s4_last[300] = {false};

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
static int g_prev_packetin[300]      = {0};   // baseline for the per-cycle λ_PI delta

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

        // 3. PACKET_IN (table-miss) rate this cycle / 1 s (eq:sig_s4 λ_PI). Sourced
        //    from g_packetin_count (every new install + every full-table miss), NOT
        //    g_slowpath_hit_count (full-table only): the paper's λ_PI is the PACKET_IN
        //    flood rate, present from attack onset with a benign install baseline.
        const int hits_this_cycle = g_packetin_count[node_id] - g_prev_packetin[node_id];
        const double lambda_pi = (hits_this_cycle > 0) ? (double)hits_this_cycle : 0.0;

        // 4. Count, at this RSU: malicious entries (is_malicious — GROUND TRUTH, used
        //    ONLY for the CSV metrics/eval labels, never for the detection decision)
        //    and UNAUTHORISED entries (!authorized — the on-chain f_unauth term that
        //    actually gates S3, eq:unauth_flowmod). unauth_count reads the blockchain
        //    endorsement outcome cached on each rule at install (tcam_flowmod_authorized),
        //    derived from the observable legitimate-flow registry, NOT from is_malicious.
        int malicious_count      = 0;
        int unauth_count         = 0;  // f_unauth=1 term only (eq:unauth_flowmod)
        int unauth_orphan_count  = 0;  // BOTH eq:rule_s3 conjuncts: f_unauth=1 AND
                                        // no active flow backs it (eq:sig_s3's
                                        // nexists v: flow(r) in F_active(v) term)
        for (const auto& entry : g_tcam_table) {
            if (entry.node_id != node_id) continue;
            if (entry.is_malicious) ++malicious_count;
            if (entry.counts_capacity && !entry.authorized) {
                ++unauth_count;
                // Second conjunct of eq:rule_s3. g_tcam_installed (tcam_attack_helper.h)
                // is the F_active registry: populated only by tcam_install()'s legit
                // path and erased on eviction, so membership means "a real vehicle
                // flow is currently active for this (flow_id, node_id) pair" at this
                // instant. tcam_install_malicious() deliberately never inserts into it
                // (so attacker fids can be refreshed without dedup) -- see the NOTE at
                // its call site -- so an entry absent from this set has no active flow
                // behind it. Kept as an INDEPENDENT check from `authorized` (rather than
                // assuming f_unauth already implies it) so the two conjuncts stay
                // separately auditable even if the endorsement mechanism later becomes
                // attack-aware (docs/PENDING_FIXES.md) and the two could diverge.
                const bool no_active_flow =
                    (g_tcam_installed.count(std::make_pair(entry.flow_id, entry.node_id)) == 0);
                if (no_active_flow) ++unauth_orphan_count;
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

        // 6. S3 (eq:rule_s3): windowed density-normalised FlowMod-rate excess AND the
        //    presence of an UNAUTHORISED FlowMod (f_unauth=1, eq:unauth_flowmod).
        //    UPDATED 2026-07-20: f_unauth is now the ON-CHAIN endorsement result
        //    (unauth_count > 0, from TcamEntry::authorized set at install via the f+1
        //    quorum gate tcam_flowmod_authorized), replacing the previous is_malicious
        //    ORACLE. An RSU independently checks each FlowMod against the blockchain-
        //    committed endorsed policy set; one arriving without f+1 endorsement is
        //    unauthorised. Under enable_endorsement_requirement=false (AB8-A) every
        //    FlowMod commits, so unauth_count==0 and this term never fires — matching
        //    the paper's AB8-A/AB8-B ablation. S3 no longer consults ground truth.
        //
        //    2026-07-20: f_unauth is now the PRIMARY (and sole) S3 gate; the density-
        //    normalised rate excess λ̂_a is demoted to a corroborating/reported signal.
        //    Measured on the A3 run: f_unauth already yields 0% benign FPR (no
        //    unauthorised FlowMod exists in benign traffic), so the rate AND-term only
        //    REMOVED true positives (74.9% TPR at θ=10; and calibrating θ at the paper's
        //    benign p99≈332 collapsed it to 2.6% — the same rate-overlap pathology as
        //    S4). f_unauth is a NON-BLOCKING detection/audit signal (a local RSU-chain
        //    ledger lookup, off the flow-setup critical path), which is the timing-
        //    realistic use of the endorsement layer in an SDVN safety context — NOT a
        //    synchronous pre-install PBFT gate. *** DEVIATION from eq:rule_s3 (which
        //    ANDs the rate term); flagged, mirrors the S4 util-primary change. ***
        //
        //    2026-07-21: flag_s3 now ANDs the SECOND eq:rule_s3 conjunct too --
        //    nexists v: flow(r) in F_active(v) -- via unauth_orphan_count (computed
        //    above from g_tcam_installed membership), not just f_unauth alone. Under
        //    the current attacker model these two conjuncts are always in lockstep
        //    (an attacker fid is never in g_tcam_installed, so unauth_orphan_count ==
        //    unauth_count here), so this is not expected to change any measured
        //    TPR/FPR number -- it closes the gap between the code and the literal
        //    two-conjunct equation, and gives real protection if the endorsement
        //    mechanism later becomes attack-aware enough that an unauthorised entry
        //    could correspond to a real (temporarily unendorsed) active flow.
        (void)lambda_fm_thresh;   // rate excess corroborating/reported only, no longer gates S3
        const bool flag_s3 = (unauth_orphan_count > 0);

        // Per-RSU per-cycle detector-signal trace. Emits for EVERY RSU (2026-07-17:
        // rho>0 gate removed so attacked RSUs with no vehicles are still logged), and
        // now carries the FULL S3+S4 signal set -- lam_hat_a, mal (malicious_count),
        // lam_pi (PACKET_IN rate), util -- so the S3/S4 thresholds can be calibrated
        // on benign and applied OFFLINE to both benign (FPR) and attack (detection),
        // without baking thresholds and re-running.
        if (g_tcam_dbg_trace)
            std::cout << "[S3-DBG] t=" << (int)std::round(Simulator::Now().GetSeconds())
                      << " rsu=" << node_id << " rho=" << rho_r
                      << " E_lam=" << E_lambda_l << " E_win=" << E_lambda_win
                      << " lam_obs=" << lambda_obs_win << " lam_hat_a=" << lambda_hat_a
                      << " mal=" << malicious_count << " lam_pi=" << lambda_pi
                      << " util=" << tcam_util << std::endl;

        // 7. S4: TCAM OCCUPANCY is the firing signal -- f_S4(r,t)=1 iff util > θ_util.
        //    *** DEVIATION FROM PAPER (eq:rule_s4) — FLAGGED 2026-07-20 ***
        //    eq:rule_s4 as written fires on the PACKET_IN rate λ_PI alone. Calibration
        //    on the current (post-2026-07-16 TCAM architecture) benign baseline vs
        //    attack4_n200 shows that rule is NOT viable and is physically backwards:
        //      - rate λ_PI does NOT separate attack from benign (ROC ≈ diagonal:
        //        TPR≈FPR at every threshold), because a dense benign vehicle installs
        //        as fast as a 20-pps attacker;
        //      - worse, once the table saturates the attacker's installs hit TABLE_FULL
        //        and STOP, so λ_PI COLLAPSES TO ZERO during sustained exhaustion
        //        (attacked-cell median λ_PI = 0) -- the rate is inversely present.
        //      - the old λ_PI>15 AND util>0.055 gate scores 16% TPR / 7.6% FPR here.
        //    Occupancy is monotonic and stays pegged: benign util maxes at 0.289
        //    (cap=1500), attacked RSUs saturate to 1.0. util > 0.30 gives ~88% TPR at
        //    0% benign FPR (91%/1% at the benign p99 0.213). This matches eq:sig_s4's
        //    U_TCAM conjunct, so the fix belongs in eq:rule_s4 (make util PRIMARY, rate
        //    demoted to corroboration/attribution), NOT in leaving the code rate-driven.
        //    λ_PI is still computed and reported for the [S3-DBG] trace and for naming
        //    the flooding source (attribution), but no longer gates S4.
        (void)lambda_pi_thresh;   // retained in the signature; corroborating/attribution only, not an S4 conjunct
        const bool flag_s4 = (tcam_util > tcam_util_thresh);

        // 8. Advance per-RSU baseline counters for the next cycle
        g_prev_rule_count[node_id]    = g_tcam_rule_count[node_id];
        g_prev_slowpath_hits[node_id] = g_slowpath_hit_count[node_id];
        g_prev_packetin[node_id]      = g_packetin_count[node_id];
        // Issue 6 fix: v_atk = argmax_v λ_PI(v,r,t) this cycle. Called
        // unconditionally (not just when flag_s4 fires) so its snapshot
        // advance stays in lockstep with every other per-RSU counter above —
        // a strict per-cycle window, not a sparse one that silently spans
        // multiple cycles whenever S4 didn't fire.
        const uint32_t v_atk = s4_attribute_attacker(node_id);

        // Publish this cycle's S3/S4 state for lrad_rsu()'s flag_LSTM gate
        // (see g_tcam_flag_s3_last/g_tcam_flag_s4_last declaration above).
        g_tcam_flag_s3_last[node_id] = flag_s3;
        g_tcam_flag_s4_last[node_id] = flag_s4;

        // Accumulate into cycle-level aggregate
        util_sum                += tcam_util;
        if (tcam_util > metrics.max_tcam_util) metrics.max_tcam_util = tcam_util;
        metrics.total_lambda_fm += lambda_fm;
        metrics.total_lambda_pi += lambda_pi;
        metrics.total_malicious += malicious_count;
        if (flag_s3) {
            ++metrics.s3_fired_count;
            if (!g_disable_s3_s4) record_detection_event(2, node_id);
            // S3 (eq:rule_s3): unauthorised-FlowMod rate anomaly — this RSU's
            // FlowMod-install rate λ_FM exceeds the benign threshold with no
            // matching active flow, the control-plane TCAM-exhaustion signature.
            std::cout << "[S3] ⚠️ SIGNATURE S3 TRIGGERED!"
                      << " unauthorised-FlowMod rate anomaly on RSU " << node_id
                      << " λ_FM=" << lambda_fm << " rules/s"
                      << " (malicious=" << malicious_count
                      << ", TCAM util=" << tcam_util << ")"
                      << " t=" << Simulator::Now().GetSeconds() << "s" << std::endl;
        }
        if (flag_s4) {
            ++metrics.s4_fired_count;
            if (!g_disable_s3_s4) record_detection_event(3, node_id);
            // S4 (eq:rule_s4): TCAM saturation — utilisation U_TCAM exceeds the
            // threshold; the attacker is the vehicle with the highest packet-in
            // rate (argmax λ_PI), the data-plane TCAM-exhaustion signature.
            std::cout << "[S4] ⚠️ SIGNATURE S4 TRIGGERED!"
                      << " TCAM-saturation on RSU " << node_id
                      << " util=" << tcam_util
                      << " (λ_PI=" << lambda_pi
                      << ", malicious=" << malicious_count << ")"
                      << " v_atk=" << (v_atk == UINT32_MAX ? std::string("none")
                                                             : std::to_string(v_atk))
                      << " t=" << Simulator::Now().GetSeconds() << "s" << std::endl;
        }
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
