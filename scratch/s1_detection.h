#ifndef S1_DETECTION_H
#define S1_DETECTION_H

// Normal runs: DETECTION_DEBUG_LOG_S1 = false -> zero per-packet terminal
// noise from the routine "no violation"/diagnostic lines below. The rare
// "TRIGGERED"/record_detection_event lines stay unconditional regardless —
// those are the ones that matter for verification. Same convention as
// crypto_layer.h's CRYPTO_DEBUG_LOG / s2_detection.h's DETECTION_DEBUG_LOG_S2.
static bool DETECTION_DEBUG_LOG_S1 = false;

// Defined in crypto_layer.h, which routing.cc includes AFTER this header, so it
// must be forward-declared here. Used below to gate S1's record_detection_event()
// while leaving the g_s1_gt_delay_exceeded[] GROUND-TRUTH latch untouched — see
// the note at that latch for why the two must be separable.
extern bool g_disable_s1_s2;

// =========================================================================
// s1_detection.h — MOBIGUARD Signature S1 Detection
//
// Implements Signature S1 (Selective Time Delay, Control Plane) from the
// proposal, as defined in Equations 3.4, 3.11, 3.12, 3.13, 3.14.
//
// S1 (Attack 1 — Selective Time Delay, Control Plane):
//   δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)  ∧  Priority(p) = HIGH
//   ∧  δ_best(r,t) ≤ δ̄_r(t) + k·σ_r(t)
//   Eq. 3.4/eq:rule_s1, main.tex ~L1930 (post 2026-07-20 dev merge)
//   Detection uses a per-RSU mobility-adjusted baseline delay (Eq. 3.11)
//   and an EWMA variance estimator (Eq. 3.12/3.13). The third conjunct
//   (selectivity condition, δ_best) requires best-effort traffic to remain
//   within the same threshold that safety-critical traffic just violated —
//   under genuine congestion both classes are delayed together, so this
//   conjunct evaluates false and S1 correctly does not fire; under Attack 1
//   only high-priority traffic is delayed, so δ_best stays low and the
//   conjunct passes.
//
// DESIGN NOTE:
//   This header is included inside routing.cc AFTER all global variables
//   have been declared, so it reads globals directly without externs (same
//   pattern as tap_detection.h and s2_detection.h). Do not include it
//   before the global declarations.
//
// INDEPENDENCE:
//   S1 has no individual master-enable flag — gated solely by
//   enable_lrad_obu (AB1, lrad.h), matching main.tex's only mode-level
//   ablation for this part of the architecture. No per-signature toggle is
//   specified anywhere in main.tex; removed 2026-07-09.
// =========================================================================

#include <iostream>
#include <cmath>
#include <fstream>
#include <vector>
#include "ns3/simulator.h"

using namespace ns3;
using namespace std;

// =========================================================================
// S1 per-RSU state — mobility-adjusted baseline and EWMA variance
// =========================================================================

// ── S1 parameters — ALL VALUES ARE INITIAL CANDIDATES, NOT VALIDATED FINALS ──
// The thesis marks δ₀, α_ρ, α_v as pending least-squares regression against
// benign SUMO mobility traces, and β, k as pending grid-search validation
// (thesis §3473–3479, §3485). Results produced with these values are
// preliminary. Update each constant once the corresponding calibration or
// grid-search sweep has been completed.

// δ₀ — baseline intercept (seconds). Eq. 3.11.
// Pending: least-squares regression on benign (0% attack) SUMO traces.
// Initial estimate: 2 ms — typical DSRC propagation + MAC overhead at zero load.
// Calibrated 2026-07-05 via OLS on 27,795 benign rows (5 seeds × 148 cycles × 64 RSUs).
// rule_calibrator.py steps: OLS → β sweep {0.7,0.8,0.9,0.95} → k sweep {1,2,3} → robustness ±30%.
// R²=0.0004: α_ρ and α_v are near-zero — delay in NS-3 DSRC is dominated by crypto/routing
// overhead rather than vehicle density/speed; baseline effectively collapses to δ₀.
// Recalibrated 2026-08-08 (rule_calibrator.py) on lambda_PI-fixed benign SUMO
// traces, seeds 1-3, 120s each (22,087 traffic rows, rho>0). Supersedes the
// 2026-07-25 values above -- that run's delta0=0.00195355 was later traced to
// a corrupted manual test-run CSV (constant delta_t), not real benign data.
// beta: empirical 1% convergence test never latches on real (non-stationary)
// traffic (confirmed again on this data: all of {0.7,0.8,0.9,0.95} exceed the
// 22s ceiling) -- selected instead via the analytic N_eff=1/(1-beta) criterion.
//
// UPDATED 2026-08-13 (supervisor call): the 9s figure in main.tex:6049 is the
// MINIMUM RSU zone residence, so it is a FLOOR on N_eff, not a ceiling -- the
// EWMA must form a useful estimate within that shortest window. The 22s maximum
// crossing supplies the ceiling. Band: 9 <= N_eff <= 22, i.e. beta in
// [0.889, 0.955]. That rejects the previous beta=0.8 (N_eff=5) as adapting
// faster than the shortest crossing -- the baseline tracks the attack and
// absorbs it -- and selects beta=0.95 (N_eff=20, matching the longest crossing).
// Empirical A/B 2026-08-13 (40s, 60% attack, seed1, only --s1_beta varied)
// agreed: beta=0.95 higher MCC and lower FPR on both A1 and A2, DR unchanged.
// k unchanged at 3.0 (still smallest k with FPR <= 1%, though no candidate
// actually clears 1% on this data -- FPR=0.0287 at k=3.0, robustness
// max|ΔFPR| = 0.0051). OLS R² ≈ 0.0074.
double s1_delta0    = 0.00447305;   // s  — OLS intercept (≈4.473 ms)
double s1_alpha_rho = 0.00011315;   // s/vehicle — density term
double s1_alpha_v   = -0.00150238;  // s²/m — speed term
double s1_k         = 3.0;          // sigma multiplier — k sweep: smallest k with FPR ≤ 1%

// ── Robust variance update (2026-08-24) ─────────────────────────────────
// sigma2 was updated on EVERY packet, attack packets included. Since
// threshold = delta_bar + k*sigma, a sustained attack inflates the very
// threshold meant to catch it: the detector masks itself.
//
// Measured, A1 @60% seed 1 90 s (attack injects 99.568 ms):
//     k*sigma at first fire      8.97 ms
//     k*sigma at last fire      62.05 ms
//     mean threshold 10-30 s    98.59 ms
//     mean threshold 50-70 s   114.88 ms   <- ABOVE the injected delay
// Mean delay at firing was 178-195 ms, roughly double what the attack
// injects, because once the bar passes ~100 ms only tail packets that
// queue beyond it can still fire. That is the direct cause of S1's ~53%
// recall, and it worsens monotonically as an attack persists.
//
// Excluding violating packets was tried before and abandoned: it produced
// "a self-reinforcing feedback loop where a shrinking sigma excludes more
// packets, shrinking sigma further with no floor" (see the sigma2 update
// site below). The floor is the missing ingredient, not the exclusion --
// with sigma2 clamped from below, the loop has a fixed point and cannot
// collapse. Genuine congestion is still handled, by the separate
// selectivity conjunct (delta_best <= threshold), which is what
// distinguishes congestion from a targeted high-priority-only delay.
bool   s1_robust_sigma = true;      // exclude violating packets from sigma2
double s1_sigma_floor  = 0.001;     // s — 1 ms floor on sigma (sigma2 >= 1e-6)
double s1_beta      = 0.95;         // EWMA factor — analytic N_eff=1/(1-β)=20, band 9<=N_eff<=22 (main.tex:6049; supervisor 2026-08-13)

// Per-RSU EWMA baseline and variance, indexed by RSU index (0..N_RSUs-1).
// Sized dynamically at runtime by s1_init_state(N_RSUs) — no hardcoded ceiling.
std::vector<double>   s1_delta_bar;     // δ̄_r(t): mobility-adjusted baseline per RSU
std::vector<double>   s1_sigma2;        // σ²_r(t): EWMA variance per RSU

// ── Non-parametric percentile threshold (supervisor item 7, 2026-08-27) ────
//
// Replaces the Gaussian delta_bar + k*sigma bound with a cutoff read directly
// off each RSU's own observed benign delay distribution.
//
// Justification, from our own zero-attack measurement (300 s, seed 1, current
// build): benign hop delay is strongly heavy-tailed, not bell-shaped. Mean and
// median delay AT FIRING were both ~177 ms against a mean threshold of ~24 ms,
// with 81% of firings above 100 ms and 99.95% above 50 ms -- 6,156 S1 firings
// on a run with zero attackers. A symmetric k*sigma bound cannot cover that
// tail at any k in {1,2,3} without becoming too loose to detect anything; the
// codebase already recorded that no k cleared the 1% FPR target
// ("FPR=0.0287 at k=3.0", the calibration note above). That is a distribution-
// SHAPE mismatch, not a threshold-VALUE mistake, so the fix is to stop
// assuming a shape.
//
// The delay distribution itself is untouched -- it is a real property of the
// network, not a defect. Only the detector's notion of "unusual" changes.
//
// Implementation: a fixed-bin histogram of benign delays per RSU, from which
// the s1_pctl quantile is read. Chosen over a reservoir because it updates in
// O(1) per packet with no allocation, and the quantile is recomputed once per
// cycle in s1_update_baseline() rather than per packet -- the same cadence
// delta_bar already updates on.
//
// Samples are admitted under the SAME robustness gate as sigma2
// (s1_robust_sigma): a packet that violates the current threshold is excluded,
// so a sustained attack cannot walk the percentile up to swallow itself --
// the identical self-masking failure fixed in 033210a. Below the minimum
// sample count the estimate is not yet meaningful and the detector falls back
// to the k*sigma bound, so early-run behaviour is unchanged.
// DEFAULT FLIPPED TO OFF, 2026-08-27, after measuring it. Zero-attack
// baseline, 300 s seed 1, both arms from one binary with only this flag
// varied:
//     k*sigma      6,156 S1 firings   OBU window FPR 18.86 %
//     percentile   8,005 S1 firings   OBU window FPR 44.66 %
// i.e. 2.4x WORSE, against a 1 % target.
//
// The defect is the histogram's admission rule below, not the approach. It is
// fed only samples that did not breach the current threshold -- copied from
// sigma's robustness gate -- but for a quantile that is truncation, not
// protection: the distribution is cut off at the very threshold derived from
// it, so each cycle's estimate sinks further with no floor. Measured, the
// threshold median collapsed 23.27 ms -> 4.00 ms. Exactly the runaway the
// sigma path documents and defeats with a floor; this one had none.
//
// Correction proposed but NOT built: calibrate on delta_best (best-effort
// delay), which the attack model leaves untouched by construction -- eq:rule_s1's
// selectivity conjunct is precisely that only HIGH-priority traffic is delayed.
// The estimator then never observes the samples it judges, so the loop cannot
// close. Left default-off until that is built and measured.
bool     s1_use_percentile = false;   // --s1_use_percentile: item 7 (default OFF, see above)
double   s1_pctl           = 0.99;    // --s1_pctl: quantile, e.g. 0.99 = p99
uint32_t s1_pctl_min_n     = 200;     // min samples before the percentile is trusted
// 1 ms bins. 1000 bins covers 0..1 s; anything above lands in the top bin,
// which is correct for a cutoff estimator (an over-1s benign hop is already
// far beyond any threshold we would set).
static const uint32_t S1_HIST_BINS   = 1000;
static const double   S1_HIST_BIN_S  = 0.001;   // 1 ms per bin
std::vector<std::vector<uint32_t>> s1_delay_hist;   // [rsu][bin] benign-delay counts
std::vector<uint32_t> s1_hist_n;                    // [rsu] total admitted samples
std::vector<double>   s1_pctl_threshold;            // [rsu] cached quantile (s)

// Per-RSU observed-delay accumulators for the EWMA input δ_r(t) (Eq. 3.12).
// Accumulated inside s1_detect_packet() for every valid packet; drained
// and reset at each s1_update_baseline() call site in routing.cc.
std::vector<double>   s1_rsu_obs_sum;
std::vector<uint32_t> s1_rsu_obs_count;

// Supervisor Fix 3 (2026-08-14): LSTM-only per-cycle MAX hop-delay and Δ_max
// exceedance flag, accumulated alongside s1_rsu_obs_sum/count at the exact
// same site (s1_detect_packet()) but NOT consumed by s1_update_baseline() —
// obs_delay (the mean) still drives S1's own EWMA baseline, unchanged;
// these feed ONLY the LSTM's replacement δ_t_max feature and its new 11th
// binary-exceedance feature (eq:lstm_input, both changed per Fix 3). Kept
// separate rather than reusing s1_rsu_obs_sum/count specifically so S1's
// rule-based detection logic is untouched by this change.
std::vector<double> s1_rsu_obs_max;      // max(effective_delay_s) this cycle
std::vector<bool>   s1_rsu_exceeded_dmax; // true if any packet this cycle had delay > Delta_max (50ms)
// Same value as S2_DELTA_MAX (s2_detection.h) -- redefined locally rather
// than depending on it, since s1_detection.h is #include'd before
// s2_detection.h in routing.cc and S2_DELTA_MAX isn't visible here yet.
static const double LSTM_DELTA_MAX_S = 0.050;

// Per-RSU δ_best(r,t): mean per-hop delay of best-effort (non-high-priority)
// packets, the S1 selectivity conjunct (main.tex eq:rule_s1, symbol table
// ~L1298). Accumulated in s1_detect_packet() for non-safety-critical
// packets; drained into s1_delta_best[] once per cycle at the same call
// site that drains s1_rsu_obs_sum/count, mirroring δ̄_r(t)'s own per-cycle
// cadence. No-observation cycles default to 0.0 (fail-open: absence of
// best-effort traffic must not suppress a genuine S1 detection).
std::vector<double>   s1_best_obs_sum;
std::vector<uint32_t> s1_best_obs_count;
std::vector<double>   s1_delta_best;

// =========================================================================
// s1_update_baseline():
// Updates the mobility-adjusted baseline δ̄_r(t) for one RSU (Eq. 3.11).
// σ²_r(t) is NOT updated here — see s1_detect_packet() below for why.
//
//   rsu_idx       — RSU index (0..N_RSUs-1), NOT the ns-3 node ID
//   rho_t         — current vehicle density ρ(t) for this RSU
//   v_bar_t       — current mean vehicle speed v̄(t) in m/s
//   observed_delay — δ_r(t): last cycle-averaged forwarding delay (seconds),
//                    used only for the LSTM per-cycle delta_t log column
//                    (see routing.cc call site) — NOT for σ² (see below).
// =========================================================================
inline void s1_update_baseline(uint32_t rsu_idx,
                                double   rho_t,
                                double   v_bar_t,
                                double   observed_delay)
{
    if (rsu_idx >= (uint32_t)N_RSUs) return;

    // Eq. 3.11: δ̄_r(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
    double inv_v = (v_bar_t > 0.1) ? (1.0 / v_bar_t) : 10.0;
    double db = s1_delta0 + s1_alpha_rho * rho_t + s1_alpha_v * inv_v;

    // Floor at delta_0 (added 2026-08-08). main.tex:2205-2211 states the baseline
    // "increases linearly with vehicle density" and "decreases with mean speed" --
    // i.e. eq:mobility_baseline intends alpha_rho > 0 AND alpha_v > 0, since the
    // speed term is alpha_v * v_bar^-1 and only a POSITIVE alpha_v decays toward
    // delta_0 as v_bar rises. With both coefficients sign-correct, v_bar^-1 > 0
    // makes both correction terms positive, so delta_bar >= delta_0 identically:
    // the baseline decays TOWARD delta_0, never below it.
    //
    // The 2026-08-08 calibration violates that: alpha_v = -0.00150238 (negative).
    // Because inv_v is capped at 10.0 for stopped vehicles (v_bar <= 0.1 m/s,
    // 14.9% of RSU-cycles on the seed-1 trace), alpha_v*inv_v reaches -15.02ms and
    // swamps delta_0 = +4.47ms, driving delta_bar NEGATIVE in 15.2% of samples
    // (min -10.44ms; confirmed in the live Q1 logs). A negative expected delay is
    // physically meaningless, and since threshold = delta_bar + k*sigma it DEPRESSES
    // the firing threshold precisely in stopped/congested traffic -- where benign
    // delays are highest -- inflating S1 false positives.
    //
    // This floor enforces the constraint the fitted coefficients should have
    // satisfied. It is a guard, not a model change: with sign-correct coefficients
    // it never binds. The real fix is a sign-constrained (non-negative) re-fit in
    // rule_calibrator.py -- with R^2 = 0.0074 the OLS is fitting noise, so the
    // coefficient signs are essentially arbitrary. Remove this floor once the
    // calibration is re-run under that constraint.
    s1_delta_bar[rsu_idx] = (db > s1_delta0) ? db : s1_delta0;
    (void)observed_delay;   // no longer feeds sigma2 here — see s1_detect_packet()

    // Item 7: recompute this RSU's percentile cutoff once per cycle, the same
    // cadence delta_bar updates on. Walking S1_HIST_BINS once per RSU per cycle
    // is negligible; doing it per packet would not be.
    //
    // Cutoff = the upper edge of the bin containing the s1_pctl quantile, so
    // the returned value is one a genuinely benign delay at that quantile falls
    // UNDER rather than exactly on -- a strictly-greater-than comparison at the
    // firing site would otherwise fire on the quantile sample itself.
    if (s1_use_percentile &&
        rsu_idx < s1_delay_hist.size() &&
        rsu_idx < s1_hist_n.size() &&
        rsu_idx < s1_pctl_threshold.size() &&
        s1_hist_n[rsu_idx] >= s1_pctl_min_n)
    {
        const uint32_t _target = (uint32_t)(s1_pctl * (double)s1_hist_n[rsu_idx]);
        uint32_t _cum = 0;
        uint32_t _bin = S1_HIST_BINS - 1;
        for (uint32_t b = 0; b < S1_HIST_BINS; ++b)
        {
            _cum += s1_delay_hist[rsu_idx][b];
            if (_cum >= _target) { _bin = b; break; }
        }
        s1_pctl_threshold[rsu_idx] = (double)(_bin + 1) * S1_HIST_BIN_S;
    }
}

// =========================================================================
// s1_update_best_effort_baseline():
// Sets δ_best(r,t) — mean best-effort packet delay for this cycle — from
// the accumulator drained by the caller (mirrors s1_update_baseline()'s
// obs_delay pattern). Call once per RSU per cycle, right after draining
// s1_best_obs_sum/count, matching δ̄_r(t)'s own update cadence.
// =========================================================================
inline void s1_update_best_effort_baseline(uint32_t rsu_idx, double delta_best_t)
{
    if (rsu_idx >= (uint32_t)N_RSUs) return;
    s1_delta_best[rsu_idx] = delta_best_t;
}

// =========================================================================
// Handoff-induced legitimate jitter (mobility amplification fix §4.2,
// docs/MOBILITY_AMPLIFICATION_FIX_PLAN.md). A vehicle that just handed off
// to a new serving RSU (handoff_tracker.h, §4.1) incurs a one-time
// flow-rule recomputation/reinstallation cost before the new RSU's data
// plane is fully set up — main.tex Mechanism 1, ~L1524, citing
// Islam2021SDVN: "legitimate handoff latencies of 50-300 ms during
// flow-rule recomputation and reinstallation". Reused directly as the
// jitter band here rather than inventing a new number.
//
// Drawn from ns-3's own seeded UniformRandomVariable (governed by
// RngSeedManager::SetSeed/SetRun in main(), same reproducibility
// convention as GetBooleanWithProbability()/ShuffleNodeIndices() in
// routing.cc) — NOT srand()/rand(), so results stay deterministic per
// sim_seed + sim_run.
// =========================================================================
const double S1_HANDOFF_JITTER_MIN_S = 0.050;   // 50 ms, Islam2021SDVN lower bound
const double S1_HANDOFF_JITTER_MAX_S = 0.300;   // 300 ms, Islam2021SDVN upper bound

inline double s1_sample_handoff_jitter()
{
    static Ptr<UniformRandomVariable> rng = nullptr;
    if (!rng) {
        rng = CreateObject<UniformRandomVariable>();
        rng->SetAttribute("Min", DoubleValue(S1_HANDOFF_JITTER_MIN_S));
        rng->SetAttribute("Max", DoubleValue(S1_HANDOFF_JITTER_MAX_S));
    }
    return rng->GetValue();
}

// =========================================================================
// s1_detect_packet():
// Evaluates Signature S1 for one packet at one RSU (Eq. 3.4 / 3.14).
//
// Returns true when BOTH hold:
//   1. δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)   [delay threshold violation]
//   2. Priority(p) = HIGH                   [safety-critical packet only]
//
//   rsu_idx        — RSU index (0..N_RSUs-1), derived from current_hop
//   vehicle_id     — originating vehicle's sim index (0..N_Vehicles-1).
//                    Used solely to check handoff_just_occurred()
//                    (handoff_tracker.h, §4.1) for the handoff-jitter term
//                    below — not otherwise part of Eq. 3.4/3.14.
//   packet_delay_s — t_recv - t_claimed_fwd for this hop (seconds)
//   is_safety_crit — Priority(p) = HIGH
//   sender_node_id — sim index of the node that SENT this packet (the RSU
//                    that applied the injected delay — this is the malicious
//                    node to record in the detection event, NOT current_hop)
//   current_hop    — receiving RSU node ID (for EWMA baseline and logging)
//   packet_id      — packet ID (for logging)
//   flow_id        — flow ID (for logging)
// =========================================================================
inline bool s1_detect_packet(uint32_t rsu_idx,
                              uint32_t vehicle_id,
                              double   packet_delay_s,
                              bool     is_safety_crit,
                              uint32_t sender_node_id,
                              uint32_t current_hop,
                              uint32_t packet_id,
                              uint32_t flow_id,
                              // Synthetic-sample opt-out. The TCAM flow generator
                              // (tcam_flow_generator.h:114) feeds this function a
                              // hardcoded benign 1.5 ms hop delay attributed to a
                              // VEHICLE, purely to keep the per-RSU EWMA baseline
                              // and variance fed. That contradicts this function's
                              // own contract for sender_node_id (documented above
                              // as the RSU that applied the delay), and because S1
                              // always records into S1_HOME_VARIANT = 0 = Attack 1,
                              // where ground truth marks only RSUs malicious, every
                              // such firing is a guaranteed false positive. It fired
                              // often: once the EWMA converges on sub-millisecond
                              // hops, a 1.5 ms sample clears baseline + k*sigma.
                              // Measured on A1 @60% seed 1 90 s: 32 distinct
                              // vehicles accused, 32 of S1's 47 false positives.
                              // With this true the sample still updates the
                              // baseline and variance -- all the generator wanted --
                              // but records no detection event.
                              bool     suppress_detection = false)
{
    if (rsu_idx >= (uint32_t)N_RSUs) return false;

    // §4.2: fold in handoff-induced jitter before this packet's delay feeds
    // anything downstream (accumulation, EWMA variance, threshold test).
    // handoff_just_occurred(vehicle_id) is true only for the cycle
    // handoff_tracker_cycle_update() (routing.cc) detected this vehicle's
    // serving-RSU change, so the jitter applies once, to whichever
    // packet(s) from that vehicle land in that same cycle — not a
    // hand-tuned function of ρ(t)/v̄(t). Handoffs simply happen more often
    // as v̄ increases (zone residence time shrinks, eq:observation_window),
    // so this term fires more often at higher mobility without needing a
    // per-speed-point knob (see §7 overfitting risk).
    double effective_delay_s = packet_delay_s;
    if (packet_delay_s > 0.0 && handoff_just_occurred(vehicle_id))
    {
        double jitter_s = s1_sample_handoff_jitter();
        effective_delay_s += jitter_s;
        if (DETECTION_DEBUG_LOG_S1)
            cout << "[S1] Handoff jitter: vehicle " << vehicle_id
                 << " handed off this cycle — adding " << jitter_s * 1000.0
                 << "ms (raw delay=" << packet_delay_s * 1000.0
                 << "ms, effective=" << effective_delay_s * 1000.0 << "ms)." << endl;
    }

    // Condition 2: Priority(p) = HIGH — mandatory conjunction (Eq. 3.4).
    // Best-effort packets can never trigger S1 themselves, but their delay
    // still feeds δ_best(r,t) (the selectivity conjunct below) — accumulate
    // before returning.
    if (!is_safety_crit)
    {
        if (packet_delay_s > 0.0)
        {
            s1_best_obs_sum[rsu_idx]   += effective_delay_s;
            s1_best_obs_count[rsu_idx] += 1;
        }
        return false;
    }

    double delta_bar = s1_delta_bar[rsu_idx];
    double sigma     = std::sqrt(s1_sigma2[rsu_idx]);
    double threshold = delta_bar + s1_k * sigma;

    // Item 7: prefer the non-parametric cutoff once this RSU has enough benign
    // samples for the quantile to mean anything. Falls back to the k*sigma
    // bound before then, so warm-up behaviour is unchanged. See the
    // s1_use_percentile declaration for why the shape assumption is the
    // problem being fixed.
    if (s1_use_percentile &&
        rsu_idx < s1_pctl_threshold.size() &&
        rsu_idx < s1_hist_n.size() &&
        s1_hist_n[rsu_idx] >= s1_pctl_min_n &&
        s1_pctl_threshold[rsu_idx] > 0.0)
    {
        threshold = s1_pctl_threshold[rsu_idx];
    }

    // Accumulate observed hop-delay for the LSTM per-cycle delta_t log column
    // (cycle-averaged; see s1_update_baseline()'s call site in routing.cc).
    // UNCONDITIONAL regardless of training mode — same "no only-if-compliant
    // clause" reasoning as below.
    if (packet_delay_s > 0.0)
    {
        s1_rsu_obs_sum[rsu_idx]   += effective_delay_s;
        s1_rsu_obs_count[rsu_idx] += 1;
        // Fix 3: LSTM-only max/exceedance tracking, same per-packet
        // population as the mean above, but not fed into S1's own baseline.
        if (effective_delay_s > s1_rsu_obs_max[rsu_idx])
            s1_rsu_obs_max[rsu_idx] = effective_delay_s;
        if (effective_delay_s > LSTM_DELTA_MAX_S)
            s1_rsu_exceeded_dmax[rsu_idx] = true;
    }

    // Eq. 3.12/3.13: σ²_r(t) = β·σ²_r(t-1) + (1-β)·(δ_r(t)-δ̄_r(t))², updated
    // from THIS packet's raw delay δ_p (effective_delay_s, i.e. including
    // §4.2's handoff jitter — the detector only ever observes the total
    // delay, not a decomposition of it), not a cycle-averaged proxy. Eq.
    // 3.14's own comparand is δ_p (per-packet), so σ_r(t) must be
    // estimated from the same per-packet population it is compared against.
    // The previous version fed σ² from the cycle-AVERAGED obs_delay once per
    // cycle (s1_update_baseline()) while s1_detect_packet() compared raw
    // per-packet delays against the resulting threshold — averaging N packets
    // shrinks variance by ~1/N (Var(mean)=Var(x)/N), so the threshold's k·σ
    // margin was calibrated ~sqrt(N) too tight for what it was actually being
    // tested against. Confirmed: 11,193 S1 triggers in a single 38-cycle/40s
    // run (FPR 28-50%, target ≤1%) collapsed to a normal firing rate once σ²
    // was switched to this per-packet estimate.
    // Kept UNCONDITIONAL (updates on every packet, including violations) for
    // the same reason as before: excluding violating packets from the update
    // created a self-reinforcing feedback loop where a shrinking σ excludes
    // more packets, shrinking σ further with no floor — confirmed via FP
    // climbing continuously across an entire benign-only run rather than
    // plateauing after warmup.
    // s1_robust_sigma (see its declaration for the measured justification):
    // skip the update for packets that BREACH the current threshold, so an
    // attack cannot raise the bar that is supposed to catch it, then clamp
    // from below so the exclusion can never run away downward. threshold
    // here is the pre-update value computed above, so this tests the packet
    // against the state that judged it.
    double deviation = effective_delay_s - delta_bar;
    const bool _sigma_violating = (effective_delay_s > threshold);
    if (!s1_robust_sigma || !_sigma_violating)
    {
        s1_sigma2[rsu_idx] = s1_beta * s1_sigma2[rsu_idx]
                           + (1.0 - s1_beta) * deviation * deviation;
    }
    if (s1_robust_sigma)
    {
        const double _sigma2_min = s1_sigma_floor * s1_sigma_floor;
        if (s1_sigma2[rsu_idx] < _sigma2_min) s1_sigma2[rsu_idx] = _sigma2_min;
    }

    // Item 7: feed the benign-delay histogram under the SAME admission gate as
    // sigma2 above -- a packet that breached the current threshold is presumed
    // attack-or-anomaly and excluded, so a sustained attack cannot walk the
    // percentile up until it no longer fires (the self-masking failure fixed
    // in 033210a, which would otherwise reappear here in a new form).
    // O(1) per packet; the quantile itself is recomputed once per cycle in
    // s1_update_baseline().
    if (s1_use_percentile && !_sigma_violating &&
        rsu_idx < s1_delay_hist.size() && effective_delay_s >= 0.0)
    {
        uint32_t _bin = (uint32_t)(effective_delay_s / S1_HIST_BIN_S);
        if (_bin >= S1_HIST_BINS) _bin = S1_HIST_BINS - 1;   // clamp into top bin
        s1_delay_hist[rsu_idx][_bin]++;
        if (rsu_idx < s1_hist_n.size()) s1_hist_n[rsu_idx]++;
    }

    // Condition 3 (selectivity, eq:rule_s1): δ_best(r,t) ≤ δ̄_r(t)+k·σ_r(t).
    // Under genuine congestion, best-effort traffic is delayed alongside
    // high-priority traffic, so δ_best exceeds the same threshold and this
    // conjunct evaluates false — S1 must not fire. Under Attack 1, only
    // high-priority packets are delayed, so δ_best stays low and this
    // conjunct passes.
    double delta_best   = s1_delta_best[rsu_idx];
    bool   selective_ok  = (delta_best <= threshold);

    // Issue 5 fix (2026-08-02, ground truth vs detection decision): latch
    // g_s1_gt_delay_exceeded independently of selective_ok/detection dedup —
    // this is "did the packet's delay genuinely exceed Eq. 3.4's own
    // threshold," not "did S1 fire." See its declaration (routing.cc) for
    // why calculate_security_detection_metrics() needs this instead of the
    // static is_malicious_node[0] identity flag.
    //
    // 2026-08-05: this latch is also why g_disable_s1_s2 must NOT skip the
    // call to this function (see lrad.h). It is A1's GROUND TRUTH, read at
    // routing.cc:117328. When the ablation skipped the call, the latch never
    // set, every A1 node scored benign, and A1 reported TP+FN=0 in Q2/Q3/Q4 —
    // which reads as "the attack produced no detectable event" when the real
    // meaning is "nothing was measuring whether it did." Ground truth must
    // never depend on which detector a diagnostic flag switches off.
    if (effective_delay_s > threshold && sender_node_id < (uint32_t)total_size)
        g_s1_gt_delay_exceeded[sender_node_id] = true;

    if (DETECTION_DEBUG_LOG_S1)
        cout << "[S1] RSU_idx=" << rsu_idx
             << " node=" << current_hop
             << " flow=" << flow_id
             << " pkt=" << packet_id
             << " delay=" << effective_delay_s * 1000.0 << "ms"
             << " baseline=" << delta_bar * 1000.0 << "ms"
             << " sigma=" << sigma * 1000.0 << "ms"
             << " threshold=" << threshold * 1000.0 << "ms"
             << " delta_best=" << delta_best * 1000.0 << "ms"
             << " [SAFETY-CRITICAL]" << endl;

    // Condition 1: δ_p > δ̄_r(t) + k·σ_r(t)  (Eq. 3.14)
    // Condition 3: δ_best(r,t) ≤ δ̄_r(t) + k·σ_r(t)  (selectivity, eq:rule_s1)
    if (effective_delay_s > threshold && selective_ok)
    {
        cout << "[S1] ⚠️ SIGNATURE S1 TRIGGERED!"
             << " Delay " << effective_delay_s * 1000.0
             << "ms exceeds threshold " << threshold * 1000.0 << "ms"
             << " (baseline=" << delta_bar * 1000.0
             << "ms + " << s1_k << "σ=" << (s1_k * sigma * 1000.0) << "ms)"
             << " on safety-critical flow " << flow_id
             << " at RSU node " << current_hop
             << " t=" << Simulator::Now().GetSeconds() << "s" << endl;

        // Record detection against the SENDER (the RSU that applied the delay),
        // not current_hop (the innocent receiver). is_malicious_node[0] is set
        // on the sending RSU under the compromised controller — recording
        // current_hop would produce a FP (benign receiver) and FN (malicious
        // sender missed), corrupting TP/FP/TN/FN counts.
        //
        // Bucket is S1's OWN designated variant (0 = Attack 1, Selective Delay
        // CP), NOT active_attack_variant. main.tex Attack Signature
        // Identification (line ~1722): "We derive one primary signature per
        // variant" — S1 is permanently Attack 1's signature regardless of
        // which attack_number the CLI selected for this run. S1 has no
        // variant gate (evaluates every safety-critical packet unconditionally,
        // matching tcam_detection.h's S3/S4 precedent), so using
        // active_attack_variant here misattributed every S1 firing into
        // whichever OTHER attack's confusion matrix was being measured —
        // confirmed 2026-07-14: S1 contributed 22 of 221 detection events
        // recorded into Attack 6's own bucket during an A6-only run.
        // g_disable_s1_s2 gates the DETECTION RECORD only, never the ground-truth
        // latch above — the same asymmetry, for the same reason, as
        // g_disable_s3_s4 in tcam_detection.h.
        const int S1_HOME_VARIANT = 0;   // Attack 1, per main.tex Signature S1
        if (!g_disable_s1_s2 && !suppress_detection &&
            sender_node_id < (uint32_t)total_size &&
            !is_detected_node[S1_HOME_VARIANT][sender_node_id])
        {
            record_detection_event(S1_HOME_VARIANT, sender_node_id, DSRC_RULE_S1);
            cout << "[S1] record_detection_event fired for sender node "
                 << sender_node_id << " (detected at RSU " << current_hop
                 << ") variant=" << S1_HOME_VARIANT
                 << " at t=" << Simulator::Now().GetSeconds() << "s" << endl;
        }
        return true;
    }

    if (effective_delay_s > threshold && !selective_ok)
    {
        if (DETECTION_DEBUG_LOG_S1)
            cout << "[S1] Threshold exceeded but selectivity conjunct failed: "
                 << "delta_best=" << delta_best * 1000.0 << "ms > threshold "
                 << threshold * 1000.0 << "ms — best-effort traffic also delayed, "
                 << "treating as genuine congestion, not Attack 1." << endl;
    }
    else
    {
        if (DETECTION_DEBUG_LOG_S1)
            cout << "[S1] No violation: delay " << effective_delay_s * 1000.0
                 << "ms within threshold " << threshold * 1000.0 << "ms" << endl;
    }
    return false;
}

// =========================================================================
// s1_init_state():
// Allocates and zero-initialises all per-RSU S1 vectors to exactly n_rsus
// entries. Must be called once after N_RSUs is finalised (i.e. from
// initialise_stub_attack_state() in routing.cc), before any detection or
// baseline-update calls.
// =========================================================================
inline void s1_init_state(uint32_t n_rsus)
{
    // Seed delta_bar from eq:mobility_baseline's own intercept (delta_0),
    // NOT 0.0. delta_bar_r(t) = delta_0 + alpha_rho*rho(t) + alpha_v*v_bar(t)^-1
    // is a closed-form formula computable at any t, including t=0 -- it is
    // not a "starts empty, learns over time" accumulator. delta_0 alone is
    // an accurate seed here since alpha_rho/alpha_v are calibrated near-zero
    // (R^2=0.0004, see the calibration note above -- "baseline effectively
    // collapses to delta_0"). Leaving this at 0.0 previously made the very
    // first packets face threshold=delta_bar+k*sigma=0, so any nonzero delay
    // trivially "violated" it -- a confirmed false-positive source (280 of
    // 719 S1 triggers in one 0%-attack run showed baseline=0.000ms). sigma2
    // legitimately starts at 0.0: eq:ewma_variance is a recursive update
    // that needs a seed, and "no prior variance information" is the
    // standard EWMA bootstrap convention, unlike delta_bar which has no
    // such recursion to justify starting from zero.
    s1_delta_bar.assign(n_rsus, s1_delta0);
    s1_sigma2.assign(n_rsus, 0.0);
    // Item 7 percentile-threshold state.
    s1_delay_hist.assign(n_rsus, std::vector<uint32_t>(S1_HIST_BINS, 0u));
    s1_hist_n.assign(n_rsus, 0u);
    s1_pctl_threshold.assign(n_rsus, 0.0);
    s1_rsu_obs_sum.assign(n_rsus, 0.0);
    s1_rsu_obs_count.assign(n_rsus, 0);
    s1_rsu_obs_max.assign(n_rsus, 0.0);
    s1_rsu_exceeded_dmax.assign(n_rsus, false);
    // δ_best(r,t) seeded to 0.0 (fail-open — see s1_best_obs_sum/count
    // declaration comment): the first cycle has no prior best-effort
    // observation, and 0.0 ≤ any threshold keeps the selectivity conjunct
    // from spuriously blocking a genuine first-cycle S1 detection.
    s1_best_obs_sum.assign(n_rsus, 0.0);
    s1_best_obs_count.assign(n_rsus, 0);
    s1_delta_best.assign(n_rsus, 0.0);
    cout << "[S1] S1 per-RSU state initialised for " << n_rsus << " RSUs "
         << "(delta_bar seeded to delta_0=" << s1_delta0 * 1000.0 << "ms)." << endl;
}

// =========================================================================
// s1_reset_state():
// Zeros all per-RSU S1 state without reallocating (for mid-run resets).
// Requires s1_init_state() to have been called first.
// =========================================================================
inline void s1_reset_state()
{
    // See s1_init_state() for why delta_bar is seeded to s1_delta0, not 0.0.
    std::fill(s1_delta_bar.begin(),     s1_delta_bar.end(),     s1_delta0);
    std::fill(s1_sigma2.begin(),        s1_sigma2.end(),        0.0);
    // Item 7 percentile-threshold state -- cleared with the rest so a reset
    // genuinely restarts the estimate rather than carrying stale counts.
    for (auto& _h : s1_delay_hist) std::fill(_h.begin(), _h.end(), 0u);
    std::fill(s1_hist_n.begin(),         s1_hist_n.end(),         0u);
    std::fill(s1_pctl_threshold.begin(), s1_pctl_threshold.end(), 0.0);
    std::fill(s1_rsu_obs_sum.begin(),   s1_rsu_obs_sum.end(),   0.0);
    std::fill(s1_rsu_obs_count.begin(), s1_rsu_obs_count.end(), 0u);
    std::fill(s1_best_obs_sum.begin(),   s1_best_obs_sum.end(),   0.0);
    std::fill(s1_best_obs_count.begin(), s1_best_obs_count.end(), 0u);
    std::fill(s1_delta_best.begin(),     s1_delta_best.end(),     0.0);
    cout << "[S1] All S1 per-RSU baseline/variance state reset "
         << "(delta_bar seeded to delta_0=" << s1_delta0 * 1000.0 << "ms)." << endl;
}

#endif // S1_DETECTION_H
