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
double s1_beta      = 0.95;         // EWMA factor — analytic N_eff=1/(1-β)=20, band 9<=N_eff<=22 (main.tex:6049; supervisor 2026-08-13)

// Per-RSU EWMA baseline and variance, indexed by RSU index (0..N_RSUs-1).
// Sized dynamically at runtime by s1_init_state(N_RSUs) — no hardcoded ceiling.
std::vector<double>   s1_delta_bar;     // δ̄_r(t): mobility-adjusted baseline per RSU
std::vector<double>   s1_sigma2;        // σ²_r(t): EWMA variance per RSU

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
                              uint32_t flow_id)
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
    double deviation = effective_delay_s - delta_bar;
    s1_sigma2[rsu_idx] = s1_beta * s1_sigma2[rsu_idx]
                       + (1.0 - s1_beta) * deviation * deviation;

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
        if (!g_disable_s1_s2 &&
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
    std::fill(s1_rsu_obs_sum.begin(),   s1_rsu_obs_sum.end(),   0.0);
    std::fill(s1_rsu_obs_count.begin(), s1_rsu_obs_count.end(), 0u);
    std::fill(s1_best_obs_sum.begin(),   s1_best_obs_sum.end(),   0.0);
    std::fill(s1_best_obs_count.begin(), s1_best_obs_count.end(), 0u);
    std::fill(s1_delta_best.begin(),     s1_delta_best.end(),     0.0);
    cout << "[S1] All S1 per-RSU baseline/variance state reset "
         << "(delta_bar seeded to delta_0=" << s1_delta0 * 1000.0 << "ms)." << endl;
}

#endif // S1_DETECTION_H
