#ifndef CRYPTO_LAYER_H
#define CRYPTO_LAYER_H

// routing.cc defines 'max' and 'min' as object-like macros (#define max 40).
// Save and remove them for all header includes below so that openssl/oqs headers
// that use max/min as function calls compile correctly. Restored at end of header.
#pragma push_macro("max")
#pragma push_macro("min")
#undef max
#undef min

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <algorithm>
#include <chrono>   // M7: wall-clock timing of batch verification (eq:t_verify)
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <oqs/oqs.h>
// ns3/simulator.h and ns3/log.h are already included earlier in routing.cc.

#pragma pop_macro("min")
#pragma pop_macro("max")

// Forward declarations — bc_commit_dkg defined in bc_blockchain_helper.h (included after this).
void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][64],
                   uint32_t n_rsus, double ts_setup);
// bc_commit_tref_to_chain defined in bc_blockchain_helper.h (included after this) —
// called from update_T_ref() below so every T_SYNC_INTERVAL tick's T_ref(t) is
// committed on-chain (main.tex sec:time_ref: "T_ref(t) is committed to the
// blockchain by RSU consensus at regular intervals to provide a tamper-evident
// audit trail"), same pattern as bc_commit_dkg above.
void bc_commit_tref_to_chain(double t_ref_value, double eps_ref, double ts);
// dkg_rotate_keys defined in dkg_setup.h (included after this) — called from trust_update_negative
// per eq:key_rotation_trigger when a quarantined node is an RSU.
inline void dkg_rotate_keys(uint32_t revoked_rsu_node_index);

// crypto_log_event defined in crypto_event_log.h (included after this header in
// routing.cc, same translation unit) — forward-declared so crypto_batch_verify_tick
// can emit a "batch_verify" row into crypto_timing_log.csv (M7, eq:t_verify).
// CryptoTimePoint alias must match crypto_event_log.h exactly (legal redeclaration).
using CryptoTimePoint = std::chrono::high_resolution_clock::time_point;
inline void crypto_log_event(const char* op, uint32_t node_id, uint32_t pkt_id,
                             uint32_t flow_id, CryptoTimePoint t0, bool result);

// ── Evidence-quality debug logging ───────────────────────────────────────────
// Normal runs: CRYPTO_DEBUG_LOG = false → zero terminal noise, CSV unaffected.
// flip to true for rich per-operation output proving every
// cryptographic component is executing with real liboqs/OpenSSL values.
// High-frequency per-packet ops are gated on this flag.
// Low-frequency high-importance events (DKG, quarantine, failures, blockchain
// commits) fire unconditionally regardless of this flag.
static bool CRYPTO_DEBUG_LOG = false;  // default true for dev/debug, false for normal runs

// Formats first 4 bytes of buf as compact hex — evidence token in debug lines.
static std::string _hex4(const uint8_t* b) {
    char s[9];
    snprintf(s, sizeof(s), "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    return std::string(s);
}

// Formats first 8 bytes as hex — used in [PKT-CRYPTO] verbose field logs.
static std::string _hex8(const uint8_t* b) {
    char s[17];
    snprintf(s, sizeof(s), "%02x%02x%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
    return std::string(s);
}

// Formats a uint32 as 8-char hex — for nonce / zone / next_hop in verbose logs.
static std::string _hex32(uint32_t v) {
    char s[9];
    snprintf(s, sizeof(s), "%08x", v);
    return std::string(s);
}

// ── SHA3-512 and HMAC-SHA3-512 via OpenSSL ───────────────────────────────────

static inline bool sha3_512_hash(const uint8_t* data, size_t len, uint8_t* out_64) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    unsigned int out_len = 64;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out_64, &out_len) == 1 && out_len == 64);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static inline bool hmac_sha3_512(const uint8_t* key, size_t klen,
                           const uint8_t* data, size_t dlen, uint8_t* out_64) {
    unsigned int out_len = 64;
    return HMAC(EVP_sha3_512(), key, (int)klen, data, dlen, out_64, &out_len) != nullptr
           && out_len == 64;
}

// ── Tunable Parameters (all CLI-exposed) ─────────────────────────────────────

double   TRUST_DELTA_R      = 0.05;
double   TRUST_DELTA_P      = 0.10;
double   TRUST_T_MIN        = 0.50;
double   TRUST_T_MIN_CTRL   = 0.50;
double   TRUST_DELTA_R_CTRL = 0.05;
double   TRUST_DELTA_P_CTRL = 0.10;
double   STARK_DELTA_MAX    = 0.050;
double   ML_DSA_SIGN_DELAY  = 0.0015;
double   T_SYNC_INTERVAL    = 1.0;
uint32_t BATCH_SIZE         = 15;
double   WITNESS_WINDOW     = 10.0;
uint32_t WITNESS_F          = 1;
double   VOL_RATE_THRESH    = 5.0;

// M5 — Controller failover latency modeling (eq:sc_revoke → eq:ctrl_failover).
// Per the proposal, SC.Revoke commits the revocation on-chain and broadcasts a
// ControllerRevoked event; each affected RSU re-executes failover on receipt
// ("immediately" on arrival — the arg-min compute itself is instantaneous), so
// L_failover is dominated by event propagation under geographic dispersion.
// Modeled as a base broadcast latency plus a per-zone-distance increment to the
// RSU's NEW controller (same 1-D zone-index proxy ctrl_reassign_rsus already
// uses for d(r_k,c_j)); distant RSUs finish later, giving eq:l_failover's max
// real straggler content. Both CLI-exposed.
double   FAILOVER_BCAST_BASE_MS     = 10.0;  // on-chain commit + event emission
double   FAILOVER_BCAST_PER_ZONE_MS = 1.0;   // per unit zone-index distance

// ── Ablation gate flags (Phase 3, SIGNATURE_ATTACK_DECOUPLING_PLAN.md) ──────
// One boolean per ablated component, all defaulting to the full/proposed
// behavior (true), each checked at the single natural chokepoint for that
// component. Disabling a STARK proof makes it vacuously PASS (contributes
// nothing) rather than vacuously fail, so signatures fall back to their
// other, non-STARK conjuncts (AB4-A/B/C in docs/main.tex). All CLI-exposed
// via crypto_register_cli_params().
bool enable_lrad_obu               = true;  // AB1: OBU rule engine (lrad_obu)
bool enable_lrad_rsu               = true;  // AB1: RSU full-mode engine (lrad_rsu)
// DIAGNOSTIC ONLY (added 2026-07-25) — disables S1 + S2 (both partial and full)
// while leaving S3-S8 untouched, unlike enable_lrad_obu/rsu which are coarse
// mode-level switches that would also disable S5-S8 (they share enable_lrad_rsu's
// gate). Default false: normal/default-settings runs are completely unaffected.
// For isolating a single signature's own FPR from S1/S2 cross-signal noise on the
// shared trust ledger — NOT a replacement for default-settings evaluation numbers.
bool g_disable_s1_s2                = false;
// DIAGNOSTIC ONLY (added 2026-08-03, supervisor ablation study Q1-Q6) — three
// per-signature-group companions to g_disable_s1_s2. All default false: normal/
// default-settings runs are completely unaffected.
//
// NOTE the deliberate asymmetry in WHERE each flag is applied. It is not an
// inconsistency — it follows from what each signature's flag feeds downstream:
//
//   g_disable_s3_s4 — gates ONLY the confusion-matrix record_detection_event()
//     calls in tcam_detection.h, NOT flag_s3/flag_s4 themselves. S3/S4 fire in
//     calculate_security_detection_metrics(), architecturally independent of the
//     OBU/RSU LRAD wrapper (enable_lrad_obu/rsu do not gate them). flag_s3/flag_s4
//     must keep being computed from the RAW condition because they are published
//     as g_tcam_flag_s3_last/g_tcam_flag_s4_last and read by lrad_rsu() as the
//     eq:lstm_gate (main.tex:3317-3326) LSTM suppression gate. That gate's stated
//     rationale is STRUCTURAL — TCAM residual occupancy inflates reconstruction
//     error at non-attacking RSUs "throughout the simulation run" — a physical
//     condition a diagnostic flag does not change. Gating the flag itself would
//     silently un-suppress the LSTM during TCAM saturation and inflate FPR in
//     exactly the runs meant to isolate the LSTM (supervisor Q3 requires the
//     gate stay live while S3/S4's own output is disabled).
//
//   g_disable_s5_s6 / g_disable_s7_s8 — gate the SIGNATURE COMPUTATION ITSELF at
//     the lrad_rsu() call site (the s5_detect()..s8_detect() calls are skipped and
//     the flags stay false). Unlike S3/S4 these have no structural consumer: per
//     alg:lrad_rsu (main.tex:2544-2546) flag_S5..flag_S8 feed D_RSU, and through
//     it the BTMM trust penalty and the BC.Write detection-event record. Gating
//     only record_detection_event() would leave all three of those still firing,
//     so a "witness only" (Q4) or "crypto only" (Q2) configuration would not
//     actually isolate the component — the S7/S8 rule path would keep penalising
//     trust and writing to the ledger while claiming to be off. S7/S8 are
//     genuinely independent code from the witness/BFT mechanism
//     (enable_witness_mechanism, eq:dup_alert_cond/eq:bft_penalty below): both
//     target A7/A8 but on different evidence (S7/S8: fresh stark_verify_hop() +
//     volume rate; witness: cross-node alert pooling with its own ML-DSA-87
//     sign/verify), sharing only trust_update_negative() — which is precisely
//     why S7/S8 must be switchable off for the witness path to be measured alone.
bool g_disable_s3_s4                = false;
bool g_disable_s5_s6                = false;
bool g_disable_s7_s8                = false;

// ── Item 5 (supervisor, 2026-08-29): decouple R_anom from S7/S8 ───────────
// The A7/A8 ablation ladder's first rung is specified as "witness + R_anom".
// No Q-config could express that: the R_anom>0 zero-tolerance rule (lrad.h,
// DSRC_RULE_RANOM) rides the S7/S8 path and is gated by g_disable_s7_s8, so
// silencing S7/S8 to isolate the witness silenced R_anom with it, and the
// only config carrying R_anom (Q2) also carries the whole crypto layer.
//
// TRI-STATE, deliberately, so that no existing configuration changes
// behaviour:
//   -1 (default) = follow g_disable_s7_s8, exactly the pre-existing coupling
//    0           = force R_anom ON  even with S7/S8 silenced  <- the new rung
//    1           = force R_anom OFF even with S7/S8 live
// Every Q1-Q6 run therefore produces bit-identical results to before unless
// this flag is passed explicitly. Use g_ranom_is_disabled() to read it.
int g_disable_ranom                 = -1;
inline bool g_ranom_is_disabled()
{
    return (g_disable_ranom < 0) ? g_disable_s7_s8 : (g_disable_ranom != 0);
}
// DIAGNOSTIC ONLY (added 2026-08-05) — gates the §BTMM PER-PACKET trust update
// (eq:trust_update) at routing.cc's ML-DSA-87 verify block, i.e. the
// "if (hop_ok && timing_ok && g_batch_passed) trust_update_positive(...) else
// trust_update_negative(...)" pair. Default false: normal runs unaffected.
//
// Why this needed its own flag. That else-branch was reachable in EVERY Q1-Q6
// ablation configuration — none of the seven existing flags gated it — and it
// feeds trust_update_negative() -> quarantine -> record_detection_event(), the
// same confusion-matrix counters the ablation reads. timing_ok is a RAW
// wall-clock comparison with no crypto gate, so it stays live even under
// disable_crypto=1. Measured 2026-08-05 on Q4: TP+FP equalled the
// TRUST-QUARANTINE count EXACTLY on 7 of 8 variants (A1 14/14, A2 102/102,
// A3 0/0, A5 199/199, A6 190/190, A7 200/200, A8 68/68), i.e. not one
// "detection" in the witness-only config came from a signature or from the
// witness scoring a node — all of them came from this path. Until it is
// gated, no Q-config isolates the component named in its own row.
//
// NOT gated by this flag: the witness mechanism's own calls to
// trust_update_negative() (eq:bft_penalty), which are what Q4 exists to
// measure, and the controller-plane ctrl_trust_update_negative().
bool g_disable_btmm_trust           = false;
// DIAGNOSTIC (2026-08-06): per-firing trace of eq:dup_alert_cond, used to
// characterise the witness false-positive mechanism. Off by default (the
// alert fires thousands of times per run).
bool g_dup_diag_log                 = false;
// Defined in detector_windows.h, which routing.cc includes AFTER this header
// (it needs lstm_rsu_ground_truth_label from lstm_logger.h). Forward-declared
// so crypto_register_cli_params() below can register its CLI flag.
extern bool enable_detector_windows;
bool enable_stark_delay            = true;  // AB4: π_delay timing proof
bool enable_stark_hop              = true;  // AB4: π_hop hop-legitimacy proof
bool enable_witness_mechanism      = true;  // AB6: witness alert/BFT mechanism
bool enable_quarantine             = true;  // AB7: trust updates + SC.Quarantine

// ── SC.Quarantine ENFORCEMENT (eq:quarantine, 2026-08-30) ───────────────────
// Default OFF so every result produced before this date reproduces exactly.
//
// Why this exists. Until now g_quarantined[] was WRITE-ONLY: it is set when
// trust falls below T_MIN and read nowhere except its own double-set guard.
// Nothing consulted it before forwarding a packet, installing a FlowMod, or
// scheduling a hidden duplicate, so quarantine had no effect on the data path.
// Measured on A5 @60% seed 1: of 43 quarantined RSUs, 39 kept scheduling
// hidden duplicates afterwards -- 1,329 post-quarantine firing cycles. The
// paper's mitigation claim (SC.Quarantine / BTMM / Full-Mode isolation) was
// therefore unbacked in simulation: we had detection, not mitigation.
//
// This is the missing enforcement point for a mechanism main.tex already
// specifies -- not a new design decision.
//
// NOTE ON M4 (eq:l_mit). Lmit is computed from t_quarantine[], i.e. the
// instant the flag is SET. With enforcement off that measures the latency of
// an inert flag, so M4 must not be reported until this is enabled.
bool enable_quarantine_enforcement = false; // --enable_quarantine_enforcement
// ── eq:local_quarantine / HOLD_FORWARD (added 2026-08-06) ───────────────────
// alg:lrad_obu (main.tex:2395-2397) specifies TWO actions on D_OBU=1:
//     HOLD_FORWARD(v,r)   and   ESCALATE(p,v,r,{flag_S1,flag_S2p})
// Only ESCALATE was implemented. eq:local_quarantine formalises the missing
// half:
//     HOLD_FORWARD(v,r) => fwd_state(v) = Hold
//       until RSU.Confirm(v,r) \/ t > t_detect + T_hold
// with the prose: "upon D_OBU=1 the OBU suspends forwarding of flows matching
// the flagged signature for a maximum hold window T_hold, awaiting either RSU
// confirmation or timeout."
//
// DEFAULT OFF, deliberately. Enabling it changes every delivery/latency metric,
// so switching it on by default would silently invalidate all existing results
// without anyone choosing to. Off reproduces every run to date; --enable_local_
// quarantine=1 gives the spec-faithful arm, and the pair is exactly the
// with/without comparison the thesis needs to justify the mechanism.
bool   enable_local_quarantine     = false;
// T_hold is NOT given a numeric value anywhere in main.tex — the symbol table
// (main.tex:1274) defines it only as "maximum duration for OBU local forwarding
// suspension pending RSU confirmation" (see also main.tex:2371, 2377).
//
// SELECTION CRITERION (2026-09-01). The value is not arbitrary even though the
// paper leaves it open, because the mechanism bounds it from both sides:
//
//   Lower bound — the hold must outlast the RSU.Confirm round trip, or a real
//   attacker resumes forwarding before confirmation can arrive and the
//   mitigation leaks. escalate_to_rsu() schedules RSU-side processing exactly
//   1 ms out (lrad.h:746, Simulator::Schedule(Seconds(0.001))), and that
//   handler calls rsu_confirm_release() (lrad.h:687). So the floor is ~1 ms
//   plus scheduling jitter.
//
//   Upper bound — T_hold is the latency penalty paid by any vehicle held in
//   error. A false D_OBU costs that vehicle exactly T_hold of deferred
//   forwarding, so oversizing it degrades delivery/latency in proportion to the
//   OBU false-positive rate.
//
//   Criterion: pick the SMALLEST T_hold at which releases are dominated by
//   RSU.Confirm rather than timeout expiry. The instrumentation to decide this
//   already exists -- g_fwd_release_confirm vs g_fwd_release_timeout below --
//   so the answer is measured, not argued. scripts/sweep_t_hold.py runs it.
//
// MEASURED 2026-09-01 (scripts/sweep_t_hold.py, attack 2 @60%, seed 1, 90 s,
// 17k+ hold events per point). The floor is exactly 1 ms -- the confirm RTT:
//
//     T_hold     confirm   timeout   timeout%
//     0.0002      16973       476      2.7%
//     0.0005      16832       342      2.0%
//     0.00075     16440       201      1.2%
//     0.001       17499         0      0.0%   <- floor
//     0.01        16126         0      0.0%
//     0.1         3882          0      0.0%   (old default)
//
// Timeout releases appear below 1 ms and vanish at it, matching the analytic
// prediction exactly. Containment is identical for every value at or above the
// floor, so the only thing larger values buy is latency: cost is linear
// (mean hold tracks T_hold almost exactly, ~250-1250 packets caught in the
// 1 ms gap and charged the full remaining window).
//
// 0.01 = 10x the measured floor: real margin against confirm-latency jitter
// under load, at 9.74 ms mean hold. The previous 0.1 was 100x the floor and
// bought nothing -- identical containment for 10x the latency.
//
// Do NOT lower this toward the floor for cheapness: below 1 ms containment
// fails SILENTLY (a timeout release lets a real attacker resume forwarding,
// with nothing in the logs saying so), which is the exact failure the
// mechanism exists to prevent.
double T_HOLD                      = 0.01;
double g_fwd_hold_until[268]       = {};          // 0.0 = not held
uint32_t g_fwd_hold_flow[268]      = {};          // flagged flow id
uint32_t g_fwd_hold_events         = 0;           // HOLD_FORWARD invocations
uint32_t g_fwd_suspended_pkts      = 0;           // packets actually deferred
double   g_fwd_suspended_time_sum  = 0.0;         // total deferral applied (s)
uint32_t g_fwd_release_confirm     = 0;           // released by RSU.Confirm
uint32_t g_fwd_release_timeout     = 0;           // released by T_hold expiry

// HOLD_FORWARD(v,r) — set fwd_state(v) = Hold for the flagged flow.
inline void hold_forward(uint32_t v, uint32_t fid) {
    if (!enable_local_quarantine) return;
    if (v >= 268u) return;
    g_fwd_hold_until[v] = ns3::Simulator::Now().GetSeconds() + T_HOLD;
    g_fwd_hold_flow[v]  = fid;
    ++g_fwd_hold_events;
}

// RSU.Confirm(v,r) — the RSU has completed full-mode analysis; release the hold.
inline void rsu_confirm_release(uint32_t v) {
    if (!enable_local_quarantine) return;
    if (v >= 268u) return;
    if (g_fwd_hold_until[v] > 0.0) {
        g_fwd_hold_until[v] = 0.0;
        ++g_fwd_release_confirm;
    }
}

// Remaining suspension for (v, fid), in seconds; 0.0 when not held.
//
// APPROXIMATION, stated openly: a packet reaching the forward path while the
// hold is still active is deferred by the FULL remaining window rather than
// being released the instant RSU.Confirm arrives, because the ns-3 send is
// already scheduled by then and cannot be pulled forward. Since confirmation
// lands ~1 ms after escalation and T_hold is 0.1 s, this over-holds only those
// packets forwarded inside that 1 ms gap; every packet after the confirm sees
// 0.0. The error is conservative (over-suspension), never under-suspension.
inline double fwd_hold_remaining(uint32_t v, uint32_t fid) {
    if (!enable_local_quarantine) return 0.0;
    if (v >= 268u) return 0.0;
    if (g_fwd_hold_until[v] <= 0.0) return 0.0;
    double now = ns3::Simulator::Now().GetSeconds();
    if (now >= g_fwd_hold_until[v]) {          // t > t_detect + T_hold
        g_fwd_hold_until[v] = 0.0;
        ++g_fwd_release_timeout;
        return 0.0;
    }
    if (g_fwd_hold_flow[v] != fid) return 0.0; // "flows matching the flagged signature"
    double rem = g_fwd_hold_until[v] - now;
    ++g_fwd_suspended_pkts;
    g_fwd_suspended_time_sum += rem;
    return rem;
}

bool enable_endorsement_requirement = true; // AB8: f+1 RSU FlowMod endorsement
bool enable_controller_failover    = true;  // AB9: controller trust/revoke/failover
bool enable_key_rotation           = true;  // AB11: DKG key rotation on RSU revocation
bool enable_lstm_inference         = false; // main.tex sec:fed_lstm: live in-sim LSTM
                                             // (lstm_inference.h). Default OFF — needs
                                             // lstm_pipeline/lstm_weights_cpp.bin to already
                                             // exist (a prior offline training run's
                                             // export_weights_cpp.py output); every other
                                             // run/script in the repo must keep working
                                             // unchanged without that file present.

// HF-context theta override — CLI: --enable_hf_theta (default false).
// Supervisor Change 2 (2026-08-20): A5-A8's per-RSU theta is calibrated on
// a pool that's 94% A1-A4 traffic; loading lstm_pipeline/hf_theta.json
// (calibrate_hf_theta.py) and using its single pooled HF-context threshold
// for A5-A8 runs instead fixed A8's live FPR in offline validation
// (48.28%->0.00%). Default OFF -- A1-A4 runs, and any run without
// hf_theta.json exported yet, are completely unaffected. Loaded once at
// LSTM-logger init (lstm_logger.h) alongside the main weights; applied
// only when active_attack_variant is 4-7 (attacks 5-8) at the lstm_detect()
// call site (lstm_logger.h) -- see lstm_inference.h's theta_override param.
bool enable_hf_theta                = false;

// Supervisor Fix 2 (2026-08-20): use the trained classification head's
// P(attack) as the live detection signal instead of reconstruction error.
// Requires a lstm_weights_cpp.bin exported from a checkpoint containing
// fc_cls; falls back to the reconstruction path with a warning otherwise.
// Threshold comes from cls_theta.json (per-RSU, swept on the validation
// split for FPR<=1% at highest DR), defaulting to P>0.5 where absent.
bool enable_lstm_cls                = false;

// FPR fix 1 (2026-08-31) — CLI: --require_lstm_high_conf (default false).
//
// D_RSU (lrad.h) currently ORs in `flag_LSTM` alone, so a SOFT LSTM-only hit
// (flag_LSTM set, flag_LSTM_high_conf clear, no signature co-firing) marks the
// window via dw_mark_rsu() and lands in M1.
//
// That is inconsistent with how this codebase already treats soft LSTM hits
// everywhere else. Both existing sites deliberately withhold them:
//   * lrad.h:571-574 -- `lstm_only_soft` blocks the BTMM trust gate entirely,
//     for either outcome, rather than hand out an unearned trust update.
//   * lrad.h:628     -- only `flag_LSTM && flag_LSTM_high_conf` latches into
//     the per-node confusion matrix; "only the permanent TP/FP confusion-matrix
//     latch is withheld from soft hits".
// So the project twice ruled a soft LSTM-only hit too weak to act on, and then
// let it into the one score M1 actually reports.
//
// When true, D_RSU admits the LSTM term only at high confidence. Signatures are
// untouched: whenever any of S2f/S5-S8 fires, D_RSU is true regardless, so this
// removes exactly the soft-LSTM-ONLY windows and nothing else.
//
// Default false so every pre-existing number reproduces byte-for-byte; turn on
// explicitly to measure. Motivation and measured FP attribution:
// docs/FPR_REDUCTION_ANALYSIS_2026-08-31.md.
bool require_lstm_high_conf         = false;

// FPR fix 2 (2026-09-01) — CLI: --dw_mark_suspect (default false).
//
// dw_mark_rsu() is called with `rsu` -- the RSU *processing* the packet -- so an
// RSU that correctly detects a malicious neighbour is marked positive against
// its OWN truth=0. lrad.h's own comment on the primary column says it plainly:
// such a node is "penalised for detecting... why benign nodes fire in 58/58
// windows, and why all six detectors with node-level FP=0 (S3-S8) still
// collapse at window level."
//
// The 2026-08-22 fix corrected this by marking the SUSPECT (prev_sender), but
// was applied ONLY to the primary column (dw_mark_rsu_primary, lrad.h:550).
// The `score` column -- the one M1 is actually computed from -- kept the
// observer attribution. Measured on arm A: 44.7% of A5-A8 `score` false
// positives land on RSUs that are not declared attackers at all (39.3-48.9%
// per variant), versus 0-4.9% for the primary column.
//
// When true, dw_mark_rsu() is handed prev_sender instead, making the two
// columns consistent. This is MEASUREMENT-ONLY: dw_mark_rsu() writes only
// g_dw_rsu_fired[] (detector_windows.h:109-115) and touches no simulation
// state -- D_RSU itself is unchanged, so BC.Write, the BTMM trust penalty and
// quarantine all behave exactly as before.
//
// Default false so every existing M1 number reproduces byte-for-byte.
// See docs/S5_S8_ORACLE_GATE_2026-09-01.md and the FPR reduction analysis.
bool dw_mark_suspect                = false;

// Crypto on/off switch — CLI: --disable_crypto (default 0 = crypto ON).
// When set to 1, short-circuits the DKG ceremony's key generation and the
// per-packet ML-DSA-87 sign/verify + STARK hop-proof (dkg_run_ceremony,
// mldsa87_sign, mldsa87_verify, stark_verify_hop) so they no-op instead of
// running real PQC operations for every node at startup and every packet/hop
// at runtime. Useful for runs that only need TCAM/routing behavior (e.g. S3/S4
// rate-and-capacity detection, which never reads crypto state) and don't
// depend on crypto-derived metrics (trust score, S1/S2/S5-S8 detection).
bool     g_disable_crypto   = false;

// ── Data Structures ───────────────────────────────────────────────────────────

struct NodeKeyMaterial {
    uint8_t  pk[OQS_SIG_ml_dsa_87_length_public_key];
    uint8_t  sk[OQS_SIG_ml_dsa_87_length_secret_key];
    uint8_t  hmac_key[64];
    bool     keys_generated = false;
    uint32_t node_id        = UINT32_MAX;
};
NodeKeyMaterial g_node_keys[268]; // sized to total_size

struct PacketCryptoMeta {
    uint8_t  sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t   sig_len          = 0;
    uint8_t  msg_digest[64]   = {};
    uint8_t  hmac_tag[64]     = {};
    double   sign_timestamp   = 0.0;
    uint32_t signed_next_hop  = (uint32_t)-1;  // intended next hop at sign time
    uint32_t signed_zone_id   = 0;             // zone_id at sign time (rsu_controller_assignment changes)
    uint32_t nonce            = 0;             // fresh random nonce (η_i ← RAND()) — eq:mldsa_sign
    bool     sig_valid        = false;
    bool     stark_timing_ok  = false;
    bool     stark_hop_ok     = false;
};
std::map<std::pair<uint32_t,uint32_t>, PacketCryptoMeta> g_packet_crypto;

// eq:mldsa_sign's msg_id must uniquely identify "a message"; pkt_id alone
// does not, because it is a per-flow counter that restarts at 1 for every
// flow (routing.cc: packet_id = total_packet_counter + 1). Two concurrent
// flows relaying through the same node with the same pkt_id collide on the
// same g_packet_crypto slot -- confirmed root cause of the FV688 causal-
// order failures (a downstream verify silently validated against a
// different flow's stale sign record; see docs/task8_verification/
// FUNCTIONAL_VERIFICATION_GUIDE.md investigation, 2026-07-27). Composing
// flow_id into msg_id fixes this without adding a field to eq:mldsa_sign --
// main.tex never defines msg_id's exact contents, only that it identifies
// the message. 12 bits per side comfortably covers 2*flows<=8 concurrent
// streams and Flow_size<=55 packets/flow with zero collision risk.
// Reversible so batch_verify_mldsa87() can recover the raw pair from the
// map's own stored keys.
inline uint32_t crypto_msg_key(uint32_t pkt_id, uint32_t flow_id) {
    return ((flow_id & 0xFFFu) << 12) | (pkt_id & 0xFFFu);
}
inline uint32_t crypto_msg_key_pkt(uint32_t key)  { return key & 0xFFFu; }
inline uint32_t crypto_msg_key_flow(uint32_t key) { return key >> 12; }

// ---------------------------------------------------------------------------
// H(p) — the universal packet identity of main.tex:1306 ("SHA3-512 packet hash
// used as the universal packet identity across UCR (eq:ucr), witness cache, and
// Signature S6").  Returns the leading 64 bits of SHA3-512(flow_id || pkt_id ||
// original_ts_ns).
//
// Why these three fields and not the payload: ns-3 payloads here are synthetic
// (Create<Packet>(p_size - 28), zero-filled), so hashing packet CONTENT would
// give every packet the same digest.  The three fields below all travel in
// CustomDataUnicastTag_ModifiedRouting, so every receiver of the same packet
// derives the same H(p), and original_timestamp differs per cycle -- which is
// exactly what (flow_id, packet_id) alone lacks, since packet_id is a per-cycle
// slot index that restarts at 1 every cycle.
//
// A hidden duplicate carries the ORIGINAL's original_timestamp
// (routing.cc: dup_tag.Setoriginal_timestamp(original_timestamp)), so a copy and
// its original share one H(p).  That is the eq:ucr semantics: the numerator
// counts distinct packets p that reached an off-path receiver, not copy events.
//
// 64-bit truncation: a 300 s run yields on the order of 4e3 distinct eavesdropped
// packets, so the birthday collision bound is n^2/2^65 ~ 4e-13 -- far below any
// other error term in the metric.
inline uint64_t ucr_packet_identity(uint32_t flow_id, uint32_t pkt_id,
                                    int64_t original_ts_ns)
{
    uint8_t buf[16];
    memcpy(buf,     &flow_id,         4);
    memcpy(buf + 4, &pkt_id,          4);
    memcpy(buf + 8, &original_ts_ns,  8);

    uint8_t digest[64];
    if (!sha3_512_hash(buf, sizeof(buf), digest))
        return ((uint64_t)flow_id << 32) ^ ((uint64_t)pkt_id << 16)
               ^ (uint64_t)original_ts_ns;   // hash unavailable: degrade, don't drop

    uint64_t id = 0;
    memcpy(&id, digest, 8);
    return id;
}

// Sign buffer layout per eq:mldsa_sign: msg_id(4)|ts(8)|η(4)|nh(4)|z(4) = 24 bytes
// No node_id, no padding — explicit memcpy, not struct cast.
static constexpr size_t MLDSA_SIGN_BUF = 4 + 8 + 4 + 4 + 4;

struct DKGState {
    uint8_t  vk_zkp[64]  = {};
    uint8_t  com[64][64] = {};
    bool     ceremony_done = false;
    double   last_rotation = 0.0;
};
DKGState g_dkg;

struct FlowModEndorsement {
    uint8_t               flowmod_hash[64]     = {};
    uint8_t               endorsement_hash[64] = {};
    std::vector<uint32_t> endorsing_rsus;
    bool   committed   = false;
    bool   logged      = false;
    double log_time    = 0.0;
    double commit_time = 0.0;
};
std::map<uint32_t, FlowModEndorsement> g_flowmod_endorsements;

struct StarkTimingProof { uint8_t commitment[64] = {}; bool valid = false; };
struct BatchVerifyResult { bool passed; uint32_t n_verified; double elapsed_s; uint8_t challenge[64]; };

// Verification outcome counters — for sig_valid_rate metric
static uint32_t g_verify_attempts = 0;
static uint32_t g_verify_passed   = 0;
// Batch challenge result — updated each 50ms tick; feeds LRAD b_batch (eq:batch_challenge)
static bool g_batch_passed = true;

struct WitnessLogEntry {
    uint8_t  pkt_hash[64] = {};
    uint32_t dst;
    double   ts;
};

struct WitnessAlert {
    uint32_t witness_id    = 0;
    uint8_t  alert_type   = 0; // 0 = α_w (DA), 1 = β_w (NFA)
    uint8_t  signed_digest[64] = {};                              // h_alert signed by witness
    uint8_t  alert_sig[OQS_SIG_ml_dsa_87_length_signature] = {}; // full 4595-byte ML-DSA-87 sig
    size_t   alert_sig_len = 0;
    double   ts            = 0.0; // submission time — needed to prune the pool by
                                  // WITNESS_WINDOW (see witness_bft_quorum_reached)
    // The (v_i, p) EVENT this alert concerns: ((flow_id << 32) | pkt_id).
    // eq:bft_penalty's quorum is over distinct witnesses reporting "the same
    // (v_i, p) event" — v_i is already the pool's map key (target_node), so
    // this supplies p. Derived from the raw identifiers rather than from H(p)
    // because h_p degrades to all-zeros when no g_packet_crypto record exists,
    // which would silently collapse every event onto one key.
    uint64_t event_key     = 0;
};


double g_trust_score[268]       = {};
double g_trust_last_update[268] = {};
bool   g_quarantined[268]       = {};

// True when `node` must be denied a data-path action because it is under
// SC.Quarantine. Returns false unconditionally while enforcement is disabled,
// so guarded call sites are bit-identical to the pre-2026-08-30 behaviour.
// Indexed over the full node space (vehicles included), so DP variants whose
// forwarder is a vehicle relay are covered on the relay's own quarantine state.
inline bool quarantine_blocks(uint32_t node) {
    if (!enable_quarantine_enforcement) return false;
    if (node >= 268u) return false;
    return g_quarantined[node];
}
double g_ctrl_trust_score[268]  = {};
bool   g_ctrl_revoked[268]      = {};

// M5 — eq:l_failover instrumentation state
double   g_failover_max_ms     = 0.0; // max_k(t_reassign^(k) − t_revoke), most recent revocation event
uint32_t g_failover_events     = 0;   // SC.Revoke events fired (ControllerRevoked broadcasts)
uint32_t g_failover_reassigned = 0;   // RSU reassignment completions across all events

// M7 — eq:o_crypto / eq:t_verify / eq:t_consensus instrumentation state.
// All wall-clock (std::chrono) sums in microseconds; cumulative since sim start
// (CSV exports running averages, matching the avg_* idiom of the metrics CSV).
//
// eq:overhead_full / main.tex:5124: "proof size is modelled as ≤100KB per
// verification cycle (FRI-STARK, conservative blowup)". The ZKP layer's
// PROOF OUTCOME is intentionally modelled via the t_fwd-t_recv<=Delta_max
// constraint check (main.tex:5128-5130 — no real FRI polynomial commitments
// are constructed), but the proposal still specifies a concrete conservative
// BYTE-SIZE bound for the overhead/bandwidth characterisation in
// eq:overhead_full. STARK_PROOF_SIZE_MODELED_BYTES applies that same
// proposal-specified bound to O_crypto, rather than a smaller ad-hoc
// SHA3-512-commitment-sized placeholder unconnected to the modeled figure.
const double STARK_PROOF_SIZE_MODELED_BYTES = 100.0 * 1024.0; // 100 KB, main.tex:5124

// O_crypto counts the bytes the simulation attaches per signed packet, per
// eq:overhead_full: |σ_i| (real, measured ML-DSA-87 signature) plus
// |π_delay,i| and |π_hop,i|, each the proposal's own modeled ≤100KB bound.
// Both proofs are generated once per hop per Algorithm FCIP (alg:fcip,
// main.tex:2686-2726) regardless of which signature check later consumes
// them, so both contribute here.
double   g_m7_crypto_bytes_sum    = 0.0; // Σ (sig_len + 2*STARK_PROOF_SIZE_MODELED_BYTES)
uint64_t g_m7_signed_pkts         = 0;   // packets signed (O_crypto denominator)
double   g_m7_batch_wall_us_sum   = 0.0; // Σ wall-clock µs of batch_verify_mldsa87 calls
uint64_t g_m7_batch_calls         = 0;   // number of batch verify invocations
uint64_t g_m7_batch_pkts          = 0;   // Σ batch sizes B (for mean B)
double   g_m7_consensus_wall_us_sum = 0.0; // Σ wall-clock µs of endorse→commit sequences
uint64_t g_m7_consensus_count     = 0;   // number of FlowMod consensus rounds
// eq:o_crypto / main.tex:5123 "Proof generation overhead is modelled as
// <=10ms per packet". This measures the REAL wall-clock cost of the
// simulation's own stark_prove_timing()/stark_verify_timing()/
// stark_verify_hop() calls (a SHA3-512 hash + constraint check, so far
// smaller than the modeled 10ms bound) — a characterisation metric only,
// same as g_m7_batch_wall_us_sum/g_m7_consensus_wall_us_sum. Deliberately
// NOT injected as an artificial Simulator::Schedule delay into the packet
// forwarding pipeline, since that would change M2/M6/S1/S2 detection
// outcomes network-wide rather than simply reporting overhead.
double   g_m7_stark_wall_us_sum   = 0.0; // Σ wall-clock µs of STARK prove/verify calls
uint64_t g_m7_stark_calls         = 0;   // number of STARK prove/verify invocations

double g_T_ref = 0.0, g_T_ref_last_sync = 0.0;

// M9 — eq:eps_ref / eq:time_consensus instrumentation [Ablation only].
// T_ref(t) is the coordinate-wise median across N_RSUs simulated RSU clocks.
// The first TIME_REF_F_BAD RSUs (by index) have their clock offset by a fixed
// TIME_REF_DELTA_ATTACK seconds, modeling f_bad Byzantine-compromised clocks;
// the rest read true simulator time. eps_ref = |T_ref(t) - T_ground(t)| is
// recomputed on every sync tick, where T_ground(t) is the simulator's own
// clock (always available/authoritative in ns-3). Default f_bad=0 reproduces
// the original all-honest stub exactly (eps_ref ≡ 0).
uint32_t TIME_REF_F_BAD          = 0;    // number of compromised RSU clocks (CLI sweep var)
double   TIME_REF_DELTA_ATTACK   = 0.5;  // fixed attack offset (s) injected into compromised RSUs
double   g_eps_ref               = 0.0;  // |T_ref - T_ground| at most recent sync tick
double   g_eps_ref_cumulative    = 0.0;
uint32_t g_eps_ref_samples       = 0;

// node_clock_offset()/node_local_time() — eq:time_consensus tau_j(t).
// This node's own (possibly Byzantine-compromised) clock offset from true
// simulator time. Only RSUs can have a non-zero offset (vehicles/controllers
// always read true time). Stateless — a pure function of TIME_REF_F_BAD /
// TIME_REF_DELTA_ATTACK and the RSU's local index, so it cannot drift out of
// sync with update_T_ref()'s own per-RSU model; both now call this same
// function (single source of truth, eq:eps_ref M9 report Tier-2 item).
inline double node_clock_offset(uint32_t node) {
    if (node < N_Vehicles || node >= N_Vehicles + N_RSUs) return 0.0;
    uint32_t rsu_local_idx = node - N_Vehicles;
    return (rsu_local_idx < TIME_REF_F_BAD) ? TIME_REF_DELTA_ATTACK : 0.0;
}

// This node's own local clock reading — true simulator time plus this
// node's own (possibly wrong) offset. Per-packet "claimed" timestamps
// (eq:delay_updated t_send/t_recv) should be recorded via this function,
// not raw Simulator::Now(), so a compromised RSU's self-reported claim is
// genuinely wrong rather than always reading the same global clock as
// everyone else.
inline double node_local_time(uint32_t node) {
    return ns3::Simulator::Now().GetSeconds() + node_clock_offset(node);
}

std::map<uint32_t, std::vector<WitnessLogEntry>> g_witness_log;
std::map<uint32_t, std::vector<WitnessAlert>>    g_witness_alert_pool;
std::map<uint64_t, std::pair<uint32_t,double>>   g_msg_id_seen;
std::map<uint32_t, double> g_dst_volume_prev, g_dst_volume_curr;

struct CryptoLstmFeatures {
    float stark_timing_fail;
    float stark_hop_fail;
};
std::map<uint32_t, std::pair<uint32_t,uint32_t>> g_lstm_stark_counts;
std::map<uint32_t, uint32_t>                      g_lstm_pkt_counts;

// 2026-07-26: R_anom(r,t) (eq:feat_ranom) -- cumulative count of distinct
// unauthorized-destination receptions attributed to malicious RSU r
// (prev_sender), i.e. exactly the same event UCR/M8 already counts via
// fade_eavesdrop_counter, just broken out per-RSU instead of one global
// running total. Incremented at the SAME two MacRx insertion points (passive
// S7/S8 and active S5/S6 hidden-forwarding receive blocks in routing.cc)
// that already increment g_lstm_stark_counts[prev_sender]/g_lstm_pkt_counts,
// guarded by the same fade_eavesdropped_packets dedup check so it can never
// double-count. lstm_log_rsu_cycle() (lstm_logger.h) takes the per-cycle
// DELTA of this cumulative counter (mirrors lambda_PI's pattern exactly,
// NOT g_lstm_stark_counts' cumulative-latch "> 0 ever" pattern) to compute
// the windowed rate the equation actually specifies ("per unit time W").
std::map<uint32_t, uint32_t> g_lstm_ranom_count;

// Supervisor Decision 2 (2026-08-21): R_anom as a zero-tolerance rule-based
// detector feeding S7/S8. Precondition verified before wiring: r_anom is
// EXACTLY 0 across all 95,360 benign rows of the collected dataset, every
// seed -- zero exceptions -- so R_anom(r,t) > 0 needs no percentile
// calibration, architecturally the same as f_unauth for S3.
//
// Published per cycle as a "_last" latch (same pattern as
// g_tcam_flag_s3_last): lstm_log_rsu_cycle() computes the per-cycle delta at
// the cycle boundary while lrad_rsu() reads it per packet, so the value lrad
// sees is the previous cycle's. That one-cycle lag is inherent to the
// existing S3/S4 pattern and accepted for the same reason.
//
// Attribution note: g_lstm_ranom_count is keyed by
// hf_gt_attribution_node(prev_sender) -- the malicious forwarder's COVERING
// RSU -- not by raw prev_sender. That matters: the witness duplication path
// accuses prev_sender directly, and measurement showed 79.2% of its alerts
// land on vehicle relays that can never be the passive-HF attacker in this
// config (11,384 of 14,367). R_anom does not inherit that failure mode.
std::vector<uint8_t> g_ranom_flag_last;
// Own prev-value array for the rule's per-cycle delta. Separate from
// g_lstm_prev_ranom so the rule and the LSTM feature never consume each
// other's delta.
std::vector<uint32_t> g_ranom_rule_prev;

// Item 9 correction (supervisor, 2026-08-29): A5-A8's window activity gate
// (g_dw_activity_last, below) was reading g_ranom_flag_last -- R_anom's
// per-cycle delta, a RECEIVE-side signal -- while the detector it gates is
// S5, a SEND-side one (main.tex: "a hidden-duplicate SEND event"). The
// correct send-side signal already exists: g_lstm_hf_sendgt_count
// (immediately below), incremented exactly when an RSU schedules a hidden
// duplicate. These mirror g_ranom_flag_last/g_ranom_rule_prev's own pattern
// -- a same-cadence latch computed in routing.cc's per-RSU metrics loop
// (not inside lstm_log_rsu_cycle(), which early-returns without
// --training/--enable_lstm_inference and would leave this silently zero in
// exactly the ablation configs that need the rule) plus its own prev-value
// array, kept separate so this delta and the LSTM feature's own
// consumption of g_lstm_hf_sendgt_count never collide.
std::vector<uint8_t>  g_hf_send_flag_last;

// ── HF truth semantics (2026-09-01) — CLI: --hf_truth_latched (default false)
//
// The A5-A8 window truth is gated per-cycle by g_hf_send_flag_last, i.e. "did
// this RSU schedule a duplicate in THIS cycle" — EVENT semantics. S5-S8 fire on
// persistent compromise state: their conjunctions are latched, the unendorsed
// FlowMod stays installed, and active_hf_malicious_nodes is never cleared.
// s5_detection.h says so directly: "every [S5] line is evidence of an ongoing
// compromised state, not of a discrete send event -- which is exactly why S5
// fires far more often than hf_send_gt." Detector and truth were given OPPOSITE
// temporal semantics and the score is taken across the gap.
//
// Measured 2026-09-01 (arm D, A5-A8): 1,432 of 1,621 false positives (88%) are
// windows where a declared attacker simply did not fire that cycle. Aligning the
// semantics moves A5-A8 MCC 0.5928 -> 0.7674 and FPR 38.9% -> 8.5%. NOTHING
// about detection changes -- this corrects a measurement mismatch, and must be
// reported that way, never as a detector improvement.
//
// This is the SAME latch preprocessor.py already applies to y_indep's HF term
// (`hflat = np.maximum.accumulate(hfgt > 0)`, line 229), which the supervisor
// approved. Today the LSTM label uses latched semantics while the M1 truth uses
// event semantics; this makes them agree.
//
// Kept in its OWN array, not folded into g_dw_activity_last: that one is
// std::fill()'d to 0 after every dw_end_cycle() (routing.cc), so a latch stored
// there would be silently erased each cycle and appear to do nothing.
//
// RESET BOUNDARY. End-of-run is correct only while the compromised state never
// actually ends -- which is true today ONLY because quarantine does not enforce
// (enable_quarantine_enforcement defaults off). Once enforcement is on, the
// latch must be released at quarantine time per eq:local_quarantine, or a
// contained attacker keeps counting as a positive forever. hf_truth_latch_clear()
// below is that hook; wire it into the quarantine path when enforcement lands.
bool hf_truth_latched = false;

// A3/A4 truth semantics (2026-09-01) — CLI: --tcam_truth_live (default false).
// Use the LIVE "holds >=1 malicious TCAM entry" scan for variants 2/3 instead
// of the never-cleared is_malicious_node latch. See the full rationale at
// lstm_rsu_ground_truth_label() in lstm_logger.h. Measurement-only: this label
// feeds the window grid and the LSTM CSV, never a detection or enforcement path.
bool tcam_truth_live = false;
std::vector<uint8_t> g_hf_activity_latch;

// Release the latch for one node (call when it is genuinely contained).
inline void hf_truth_latch_clear(uint32_t rsu_local_idx) {
    if (rsu_local_idx < g_hf_activity_latch.size())
        g_hf_activity_latch[rsu_local_idx] = 0;
}

// ── Item 4 (supervisor round 7, 2026-09-05): the latch RESET BOUNDARY ────────
//
// Moving the reset from end-of-run to quarantine time is correct only for
// variants whose enforcement is CONFIRMED working, because only there does the
// compromised state genuinely end. Where enforcement is absent or unvalidated,
// the state really does persist to end of run and the old boundary is the
// correct one. So this is deliberately per-variant, split on ATTACKER TYPE --
// which is the axis the enforcement evidence actually falls along:
//
//   A5/A7 (variants 4/6, CP) -- attacker IS the RSU. Enforcement confirmed
//       directly: post-quarantine fires drop to 0. --hf_latch_reset_rsu_attacker
//   A6/A8 (variants 5/7, DP) -- attacker is a VEHICLE. Enforcement confirmed
//       2026-08-30, and it bites through hf_gt_attribution_node(), the COVERING
//       RSU. Post-quarantine fires 50->0 and 137->0. Separate flag so this can
//       be switched off independently if the proxy attribution is ruled
//       unacceptable. --hf_latch_reset_vehicle_attacker
//
//       CORRECTION 2026-09-07: this note used to justify the covering-RSU proxy
//       with "because vehicles never cross the trust threshold". That is not
//       true and may never have been. Measured on the gate-removed build, 90s,
//       60%, seed 1, counting distinct [TRUST-QUARANTINE] node ids:
//           A5 199/200 vehicles   A6 199/200   A7 173/200   A8 167/200
//       Even with the legacy oracle gate still in, A6 quarantines 128 vehicles
//       and A8 125. Vehicles cross the threshold routinely. The proxy may still
//       be the right attribution for other reasons -- it is what truth's latch
//       is indexed on (hf_truth_latch_clear takes an RSU local index) -- but it
//       is NOT justified by vehicles being unreachable by trust decay, and any
//       reasoning that depends on that premise needs re-deriving.
//
// A1-A4 are not covered here at all and need no flag: the latch is HF-only
// (g_hf_activity_latch is written only under variants 4-7, routing.cc:118534).
// A3/A4 use --tcam_truth_live and A1/A2 their own per-cycle exceedance gate.
//
// BOTH DEFAULT FALSE = end-of-run reset = today's behaviour, bit-identical.
// Once item 1 closes across all eight variants these collapse into one uniform
// setting and the distinction disappears, as instructed.
bool hf_latch_reset_rsu_attacker     = false;
bool hf_latch_reset_vehicle_attacker = false;

// Does the active variant reset its latch at quarantine time?
inline bool hf_latch_resets_at_quarantine() {
    switch (active_attack_variant) {
        case 4: case 6: return hf_latch_reset_rsu_attacker;      // A5, A7 (CP)
        case 5: case 7: return hf_latch_reset_vehicle_attacker;  // A6, A8 (DP)
        default:        return false;                            // A1-A4: N/A
    }
}
std::vector<uint32_t> g_hf_send_rule_prev;

// Supervisor Decision 4 (2026-08-21): per-RSU, per-cycle ATTACK-ACTIVITY
// latch for detector_windows.csv's ground truth. Window-level detectors must
// be scored against window-level truth; the previous truth column was
// is_malicious_node, which is node-level and constant for the whole run, so
// every window in which a genuine attacker happened to be dormant counted as
// a positive no detector could catch. Measured: 40.7% of node-level positive
// windows (30,730 of 75,578) contain no attack activity at all, capping even
// a perfect zero-FP detector at DR ~59.3%.
//
// Populated in routing.cc's per-RSU metrics loop, which runs BEFORE
// dw_end_cycle() in the same cycle. Latched rather than read live because
// s1_rsu_exceeded_dmax is reset inside that same loop.
std::vector<uint8_t> g_dw_activity_last;

// 2026-08-02 (Issue 1 fix, HF ground-truth/feature separation): per-RSU
// count of hidden-duplicate SEND events this malicious RSU has scheduled
// (incremented at the same two call sites as g_total_copies_scheduled++ in
// routing.cc, keyed by the sending RSU instead of one global total). This
// exists ONLY to build an independent ground-truth label for A5-A8 windows
// in preprocessor.py -- it fires at attack-injection time, before any
// detection/receive logic runs, so it shares no computation path with
// r_anom (a receive-side, detection-facing signal that IS fed to the LSTM
// as input feature #10). Using r_anom>0 to both define the ground-truth
// window label AND as a raw model input let the model trivially recover
// the label from its own input for HF variants; this counter breaks that
// overlap. Logged as a label-only CSV column (hf_send_gt), excluded from
// FEATURES in preprocessor.py.
std::map<uint32_t, uint32_t> g_lstm_hf_sendgt_count;

// Fix 2 (supervisor-approved 2026-08-25): per-RSU count of Selective Time
// Delay (A1/A2) attack-CONFORMING delay injections scheduled this run --
// the exact timing equivalent of g_lstm_hf_sendgt_count above, for the same
// reason. delta_t_exceeded was banned as a training/eval feature (2026-08-14,
// supervisor Fix 3) because it is derived from the same measured-delay
// computation the detectors themselves consume, so scoring against it lets a
// model recover its own label from its input. g_s1_gt_delay_exceeded /
// g_s2_gt_delay_exceeded are STICKY node-level latches (set once, true for
// the rest of the run -- see s1_detection.h/s2_detection.h), not per-window
// signals, so neither is a valid per-window ground truth either.
//
// Incremented at the two live injection sites (routing.cc, inside
// calculate_unified_selective_delay's caller and
// schedule_unified_selective_delay_attack's caller) at the exact simulation
// moment a packet is scheduled for attack-conforming delay -- i.e. the
// return value/the `attacked` flag is non-zero/true -- BEFORE any detector
// runs, so this shares no computation path with S1/S2's own delay
// measurement. A1's injecting node is always the RSU holding the poisoned
// FlowMod (cp_poisoned_flowmod_delay is only ever non-zero at RSU node ids --
// see reapply_cp_selective_delay(), attack_declaration.h), so no attribution
// mapping is needed there. A2's malicious-node pool spans the full node
// space (declare_attackers(), attack_declaration.h: n_candidates =
// N_Vehicles+N_RSUs) and CAN be a vehicle, which is not a node any RSU's CSV
// row indexes -- same class of bug g_lstm_hf_sendgt_count exists to avoid
// for HF, so A2 vehicle injectors are attributed to their covering RSU via
// hf_gt_attribution_node(), exactly like hf_send_gt. UINT32_MAX (no RSU
// currently covers the injecting vehicle) correctly latches nothing.
//
// Logged as a label-only CSV column (std_send_gt), excluded from FEATURES in
// preprocessor.py -- same treatment as hf_send_gt.
std::map<uint32_t, uint32_t> g_lstm_std_sendgt_count;

// 2026-08-28: per-VICTIM-RSU count of malicious TCAM FlowMod installations
// attempted against it -- the A3/A4 member of the same family as
// g_lstm_hf_sendgt_count (HF) and g_lstm_std_sendgt_count (timing).
//
// Why A3/A4 needed one. y_indep, the leak-free window label, is built from
// those two counters, and neither covers TCAM exhaustion -- so A3 and A4 had
// ZERO positive leak-free windows in every split (measured 2026-08-28, all of
// train/val/test). No A3/A4 score could be called leak-free. Their only label
// path ran through is_spike, whose A3 leg is U_TCAM > benign-p99 and whose A4
// leg falls back to delta_t; both of those ARE in FEATURES, i.e. a label that
// is a transform of a model input -- the leakage class that is not permitted.
//
// Keyed by the VICTIM RSU (tcam_install_malicious's target_rsu_node_id), not
// the attacker, because that is exactly what A3/A4 ground truth labels: "any
// RSU holding >=1 malicious TCAM entry" (lstm_rsu_ground_truth_label(),
// lstm_logger.h). For A3 (CP) attacker and victim are the same node; for A4
// (DP) the attacker is a vehicle and only the victim RSU is ever read by an
// RSU-indexed CSV row -- the same orphaning that motivated hf_send_gt's
// covering-RSU attribution.
//
// Counts ATTEMPTS, including those refused with TABLE_FULL. A refused install
// still means the attacker was actively attacking this RSU in this window --
// indeed saturation is when S4's PACKET_IN signal is strongest -- so counting
// only successful installs would mark the peak of the attack as benign.
//
// Label-only, emitted as tcam_send_gt, excluded from FEATURES like its two
// siblings.
std::map<uint32_t, uint32_t> g_lstm_tcam_sendgt_count;

// 2026-07-28 (main.tex:5783-5794 spec correction): D_div/A_tp (eq:feat_ddiv,
// eq:feat_atp) must be computed from "per-source per-destination byte counts"
// and "per-flow directional byte rate logs" respectively -- genuinely
// independent local delivery counters, NOT derived from R_anom/the
// blockchain receipt log (that separation is the whole point of the
// three-feature design: R_anom is the only one requiring blockchain read
// access, so D_div/A_tp must keep working from purely local RSU state).
// The previous implementation (2026-07-26) computed both as deterministic
// transforms of R_anom's delta -- a real deviation from spec, not a
// harmless simplification, since it collapsed three independent evidence
// channels main.tex explicitly designs for down to one.
//
// g_lstm_flow0_legit_count: cumulative count of flow 0's genuine final
// deliveries (packet reaches its authorized destination_f). This is the
// A_tp "authorized" numerator. Not per-RSU: flow 0 has exactly one final
// destination reached once per packet, regardless of how many RSUs relayed
// it. Delta'd against g_lstm_prev_flow0_legit once per cycle in
// lstm_logger.h. fade_received_count (efade_detection.h) is NOT usable
// directly for this -- it's only cleared per-epoch inside
// fade_detect_anomaly(), which early-returns unless fade_detection_active
// (requires the FADE-isolated !enable_lrad_obu && !enable_lrad_rsu config)
// -- in a normal run it's never cleared and grows cumulatively for the
// whole run, same problem this dedicated counter avoids via the delta
// pattern.
uint32_t g_lstm_flow0_legit_count = 0;

// g_lstm_flow0_dest_set: distinct destination node IDs that have received
// >=1 flow-0 packet this window (both the authorized destination_f AND any
// unauthorized eavesdropper/duplicate-recipient reached via hidden
// forwarding). This is the eq:feat_ddiv numerator -- a genuine
// per-destination delivery count populated directly at the MacRx receive
// sites in routing.cc, independent of g_lstm_ranom_count. |P(v,.)|=1 in
// this sim (flow 0 has exactly one authorized destination at any instant),
// so D_div = |g_lstm_flow0_dest_set| directly, no further normalization
// needed. Snapshotted then cleared once per cycle in lstm_logger.h (same
// cadence as g_lstm_flow0_legit_count's delta).
//
// g_lstm_flow0_total_delivery_count: total flow-0 delivery events this
// window (authorized + unauthorized) -- the eq:feat_atp denominator.
// Packet-count based rather than raw-byte based: this sim already measures
// every other per-cycle feature (R_anom, lambda_PI, escalation) at
// packet/event granularity, not byte granularity, and packets on a given
// flow are uniform size in this model, so a packet-count ratio equals the
// byte-count ratio main.tex specifies.
std::set<uint32_t> g_lstm_flow0_dest_set;
uint32_t            g_lstm_flow0_total_delivery_count = 0;

// ── Item 3 (supervisor round 7, 2026-09-05): PER-RSU D_div / A_tp ───────────
//
// The three accumulators above are simulation-wide globals with no RSU key, so
// every RSU's CSV row receives the identical value every cycle. Measured over
// 1,372,800 rows: 100.0% of cycles have all sampled RSUs reporting the same
// d_div/a_tp (r_anom control: 3.0%), and within-(pct,seed,cycle)-stratum AUC is
// exactly 0.500 -- the theoretical value for a constant, i.e. zero per-node
// information. Under A5-A8 that hands every bystander RSU a network-wide "an
// attack is happening" signal while ground truth labels only the attacker, so
// each bystander is a structurally guaranteed false positive and no threshold
// can separate them. main.tex specifies both features per-RSU ("D_div is
// computed from per-source per-destination byte counts logged at each RSU";
// "A_tp is computed from per-flow directional byte rate logs"), so the global
// scope is a defect against spec, not an alternative design.
//
// The maps below are the spec-conformant form. Keyed by RSU NODE ID, exactly
// like g_lstm_ranom_count, and populated at the same three MacRx sites using
// the same hf_gt_attribution_node() value already computed on the adjacent line.
//
// ATTRIBUTION RULE, and the part that needs a ruling. eq:feat_ddiv/eq:feat_atp
// do not say who is credited with an AUTHORIZED delivery: that event fires at
// flow 0's single destination node, which is not an RSU. We credit the covering
// RSU of the packet's last-hop sender -- i.e. each RSU accounts for the flow-0
// traffic it actually relayed -- which is the reading that matches main.tex's
// "per-flow directional byte rate logs" wording. Unauthorized deliveries are
// credited the same way, to the covering RSU of the duplicating forwarder.
//
// EXPECTED CONSEQUENCE, stated up front so it is not mistaken for a new bug.
// passive_hf_rsu_to_eavesdropper maps one eavesdropper per malicious node, so a
// per-RSU destination set has cardinality at most 2 (the legitimate destination
// plus that RSU's own eavesdropper). Per-RSU D_div is therefore close to
// 1 + 1[this RSU duplicated this cycle], which is largely a function of r_anom.
// The fix REMOVES a broadcast false signal; it does not ADD an independent one.
// That is still the correct outcome -- the current feature actively injects the
// FPs -- but the paper should not claim new discriminative power from it.
//
// DEFAULT OFF. With --lstm_ddiv_atp_per_rsu=0 the globals above are used exactly
// as before and every previously collected row is reproduced bit-identically.
// Turning it on requires regenerating the A5-A8 training set (the per-RSU
// granularity was never captured, so it cannot be recovered by post-processing)
// and a full retrain INCLUDING the encoder -- a frozen-encoder fine-tune will not
// transfer, since the latent was trained to treat the broadcast constant as
// meaningful.
// ── D_div smoke test (supervisor round 8, 2026-09-06) ───────────────────────
//
// INSTRUMENTATION ONLY. Measures what the supervisor's proposed richer D_div
// WOULD read, without changing any feature the model consumes, so the three
// acceptance criteria can be checked before committing to the definition:
//   (a) non-constant across the 64 RSUs during an active attack,
//   (b) exactly zero under benign traffic,
//   (c) correlation with R_anom meaningfully below 1.
//
// Proposed feature: per RSU, the number of distinct SOURCE VEHICLES routing
// through it whose destination set exceeds their authorized policy set. Unlike
// the shipped accumulators this is NOT gated on flow 0 -- attacks span 4-7
// distinct flows, so a single-flow gate discards most of the attack surface.
//
// Keyed rsu -> src -> {destinations}. A source counts as anomalous when it
// reached any destination outside its authorized set for that flow.
// ── Q5: the S5-S8 oracle gate (supervisor round 8, 2026-09-06) ─────────────
//
// All four HF signatures used to early-return unless
// active_/passive_hf_malicious_nodes[prev_sender] -- the attack injector's own
// ASSIGNMENT ARRAY. That made them structurally incapable of firing on an
// innocent node, so every precision figure they produced was guaranteed by
// construction rather than measured, and score_primary was attacker-identity-
// aware and not an achievable ceiling. eq:sig_s5's five conjuncts contain no
// such term; the gate is the same class of defect as training on a label
// derived from an input feature, hiding in C++ control flow instead of a
// training script.
//
// REMOVED BY DEFAULT. In its place each signature now evaluates the conjunct
// the gate was standing in for -- b_hop(u) = 0, i.e. STARK.Verify(pi_hop) = 0 --
// via stark_verify_hop(), which compares the receiving hop against the
// signed_next_hop embedded at sign time and references no ground truth at all.
// A benign packet arriving at its intended next hop passes and the signature
// stays silent; a duplicate diverted to an eavesdropper fails and evaluation
// continues. Crucially the signatures CAN now fire on an innocent node, which
// is what makes their precision a measurement.
//
// Set --hf_oracle_gate=1 to restore the legacy gate. That exists ONLY to A/B
// what the gate was worth; it must never be used for a reported number.
bool hf_oracle_gate = false;

// Declared ahead of the ddiv_* helpers below, which gate on it: the
// per-source-vehicle accumulator is the production N_div feature when
// --lstm_ddiv_atp_per_rsu=1, not only smoke-test instrumentation.
bool lstm_ddiv_atp_per_rsu = false;
bool ddiv_smoke_test = false;
std::map<uint32_t, std::map<uint32_t, std::set<uint32_t>>> g_ddiv_smoke_reached;
std::map<uint32_t, std::map<uint32_t, std::set<uint32_t>>> g_ddiv_smoke_auth;

inline void ddiv_smoke_record(uint32_t rsu_node, uint32_t src,
                              uint32_t dest_reached, uint32_t auth_dest)
{
    if (!ddiv_smoke_test && !lstm_ddiv_atp_per_rsu) return;
    if (rsu_node == UINT32_MAX) return;
    g_ddiv_smoke_reached[rsu_node][src].insert(dest_reached);
    g_ddiv_smoke_auth   [rsu_node][src].insert(auth_dest);
}

// Distinct source vehicles at this RSU that reached an unauthorized destination.
inline uint32_t ddiv_smoke_count(uint32_t rsu_node)
{
    if (!ddiv_smoke_test && !lstm_ddiv_atp_per_rsu) return 0;
    auto itr = g_ddiv_smoke_reached.find(rsu_node);
    if (itr == g_ddiv_smoke_reached.end()) return 0;
    auto ita = g_ddiv_smoke_auth.find(rsu_node);
    uint32_t n = 0;
    for (auto const& kv : itr->second) {
        const std::set<uint32_t>& reached = kv.second;
        static const std::set<uint32_t> empty_set;
        const std::set<uint32_t>& auth =
            (ita != g_ddiv_smoke_auth.end() && ita->second.count(kv.first))
                ? ita->second.at(kv.first) : empty_set;
        for (uint32_t d : reached) { if (!auth.count(d)) { ++n; break; } }
    }
    return n;
}

std::map<uint32_t, std::set<uint32_t>> g_lstm_flow0_dest_set_by_rsu;
std::map<uint32_t, uint32_t>           g_lstm_flow0_total_delivery_by_rsu;
std::map<uint32_t, uint32_t>           g_lstm_flow0_legit_by_rsu;

// Record one flow-0 delivery against the RSU that relayed it.
//   rsu_node -- hf_gt_attribution_node(last-hop sender); UINT32_MAX = no RSU
//               currently covers that sender, in which case nothing is recorded
//               (the same discipline every other attributed counter uses).
//   dest     -- the node that received the packet (authorized destination or
//               eavesdropper); enters that RSU's distinct-destination set.
//   legit    -- true for a delivery to the authorized destination_f.
inline void lstm_flow0_record_delivery(uint32_t rsu_node, uint32_t dest, bool legit)
{
    if (!lstm_ddiv_atp_per_rsu)   return;
    if (rsu_node == UINT32_MAX)   return;
    g_lstm_flow0_dest_set_by_rsu[rsu_node].insert(dest);
    ++g_lstm_flow0_total_delivery_by_rsu[rsu_node];
    if (legit) ++g_lstm_flow0_legit_by_rsu[rsu_node];
}

// ── liboqs Singleton and Zone Helper ─────────────────────────────────────────

static OQS_SIG* g_oqs_sig = nullptr;
static OQS_SIG* get_oqs_ctx() {
    if (!g_oqs_sig) g_oqs_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    return g_oqs_sig;
}

// z_i per eq:mldsa_sign: RSU → zone from rsu_controller_assignment; vehicles → 0
static inline uint32_t crypto_zone_id(uint32_t node_index) {
    if (node_index >= N_Vehicles && node_index < N_Vehicles + N_RSUs)
        return (uint32_t)rsu_controller_assignment[node_index - N_Vehicles];
    return 0;
}

// ── ML-DSA-87 Key Generation — eq:vk_commit ──────────────────────────────────

inline bool mldsa87_keygen(uint32_t node_index) {
    if (node_index >= (uint32_t)total_size) return false;
    NodeKeyMaterial& km = g_node_keys[node_index];
    if (km.keys_generated) return true;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_keygen: OQS_SIG_new(ml_dsa_87) failed for node="
                  << node_index << "\n";
        return false;
    }
    if (OQS_SIG_keypair(sig, km.pk, km.sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_keygen: OQS_SIG_keypair failed for node="
                  << node_index << "\n";
        return false;
    }
    km.keys_generated = true;
    km.node_id = node_index;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[CRYPTO-KEY] node=" << node_index
                  << " ML-DSA-87 keypair generated"
                  << " pk_len=" << OQS_SIG_ml_dsa_87_length_public_key
                  << " sk_len=" << OQS_SIG_ml_dsa_87_length_secret_key
                  << " pk[0..3]=" << _hex4(km.pk)
                  << " sk[0..3]=" << _hex4(km.sk) << "\n";
    return true;
}

// ── ML-DSA-87 Signing — eq:mldsa_sign ────────────────────────────────────────

inline bool mldsa87_sign(uint32_t signer, uint32_t pkt_id,
                          uint32_t next_hop, uint32_t seq) {
    if (g_disable_crypto) return true; // crypto disabled via --disable_crypto
    if (signer >= (uint32_t)total_size) return false;
    if (!g_node_keys[signer].keys_generated && !mldsa87_keygen(signer)) return false;
    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // η_i ← RAND(): fresh per-signature nonce preventing replay (eq:mldsa_sign).
    // The caller's `seq` argument is ignored for the digest — nonce is random.
    uint32_t fresh_nonce = 0;
    OQS_randombytes(reinterpret_cast<uint8_t*>(&fresh_nonce), sizeof(fresh_nonce));

    // eq:mldsa_sign: H_SHA3-512(msg_id ‖ ts_i ‖ η_i ‖ nh_i ‖ z_i) — 24-byte explicit buffer
    // msg_id = crypto_msg_key(pkt_id, seq): seq is the caller's flow_id (see
    // crypto_msg_key's declaration for why pkt_id alone is not unique).
    uint32_t msg_id = crypto_msg_key(pkt_id, seq);
    double   ts   = ns3::Simulator::Now().GetSeconds();
    uint32_t zone = crypto_zone_id(signer);
    uint8_t sign_buf[MLDSA_SIGN_BUF] = {};
    memcpy(sign_buf,    &msg_id,      4);
    memcpy(sign_buf+4,  &ts,          8);
    memcpy(sign_buf+12, &fresh_nonce, 4);
    memcpy(sign_buf+16, &next_hop,    4);
    memcpy(sign_buf+20, &zone,        4);

    uint8_t digest[64];
    if (!sha3_512_hash(sign_buf, MLDSA_SIGN_BUF, digest)) {
        std::cerr << "[CRYPTO-ERROR] mldsa87_sign: SHA3-512 failed node=" << signer
                  << " pkt=" << pkt_id << "\n";
        return false;
    }

    PacketCryptoMeta& meta = g_packet_crypto[{signer, msg_id}];
    memcpy(meta.msg_digest, digest, 64);
    meta.sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(sig, meta.sig, &meta.sig_len,
                     digest, 64, g_node_keys[signer].sk) != OQS_SUCCESS) {
        meta.sig_len = 0;
        std::cerr << "[CRYPTO-ERROR] mldsa87_sign: OQS_SIG_sign failed node=" << signer
                  << " pkt=" << pkt_id << "\n";
        return false;
    }
    meta.sign_timestamp  = ts;
    meta.signed_next_hop = next_hop;
    meta.signed_zone_id  = zone;
    meta.nonce           = fresh_nonce;
    meta.sig_valid = true;
    // M7 eq:o_crypto — per-packet crypto bytes attached at this hop:
    // |σ_i| (real, measured sig_len) + |π_delay,i| + |π_hop,i|, both proofs
    // at the proposal's own modeled ≤100KB bound (main.tex:5124, eq:overhead_full).
    g_m7_crypto_bytes_sum += (double)meta.sig_len + 2.0 * STARK_PROOF_SIZE_MODELED_BYTES;
    ++g_m7_signed_pkts;
    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[CRYPTO-SIGN] node=" << signer
                  << " pkt=" << pkt_id
                  << " flow=" << seq
                  << " next_hop=" << next_hop
                  << " sig_len=" << meta.sig_len  // expected 4627
                  << " zone=" << zone
                  << " t=" << ts
                  << " digest[0..3]=" << _hex4(digest)
                  << " sig[0..3]=" << _hex4(meta.sig) << "\n";
        // [PKT-CRYPTO] — human-readable field-level breakdown for manual inspection
        std::cout << "[PKT-CRYPTO] ── SIGN ─────────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   node      = " << signer << "  (signer)\n"
                  << "[PKT-CRYPTO]   pkt_id    = " << pkt_id << "  (flow=" << seq << ", msg_id=" << msg_id << ")\n"
                  << "[PKT-CRYPTO]   next_hop  = " << next_hop << "\n"
                  << "[PKT-CRYPTO]   zone      = " << zone << "\n"
                  << "[PKT-CRYPTO]   t_sign    = " << ts << " s  (NS-3 simulation time)\n"
                  << "[PKT-CRYPTO]   nonce(η)  = 0x" << _hex32(fresh_nonce) << "  (random per-packet)\n"
                  << "[PKT-CRYPTO]   -- Sign buffer (eq:mldsa_sign, 24 bytes) ----------\n"
                  << "[PKT-CRYPTO]   buf[0..3]   msg_id   = " << msg_id   << "  (4 B; pkt_id|flow_id composite)\n"
                  << "[PKT-CRYPTO]   buf[4..11]  ts       = " << ts       << "  (8 B double)\n"
                  << "[PKT-CRYPTO]   buf[12..15] nonce    = 0x" << _hex32(fresh_nonce) << "  (4 B)\n"
                  << "[PKT-CRYPTO]   buf[16..19] next_hop = " << next_hop << "  (4 B)\n"
                  << "[PKT-CRYPTO]   buf[20..23] zone     = " << zone     << "  (4 B)\n"
                  << "[PKT-CRYPTO]   -- SHA3-512(buf) → 64-byte digest -----------------\n"
                  << "[PKT-CRYPTO]   digest[0..7]  = " << _hex8(digest) << "\n"
                  << "[PKT-CRYPTO]   digest[8..15] = " << _hex8(digest+8) << "\n"
                  << "[PKT-CRYPTO]   -- ML-DSA-87 signature (FIPS 204, liboqs) ---------\n"
                  << "[PKT-CRYPTO]   sig_len       = " << meta.sig_len << " bytes  (expected 4627)\n"
                  << "[PKT-CRYPTO]   sig[0..7]     = " << _hex8(meta.sig) << "\n"
                  << "[PKT-CRYPTO]   sig[8..15]    = " << _hex8(meta.sig+8) << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return true;
}

// ── ML-DSA-87 Verification ────────────────────────────────────────────────────

// is_batch_call: true when called from batch_verify_mldsa87() (50ms tick),
//                false when called at packet receive time (MacRx callback).
//                Logged as batch=0/1 so timing tools can distinguish the two call sites.
inline bool mldsa87_verify(uint32_t claimed_signer, uint32_t pkt_id,
                            uint32_t next_hop, uint32_t seq,
                            bool is_batch_call = false,
                            bool* out_broadcast_skip = nullptr) {
    // out_broadcast_skip distinguishes "this node was never the intended
    // recipient of the broadcast, so verification was never attempted" from
    // a genuine cryptographic rejection. Both paths return false below (the
    // caller-facing pass/fail semantics are unchanged), but a caller that
    // logs this outcome (e.g. crypto_timing_log*.csv) needs the distinction:
    // without it, every one of the many neighbours that merely overheard a
    // broadcast not addressed to them is indistinguishable from an actual
    // ML-DSA-87 signature rejection, which silently inflates any "verify
    // fail rate" computed from that log to mostly-meaningless noise.
    if (out_broadcast_skip) *out_broadcast_skip = false;
    if (g_disable_crypto) return true; // crypto disabled via --disable_crypto
    if (claimed_signer >= (uint32_t)total_size) return false;
    // msg_id = crypto_msg_key(pkt_id, seq): must match mldsa87_sign()'s key
    // exactly, or a genuinely-signed packet would never be found.
    uint32_t msg_id = crypto_msg_key(pkt_id, seq);
    auto it = g_packet_crypto.find({claimed_signer, msg_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) {
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                      << " pkt=" << pkt_id << " flow=" << seq
                      << " → no_record (not signed by this node)\n";
        return false;
    }

    // Broadcast MAC: every node in range overhears every packet. Only the
    // intended next hop can produce a matching digest (next_hop is embedded
    // in the signed message). Skip OQS_SIG_verify and don't count overheard
    // packets in sig_valid_rate — they would always fail and dilute the metric.
    if (it->second.signed_next_hop != (uint32_t)-1 && next_hop != it->second.signed_next_hop) {
        if (out_broadcast_skip) *out_broadcast_skip = true;
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                      << " pkt=" << pkt_id << " flow=" << seq
                      << " → skip_broadcast (intended_hop=" << it->second.signed_next_hop
                      << " actual_hop=" << next_hop << ")\n";
        return false;
    }

    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    // Reconstruct eq:mldsa_sign buffer identically to sign: msg_id|ts|η|nh|z (24 bytes)
    uint8_t sign_buf[MLDSA_SIGN_BUF] = {};
    memcpy(sign_buf,    &msg_id,                   4);
    memcpy(sign_buf+4,  &it->second.sign_timestamp, 8);
    memcpy(sign_buf+12, &it->second.nonce,          4);
    memcpy(sign_buf+16, &next_hop,                  4);
    memcpy(sign_buf+20, &it->second.signed_zone_id, 4);

    uint8_t digest[64];
    if (!sha3_512_hash(sign_buf, MLDSA_SIGN_BUF, digest))
        return false;

    bool ok = OQS_SIG_verify(sig, digest, 64,
                              it->second.sig, it->second.sig_len,
                              g_node_keys[claimed_signer].pk) == OQS_SUCCESS;
    it->second.sig_valid = ok;
    g_verify_attempts++;
    if (ok) g_verify_passed++;

    if (CRYPTO_DEBUG_LOG && !is_batch_call) {
        // [PKT-CRYPTO] — human-readable field-level breakdown for manual inspection
        std::cout << "[PKT-CRYPTO] ── VERIFY ────────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   claimed   = " << claimed_signer << "  (original signer)\n"
                  << "[PKT-CRYPTO]   pkt_id    = " << pkt_id << "  (flow=" << seq << ", msg_id=" << msg_id << ")\n"
                  << "[PKT-CRYPTO]   verifier  = " << next_hop << "  (this hop)\n"
                  << "[PKT-CRYPTO]   -- Reconstructed sign buffer (must match signer) -\n"
                  << "[PKT-CRYPTO]   msg_id    = " << msg_id                        << "  ✓ (same as signed)\n"
                  << "[PKT-CRYPTO]   ts_sign   = " << it->second.sign_timestamp     << " s  (from signed record)\n"
                  << "[PKT-CRYPTO]   nonce(η)  = 0x" << _hex32(it->second.nonce)   << "  (from signed record)\n"
                  << "[PKT-CRYPTO]   next_hop  = " << next_hop                      << "  (must equal signed_next_hop=" << it->second.signed_next_hop << ")\n"
                  << "[PKT-CRYPTO]   zone      = " << it->second.signed_zone_id     << "  (from signed record)\n"
                  << "[PKT-CRYPTO]   -- SHA3-512 recomputed digest ----------------------\n"
                  << "[PKT-CRYPTO]   digest[0..7]  = " << _hex8(digest) << "\n"
                  << "[PKT-CRYPTO]   digest[8..15] = " << _hex8(digest+8) << "\n"
                  << "[PKT-CRYPTO]   -- OQS ML-DSA-87 verify result --------------------\n"
                  << "[PKT-CRYPTO]   sig[0..7]  = " << _hex8(it->second.sig) << "\n"
                  << "[PKT-CRYPTO]   pk[0..7]   = " << _hex8(g_node_keys[claimed_signer].pk) << "\n"
                  << "[PKT-CRYPTO]   result     = " << (ok ? "PASS ✓  signature authentic" : "FAIL ✗  signature invalid") << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[CRYPTO-VERIFY] claimed=" << claimed_signer
                  << " pkt=" << pkt_id
                  << " flow=" << seq
                  << " ok=" << ok
                  << " sig_len=" << it->second.sig_len  // expected 4627
                  << " t_verify=" << ns3::Simulator::Now().GetSeconds()
                  << " t_sign=" << it->second.sign_timestamp
                  << " Δ=" << (ns3::Simulator::Now().GetSeconds() - it->second.sign_timestamp)
                  << " batch=" << is_batch_call
                  << " attempts=" << g_verify_attempts
                  << " passed=" << g_verify_passed
                  << " rate=" << (g_verify_attempts > 0
                                  ? (double)g_verify_passed / g_verify_attempts : 1.0)
                  << " pk[0..3]=" << _hex4(g_node_keys[claimed_signer].pk) << "\n";
    if (!ok)
        std::cout << "[CRYPTO-WARN] ML-DSA-87 verify FAILED:"
                  << " claimed_signer=" << claimed_signer
                  << " pkt=" << pkt_id
                  << " sig[0..3]=" << _hex4(it->second.sig)
                  << " digest[0..3]=" << _hex4(digest) << "\n";
    return ok;
}

// ── ML-DSA-87 Content-Authenticity Verify (Hidden-Forwarding copies) ────────
//
// mldsa87_verify()'s broadcast-skip branch (next_hop != signed_next_hop)
// early-returns false for ANY receiver that is not the intended next hop,
// BEFORE ever running real cryptography. That is correct for statistics like
// sig_valid_rate, but it means it can never distinguish a content-fabricated
// copy (Active HF, Attacks 5/6, eq:sig_s5/eq:sig_s6) from a content-unmodified
// copy (Passive HF, Attacks 7/8, eq:sig_s7/eq:sig_s8): an eavesdropper's
// current_hop never equals signed_next_hop in EITHER case, so the same
// early-return fires regardless of content. Hop-legitimacy (b_hop(u), the
// STARK check) is already handled independently by stark_verify_hop().
//
// This function checks ONLY content authenticity, decoupled from hop
// identity, by genuinely re-running OQS_SIG_verify() against the ORIGINAL
// signature the honest sender produced:
//   fabricated=false  reconstructs the exact digest that was signed (real
//                      nonce) — OQS_SIG_verify genuinely succeeds, matching
//                      "the passive copy's content is unmodified."
//   fabricated=true   recomputes the digest with the nonce field flipped,
//                      simulating that the attacker altered the message
//                      before forwarding it — the digest no longer matches
//                      what OQS_SIG_sign() actually signed, so
//                      OQS_SIG_verify() genuinely (not by hardcoding) fails.
// Side-effect-free: unlike mldsa87_verify(), this does not write sig_valid,
// nor touch g_verify_attempts/g_verify_passed — those belong to the
// legitimate recipient's own verify call and must not be perturbed by this
// receiver-specific, out-of-band content check performed at the eavesdropper.
//
// FIXED 2026-07-27 (was: "KNOWN LIMITATION (inherited, not introduced here):
// g_packet_crypto is keyed only by (signer, pkt_id)..."): the map is now
// keyed by (signer, crypto_msg_key(pkt_id, flow_id)) everywhere it is
// touched, so pkt_id reuse across flows/cycles no longer aliases onto the
// same slot. Caller must pass the packet's true flow_id (base_flow_id in
// s5-s8_detection.h, i.e. the marker-stripped value, not recv_flow_id).
inline bool mldsa87_verify_copy_content(uint32_t claimed_signer, uint32_t pkt_id,
                                         uint32_t flow_id, bool fabricated) {
    if (g_disable_crypto) return !fabricated; // crypto disabled: keep deterministic semantics
    if (claimed_signer >= (uint32_t)total_size) return false;
    uint32_t msg_id = crypto_msg_key(pkt_id, flow_id);
    auto it = g_packet_crypto.find({claimed_signer, msg_id});
    if (it == g_packet_crypto.end() || it->second.sig_len == 0) return false;

    uint32_t nonce_for_digest = fabricated ? (it->second.nonce ^ 0xFFFFFFFFu)
                                            : it->second.nonce;

    uint8_t sign_buf[MLDSA_SIGN_BUF] = {};
    memcpy(sign_buf,    &msg_id,                     4);
    memcpy(sign_buf+4,  &it->second.sign_timestamp,   8);
    memcpy(sign_buf+12, &nonce_for_digest,             4);
    memcpy(sign_buf+16, &it->second.signed_next_hop,   4);
    memcpy(sign_buf+20, &it->second.signed_zone_id,    4);

    uint8_t digest[64];
    if (!sha3_512_hash(sign_buf, MLDSA_SIGN_BUF, digest)) return false;

    OQS_SIG* sig = get_oqs_ctx();
    if (!sig) return false;

    bool ok = OQS_SIG_verify(sig, digest, 64,
                              it->second.sig, it->second.sig_len,
                              g_node_keys[claimed_signer].pk) == OQS_SUCCESS;

    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[PKT-CRYPTO] ── VERIFY-COPY-CONTENT (HF) ────────────────────────\n"
                  << "[PKT-CRYPTO]   claimed_signer = " << claimed_signer << "\n"
                  << "[PKT-CRYPTO]   pkt_id         = " << pkt_id << "\n"
                  << "[PKT-CRYPTO]   fabricated     = " << fabricated << "\n"
                  << "[PKT-CRYPTO]   result         = "
                  << (ok ? "PASS ✓  content authentic" : "FAIL ✗  content fabricated") << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return ok;
}

// ── STARK Proof Simulation — eq:stark_delay / eq:stark_hop ───────────────────

inline StarkTimingProof stark_prove_timing(double t_recv, double t_fwd, uint32_t nonce) {
    StarkTimingProof proof;
    if (!enable_stark_delay) { proof.valid = true; return proof; } // AB4: π_delay removed — vacuously passes
    // M7 eq:o_crypto / main.tex:5123 "Proof generation overhead is modelled as
    // <=10ms per packet" — measures the real wall-clock cost of this simulated
    // proof-generation step (see g_m7_stark_wall_us_sum comment for scope).
    auto _st0 = std::chrono::high_resolution_clock::now();
    proof.valid = (t_fwd - t_recv) <= STARK_DELTA_MAX;
    // c_i = H_SHA3-512(ρ_i) — commit to blinding randomness only; timestamps are
    // private witnesses and must not appear in the public commitment (eq:stark_delay ZK)
    sha3_512_hash(reinterpret_cast<const uint8_t*>(&nonce), sizeof(nonce), proof.commitment);
    auto _st1 = std::chrono::high_resolution_clock::now();
    g_m7_stark_wall_us_sum += std::chrono::duration<double, std::micro>(_st1 - _st0).count();
    ++g_m7_stark_calls;
    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[PKT-CRYPTO] ── STARK-PROVE ────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   nonce(ρ_i)    = 0x" << _hex32(nonce) << "  (blinding randomness)\n"
                  << "[PKT-CRYPTO]   t_recv        = " << t_recv << " s  (private witness)\n"
                  << "[PKT-CRYPTO]   t_fwd         = " << t_fwd  << " s  (private witness)\n"
                  << "[PKT-CRYPTO]   Δ = t_fwd-t_recv = " << (t_fwd - t_recv)*1000.0 << " ms\n"
                  << "[PKT-CRYPTO]   STARK_DELTA_MAX  = " << STARK_DELTA_MAX*1000.0   << " ms\n"
                  << "[PKT-CRYPTO]   timing_valid  = " << (proof.valid ? "YES ✓  within bound" : "NO ✗   DELAY EXCEEDS LIMIT") << "\n"
                  << "[PKT-CRYPTO]   commitment    = H(ρ_i) = " << _hex8(proof.commitment) << "  (ZK: no ts in commit)\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return proof;
}

inline bool stark_verify_timing(const StarkTimingProof& proof,
                                 double t_recv, double t_fwd) {
    if (!enable_stark_delay) return true; // AB4: π_delay removed — vacuously passes
    auto _st0 = std::chrono::high_resolution_clock::now();
    bool ok = proof.valid && (t_fwd - t_recv) <= STARK_DELTA_MAX;
    auto _st1 = std::chrono::high_resolution_clock::now();
    g_m7_stark_wall_us_sum += std::chrono::duration<double, std::micro>(_st1 - _st0).count();
    ++g_m7_stark_calls;
    return ok;
}

// Verify that current_hop is the node the sender intended as its next hop
// (embedded in the signature at sign time). Re-running find_next_hop at
// verification time is unreliable in a dynamic VANET because routing tables
// change between send and receive. Using the signed_next_hop eliminates
// false positives from routing churn while still catching misdirected packets.
inline bool stark_verify_hop(uint32_t current_hop, uint32_t signer, uint32_t pkt_id,
                              uint32_t flow_id) {
    if (!enable_stark_hop) return true; // AB4: π_hop removed — vacuously passes
    if (g_disable_crypto) return true; // crypto disabled via --disable_crypto
    auto it = g_packet_crypto.find({signer, crypto_msg_key(pkt_id, flow_id)});
    if (it == g_packet_crypto.end() || it->second.signed_next_hop == (uint32_t)-1)
        return true;  // no signing record — can't verify, assume valid
    auto _st0 = std::chrono::high_resolution_clock::now();
    bool hop_ok = (current_hop == it->second.signed_next_hop);
    auto _st1 = std::chrono::high_resolution_clock::now();
    g_m7_stark_wall_us_sum += std::chrono::duration<double, std::micro>(_st1 - _st0).count();
    ++g_m7_stark_calls;
    if (CRYPTO_DEBUG_LOG) {
        std::cout << "[PKT-CRYPTO] ── STARK-HOP ─────────────────────────────────────\n"
                  << "[PKT-CRYPTO]   signer          = " << signer << "\n"
                  << "[PKT-CRYPTO]   pkt_id          = " << pkt_id << "\n"
                  << "[PKT-CRYPTO]   signed_next_hop = " << it->second.signed_next_hop << "  (embedded at sign time)\n"
                  << "[PKT-CRYPTO]   current_hop     = " << current_hop << "  (actual receiver)\n"
                  << "[PKT-CRYPTO]   hop_ok          = " << (hop_ok ? "YES ✓  packet on intended path"
                                                                     : "NO ✗   packet misdirected!") << "\n"
                  << "[PKT-CRYPTO] ─────────────────────────────────────────────────────\n";
    }
    return hop_ok;
}

// Defined in routing.cc (after this header is included) alongside the other HF
// ground-truth attribution helpers; forward-declared here so stark_update_meta
// can use it. Same pattern routing.cc itself uses for
// lookup_vehicle_associated_rsu_local_idx (routing.cc:115058) -- both are inline
// and defined later in this same translation unit.
inline uint32_t hf_gt_attribution_node(uint32_t node);

inline void stark_update_meta(uint32_t signer, uint32_t pkt_id, uint32_t flow_id,
                               bool timing_ok, bool hop_ok) {
    auto it = g_packet_crypto.find({signer, crypto_msg_key(pkt_id, flow_id)});
    if (it == g_packet_crypto.end()) return;
    // Packet-level STARK state stays keyed by the SIGNER -- it is read back per
    // packet by S5-S8 via g_packet_crypto, not by RSU, so it must not be
    // re-attributed.
    it->second.stark_timing_ok = timing_ok;
    it->second.stark_hop_ok    = hop_ok;

    // Supervisor review fix (2026-08-03): the LSTM counters below are only ever
    // READ by lstm_log_rsu_cycle() (lstm_logger.h) and crypto_get_lstm_features()
    // via RSU-indexed keys. For the DP variants (A2/A4/A6/A8) `signer` is very
    // often a VEHICLE, so incrementing under the vehicle's own node index
    // silently orphaned the entry -- never surfacing in any RSU's CSV row -- and
    // zkp_hop_fail/zkp_delay_fail read a permanent 0 for every DP attacker.
    // That is a systematically wrong input feature on four of the eight
    // variants, so it must be fixed before the retrain, not after.
    // Same covering-RSU attribution already applied to hf_send_gt/r_anom: the
    // RSU with the strongest current DSRC link to that vehicle, i.e. the vantage
    // point from which a real IDS would actually observe this failure.
    // UINT32_MAX => no RSU currently in range, so no RSU observes it and
    // correctly nothing is counted anywhere.
    // Both counters are attributed together so crypto_get_lstm_features()'s
    // fail/total ratio stays consistent.
    // Measured A/B on A2 (p=60, 30s, seed 7, identical params): attributing to
    // `signer` directly yielded zkp_delay_fail = 0 RSUs / 0 cycles -- the feature
    // was dead across the ENTIRE training set. Via the covering RSU: 37 RSUs /
    // 187 cycles. zkp_hop_fail stayed 0 in both, correctly: per eq:stark_hop
    // (main.tex:2993-3010) pi_hop encodes next-hop policy compliance, which a
    // delay attack never violates -- only the misrouting families A5-A8 exercise it.
    uint32_t lstm_node = hf_gt_attribution_node(signer);
    if (lstm_node != UINT32_MAX) {
        g_lstm_pkt_counts[lstm_node]++;
        if (!timing_ok) g_lstm_stark_counts[lstm_node].first++;
        if (!hop_ok)    g_lstm_stark_counts[lstm_node].second++;
    }
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[STARK] signer=" << signer
                  << " lstm_attrib=" << (lstm_node == UINT32_MAX
                                          ? std::string("none")
                                          : std::to_string(lstm_node))
                  << " pkt=" << pkt_id
                  << " flow=" << flow_id
                  << " t=" << ns3::Simulator::Now().GetSeconds()
                  << " timing_ok=" << timing_ok
                  << " hop_ok=" << hop_ok
                  << " | lstm_t_fails=" << (lstm_node == UINT32_MAX ? 0u : g_lstm_stark_counts[lstm_node].first)
                  << " lstm_h_fails=" << (lstm_node == UINT32_MAX ? 0u : g_lstm_stark_counts[lstm_node].second)
                  << " pkt_count="    << (lstm_node == UINT32_MAX ? 0u : g_lstm_pkt_counts[lstm_node]) << "\n";
}

// ── Randomised Batch Verification — eq:batch_challenge / eq:batch_verify ─────

inline BatchVerifyResult batch_verify_mldsa87(
    const std::vector<std::pair<uint32_t,uint32_t>>& node_pkt_pairs,
    double budget_s = 0.050)
{
    BatchVerifyResult res{true, 0, 0.0};

    std::vector<uint8_t> combined;
    combined.reserve(node_pkt_pairs.size() *
                     (OQS_SIG_ml_dsa_87_length_signature + 64));
    for (auto& [node, pkt] : node_pkt_pairs) {
        auto it = g_packet_crypto.find({node, pkt});
        if (it != g_packet_crypto.end() && it->second.sig_len > 0)
            combined.insert(combined.end(),
                            it->second.sig,
                            it->second.sig + it->second.sig_len);
    }
    for (auto& [node, pkt] : node_pkt_pairs) {
        auto it = g_packet_crypto.find({node, pkt});
        if (it != g_packet_crypto.end() && it->second.sig_len > 0)
            combined.insert(combined.end(),
                            it->second.msg_digest, it->second.msg_digest + 64);
    }
    // r = H(σ_1 ‖ … ‖ σ_n ‖ m_1 ‖ … ‖ m_n) — eq:batch_challenge shared binding
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), res.challenge);

    for (auto& [node, pkt] : node_pkt_pairs) {
        if (res.elapsed_s >= budget_s) break;
        // Use the stored signed_next_hop so the broadcast-skip guard in mldsa87_verify
        // does not reject every packet when called with next_hop=0.
        auto it_bv = g_packet_crypto.find({node, pkt});
        uint32_t nh = (it_bv != g_packet_crypto.end())
                      ? it_bv->second.signed_next_hop : 0;
        // node_pkt_pairs' second element is a raw g_packet_crypto KEY (already
        // crypto_msg_key(pkt_id,flow_id) — see crypto_batch_verify_tick(),
        // which builds `pending` straight from the map's own keys). Decompose
        // it back to the raw (pkt_id, flow_id) pair mldsa87_verify() expects,
        // so its internal re-composition reproduces this exact `pkt` value
        // instead of re-encoding an already-composite number.
        if (!mldsa87_verify(node, crypto_msg_key_pkt(pkt), nh,
                             crypto_msg_key_flow(pkt), /*is_batch_call=*/true))
            res.passed = false;
        ++res.n_verified;
        res.elapsed_s += 0.001;
    }

    if (CRYPTO_DEBUG_LOG && res.n_verified > 0)
        std::cout << "[BATCH-VERIFY] n=" << res.n_verified
                  << " passed=" << res.passed
                  << " challenge[0..3]=" << (combined.empty() ? "n/a" : _hex4(res.challenge))
                  << " elapsed=" << res.elapsed_s << "s\n";
    return res;
}

// ── LSTM Feature Export Bridge — eq:lstm_input ────────────────────────────────

inline CryptoLstmFeatures crypto_get_lstm_features(uint32_t node) {
    CryptoLstmFeatures f{0.0f, 0.0f};
    auto pc = g_lstm_pkt_counts.find(node);
    if (pc == g_lstm_pkt_counts.end() || pc->second == 0) return f;
    auto sc = g_lstm_stark_counts.find(node);
    if (sc == g_lstm_stark_counts.end()) return f;
    float total = (float)pc->second;
    f.stark_timing_fail = (float)sc->second.first  / total;
    f.stark_hop_fail    = (float)sc->second.second / total;
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[LSTM-FEAT] node=" << node
                  << " pkt_count=" << pc->second
                  << " stark_timing_fail=" << f.stark_timing_fail
                  << " stark_hop_fail=" << f.stark_hop_fail << "\n";
    return f;
}

inline void crypto_reset_lstm_accumulators() {
    g_lstm_pkt_counts.clear();
    g_lstm_stark_counts.clear();
}

// ── Controller RSU Re-assignment — eq:ctrl_failover ───────────────────────────

inline void ctrl_reassign_rsus(uint32_t revoked_ctrl);

// ── Trust Management — eq:trust_update / eq:quarantine ───────────────────────

inline void trust_init_all() {
    for (uint32_t i = 0; i < (uint32_t)total_size; ++i) {
        g_trust_score[i] = g_ctrl_trust_score[i] = 1.0;
        g_quarantined[i] = g_ctrl_revoked[i]      = false;
        g_trust_last_update[i] = 0.0;
        g_node_keys[i] = NodeKeyMaterial{};
    }
    g_dkg = DKGState{};
    g_T_ref = g_T_ref_last_sync = 0.0;
    g_packet_crypto.clear(); g_flowmod_endorsements.clear();
    g_witness_log.clear(); g_witness_alert_pool.clear();
    g_msg_id_seen.clear(); g_dst_volume_prev.clear(); g_dst_volume_curr.clear();
    g_lstm_pkt_counts.clear(); g_lstm_stark_counts.clear();
    g_failover_max_ms = 0.0; g_failover_events = 0; g_failover_reassigned = 0;
    g_m7_crypto_bytes_sum = 0.0; g_m7_signed_pkts = 0;
    g_m7_batch_wall_us_sum = 0.0; g_m7_batch_calls = 0; g_m7_batch_pkts = 0;
    g_m7_consensus_wall_us_sum = 0.0; g_m7_consensus_count = 0;
    g_m7_stark_wall_us_sum = 0.0; g_m7_stark_calls = 0;
    if (g_oqs_sig) { OQS_SIG_free(g_oqs_sig); g_oqs_sig = nullptr; }
}

inline void trust_update_positive(uint32_t node) {
    if (!enable_quarantine) return; // AB7-A: detection-only — trust never moves
    if (node >= (uint32_t)total_size) return;
    double old_v = g_trust_score[node];
    double v = old_v + TRUST_DELTA_R;
    g_trust_score[node] = (v < 1.0 ? v : 1.0);
    g_trust_last_update[node] = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[TRUST+] node=" << node
                  << " " << old_v << " → " << g_trust_score[node]
                  << " (Δ_r=" << TRUST_DELTA_R << ")"
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
}

inline void trust_update_negative(uint32_t node) {
    if (!enable_quarantine) return; // AB7-A: detection-only — no SC.Quarantine
    if (node >= (uint32_t)total_size) return;
    double old_v = g_trust_score[node];
    double v = old_v - TRUST_DELTA_P;
    g_trust_score[node] = (v > 0.0 ? v : 0.0);
    g_trust_last_update[node] = ns3::Simulator::Now().GetSeconds();
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[TRUST-] node=" << node
                  << " " << old_v << " → " << g_trust_score[node]
                  << " (Δ_p=" << TRUST_DELTA_P
                  << " T_min=" << TRUST_T_MIN << ")"
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
    if (g_trust_score[node] < TRUST_T_MIN && !g_quarantined[node]) {
        g_quarantined[node] = true;
        t_quarantine[node]  = ns3::Simulator::Now().GetSeconds();

        // Item 4 (2026-09-05): release the HF activity latch here, per
        // eq:local_quarantine -- but only for variants whose enforcement is
        // confirmed (see hf_latch_resets_at_quarantine()). Default-off, so this
        // block does nothing unless explicitly enabled.
        //
        // Which latch index. g_hf_activity_latch is keyed by RSU LOCAL index and
        // is set through hf_gt_attribution_node(), so:
        //   - node is an RSU (A5/A7): clear its own latch. Unambiguous.
        //   - node is a vehicle (A6/A8): the latch sits on its COVERING RSU,
        //     which may also cover other attacking vehicles. Clearing it
        //     unconditionally would blank the truth for attackers that are still
        //     active -- the mirror image of the guard's over-block. So clear only
        //     once no non-quarantined HF attacker still attributes to that RSU.
        //     Same iteration the witness path already uses (see g_witness_TP_W).
        if (hf_latch_resets_at_quarantine()) {
            uint32_t _tgt = hf_gt_attribution_node(node);
            if (_tgt != UINT32_MAX && _tgt >= (uint32_t)N_Vehicles) {
                bool _still_active = false;
                for (int _n = 0; _n < total_size; ++_n) {
                    if (!active_hf_malicious_nodes[_n]
                        && !passive_hf_malicious_nodes[_n]) continue;
                    if ((uint32_t)_n == node)   continue;  // the one just contained
                    if (g_quarantined[_n])      continue;  // already contained
                    if (hf_gt_attribution_node((uint32_t)_n) == _tgt) {
                        _still_active = true;
                        break;
                    }
                }
                if (!_still_active) {
                    hf_truth_latch_clear(_tgt - (uint32_t)N_Vehicles);
                    std::cout << "[HF-LATCH-CLEAR] rsu=" << _tgt
                              << " on quarantine of node=" << node
                              << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
                }
            }
        }
        // Supervisor Fix 1 (2026-08-19): record_detection_event() removed from
        // this path. Quarantine is a MITIGATION consequence of trust falling
        // below T_MIN, not a detection event -- the node was already recorded
        // (is_detected_node[][] set) at whichever signature/LSTM/witness call
        // first fired to cause the trust drop. Calling record_detection_event()
        // again here double-counted that same detection AND, independently,
        // caught benign nodes whose trust collapsed from transient disruption
        // at attack arming (confirmed: 254 quarantine events for A5 vs its
        // FP=219 in the sticky-latch table, 57% firing within 10s of
        // attack_start_time -- see docs/SUPERVISOR_FIXES_2026-08-14.md's A5/A7
        // root-cause section). The quarantine itself -- trust penalty, T_MIN
        // check, node isolation, key rotation below -- is completely
        // unchanged; only the confusion-matrix recording is removed.
        // Unconditional: quarantine is a high-importance MITIGATION event
        std::cout << "[TRUST-QUARANTINE] node=" << node
                  << " trust=" << g_trust_score[node]
                  << " < T_min=" << TRUST_T_MIN
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
        NS_LOG_WARN("[TRUST] Quarantine: node=" << node
            << " trust=" << g_trust_score[node]
            << " t=" << ns3::Simulator::Now().GetSeconds());
        // eq:key_rotation_trigger: if revoked node is an RSU, rotate all proving keys
        // AB11-A (enable_key_rotation=false): revoked RSU's key material stays live
        if (enable_key_rotation && node >= N_Vehicles && node < N_Vehicles + N_RSUs)
            dkg_rotate_keys(node);
    }
}

inline void ctrl_trust_update_positive(uint32_t ctrl) {
    if (!enable_controller_failover) return; // AB9-A: controller trust scoring inert
    if (ctrl >= N_Controllers || g_ctrl_revoked[ctrl]) return;
    double v = g_ctrl_trust_score[ctrl] + TRUST_DELTA_R_CTRL;
    g_ctrl_trust_score[ctrl] = (v < 1.0 ? v : 1.0);
}

inline void ctrl_trust_update_negative(uint32_t ctrl) {
    if (!enable_controller_failover) return; // AB9-A: no trust scoring, no revoke/failover
    if (ctrl >= N_Controllers) return;
    double old_v = g_ctrl_trust_score[ctrl];
    double v = old_v - TRUST_DELTA_P_CTRL;
    g_ctrl_trust_score[ctrl] = (v > 0.0 ? v : 0.0);
    if (g_ctrl_trust_score[ctrl] < TRUST_T_MIN_CTRL && !g_ctrl_revoked[ctrl]) {
        g_ctrl_revoked[ctrl] = true;
        ctrl_reassign_rsus(ctrl);
        // Unconditional: controller revocation is high-importance
        std::cout << "[CTRL-REVOKED] controller idx=" << ctrl
                  << " trust=" << old_v << " → " << g_ctrl_trust_score[ctrl]
                  << " < T_min_ctrl=" << TRUST_T_MIN_CTRL
                  << " t=" << ns3::Simulator::Now().GetSeconds() << "\n";
        NS_LOG_WARN("[CTRL-TRUST] Controller revoked: idx=" << ctrl
            << " t=" << ns3::Simulator::Now().GetSeconds());
    }
}

// M5 completion handler — fires when the ControllerRevoked broadcast reaches
// RSU r. Applies the failover target chosen at revocation time (eq:ctrl_failover
// arg-min over C_trusted(t)\{c_i}) and stamps t_reassign^(k) for eq:l_failover.
inline void ctrl_complete_rsu_reassign(uint32_t r, uint32_t best,
                                       uint32_t revoked_ctrl, double t_revoke) {
    rsu_controller_assignment[r] = (int)best;
    ++g_failover_reassigned;
    double lat_ms = (ns3::Simulator::Now().GetSeconds() - t_revoke) * 1000.0;
    if (lat_ms > g_failover_max_ms) g_failover_max_ms = lat_ms;
    NS_LOG_WARN("[CTRL-FAILOVER] RSU " << r << " ctrl " << revoked_ctrl
        << " → " << best << " L=" << lat_ms << "ms");
    // eq:l_failover target: L_failover ≤ 100 ms (proposal Table, M5)
    if (lat_ms > 100.0)
        std::cout << "[CTRL-FAILOVER] WARNING: RSU " << r
                  << " reassignment latency " << lat_ms
                  << " ms EXCEEDS 100ms bound\n";
}

inline void ctrl_reassign_rsus(uint32_t revoked_ctrl) {
    std::vector<uint32_t> trusted;
    for (uint32_t c = 0; c < N_Controllers; ++c)
        if (!g_ctrl_revoked[c]) trusted.push_back(c);
    if (trusted.empty()) {
        std::cerr << "[CRYPTO-ERROR] ctrl_reassign_rsus: ALL controllers revoked"
                  << " — no failover possible\n";
        NS_LOG_ERROR("[CTRL] All controllers revoked — no failover possible");
        return;
    }
    // t_revoke — SC.Revoke has just fired (eq:sc_revoke); the ControllerRevoked
    // event broadcast starts now.
    //
    // g_failover_max_ms is a MONOTONIC running max across the whole simulation
    // (never reset here) — deliberately NOT reset per-event. An earlier version
    // reset it to 0.0 on every call, which is race-prone whenever two
    // revocations overlap in time (realistic under the proposal's "2
    // compromised controllers" scenario, since the default broadcast
    // completion delay is only ~10-15ms): a second revocation's reset could
    // discard an in-flight first revocation's already-recorded latency, and
    // the first revocation's still-pending completions would then update a
    // max that was reset for an unrelated event, mixing two events' latencies
    // together. Reporting the worst L_failover observed by ANY revocation
    // event so far in the run avoids the race entirely and still answers the
    // proposal's target-bound question (does L_failover stay <= 100ms across
    // every event). See docs/METRICS_DEVIATIONS_FROM_PROPOSAL.md.
    double t_revoke = ns3::Simulator::Now().GetSeconds();
    ++g_failover_events;
    uint32_t zone_size = N_RSUs / N_Controllers;
    uint32_t affected = 0;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        if ((uint32_t)rsu_controller_assignment[r] != revoked_ctrl) continue;
        uint32_t rsu_zone = r / (zone_size > 0 ? zone_size : 1);
        // eq:ctrl_failover — target selected from C_trusted(t)\{c_i} at t_revoke
        uint32_t best = trusted[0], min_d = UINT32_MAX;
        for (uint32_t c : trusted) {
            uint32_t d = (rsu_zone > c) ? rsu_zone - c : c - rsu_zone;
            if (d < min_d) { min_d = d; best = c; }
        }
        // Reassignment completes when the ControllerRevoked event reaches RSU r
        // and it re-attaches to its new controller: base broadcast latency plus
        // a geographic-dispersion increment proportional to the zone distance
        // min_d to that new controller. Until the event fires, the RSU still
        // points at the revoked controller — the realistic vulnerability window
        // whose worst case eq:l_failover's max is designed to capture.
        double delay_ms = FAILOVER_BCAST_BASE_MS
                        + FAILOVER_BCAST_PER_ZONE_MS * (double)min_d;
        ns3::Simulator::Schedule(ns3::Seconds(delay_ms / 1000.0),
                                 &ctrl_complete_rsu_reassign,
                                 r, best, revoked_ctrl, t_revoke);
        ++affected;
    }
    // Unconditional: failover summary
    std::cout << "[CTRL-FAILOVER] SC.Revoke ctrl=" << revoked_ctrl
              << " t_revoke=" << t_revoke
              << " ControllerRevoked broadcast to " << affected
              << " affected RSUs (trusted_count=" << trusted.size()
              << "); completions scheduled at " << FAILOVER_BCAST_BASE_MS
              << "ms + " << FAILOVER_BCAST_PER_ZONE_MS << "ms/zone\n";
}

// ── Distributed Time Reference — eq:time_consensus ───────────────────────────

inline void update_T_ref() {
    double t_ground = ns3::Simulator::Now().GetSeconds(); // eq:eps_ref T_ground(t)
    std::vector<double> times;
    times.reserve(N_RSUs);
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        // eq:time_consensus tau_j(t): each RSU's own local clock reading,
        // via the same node_clock_offset() every per-packet timestamp uses
        // (single source of truth — see M9 report Tier-2 item).
        times.push_back(node_local_time(N_Vehicles + r));
    }
    std::sort(times.begin(), times.end());
    g_T_ref           = times[times.size() / 2];
    g_T_ref_last_sync = t_ground;

    // M9 — eq:eps_ref: deviation of the consensus median from ground truth.
    g_eps_ref = (g_T_ref > t_ground) ? (g_T_ref - t_ground) : (t_ground - g_T_ref);
    g_eps_ref_cumulative += g_eps_ref;
    ++g_eps_ref_samples;

    // sec:time_ref — commit this tick's T_ref(t) to the blockchain (tamper-evident
    // audit trail), same T_SYNC_INTERVAL cadence as bc_anchor_to_global().
    bc_commit_tref_to_chain(g_T_ref, g_eps_ref, t_ground);

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[T-REF] Distributed time synced T_ref=" << g_T_ref
                  << " from " << N_RSUs << " RSUs (f_bad=" << TIME_REF_F_BAD
                  << ", delta_attack=" << TIME_REF_DELTA_ATTACK << "s)"
                  << " eps_ref=" << g_eps_ref << "s t=" << g_T_ref_last_sync << "\n";
}

inline void update_T_ref_recurring() {
    update_T_ref();
    ns3::Simulator::Schedule(ns3::Seconds(T_SYNC_INTERVAL), &update_T_ref_recurring);
}

// ── Map Eviction ──────────────────────────────────────────────────────────────

inline void crypto_evict_old_entries() {
    double cutoff = ns3::Simulator::Now().GetSeconds() - 5.0;
    size_t before = g_packet_crypto.size();
    for (auto it = g_packet_crypto.begin(); it != g_packet_crypto.end(); )
        it = (it->second.sign_timestamp < cutoff)
             ? g_packet_crypto.erase(it) : std::next(it);
    double wcut = ns3::Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    for (auto& [w, entries] : g_witness_log)
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [wcut](const WitnessLogEntry& e){ return e.ts < wcut; }),
            entries.end());
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[EVICT] crypto_map " << before << " → " << g_packet_crypto.size()
                  << " (cutoff t=" << cutoff << ")\n";
}

inline void crypto_evict_old_entries_recurring() {
    crypto_evict_old_entries();
    ns3::Simulator::Schedule(ns3::Seconds(5.0), &crypto_evict_old_entries_recurring);
}

// ── Batch Verify Tick (recurring, 50 ms) ─────────────────────────────────────

inline void crypto_batch_verify_tick() {
    std::vector<std::pair<uint32_t,uint32_t>> pending;
    double window = ns3::Simulator::Now().GetSeconds() - 0.050;
    for (auto& [key, meta] : g_packet_crypto)
        if (meta.sign_timestamp >= window) pending.push_back(key);
    if (!pending.empty()) {
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[BATCH-TICK] t=" << ns3::Simulator::Now().GetSeconds()
                      << " pending=" << pending.size() << " pkts in 50ms window\n";
        // M7 eq:t_verify — T_batch(B): real wall-clock time of BatchVerify over B pkts
        auto _bt0 = std::chrono::high_resolution_clock::now();
        auto result = batch_verify_mldsa87(pending);
        auto _bt1 = std::chrono::high_resolution_clock::now();
        double _b_us = std::chrono::duration<double, std::micro>(_bt1 - _bt0).count();
        g_m7_batch_wall_us_sum += _b_us;
        ++g_m7_batch_calls;
        g_m7_batch_pkts += pending.size();
        // per-op row: node_id column carries B (batch size), pkt_id carries
        // n_verified; not a single-packet/single-flow event, so flow_id is
        // UINT32_MAX (not applicable).
        crypto_log_event("batch_verify", (uint32_t)pending.size(),
                         result.n_verified, UINT32_MAX, _bt0, result.passed);
        g_batch_passed = result.passed; // feed b_batch into LRAD (eq:batch_challenge)
        if (!result.passed) {
            std::cerr << "[CRYPTO-ERROR] Batch verify tick FAILED:"
                      << " " << pending.size() << " pkts"
                      << " verified=" << result.n_verified << "\n";
            NS_LOG_WARN("[BATCH] Verify failed: " << pending.size() << " pkts");
        }
    }
    ns3::Simulator::Schedule(ns3::Seconds(0.050), &crypto_batch_verify_tick);
}

// ── Witness Mechanism — eq:da_sign, eq:nfa_sign, eq:bft_penalty ──────────────

inline void witness_log_packet(uint32_t witness, const uint8_t* pkt_hash,
                                uint32_t dst, double ts) {
    WitnessLogEntry e;
    memcpy(e.pkt_hash, pkt_hash, 64); e.dst = dst; e.ts = ts;
    g_witness_log[witness].push_back(e);
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-LOG] witness=" << witness
                  << " dst=" << dst
                  << " hash[0..3]=" << _hex4(pkt_hash)
                  << " log_size=" << g_witness_log[witness].size() << "\n";
}

// matched_dst / matched_age_out: diagnostic outputs (2026-08-06) used to
// characterise WHY eq:dup_alert_cond fires. Pass nullptr to ignore.
inline bool witness_check_duplication(uint32_t witness, const uint8_t* pkt_hash,
                                       uint32_t dst_seen_now,
                                       uint32_t* matched_dst = nullptr,
                                       double*   matched_age = nullptr) {
    auto it = g_witness_log.find(witness);
    if (it == g_witness_log.end()) return false;
    double cutoff = ns3::Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    for (auto& e : it->second)
        if (memcmp(e.pkt_hash, pkt_hash, 64) == 0 &&
            e.dst != dst_seen_now && e.ts >= cutoff) {
            if (matched_dst) *matched_dst = e.dst;
            if (matched_age) *matched_age = ns3::Simulator::Now().GetSeconds() - e.ts;
            if (CRYPTO_DEBUG_LOG)
                std::cout << "[WITNESS-DUP] witness=" << witness
                          << " hash[0..3]=" << _hex4(pkt_hash)
                          << " prev_dst=" << e.dst
                          << " new_dst=" << dst_seen_now
                          << " → DUPLICATION DETECTED\n";
            return true;
        }
    return false;
}

// eq:bft_penalty quorum test — shared by the α_w (DA) and β_w (NFA) paths.
//
// main.tex, immediately below eq:bft_penalty, is explicit about three things
// this function must do, none of which the original inline loop did:
//   "The cardinality is over DISTINCT witness vehicles w that have each
//    submitted at least one valid alert (signed under their own pk_w) for the
//    same (v_i, p) event --- NOT over the total number of alert messages. A
//    single witness submitting multiple alerts for the same event is counted
//    as one, preventing any one vehicle from crossing the 2f+1 threshold
//    unilaterally. The smart contract deduplicates by (w, v_i, H(p)) before
//    counting..."
//
// The previous implementation counted alert MESSAGES with no deduplication and
// never pruned g_witness_alert_pool, so (a) one witness could cross 2f+1 alone
// and (b) every alert past the third re-crossed the threshold and re-applied a
// trust penalty. Measured 2026-08-05 on A7/Q4: 14,284 crossings in a 30 s run,
// 200 of 268 nodes quarantined, FP_W=202 at 15.5% precision, MCC=-0.051, with
// the log showing "3 verified", "4 verified", "5 verified" on one target.
// SCOPED PER (v_i, p) EVENT (corrected 2026-08-06). The first version of this
// function counted distinct witnesses across the target's WHOLE pool and the
// caller then cleared the whole pool. Both halves were wrong in the same
// direction — too strict — because eq:bft_penalty's quorum is per event:
// "distinct witness vehicles w that have each submitted at least one valid
// alert ... for the same (v_i, p) event", deduplicated by (w, v_i, H(p)).
// Alerts about DIFFERENT packets are separate events and must accumulate
// independently; wiping them together discarded live evidence.
//
// Measured cost of the over-strict version on Q4 (30 s, 60 %): every penalty
// needed a fresh 3-witness quorum, and 6 penalties are required to cross
// T_min, i.e. 18 distinct witness observations to convict one attacker inside
// a 20 s attack window. A4 fell from MCC 0.444 to 0.240 (TP 10 -> 3) and A8's
// recall stayed at 20 % with FN=127. Precision was unaffected (A1/A2/A4 held
// FP=0 throughout), confirming the loss was pure recall.
//
// Returns true only when THIS event reaches quorum; the caller then clears
// only this event's alerts, leaving other events' evidence intact.
//
// eq:dup_alert_cond fix (2026-08-13, supervisor-directed, option a): event_key
// used to be ((flow_id<<32)|pkt_id) — a RECYCLING id, same bug class as
// t_claimed_packet (routing.cc, RC1). pkt_id is bounded by Flow_size+2 and
// wraps over any run longer than that many packets on a flow, so two
// witnesses reporting on genuinely DIFFERENT packet events (different H(p),
// same recycled (flow_id, pkt_id) pair at different times) collided on one
// event_key. Per this function's own spec comment above — "the smart contract
// deduplicates by (w, v_i, H(p))" — the dedup dimension was always supposed to
// be H(p), not (flow_id, pkt_id). event_key_from_hp() folds the first 8 bytes
// of H(p) (already computed at both call sites, crypto_layer.h ~1560/1649)
// into the uint64_t key instead: content-based, immune to id recycling, and
// stable across witnesses/time since it excludes ts_w (unlike h_alert, which
// would give every submission of the same event a different key).
inline uint64_t event_key_from_hp(const uint8_t h_p[64]) {
    uint64_t key;
    memcpy(&key, h_p, sizeof(key));
    return key;
}

inline bool witness_bft_quorum_reached(uint32_t target_node, uint64_t event_key,
                                        OQS_SIG* oqs) {
    auto it = g_witness_alert_pool.find(target_node);
    if (it == g_witness_alert_pool.end()) return false;

    // Prune to the observation window W, as g_witness_log already is
    // (witness_log_packet / witness_check_duplication). An alert pool that
    // never expires makes the quorum cumulative over the whole run rather
    // than over a locality-and-window, which is not what eq:bft_penalty means.
    const double cutoff = ns3::Simulator::Now().GetSeconds() - WITNESS_WINDOW;
    auto& pool = it->second;
    pool.erase(std::remove_if(pool.begin(), pool.end(),
                              [cutoff](const WitnessAlert& a) { return a.ts < cutoff; }),
               pool.end());

    // Cardinality over DISTINCT witnesses reporting THIS event, each
    // independently verified under its own pk_w. std::set keyed on witness_id,
    // restricted to event_key, is exactly the (w, v_i, H(p)) deduplication the
    // spec assigns to the smart contract.
    std::set<uint32_t> distinct_witnesses;
    for (auto& wa : pool) {
        if (wa.event_key != event_key) continue;
        if (!g_node_keys[wa.witness_id].keys_generated) continue;
        if (OQS_SIG_verify(oqs, wa.signed_digest, 64,
                           wa.alert_sig, wa.alert_sig_len,
                           g_node_keys[wa.witness_id].pk) == OQS_SUCCESS)
            distinct_witnesses.insert(wa.witness_id);
    }
    return distinct_witnesses.size() >= (size_t)(2 * WITNESS_F + 1);
}

// Clears only the alerts belonging to one resolved (v_i, p) event.
inline void witness_clear_event(uint32_t target_node, uint64_t event_key) {
    auto it = g_witness_alert_pool.find(target_node);
    if (it == g_witness_alert_pool.end()) return;
    auto& pool = it->second;
    pool.erase(std::remove_if(pool.begin(), pool.end(),
                              [event_key](const WitnessAlert& a) {
                                  return a.event_key == event_key;
                              }),
               pool.end());
}

// α_w: duplication alert — same packet at two destinations (eq:da_sign)
inline void witness_submit_duplication_alert(uint32_t witness, uint32_t target_node,
                                              uint32_t pkt_id, uint32_t flow_id,
                                              uint32_t dst, uint32_t dup_dst) {
    if (!enable_witness_mechanism) return; // AB6-A: no alerts submitted or pooled
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    // H(p) = SHA3-512 of target's ML-DSA-87 signature on the packet (eq:da_sign)
    uint8_t h_p[64] = {};
    auto it_pkt = g_packet_crypto.find({target_node, crypto_msg_key(pkt_id, flow_id)});
    if (it_pkt != g_packet_crypto.end() && it_pkt->second.sig_len > 0)
        sha3_512_hash(it_pkt->second.sig, it_pkt->second.sig_len, h_p);

    // α_w message: H(p)(64) ‖ dst(4) ‖ dst'(4) ‖ ts_w(8) = 80 bytes (eq:da_sign)
    double ts_w = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[80] = {};
    memcpy(msg,    h_p,      64);
    memcpy(msg+64, &dst,     4);
    memcpy(msg+68, &dup_dst, 4);
    memcpy(msg+72, &ts_w,    8);
    uint8_t h_alert[64];
    sha3_512_hash(msg, sizeof(msg), h_alert);

    WitnessAlert alert;
    alert.witness_id  = witness;
    alert.alert_type  = 0;
    memcpy(alert.signed_digest, h_alert, 64);
    alert.alert_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, alert.alert_sig, &alert.alert_sig_len,
                     h_alert, 64, g_node_keys[witness].sk) != OQS_SUCCESS) return;

    alert.ts = ts_w;
    // eq:dup_alert_cond fix — content-hash key, see witness_bft_quorum_reached()
    // comment for why (flow_id, pkt_id) is a recycling id, not the spec's H(p)).
    alert.event_key = event_key_from_hp(h_p);
    g_witness_alert_pool[target_node].push_back(alert);
    uint32_t threshold = 2 * WITNESS_F + 1;

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-DA] witness=" << witness
                  << " → target=" << target_node
                  << " pkt=" << pkt_id
                  << " flow=" << flow_id
                  << " t_alert=" << ts_w
                  << " pool=" << g_witness_alert_pool[target_node].size() << "/" << threshold << "\n";

    // BFT penalty over DISTINCT verified witnesses for THIS event within W.
    if (witness_bft_quorum_reached(target_node, alert.event_key, oqs)) {
        std::cout << "[WITNESS-DA-BFT] " << threshold << " distinct verified witnesses >= 2f+1="
                  << threshold << " → trust_update_negative(target=" << target_node << ")\n";
        NS_LOG_WARN("[WITNESS-DA] BFT threshold reached for node " << target_node);
        g_current_trust_source = DSRC_WITNESS_DA;
        trust_update_negative(target_node);
        g_current_trust_source = DSRC_NONE;
        // M12 — WAP-R: count this threshold-crossing event once per node per run.
        //
        // FIXED 2026-07-11 — main.tex's M12 definition (§"Witness Alert
        // Precision and Recall") is scoped "specifically against Variants 7
        // and 8" (passive HF) — it is NOT meant to score threshold-crossing
        // events from any other scenario. This function (the duplication
        // alert, eq:dup_alert_cond) also fires correctly during ACTIVE HF
        // (Variants 5/6, gated on present_active_hf_attack||present_passive_hf_attack
        // at its only call site in routing.cc), and previously classified
        // every one of those GENUINE active-HF detections as a WAP-R false
        // positive (the `else` branch), since `present_passive_hf_attack` is
        // false during an active-only run. Empirically confirmed: A5/A6 runs
        // reported TP_W=0, FP_W=30-33, P_W=0.000% — completely misleading,
        // since those 30+ events were correct detections of a real attacker,
        // not false accusations. Now only counted when the run is genuinely
        // passive-HF-flagged; active-HF and non-HF threshold events are
        // correctly excluded from WAP-R's tally entirely (M12 is simply not
        // applicable there, not "0% precision").
        if (!g_witness_da_threshold_fired[target_node]) {
            g_witness_da_threshold_fired[target_node] = true;
            if (present_passive_hf_attack) {
                // Supervisor item 4 (2026-08-27): score against the same
                // covering-RSU attribution the alert itself now uses.
                //
                // Post-Fix-1 target_node is hf_gt_attribution_node(accused),
                // so for a VEHICLE attacker it is the covering RSU -- and
                // passive_hf_malicious_nodes[covering_rsu] is false, because
                // the RSU is not itself the attacker. Asking that question
                // directly therefore booked every correct detection of a
                // vehicle attacker as a false positive. A target is a true
                // positive when it is the attribution target of at least one
                // genuinely malicious node, which is exactly what the alert
                // side computed to pick it.
                bool _tgt_is_true = false;
                for (int _n = 0; _n < total_size; ++_n) {
                    if (!passive_hf_malicious_nodes[_n]) continue;
                    if (hf_gt_attribution_node((uint32_t)_n) == target_node) {
                        _tgt_is_true = true;
                        break;
                    }
                }
                if (_tgt_is_true)
                    ++g_witness_TP_W;
                else
                    ++g_witness_FP_W;
            }
        }
        // The episode is resolved — clear it so the next penalty requires a
        // FRESH quorum of distinct witnesses rather than the same pooled
        // alerts re-crossing on every subsequent submission. Without this the
        // pool only ever grows and trust decays monotonically to quarantine
        // for any node that ever attracted 2f+1 witnesses.
        witness_clear_event(target_node, alert.event_key);
    }
}

// β_w: non-forwarding alert — packet received but not forwarded within T_fwd (eq:nfa_sign)
inline void witness_submit_nfa_alert(uint32_t witness, uint32_t target_node,
                                      uint32_t pkt_id, uint32_t flow_id, double T_fwd) {
    if (!enable_witness_mechanism) return; // AB6-A: no alerts submitted or pooled
    if (!g_node_keys[witness].keys_generated && !mldsa87_keygen(witness)) return;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    // H(p) = SHA3-512 of target's ML-DSA-87 signature on the packet (eq:nfa_sign)
    uint8_t h_p[64] = {};
    auto it_pkt = g_packet_crypto.find({target_node, crypto_msg_key(pkt_id, flow_id)});
    if (it_pkt != g_packet_crypto.end() && it_pkt->second.sig_len > 0)
        sha3_512_hash(it_pkt->second.sig, it_pkt->second.sig_len, h_p);

    // β_w message: H(p)(64) ‖ v_i(4) ‖ ts_w(8) ‖ T_fwd(8) = 84 bytes (eq:nfa_sign)
    double ts_w = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[84] = {};
    memcpy(msg,    h_p,          64);
    memcpy(msg+64, &target_node, 4);
    memcpy(msg+68, &ts_w,        8);
    memcpy(msg+76, &T_fwd,       8);
    uint8_t h_alert[64];
    sha3_512_hash(msg, sizeof(msg), h_alert);

    WitnessAlert alert;
    alert.witness_id  = witness;
    alert.alert_type  = 1;
    memcpy(alert.signed_digest, h_alert, 64);
    alert.alert_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, alert.alert_sig, &alert.alert_sig_len,
                     h_alert, 64, g_node_keys[witness].sk) != OQS_SUCCESS) return;

    alert.ts = ts_w;
    // eq:dup_alert_cond fix — content-hash key, see witness_bft_quorum_reached()
    // comment for why (flow_id, pkt_id) is a recycling id, not the spec's H(p)).
    alert.event_key = event_key_from_hp(h_p);
    g_witness_alert_pool[target_node].push_back(alert);
    uint32_t threshold = 2 * WITNESS_F + 1;

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[WITNESS-NFA] witness=" << witness
                  << " → target=" << target_node
                  << " pkt=" << pkt_id
                  << " flow=" << flow_id
                  << " t_alert=" << ts_w
                  << " T_fwd=" << T_fwd << "s"
                  << " pool=" << g_witness_alert_pool[target_node].size() << "/" << threshold << "\n";

    // BFT penalty over DISTINCT verified witnesses for THIS event within W.
    if (witness_bft_quorum_reached(target_node, alert.event_key, oqs)) {
        std::cout << "[WITNESS-NFA-BFT] " << threshold << " distinct verified witnesses >= 2f+1="
                  << threshold << " → trust_update_negative(target=" << target_node << ")\n";
        NS_LOG_WARN("[WITNESS-NFA] BFT threshold reached for node " << target_node);
        g_current_trust_source = DSRC_WITNESS_NFA;
        trust_update_negative(target_node);
        g_current_trust_source = DSRC_NONE;
        // M12 (WAP-R) intentionally NOT counted here (fixed 2026-07-11).
        // main.tex scopes M12 to the duplication-alert mechanism only
        // (eq:dup_alert_cond, "specifically against Variants 7 and 8") — this
        // is the non-forwarding alert (eq:nfwd_detect), a different mechanism
        // tied to delay-equivalent non-delivery for Selective Time Delay
        // (Variants 1-4), not Hidden Forwarding. It previously shared
        // g_witness_threshold_fired with the duplication-alert path, so an
        // NFA crossing here could pre-set a node's flag and silently skip a
        // later, genuine duplication-alert crossing for that same node,
        // undercounting M12's TP_W. trust_update_negative() above still
        // fires correctly regardless — only the M12-specific bookkeeping is
        // removed from this function.
        //
        // Same episode-clear as the α_w path — see witness_submit_duplication_alert().
        witness_clear_event(target_node, alert.event_key);
    }
}

// ── Volume Rate Tracking — S7, eq:sig_s7 ─────────────────────────────────────

inline void volume_record_delivery(uint32_t dst) { g_dst_volume_curr[dst]++; }

inline bool volume_check_anomaly(uint32_t dst) {
    double prev = g_dst_volume_prev.count(dst) ? g_dst_volume_prev[dst] : 0.0;
    double curr = g_dst_volume_curr.count(dst) ? g_dst_volume_curr[dst] : 0.0;
    return (curr - prev) / (T_SYNC_INTERVAL > 0 ? T_SYNC_INTERVAL : 1.0)
           > VOL_RATE_THRESH;
}

inline void volume_tick() {
    for (auto& [dst, cnt] : g_dst_volume_curr) g_dst_volume_prev[dst] = cnt;
    g_dst_volume_curr.clear();
}

// ── Msg-ID Duplication Cache — S6 ────────────────────────────────────────────

inline bool check_msg_duplication(const uint8_t* pkt_hash, uint32_t dst_now) {
    uint64_t key; memcpy(&key, pkt_hash, 8);
    auto it = g_msg_id_seen.find(key);
    if (it == g_msg_id_seen.end()) {
        g_msg_id_seen[key] = {dst_now, ns3::Simulator::Now().GetSeconds()};
        return false;
    }
    return (it->second.first != dst_now);
}

// ── FlowMod RSU Endorsement — eq:rsu_endorsement ─────────────────────────────

inline bool flowmod_endorse(uint32_t rsu_idx, uint32_t flow_id,
                             const uint8_t* flowmod_params, size_t params_len) {
    if (rsu_idx >= (uint32_t)total_size) return false;
    if (!g_node_keys[rsu_idx].keys_generated && !mldsa87_keygen(rsu_idx)) return false;
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return false;

    double   ts            = ns3::Simulator::Now().GetSeconds();
    uint32_t rsu_local_idx = rsu_idx - N_Vehicles;
    uint32_t zone          = crypto_zone_id(rsu_idx);

    uint8_t topo_in[8];
    memcpy(topo_in,   &zone,          4);
    memcpy(topo_in+4, &rsu_local_idx, 4);
    uint8_t T_rj[64];
    sha3_512_hash(topo_in, 8, T_rj);

    uint8_t flowmod_hash[64] = {};
    if (params_len > 0 && flowmod_params)
        sha3_512_hash(flowmod_params, params_len, flowmod_hash);
    else
        sha3_512_hash(reinterpret_cast<const uint8_t*>(&flow_id), 4, flowmod_hash);

    std::vector<uint8_t> msg(params_len + 8 + 64);
    size_t off = 0;
    if (params_len && flowmod_params) { memcpy(msg.data(), flowmod_params, params_len); off += params_len; }
    memcpy(msg.data() + off, &ts,  8);  off += 8;
    memcpy(msg.data() + off, T_rj, 64);

    uint8_t msg_digest[64];
    sha3_512_hash(msg.data(), msg.size(), msg_digest);

    uint8_t endorsement_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  endorsement_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, endorsement_sig, &endorsement_sig_len,
                     msg_digest, 64, g_node_keys[rsu_idx].sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] flowmod_endorse: OQS_SIG_sign failed rsu="
                  << rsu_idx << " flow=" << flow_id << "\n";
        return false;
    }

    FlowModEndorsement& e = g_flowmod_endorsements[flow_id];
    if (e.endorsing_rsus.empty()) {
        // First endorser: seed the accumulator with H(sig_1)
        memcpy(e.flowmod_hash, flowmod_hash, 64);
        sha3_512_hash(endorsement_sig, endorsement_sig_len, e.endorsement_hash);
    } else {
        // Each subsequent endorser: H_new = SHA3-512(H_prev ‖ sig_j)
        // Binds all {ε_j} per eq:endorsed_commit: C_P = BC.Commit(H(FlowMod) ‖ {ε_j} ‖ ts)
        uint8_t rolling[64 + OQS_SIG_ml_dsa_87_length_signature];
        memcpy(rolling,    e.endorsement_hash, 64);
        memcpy(rolling+64, endorsement_sig,    endorsement_sig_len);
        sha3_512_hash(rolling, sizeof(rolling), e.endorsement_hash);
    }
    e.endorsing_rsus.push_back(rsu_idx);
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[FLOWMOD-ENDORSE] rsu=" << rsu_idx
                  << " flow=" << flow_id
                  << " zone=" << zone
                  << " sig_len=" << endorsement_sig_len  // expected 4627
                  << " sig[0..3]=" << _hex4(endorsement_sig)
                  << " flowmod_hash[0..3]=" << _hex4(flowmod_hash)
                  << " T_rj[0..3]=" << _hex4(T_rj)
                  << " endorsers_so_far=" << e.endorsing_rsus.size() << "\n";
    return true;
}

// ── CLI Parameter Registration ────────────────────────────────────────────────

inline void crypto_register_cli_params(ns3::CommandLine& cmd) {
    cmd.AddValue("trust_delta_r",      "Trust reward Δ_r",                   TRUST_DELTA_R);
    cmd.AddValue("trust_delta_p",      "Trust penalty Δ_p (must be > Δ_r)",  TRUST_DELTA_P);
    cmd.AddValue("trust_t_min",        "Quarantine threshold T_min",          TRUST_T_MIN);
    cmd.AddValue("trust_t_min_ctrl",   "Controller revocation threshold",     TRUST_T_MIN_CTRL);
    cmd.AddValue("trust_delta_r_ctrl", "Controller reward Δ_r^ctrl",          TRUST_DELTA_R_CTRL);
    cmd.AddValue("trust_delta_p_ctrl", "Controller penalty Δ_p^ctrl",         TRUST_DELTA_P_CTRL);
    cmd.AddValue("t_sync",             "T_ref sync interval (s)",             T_SYNC_INTERVAL);
    cmd.AddValue("time_ref_f_bad",
                 "M9: number of Byzantine-compromised RSU clocks (eq:eps_ref sweep var)",
                 TIME_REF_F_BAD);
    cmd.AddValue("time_ref_delta_attack",
                 "M9: fixed clock offset (s) injected into compromised RSUs",
                 TIME_REF_DELTA_ATTACK);
    cmd.AddValue("batch_size",         "Packets per batch verify cycle B",    BATCH_SIZE);
    cmd.AddValue("witness_window",     "Witness observation window W (s)",    WITNESS_WINDOW);
    cmd.AddValue("witness_f",          "Witness BFT parameter f",             WITNESS_F);
    cmd.AddValue("vol_rate_thresh",    "Volume rate threshold ε_vol (pkt/s)", VOL_RATE_THRESH);
    cmd.AddValue("failover_bcast_base_ms",
                 "M5: ControllerRevoked broadcast base latency (ms)",
                 FAILOVER_BCAST_BASE_MS);
    cmd.AddValue("failover_bcast_per_zone_ms",
                 "M5: added broadcast latency per zone-distance unit (ms)",
                 FAILOVER_BCAST_PER_ZONE_MS);
    cmd.AddValue("disable_crypto",     "Disable DKG keygen + ML-DSA-87 sign/verify + STARK hop-proof "
                                       "(0=crypto ON [default], 1=crypto OFF). Speeds up runs that don't "
                                       "need crypto-derived metrics (trust score, S1/S2/S5-S8 detection) -- "
                                       "S3/S4 TCAM detection is unaffected either way since it never reads "
                                       "crypto state.", g_disable_crypto);

    // Per-signature (S1/S2/S5-S8) CLI overrides removed 2026-07-09: main.tex
    // specifies no such ablation anywhere (the only mode-level ablation for
    // this part of the architecture is AB1 — enable_lrad_obu/enable_lrad_rsu
    // below). Signatures now evaluate continuously whenever their owning
    // engine (OBU or RSU) is on, matching alg:lrad_obu/alg:lrad_rsu's own
    // OR-across-all-signatures composite and main.tex:4621's "all eight
    // attack variants operate simultaneously in every experiment."

    // Ablation gate flags (Phase 3) — all default true (full proposed behavior);
    // flip one to its ablated value per run to reproduce AB1/AB4/AB6/AB7/AB8/AB9/AB11.
    cmd.AddValue("g_disable_s1_s2",               "DIAGNOSTIC: disable S1+S2 only, keep S3-S8 active (isolate a signature's own FPR)", g_disable_s1_s2);
    cmd.AddValue("g_disable_s3_s4",               "DIAGNOSTIC: disable S3+S4 confusion-matrix recording only, keep flag_s3/flag_s4's eq:lstm_gate LSTM-suppression publishing intact", g_disable_s3_s4);
    cmd.AddValue("g_disable_s5_s6",               "DIAGNOSTIC: disable S5+S6 (active HF) signature computation, incl. their D_RSU/BTMM/BC.Write contribution", g_disable_s5_s6);
    cmd.AddValue("g_disable_s7_s8",               "DIAGNOSTIC: disable S7+S8 (passive HF) signature computation, incl. their D_RSU/BTMM/BC.Write contribution (isolates the witness pipeline)", g_disable_s7_s8);
    cmd.AddValue("g_disable_ranom",                "DIAGNOSTIC (item 5): decouple the R_anom>0 rule from S7/S8. -1=follow g_disable_s7_s8 (default, unchanged behaviour), 0=force R_anom on, 1=force R_anom off", g_disable_ranom);
    cmd.AddValue("enable_detector_windows",       "M1: emit detector_windows.csv (per-window OBU/RSU decisions + truth) for metrics/m01_detection_quality.py", enable_detector_windows);
    cmd.AddValue("g_dup_diag_log",                "DIAGNOSTIC: trace every eq:dup_alert_cond firing (witness, accused, both destinations, ground truth)", g_dup_diag_log);
    cmd.AddValue("g_disable_btmm_trust",          "DIAGNOSTIC: disable the per-packet BTMM trust update (eq:trust_update); witness-driven and controller-plane trust updates unaffected", g_disable_btmm_trust);
    cmd.AddValue("enable_lrad_obu",               "AB1: enable OBU rule engine (lrad_obu)",        enable_lrad_obu);
    cmd.AddValue("enable_lrad_rsu",               "AB1: enable RSU full-mode engine (lrad_rsu)",   enable_lrad_rsu);
    cmd.AddValue("enable_stark_delay",            "AB4: enable STARK timing proof π_delay",        enable_stark_delay);
    cmd.AddValue("enable_stark_hop",              "AB4: enable STARK hop-legitimacy proof π_hop",  enable_stark_hop);
    cmd.AddValue("enable_witness_mechanism",      "AB6: enable witness alert/BFT mechanism",       enable_witness_mechanism);
    cmd.AddValue("enable_quarantine",             "AB7: enable trust updates + SC.Quarantine",     enable_quarantine);
    cmd.AddValue("enable_local_quarantine",       "eq:local_quarantine / HOLD_FORWARD: OBU suspends forwarding of the flagged flow pending RSU.Confirm or T_hold (default OFF — changes all delivery metrics)", enable_local_quarantine);
    cmd.AddValue("T_hold",                        "eq:local_quarantine max hold window (s). Not given numerically in main.tex; "
                                                  "bounded below by the ~1ms RSU.Confirm RTT and above by the latency cost of a "
                                                  "false hold. Criterion: smallest value where RSU.Confirm dominates timeout "
                                                  "releases (scripts/sweep_t_hold.py). Default 0.1 provisional until swept", T_HOLD);
    cmd.AddValue("enable_endorsement_requirement","AB8: require f+1 RSU FlowMod endorsement",      enable_endorsement_requirement);
    cmd.AddValue("enable_controller_failover",    "AB9: enable controller trust/revoke/failover",  enable_controller_failover);
    cmd.AddValue("enable_key_rotation",           "AB11: rotate ZKP keys on RSU revocation",       enable_key_rotation);
    cmd.AddValue("enable_lstm_inference",         "sec:fed_lstm: live in-sim LSTM inference "
                                                   "(needs lstm_weights_cpp.bin already exported)", enable_lstm_inference);
    cmd.AddValue("enable_lstm_cls",               "Fix 2 (2026-08-20): detect on the classification head's P(attack) "
                                                  "instead of reconstruction error", enable_lstm_cls);
    cmd.AddValue("tcam_truth_live",               "A3/A4 truth (2026-09-01): use the live 'holds >=1 malicious TCAM entry' "
                                                  "scan instead of the never-cleared is_malicious_node latch. Measurement-only", tcam_truth_live);
    cmd.AddValue("hf_truth_latched",              "HF truth semantics (2026-09-01): latch the A5-A8 window activity gate "
                                                  "(compromised state persists) instead of per-cycle send events, matching "
                                                  "S5-S8's design and y_indep's existing latch. Measurement-only", hf_truth_latched);
    cmd.AddValue("hf_oracle_gate",                "Q5 (2026-09-06): restore the legacy S5-S8 oracle gate, which early-returns "
                                                  "unless the sender is in the attack injector's own assignment array. Default 0 "
                                                  "= REMOVED (b_hop(u)=0 evaluated instead, per eq:sig_s5). Diagnostic A/B only -- "
                                                  "never report a number produced with this on", hf_oracle_gate);
    cmd.AddValue("ddiv_smoke_test",               "Round 8 smoke test (2026-09-06): log what the proposed per-source-vehicle "
                                                  "D_div WOULD read, per RSU per cycle, WITHOUT changing any model feature. "
                                                  "Emits [DDIV-SMOKE] lines. Diagnostic only", ddiv_smoke_test);
    cmd.AddValue("lstm_ddiv_atp_per_rsu",         "Item 3 (2026-09-05): compute D_div/A_tp per-RSU as eq:feat_ddiv/eq:feat_atp "
                                                  "specify, instead of as simulation-wide global scalars identical at every "
                                                  "RSU. Requires regenerating the A5-A8 training set and a full retrain "
                                                  "INCLUDING the encoder -- the per-RSU granularity was never logged, so it "
                                                  "cannot be recovered by post-processing. Default 0 = legacy global",
                                                  lstm_ddiv_atp_per_rsu);
    cmd.AddValue("hf_latch_reset_rsu_attacker",   "Item 4 (2026-09-05): release the HF activity latch at QUARANTINE time "
                                                  "(eq:local_quarantine) instead of end-of-run, for the RSU-attacker HF "
                                                  "variants A5/A7, whose enforcement is directly confirmed. Requires "
                                                  "--hf_truth_latched to have any effect. Default 0 = end-of-run",
                                                  hf_latch_reset_rsu_attacker);
    cmd.AddValue("hf_latch_reset_vehicle_attacker", "Item 4 (2026-09-05): as above for the VEHICLE-attacker HF variants "
                                                  "A6/A8, whose enforcement is confirmed but bites via the covering RSU "
                                                  "(proxy attribution). Separate flag so it can be disabled independently "
                                                  "if the proxy is ruled unacceptable. Default 0 = end-of-run",
                                                  hf_latch_reset_vehicle_attacker);
    cmd.AddValue("dw_mark_suspect",               "FPR fix 2 (2026-09-01): mark the SUSPECT (prev_sender) in the M1 "
                                                  "window grid instead of the observing RSU, matching the 2026-08-22 "
                                                  "fix already applied to score_primary. Measurement-only", dw_mark_suspect);
    cmd.AddValue("require_lstm_high_conf",        "FPR fix 1 (2026-08-31): admit the LSTM into D_RSU only at "
                                                  "high confidence, dropping soft LSTM-only windows from M1 "
                                                  "(matches the existing BTMM/confusion-matrix policy)", require_lstm_high_conf);
    cmd.AddValue("enable_hf_theta",               "Use pooled HF-context theta (hf_theta.json) for "
                                                   "A5-A8 instead of the standard per-RSU value "
                                                   "(supervisor Change 2, 2026-08-20)", enable_hf_theta);
}

#endif // CRYPTO_LAYER_H
