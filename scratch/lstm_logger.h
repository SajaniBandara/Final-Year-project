#ifndef LSTM_LOGGER_H
#define LSTM_LOGGER_H

// =========================================================================
// lstm_logger.h — MOBIGUARD LSTM training data logger
//
// Implements eq:lstm_input logging for the Federated LSTM pipeline.
// Writes one CSV row per RSU per 1 Hz cycle when --training=1 is passed.
//
// Output path:
//   /home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/
//       lstm_training/RSU_{r}/Attack{v}_{pct}[_d{X}ms]_seed{s}.csv
//
// CSV columns (10 features + escalation flag + metadata + live-inference
// result + label-only HF ground-truth column, full eq:lstm_input order):
//   cycle, rsu_id, delta_t, lambda_PI, U_TCAM,
//   zkp_delay_fail, zkp_hop_fail, rho, v_bar, d_div, a_tp, r_anom,
//   escalated, label, lstm_anomaly_score, d_lstm, hf_send_gt
//
// `hf_send_gt` (2026-08-02, Issue 1 fix): per-RSU count of hidden-duplicate
// SEND events this cycle (Δ(g_lstm_hf_sendgt_count[r]), crypto_layer.h) —
// fires at attack-injection time, independent of r_anom's receive-side
// signal. NOT part of FEATURES in preprocessor.py; exists only so the A5-A8
// ground-truth window label doesn't reuse a value also fed to the model as
// input feature #10 (r_anom). See g_lstm_hf_sendgt_count's declaration.
//
// `r_anom` (2026-07-26, eq:feat_ranom): per-RSU rate of distinct packets
// received at an unauthorized destination this cycle, attributed to this
// RSU as the malicious forwarder. Computed as Δ(g_lstm_ranom_count[r])
// since last cycle (crypto_layer.h declares the counter; incremented at
// the same MacRx insertion points that already feed zkp_hop_fail for
// hidden-forwarding receptions). Added because empirical analysis showed
// the original 7 features carry no reliable, non-confounded signal for
// hidden forwarding (A5-A8) once time-of-run drift is controlled for via
// a benign baseline comparison — r_anom directly observes the copy event
// instead of inferring it indirectly. Empirically validated (2026-07-26):
// genuine effect 2.1-5.9 vs. baseline drift 0 across all four HF variants.
//
// `d_div`/`a_tp` (2026-07-26, eq:feat_ddiv/eq:feat_atp; corrected 2026-07-28
// per main.tex:5783-5794): added alongside r_anom to complete the
// originally-proposed 3-feature set. Computed from dedicated local delivery
// counters (g_lstm_flow0_dest_set / g_lstm_flow0_total_delivery_count /
// g_lstm_flow0_legit_count, all in crypto_layer.h, populated at the MacRx
// receive sites in routing.cc) — genuinely independent of r_anom's
// blockchain-receipt-log source, as main.tex requires ("D_div is computed
// from per-source per-destination byte counts logged at each RSU"; "A_tp is
// computed from per-flow directional byte rate logs"). The 2026-07-26
// version derived both as deterministic transforms of r_anom's delta, which
// was a spec deviation, not a harmless simplification — it collapsed three
// features main.tex designs as independent defense-in-depth signals down to
// one. |P(v,.)|=1 still holds in this sim (HF only ever targets one
// demanding flow, flow 0, so it has exactly one authorized destination at
// any instant) — that part of the original reasoning was correct and is
// kept.
//
// `escalated`: whether >=1 OBU rule-engine escalation (D_OBU==1,
// eq:composite_light) targeted this RSU during this cycle (main.tex
// §5039/5307's "escalation to LSTM detector" — see g_lstm_escalation_count
// below for the full rationale). Logged, not used to gate whether a row
// is written — eq:lstm_threshold's per-RSU calibration needs the full
// continuous benign population regardless of escalation state; this
// column lets the offline pipeline build an escalation-conditioned view
// on top of the same data instead.
//
// `lstm_anomaly_score`/`d_lstm`: only populated when --enable_lstm_inference=1
// AND a trained model was successfully loaded (lstm_pipeline/lstm_weights_cpp.bin
// must already exist); 0/0 otherwise, including during the per-RSU
// LSTM_WINDOW-cycle bootstrap before the sliding window first fills. See
// lstm_inference.h and PENDING_FIXES.md Fix 17 for the live inference path.
// `d_lstm` (as flag_LSTM) is also read live by lrad.h and OR'd into D_RSU —
// these columns are not just an offline-training export, they mirror what
// actually drove the live detection decision that cycle (see
// docs/LSTM_LIVE_INTEGRATION_STATUS.md, 2026-07-27).
//
// Inclusion rule (same as s1_detection.h):
//   Include inside routing.cc AFTER all global variable declarations,
//   after crypto_layer.h, tcam_attack_helper.h, and s1_detection.h.
//   All globals are accessed directly — no externs needed.
//
// Call sites in routing.cc:
//   1. lstm_logger_init(N_RSUs, results_dir) — once from
//      initialise_stub_attack_state() after N_RSUs is finalised.
//   2. lstm_log_rsu_cycle(r, rho_t, v_bar_t, obs_delay, results_dir)
//      — inside the per-RSU loop in calculate_performance_evaluation_metrics().
// =========================================================================

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <iterator>
#include "lstm_inference.h"   // live in-sim forward pass — main.tex sec:fed_lstm

// Forward declaration — g_slowpath_hit_count is DEFINED in routing.cc at the
// point where it is declared (int g_slowpath_hit_count[300] = {0}).
// This extern follows the same pattern used for g_tcam_rule_count in routing.cc
// (extern int g_tcam_rule_count[300]) so the header can be included before that
// definition while still accessing the variable at runtime.
extern int g_slowpath_hit_count[300];

// ── Per-RSU slowpath counter from the previous cycle.
// Used to compute Δ(g_slowpath_hit_count) = λ_PI feature for each cycle.
// Sized by lstm_logger_init(); zero-initialised.
static std::vector<int> g_lstm_prev_slowpath;
static bool             g_lstm_logger_ready = false;

// ── Per-RSU R_anom counter from the previous cycle (eq:feat_ranom).
// Used to compute Δ(g_lstm_ranom_count) the same way λ_PI is computed from
// Δ(g_slowpath_hit_count) -- a proper per-window rate, not a cumulative
// ever-fired latch (see g_lstm_ranom_count's declaration in crypto_layer.h
// for why that distinction matters here). Sized by lstm_logger_init().
static std::vector<uint32_t> g_lstm_prev_ranom;

// ── Per-RSU HF send-side ground-truth counter from the previous cycle
// (Issue 1 fix, 2026-08-02). Same delta pattern as g_lstm_prev_ranom above,
// but tracks g_lstm_hf_sendgt_count (crypto_layer.h) -- a send-time signal
// used ONLY to build preprocessor.py's ground-truth label, never fed to the
// model. Sized by lstm_logger_init().
static std::vector<uint32_t> g_lstm_prev_hf_sendgt;

// ── D_div/A_tp (eq:feat_ddiv, eq:feat_atp): flow 0's legit-delivery delta,
// computed ONCE PER CYCLE (not once per RSU) since lstm_log_rsu_cycle() is
// called once per RSU inside the same cycle's per-RSU loop -- consuming
// the delta on the first RSU's call and returning 0 for the rest, unlike
// R_anom/lambda_PI's per-RSU deltas. Cached and only recomputed when the
// cycle number changes; every RSU call within the same cycle reuses the
// cached value. Not sized by lstm_logger_init() (global, not per-RSU).
static uint32_t g_lstm_prev_flow0_legit        = 0;
static int      g_lstm_flow0_legit_cycle_cached = -1;
static double   g_lstm_flow0_legit_delta_cached = 0.0;

// ── D_div/A_tp numerator/denominator snapshots (eq:feat_ddiv, eq:feat_atp;
// main.tex:5783-5794). g_lstm_flow0_dest_set/g_lstm_flow0_total_delivery_count
// (crypto_layer.h) are global running-window accumulators, not per-RSU, so
// (like g_lstm_flow0_legit_delta_cached above) they must be snapshotted then
// reset exactly once per cycle — not once per RSU — even though
// lstm_log_rsu_cycle() is called once per RSU inside the same cycle's
// per-RSU loop. Refreshed in the same cache-refresh block as
// g_lstm_flow0_legit_delta_cached below.
static uint32_t g_lstm_ddiv_count_cached     = 0;
static uint32_t g_lstm_total_delivery_cached = 0;

// ── Rule-engine → LSTM escalation counter (main.tex §5039/5307:
// "Escalation to LSTM detector: immediate escalation occurs when the
// lightweight anomaly score >= 0.5"). D_OBU (eq:composite_light) is a
// strict boolean OR of S1/S2-partial/S3/S4 — there is no separate
// continuous "score" defined anywhere in main.tex's equations, so
// "score >= 0.5" is equivalent to "D_OBU == 1" (D_OBU in {0,1}).
// main.tex:4159-4160 confirms the intended wiring explicitly: "LRAD-OBU
// pre-filters, escalates to LRAD-RSU and BRFA-v2 LSTM" — i.e. the SAME
// D_OBU escalation that triggers LRAD-RSU (already implemented in
// lrad.h) must also be visible to the LSTM side.
//
// Incremented by lrad.h's process_escalation_at_rsu() (included after
// this header, so it can reference this vector directly) once per
// escalation event actually delivered to RSU r this cycle. Read and
// reset to 0 by lstm_log_rsu_cycle() below, so each logged row carries
// whether >=1 OBU escalation targeted this RSU during that cycle.
// Sized by lstm_logger_init(); zero-initialised.
static std::vector<uint32_t> g_lstm_escalation_count;

// ── Live in-sim LSTM inference state (main.tex sec:fed_lstm, gated by
// --enable_lstm_inference=1; see crypto_layer.h for the flag and
// PENDING_FIXES.md Fix 17 for why this was previously missing and why a
// hand-rolled forward pass, not LibTorch, is used). g_lstm_model is the
// SAME federated global model every RSU uses for its own local inference
// (one shared model, per-RSU thetas) — matches how fed_aggregator.py
// actually trains (one W_global, per-RSU calibrated theta^(k)).
static mglstm::LSTMAutoencoderWeights g_lstm_model;
static bool                           g_lstm_model_loaded = false;
static const int                      LSTM_WINDOW = 10;  // must match preprocessor.py's WINDOW
// Per-RSU sliding buffer of NORMALISED eq:lstm_input feature vectors
// (oldest-first, capped at LSTM_WINDOW). Sized by lstm_logger_init().
static std::vector<std::vector<std::vector<float>>> g_lstm_rsu_window;
// Most recent inference result per RSU (0/false until the sliding window
// has filled to LSTM_WINDOW entries — main.tex §5039's bootstrap period).
static std::vector<float> g_lstm_last_score;
static std::vector<bool>  g_lstm_last_dlstm;

// Canonical CSV header (2026-08-02: hf_send_gt appended, 17 columns, full
// eq:lstm_input order plus the label-only HF ground-truth column). Kept as
// a single constant so lstm_migrate_stale_header() and the writer below can
// never drift apart. hf_send_gt is NOT part of FEATURES in preprocessor.py
// -- see g_lstm_hf_sendgt_count's declaration (crypto_layer.h) for why it
// must stay separate from r_anom.
static const char* LSTM_CSV_HEADER =
    "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
    "zkp_delay_fail,zkp_hop_fail,rho,v_bar,d_div,a_tp,r_anom,escalated,label,"
    "lstm_anomaly_score,d_lstm,hf_send_gt";
// 2026-07-26..2026-08-02 format, 16 columns -- same as current but no
// hf_send_gt (appended at the very end).
[[maybe_unused]] static const char* LSTM_CSV_HEADER_16COL =
    "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
    "zkp_delay_fail,zkp_hop_fail,rho,v_bar,d_div,a_tp,r_anom,escalated,label,"
    "lstm_anomaly_score,d_lstm";
static const size_t LSTM_CSV_16COL_NCOLS = 16;
// 2026-07-26 R_anom-only format, 14 columns -- same as current but no
// d_div/a_tp (inserted between v_bar and r_anom).
[[maybe_unused]] static const char* LSTM_CSV_HEADER_14COL =
    "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
    "zkp_delay_fail,zkp_hop_fail,rho,v_bar,r_anom,escalated,label,"
    "lstm_anomaly_score,d_lstm";
static const size_t LSTM_CSV_14COL_NCOLS = 14;
// Fix 16/17 format, 13 columns -- same as current but no r_anom/d_div/a_tp.
[[maybe_unused]] static const char* LSTM_CSV_HEADER_13COL =
    "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
    "zkp_delay_fail,zkp_hop_fail,rho,v_bar,escalated,label,"
    "lstm_anomaly_score,d_lstm";
static const size_t LSTM_CSV_13COL_NCOLS = 13;
// Pre-Fix-16/17 header: same leading 9 fields, but `label` is the LAST
// field (no escalated/lstm_anomaly_score/d_lstm/r_anom/d_div/a_tp) — 10
// columns total.
[[maybe_unused]] static const char* LSTM_CSV_HEADER_LEGACY =
    "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
    "zkp_delay_fail,zkp_hop_fail,rho,v_bar,label";
static const size_t LSTM_CSV_LEGACY_NCOLS = 10;

// =========================================================================
// lstm_migrate_stale_header():
// Fix 20 — a training CSV created before Fix 16/17 added the `escalated`/
// `lstm_anomaly_score`/`d_lstm` columns carries the legacy 10-column
// header, with `label` as the LAST field. Opening such a file in append
// mode (as lstm_log_rsu_cycle() does) and writing new 13-column rows —
// where `escalated` is INSERTED BEFORE `label`, not appended after it —
// under the stale header does not just mismatch the column count: a
// naive "replace the header text only" migration would leave old rows'
// `label` value sitting in the new format's `escalated` column position,
// silently corrupting the ground-truth attack label on every legacy row.
// See PENDING_FIXES.md Fix 20 — caught the column-count version of this
// corruption on a real production file during Fix 16 verification,
// 2026-07-18; the row-shift risk was caught in code review while fixing
// it, before ever running against real data.
//
// Each existing legacy (10-field) row is therefore rewritten field-by-field
// into the new column order (escalated=0, lstm_anomaly_score=0,
// d_lstm=0 for all migrated rows — these features did not exist yet when
// legacy rows were collected, matching the "0/0 otherwise" default this
// file already documents for rows where live inference wasn't active).
// Rows that already match the new format, or any row whose field count is
// neither 10 nor 13 (unexpected — logged, left untouched, not migrated),
// are passed through as-is.
//
// Called once per path per process (tracked via g_lstm_migrated_paths) right
// before the append-mode open, so the one-time rewrite cost is paid at most
// once per file per run, not once per cycle. If the file doesn't exist yet,
// or its header already matches LSTM_CSV_HEADER, this is a no-op.
// =========================================================================
static std::set<std::string> g_lstm_migrated_paths;

inline std::vector<std::string> lstm_split_csv(const std::string& line)
{
    std::vector<std::string> out;
    std::stringstream ss(line);
    std::string field;
    while (std::getline(ss, field, ',')) out.push_back(field);
    return out;
}

inline void lstm_migrate_stale_header(const std::string& path)
{
    if (g_lstm_migrated_paths.count(path)) return;
    g_lstm_migrated_paths.insert(path);

    std::ifstream in(path);
    if (!in.is_open()) return;   // file doesn't exist yet — nothing to migrate

    std::string first_line;
    if (!std::getline(in, first_line) || first_line.empty()) return; // empty file

    if (first_line == LSTM_CSV_HEADER) return;   // already current format

    std::vector<std::string> rest;
    std::string line;
    while (std::getline(in, line)) rest.push_back(line);
    in.close();

    size_t n_migrated = 0, n_passthrough = 0, n_unexpected = 0;
    std::vector<std::string> migrated_rows;
    migrated_rows.reserve(rest.size());
    for (const auto& row : rest)
    {
        if (row.empty()) continue;
        std::vector<std::string> f = lstm_split_csv(row);
        // D_div/A_tp default to 1.0 when migrating old rows (NOT 0, unlike
        // every other migrated field below) -- their eq:feat_ddiv/eq:feat_atp
        // "no attack" resting value is 1.0 (one authorized destination,
        // fully-authorized throughput), not 0. Defaulting to 0 would make
        // every migrated old row look like a maximal anomaly on these two
        // columns, which is wrong -- 1.0 correctly encodes "unknown, assume
        // benign" the same way 0 does for the flag-style columns.
        if (f.size() == LSTM_CSV_LEGACY_NCOLS)
        {
            // Legacy row: fields 0..8 = cycle..v_bar, field 9 = label.
            // Insert d_div=1, a_tp=1, r_anom=0, escalated=0 before label,
            // append lstm_anomaly_score=0 and d_lstm=0 at the end.
            std::ostringstream o;
            for (size_t i = 0; i < 9; ++i) o << f[i] << ",";
            o << "1" << "," << "1" << "," << "0" << "," << "0" << "," << f[9]
              << "," << "0" << "," << "0";
            migrated_rows.push_back(o.str());
            ++n_migrated;
        }
        else if (f.size() == LSTM_CSV_13COL_NCOLS)
        {
            // Pre-r_anom row: fields 0..8 = cycle..v_bar, field 9 = escalated,
            // field 10 = label, fields 11..12 = lstm_anomaly_score,d_lstm.
            // Insert d_div=1, a_tp=1, r_anom=0 between v_bar and escalated.
            std::ostringstream o;
            for (size_t i = 0; i < 9; ++i) o << f[i] << ",";
            o << "1" << "," << "1" << "," << "0" << ",";
            for (size_t i = 9; i < 13; ++i) o << f[i] << (i < 12 ? "," : "");
            migrated_rows.push_back(o.str());
            ++n_migrated;
        }
        else if (f.size() == LSTM_CSV_14COL_NCOLS)
        {
            // R_anom-only row: fields 0..8 = cycle..v_bar, field 9 = r_anom,
            // field 10 = escalated, field 11 = label, fields 12..13 =
            // lstm_anomaly_score,d_lstm. Insert d_div=1, a_tp=1 between
            // v_bar and r_anom.
            std::ostringstream o;
            for (size_t i = 0; i < 9; ++i) o << f[i] << ",";
            o << "1" << "," << "1" << ",";
            for (size_t i = 9; i < 14; ++i) o << f[i] << (i < 13 ? "," : "");
            migrated_rows.push_back(o.str());
            ++n_migrated;
        }
        else if (f.size() == LSTM_CSV_16COL_NCOLS)
        {
            // Pre-hf_send_gt row (2026-07-26..2026-08-02): all 16 fields
            // already in current order, just missing the trailing hf_send_gt
            // column. Append 0 -- these rows predate the counter's existence,
            // same "unknown, assume no attack activity" default the rest of
            // this function uses for absent columns.
            migrated_rows.push_back(row + ",0");
            ++n_migrated;
        }
        else if (f.size() == 17)
        {
            migrated_rows.push_back(row);   // already current format
            ++n_passthrough;
        }
        else
        {
            std::cerr << "[LSTM_LOGGER] WARNING: " << path
                       << " has a row with " << f.size()
                       << " fields (expected 10/13/14/16 legacy or 17 current) — "
                       << "left unmigrated: " << row << std::endl;
            migrated_rows.push_back(row);
            ++n_unexpected;
        }
    }

    std::string tmp_path = path + ".migrate_tmp";
    std::ofstream out(tmp_path, std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "[LSTM_LOGGER] WARNING: could not open " << tmp_path
                   << " to migrate stale header in " << path << std::endl;
        return;
    }
    out << LSTM_CSV_HEADER << "\n";
    for (const auto& l : migrated_rows) out << l << "\n";
    out.close();

    if (std::rename(tmp_path.c_str(), path.c_str()) != 0)
    {
        std::cerr << "[LSTM_LOGGER] WARNING: failed to replace " << path
                   << " with migrated header (tmp file left at " << tmp_path
                   << ")" << std::endl;
    }
    else
    {
        std::cout << "[LSTM_LOGGER] Migrated stale CSV header: " << path
                   << " (" << n_migrated << " legacy rows migrated, "
                   << n_passthrough << " already current, "
                   << n_unexpected << " unexpected left as-is)" << std::endl;
    }
}

inline std::string lstm_weights_bin_path()
{
    // Hardcoded absolute path, same convention as every other writer in this
    // codebase (routing.cc, bc_blockchain_helper.h, etc.) — NOT $HOME-relative.
    // This used to build "$HOME/ns-allinone-3.35/ns-3.35/final yr project
    // updated/Final-Year-project/..." which was already wrong even before
    // considering $HOME: that subpath doesn't exist anywhere on this host (a
    // leftover from a prior directory layout), so live LSTM inference could
    // never actually find its weights file via this path. On top of that,
    // $HOME/ns-allinone-3.35 is a symlink into a DIFFERENT group's ns-3
    // checkout (ns3-workspace) on this shared account, so even a correct
    // relative subpath would have resolved into someone else's directory.
    return "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/lstm_pipeline/lstm_weights_cpp.bin";
}

// =========================================================================
// lstm_make_base_dir():
// Resolves the results_routing base directory the same way routing.cc does,
// so the logger is self-contained and does not depend on the caller passing
// results_dir (which is set after the per-RSU loop in the original code).
// Hardcoded rather than $HOME-relative — see lstm_weights_bin_path() above
// for why: $HOME/ns-allinone-3.35 is a symlink into a different group's
// checkout on this shared account, so a --training=1 run using the old
// $HOME-based path would silently write its LSTM training data into that
// other group's results_routing/ instead of this project's.
// =========================================================================
inline std::string lstm_make_base_dir()
{
    return "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
}

// =========================================================================
// lstm_logger_init():
// Allocates the previous-cycle slowpath buffer and pre-creates the per-RSU
// output directories so ofstream never fails silently.
// Must be called once after N_RSUs is finalised.
// =========================================================================
inline void lstm_logger_init(uint32_t n_rsus)
{
    // eq:theta_adapt: clear per-RSU warm-up accumulators for this run.
    mglstm::lstm_theta_adapt_reset((size_t)N_RSUs);
    if (g_lstm_logger_ready) return;
    g_lstm_prev_slowpath.assign(n_rsus, 0);
    g_lstm_prev_ranom.assign(n_rsus, 0);
    g_lstm_prev_hf_sendgt.assign(n_rsus, 0);
    g_lstm_escalation_count.assign(n_rsus, 0);
    g_lstm_rsu_window.assign(n_rsus, {});
    g_lstm_last_score.assign(n_rsus, 0.0f);
    g_lstm_last_dlstm.assign(n_rsus, false);
    g_lstm_logger_ready = true;

    // Live inference is independent of --training (which only controls
    // whether this run COLLECTS new training data) — an evaluation-only
    // run (training=0) can still load and run a previously-trained model.
    if (enable_lstm_inference)
    {
        std::string path = lstm_weights_bin_path();
        std::string err;
        if (mglstm::load_lstm_weights(path, g_lstm_model, &err))
        {
            g_lstm_model_loaded = true;
            std::cout << "[LSTM_INFERENCE] Loaded weights from " << path
                      << " (n_rsus_theta=" << g_lstm_model.theta.size()
                      << " global_theta=" << g_lstm_model.global_theta << ")" << std::endl;

            // eq:bc_model_verify (SC.CommitModelHash): each RSU commits the
            // hash of the (shared, federated) global model it is using for
            // local inference this run. Genuinely functional now — Fix 17
            // gap 2 was that there was no live model to hash; there is now.
            std::ifstream wf(path, std::ios::binary);
            std::vector<uint8_t> raw((std::istreambuf_iterator<char>(wf)),
                                      std::istreambuf_iterator<char>());
            uint8_t model_hash[64];
            if (!raw.empty() && sha3_512_hash(raw.data(), raw.size(), model_hash))
            {
                for (uint32_t r = 0; r < n_rsus; r++)
                    bc_commit_model_hash((uint32_t)N_Vehicles + r, model_hash);
                std::cout << "[LSTM_INFERENCE] Committed model hash for "
                          << n_rsus << " RSUs" << std::endl;
            }
        }
        else
        {
            std::cerr << "[LSTM_INFERENCE] WARNING: " << err
                      << " -- live inference disabled for this run "
                      << "(run lstm_pipeline/src/export_weights_cpp.py first)." << std::endl;
            g_lstm_model_loaded = false;
        }
    }

    if (!training) return;

    std::string base = lstm_make_base_dir();
    for (uint32_t r = 0; r < n_rsus; r++)
    {
        std::string dir = base + "lstm_training/RSU_" + std::to_string(r) + "/";
#ifdef _WIN32
        std::string cmd = "mkdir \"" + dir + "\" 2>nul";
#else
        std::string cmd = "mkdir -p \"" + dir + "\"";
#endif
        (void)std::system(cmd.c_str());
    }
    std::cout << "[LSTM_LOGGER] Initialised for " << n_rsus << " RSUs. "
              << "Output base: " << base << "lstm_training/" << std::endl;
}

// =========================================================================
// lstm_log_rsu_cycle():
// Logs one row for RSU r to its dedicated CSV file.
//
//   r          — RSU index (0 .. N_RSUs-1)
//   rho_t      — vehicle density in RSU zone (vehicles, from linklifetimeMatrix_dsrc)
//   v_bar_t    — mean vehicle speed in RSU zone (m/s)
//   obs_delay  — mean observed hop delay this cycle (s) — eq:lstm_input δ_t
//
// Features logged (eq:lstm_input):
//   δ_t          = obs_delay
//   λ_PI,t       = Δ(g_slowpath_hit_count[rsu_sim_idx]) since last cycle
//   U_TCAM,t     = g_tcam_rule_count[rsu_sim_idx] / TCAM_CAPACITY (clamped 0–1)
//   𝟙[π_delay=⊥] = 1 if g_lstm_stark_counts[rsu_sim_idx].first  > 0 this cycle
//   𝟙[π_hop=⊥]   = 1 if g_lstm_stark_counts[rsu_sim_idx].second > 0 this cycle
//   ρ_t          = rho_t
//   v̄_t          = v_bar_t
//
// Label: is_malicious_node[active_attack_variant][rsu_sim_idx] — 1 if the RSU
//        is a confirmed attacker this cycle under the current attack variant.
// =========================================================================
// =========================================================================
// lstm_rsu_ground_truth_label():
// Ground-truth label for one RSU cycle row -- 1 if this RSU is attack-affected
// under the active variant, else 0.
//
// EXTRACTED 2026-08-06 from lstm_log_rsu_cycle()'s inline label block, with no
// behavioural change, so detector_windows.h can reuse the SAME definition of
// RSU ground truth instead of reimplementing it. That logic carries four
// hard-won fallbacks (A3/A4 victim-RSU, A2 covering-RSU, A6/A8 covering-RSU)
// whose rationale is documented inline below; duplicating them would guarantee
// the two copies drift.
//   rsu_sim_idx = N_Vehicles + r  (the RSU's global node index)
// =========================================================================
inline int lstm_rsu_ground_truth_label(uint32_t rsu_sim_idx)
{
int label = 0;
if (active_attack_variant >= 0 &&
    active_attack_variant < NUM_ATTACK_VARIANTS)
{
    label = is_malicious_node[active_attack_variant][rsu_sim_idx] ? 1 : 0;
    // A3/A4 (TCAM attacks): the attacker is a compromised controller (A3,
    // variant 2) or attacker vehicles (A4, variant 3), never the RSU
    // itself, so is_malicious_node stays false for RSU rows — A4 gets 0
    // positives and A3 only the single representative RSU. Label the
    // *victim* RSUs instead: any RSU holding >=1 malicious TCAM entry is
    // attack-affected (slow-flow exhaustion entries persist). g_tcam_table
    // is declared in tcam_detection.h, included just before this header.
    if (!label && (active_attack_variant == 2 || active_attack_variant == 3))
    {
        for (const auto& entry : g_tcam_table)
        {
            if (entry.node_id == rsu_sim_idx && entry.is_malicious)
            {
                label = 1;
                break;
            }
        }
    }
    // A2 (Selective Time Delay, DP — variant 1): same root cause as the
    // A3/A4 case above, missed when that fallback was added. Supervisor
    // review fix (2026-08-03).
    //
    // declare_attackers() (attack_declaration.h) picks A2 attackers from the
    // full var = N_Vehicles + N_RSUs candidate pool and sets
    // is_malicious_node[1][idx] on the attacker's OWN node index. That is
    // correct for the S1-S8 confusion matrix, which attributes detections to
    // prev_sender (itself often the attacking vehicle) -- so it must NOT be
    // changed at the declaration site. But this label indexes
    // is_malicious_node[variant][rsu_sim_idx] by RSU, so whenever the A2
    // attacker lands on a vehicle (200 of the 264 candidates) NO RSU row is
    // ever labelled 1, and every A2 training row reads label=0 for the whole
    // run even though the delay attack is firing. That is corrupted ground
    // truth, not a weak feature.
    //
    // Fix mirrors the A3/A4 "victim RSU" idea using the covering-RSU
    // attribution already used for the HF ground-truth counters: an RSU is
    // attack-affected if it currently covers (strongest DSRC link to) at
    // least one malicious A2 node. hf_gt_attribution_node() returns the node
    // itself for RSU attackers, the covering RSU for vehicle attackers, and
    // UINT32_MAX when no RSU is in range -- in which case no RSU observes
    // that attacker at this instant and correctly no row is labelled for it.
    if (!label && active_attack_variant == 1)
    {
        for (uint32_t n = 0; n < (uint32_t)var; ++n)
        {
            if (!selective_delay_malicious_nodes[n]) continue;
            if (hf_gt_attribution_node(n) == rsu_sim_idx)
            {
                label = 1;
                break;
            }
        }
    }
    // A6 (variant 5, active HF DP) and A8 (variant 7, passive HF DP):
    // identical root cause to the A2 case above. Supervisor-approved
    // 2026-08-04, scoped to these two variants ONLY.
    //
    // hf_declare_malicious_rsus() draws mal_node from a pool that for DP
    // variants is "RSUs + intermediate vehicle relays" (hf_attack_helper.h
    // :417) and sets is_malicious_node[variant][mal_node] on that node's own
    // index (hf_attack_helper.h:653). When the draw lands on a vehicle, no
    // RSU row is ever labelled 1 even though the attack is firing.
    //
    // This was structurally masked in earlier verification: at p=100% the
    // entire on-path pool is compromised, so every RSU is directly malicious
    // and the fallback is never needed. The bug only appears below 100%.
    //
    // NOT extended to A5 (variant 4) or A7 (variant 6): those are
    // control-plane variants whose attacker pool is RSUs/controllers, never
    // vehicles, so the vehicle-orphaning case cannot arise for them.
    //
    // Note this is the LABEL. The hf_gt_attribution_node() calls already
    // present in routing.cc (~121709 / ~121793) fix the FEATURE counters
    // (r_anom, hf_send_gt, the ZKP counters) and never touch the label.
    if (!label && (active_attack_variant == 5 || active_attack_variant == 7))
    {
        const bool* mal = (active_attack_variant == 5)
                            ? active_hf_malicious_nodes
                            : passive_hf_malicious_nodes;
        // MEASURED (2026-08-04, supervisor-confirmed scope call (a)): this
        // fallback is CORRECT BUT INERT for A6/A8 in the current attacker
        // model, and that is expected -- do not "fix" it by widening scope.
        // Instrumented across two runs (p=40 %: 67 malicious vehicles;
        // p=20 %: 24), the covering-RSU lookup resolved 91/91 with ZERO
        // unmapped, but in every case the covering RSU was already directly
        // malicious, so the fallback never changed a label.
        // Cause: A6/A8 draw attackers from the ON-PATH pool
        // (hf_attack_helper.h:417), which structurally places malicious
        // vehicle relays inside on-path RSU zones -- and those RSUs are
        // themselves in the draw. Lowering the attack percentage shrinks
        // both sets together rather than decoupling them. Physically
        // necessary: an off-path node never handles the traffic it would
        // have to duplicate.
        // Contrast A2 above, which draws from the full 264-node pool
        // uniformly -- there the identical fallback moved 38 -> 54 RSUs.
        // Kept as defensive code: it costs one pass over total_size per
        // logged cycle and would matter immediately if attacker selection
        // ever stops being on-path constrained.
        for (uint32_t n = 0; n < (uint32_t)total_size; ++n)
        {
            if (!mal[n]) continue;
            if (hf_gt_attribution_node(n) == rsu_sim_idx)
            {
                label = 1;
                break;
            }
        }
    }
}
    return label;
}

inline void lstm_log_rsu_cycle(uint32_t r,
                                double   rho_t,
                                double   v_bar_t,
                                double   obs_delay)
{
    if (!g_lstm_logger_ready)   return;
    if (r >= g_lstm_prev_slowpath.size()) return;
    // Live inference (main.tex sec:fed_lstm) is independent of --training
    // (which only controls whether this run COLLECTS new training data) —
    // an evaluation-only run can still load and run an already-trained
    // model. Nothing else in this function has anything to do if neither
    // is active (the overwhelmingly common case: enable_lstm_inference
    // defaults false, so this is exactly the prior `if (!training) return`
    // behavior for every existing run/script).
    const bool do_training_log = training;
    const bool do_inference    = enable_lstm_inference && g_lstm_model_loaded;
    if (!do_training_log && !do_inference) return;

    const uint32_t rsu_sim_idx = (uint32_t)N_Vehicles + r;

    // ── Feature 2: λ_PI — Δ PACKET_IN slow-path hits since last cycle
    int cur_slow  = g_slowpath_hit_count[rsu_sim_idx];
    double lam_PI = (double)(cur_slow - g_lstm_prev_slowpath[r]);
    if (lam_PI < 0.0) lam_PI = 0.0;    // guard: counter reset between cycles
    g_lstm_prev_slowpath[r] = cur_slow;

    // ── Feature 3: U_TCAM — current rule utilisation (0.0 – 1.0)
    // Uses the single shared TCAM_CAPACITY constant (routing.cc) — was a
    // locally-hardcoded `tcam_hw=256` shadow constant before 2026-07-13.
    double U_TCAM = (double)g_tcam_rule_count[rsu_sim_idx] / (double)TCAM_CAPACITY;
    if (U_TCAM > 1.0) U_TCAM = 1.0;

    // ── Feature 8 (new): R_anom — per-RSU unauthorized-reception rate
    // (eq:feat_ranom). Δ(g_lstm_ranom_count[rsu_sim_idx]) since last cycle,
    // same delta-of-a-cumulative-counter pattern as λ_PI above (NOT the
    // "> 0 ever" latch pattern zkp_delay_fail/zkp_hop_fail use below) — this
    // is what makes it a genuine per-window rate matching "per unit time W"
    // in the equation. Window W = 1 cycle = 1s here, so the raw delta IS
    // already the rate (no /W division needed).
    double R_anom = 0.0;
    {
        auto it = g_lstm_ranom_count.find(rsu_sim_idx);
        uint32_t cur_ranom = (it != g_lstm_ranom_count.end()) ? it->second : 0;
        uint32_t prev_ranom = (r < g_lstm_prev_ranom.size()) ? g_lstm_prev_ranom[r] : 0;
        R_anom = (cur_ranom >= prev_ranom) ? (double)(cur_ranom - prev_ranom) : 0.0;
        if (r < g_lstm_prev_ranom.size()) g_lstm_prev_ranom[r] = cur_ranom;
    }

    // ── hf_send_gt (label-only, NOT a model feature — Issue 1 fix,
    // 2026-08-02): Δ(g_lstm_hf_sendgt_count[rsu_sim_idx]) since last cycle,
    // same delta pattern as R_anom above but from the send/scheduling-side
    // counter (crypto_layer.h). Logged as a separate CSV column so
    // preprocessor.py can build the A5-A8 ground-truth window label from
    // this instead of from r_anom, which is also fed to the LSTM as input
    // feature #10 — reusing r_anom for both let the model trivially recover
    // the label from its own input.
    double HF_SendGT = 0.0;
    {
        auto it = g_lstm_hf_sendgt_count.find(rsu_sim_idx);
        uint32_t cur_sgt = (it != g_lstm_hf_sendgt_count.end()) ? it->second : 0;
        uint32_t prev_sgt = (r < g_lstm_prev_hf_sendgt.size()) ? g_lstm_prev_hf_sendgt[r] : 0;
        HF_SendGT = (cur_sgt >= prev_sgt) ? (double)(cur_sgt - prev_sgt) : 0.0;
        if (r < g_lstm_prev_hf_sendgt.size()) g_lstm_prev_hf_sendgt[r] = cur_sgt;
    }

    // ── Features 9 & 10: D_div, A_tp (eq:feat_ddiv, eq:feat_atp; corrected
    // 2026-07-28 per main.tex:5783-5794). Both are computed from dedicated
    // local delivery counters populated at the MacRx receive sites in
    // routing.cc (g_lstm_flow0_dest_set, g_lstm_flow0_total_delivery_count,
    // g_lstm_flow0_legit_count — all crypto_layer.h) — independent of
    // R_anom's blockchain-receipt-log source, as the spec requires.
    //
    // legit_this_cycle: Δ(g_lstm_flow0_legit_count) since last cycle,
    // computed ONCE per cycle (see g_lstm_flow0_legit_cycle_cached's
    // declaration above for why) — flow 0's legit final-delivery count
    // this window, the A_tp "authorized" numerator.
    //
    // g_lstm_ddiv_count_cached/g_lstm_total_delivery_cached: snapshotted
    // and reset in the same once-per-cycle block, for the same reason
    // (global, not per-RSU, accumulators — see their declaration above).
    int cur_cycle_num = (int)(data_gathering_cycle_number - 1.0);
    if (cur_cycle_num != g_lstm_flow0_legit_cycle_cached)
    {
        uint32_t cur_legit = g_lstm_flow0_legit_count;
        g_lstm_flow0_legit_delta_cached = (cur_legit >= g_lstm_prev_flow0_legit)
            ? (double)(cur_legit - g_lstm_prev_flow0_legit) : 0.0;
        g_lstm_prev_flow0_legit = cur_legit;
        g_lstm_flow0_legit_cycle_cached = cur_cycle_num;

        g_lstm_ddiv_count_cached     = (uint32_t)g_lstm_flow0_dest_set.size();
        g_lstm_total_delivery_cached = g_lstm_flow0_total_delivery_count;
        g_lstm_flow0_dest_set.clear();
        g_lstm_flow0_total_delivery_count = 0;
    }
    double legit_this_cycle = g_lstm_flow0_legit_delta_cached;

    // D_div = |{distinct destinations reached}| / |P(v,.)|, |P(v,.)|=1 in
    // this sim (flow 0 has exactly one authorized destination at any
    // instant — HF only ever targets this one demanding flow). No traffic
    // this window -> default to the "no attack" resting value 1.0 (matches
    // the historical CSV migration default for this column, see
    // lstm_migrate_stale_header() above), not 0 (0 would misleadingly read
    // as "zero distinct destinations reached", not "no traffic").
    double D_div = (g_lstm_total_delivery_cached > 0)
                   ? (double)g_lstm_ddiv_count_cached
                   : 1.0;
    // A_tp = authorized deliveries / total deliveries this window.
    double A_tp  = (g_lstm_total_delivery_cached > 0)
                   ? (legit_this_cycle / (double)g_lstm_total_delivery_cached)
                   : 1.0;   // no traffic this cycle -> default "fully authorized"

    // ── Features 4 & 5: ZKP failure indicators (binary {0, 1})
    int zkp_delay_fail = 0;
    int zkp_hop_fail   = 0;
    {
        auto it = g_lstm_stark_counts.find(rsu_sim_idx);
        if (it != g_lstm_stark_counts.end())
        {
            zkp_delay_fail = (it->second.first  > 0) ? 1 : 0;
            zkp_hop_fail   = (it->second.second > 0) ? 1 : 0;
        }
    }

    // ── Feature 6 (new): rule-engine → LSTM escalation flag this cycle
    // (main.tex §5039/5307, D_OBU escalation — see header comment above).
    // Read-then-reset: counts escalation events delivered to this RSU since
    // the last time this function logged a row for it.
    int escalated = 0;
    if (r < g_lstm_escalation_count.size())
    {
        escalated = (g_lstm_escalation_count[r] > 0) ? 1 : 0;
        g_lstm_escalation_count[r] = 0;
    }

    // ── Live in-sim LSTM inference (main.tex sec:fed_lstm), independent of
    // --training. Maintains a per-RSU sliding window of NORMALISED feature
    // vectors (mglstm::lstm_normalize_features — the model was trained on
    // Z-scored input and produces meaningless scores on raw features).
    // Once the window has LSTM_WINDOW entries (bootstrap complete, main.tex
    // §5039's "initial 10s window"), runs the forward pass every cycle
    // ("continuous re-evaluation... buffer shifts by one step each 1s
    // cycle"). g_lstm_last_dlstm[]/g_lstm_last_score[] set here ARE read
    // live by lrad.h (flag_LSTM, OR'd into D_RSU per alg:lrad_rsu) — this
    // is not logging-only (see docs/LSTM_LIVE_INTEGRATION_STATUS.md,
    // 2026-07-27, correcting this comment's previous claim otherwise).
    if (do_inference)
    {
        std::vector<float> raw_feat = {
            (float)obs_delay, (float)lam_PI, (float)U_TCAM,
            (float)zkp_delay_fail, (float)zkp_hop_fail,
            (float)rho_t, (float)v_bar_t,
            (float)D_div, (float)A_tp, (float)R_anom
        };
        std::vector<float> norm_feat = mglstm::lstm_normalize_features(g_lstm_model, raw_feat);

        auto& win = g_lstm_rsu_window[r];
        win.push_back(norm_feat);
        if ((int)win.size() > LSTM_WINDOW)
            win.erase(win.begin());  // slide: drop oldest

        if ((int)win.size() == LSTM_WINDOW)
        {
            float score = mglstm::lstm_forward_and_score(g_lstm_model, win);
            bool  d_lstm = mglstm::lstm_detect(g_lstm_model, r, score,
                                               ns3::Simulator::Now().GetSeconds());
            g_lstm_last_score[r] = score;
            g_lstm_last_dlstm[r] = d_lstm;
            if (CRYPTO_DEBUG_LOG)
            {
                float theta = (r < g_lstm_model.theta.size()) ? g_lstm_model.theta[r]
                                                                : g_lstm_model.global_theta;
                std::cout << "[LSTM_INFER] rsu=" << r << " score=" << score
                          << " theta=" << theta << " D_LSTM=" << (d_lstm ? 1 : 0) << std::endl;
            }
        }
    }

    if (!do_training_log) return;

    // ── Label (ground truth) — see lstm_rsu_ground_truth_label() above.
    int label = lstm_rsu_ground_truth_label(rsu_sim_idx);

    // ── File path: lstm_training/RSU_{r}/Attack{N}_{pct}[_d{X}ms]_seed{S}.csv
    // attack_v (local variable name, holds the same value the rest of the
    // codebase calls N) maps internal variant index (-1=benign→0, 0→1,
    // 1→2, ...) to the proposal's attack number (0=benign, 1–8=attacks).
    // Matches the same Attack{N}_{pct}[_d{X}ms]_seed{S} shape MOBIGUARD/TAP/
    // FADE/bc_*/g_sim_tag all use. g_delay_suffix is only ever non-empty
    // for attack_v 1/2 (Selective Time Delay), same gating as everywhere
    // else that uses it.
    int attack_v = (active_attack_variant < 0) ? 0 : (active_attack_variant + 1);
    std::string base = lstm_make_base_dir();
    std::string path = base
        + "lstm_training/RSU_" + std::to_string(r) + "/Attack"
        + std::to_string(attack_v)
        + "_" + std::to_string(attack_percentage)
        + g_delay_suffix
        + "_seed" + std::to_string(sim_seed)
        + ".csv";

    lstm_migrate_stale_header(path);   // Fix 20 — no-op if already current/new

    std::ofstream f(path, std::ios::app);
    if (!f.is_open())
    {
        std::cerr << "[LSTM_LOGGER] WARNING: cannot open " << path << std::endl;
        return;
    }

    // Write header only when the file is newly created (empty).
    if (f.tellp() == 0)
    {
        f << LSTM_CSV_HEADER << "\n";
    }

    int cycle = (int)(data_gathering_cycle_number - 1.0);
    f << cycle
      << "," << r
      << "," << obs_delay
      << "," << lam_PI
      << "," << U_TCAM
      << "," << zkp_delay_fail
      << "," << zkp_hop_fail
      << "," << rho_t
      << "," << v_bar_t
      << "," << D_div
      << "," << A_tp
      << "," << R_anom
      << "," << escalated
      << "," << label
      << "," << g_lstm_last_score[r]
      << "," << (g_lstm_last_dlstm[r] ? 1 : 0)
      << "," << HF_SendGT
      << "\n";
    f.close();
}

#endif // LSTM_LOGGER_H
