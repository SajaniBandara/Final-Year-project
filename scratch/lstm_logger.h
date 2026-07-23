#ifndef LSTM_LOGGER_H
#define LSTM_LOGGER_H

// =========================================================================
// lstm_logger.h — MOBIGUARD LSTM training data logger
//
// Implements eq:lstm_input logging for the Federated LSTM pipeline.
// Writes one CSV row per RSU per 1 Hz cycle when --training=1 is passed.
//
// Output path:
//   $HOME/ns-allinone-3.35/ns-3.35/results_routing/
//       lstm_training/RSU_{r}/A{v}_pct{p}_seed{s}.csv
//
// CSV columns (7 features + escalation flag + metadata + live-inference
// result):
//   cycle, rsu_id, delta_t, lambda_PI, U_TCAM,
//   zkp_delay_fail, zkp_hop_fail, rho, v_bar, escalated, label,
//   lstm_anomaly_score, d_lstm
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

// Canonical CSV header (Fix 16/17 format, 13 columns). Kept as a single
// constant so lstm_migrate_stale_header() and the writer below can never
// drift apart.
static const char* LSTM_CSV_HEADER =
    "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
    "zkp_delay_fail,zkp_hop_fail,rho,v_bar,escalated,label,"
    "lstm_anomaly_score,d_lstm";
// Pre-Fix-16/17 header: same leading 9 fields, but `label` is the LAST
// field (no escalated/lstm_anomaly_score/d_lstm) — 10 columns total.
static const char* LSTM_CSV_HEADER_LEGACY =
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
        if (f.size() == LSTM_CSV_LEGACY_NCOLS)
        {
            // Legacy row: fields 0..8 = cycle..v_bar, field 9 = label.
            // Insert escalated=0 before label, append lstm_anomaly_score=0
            // and d_lstm=0 at the end.
            std::ostringstream o;
            for (size_t i = 0; i < 9; ++i) o << f[i] << ",";
            o << "0" << "," << f[9] << "," << "0" << "," << "0";
            migrated_rows.push_back(o.str());
            ++n_migrated;
        }
        else if (f.size() == 13)
        {
            migrated_rows.push_back(row);   // already current format
            ++n_passthrough;
        }
        else
        {
            std::cerr << "[LSTM_LOGGER] WARNING: " << path
                       << " has a row with " << f.size()
                       << " fields (expected 10 legacy or 13 current) — "
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
    std::string dir = "/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project/";
    const char* home = std::getenv("HOME");
    if (home)
        dir = std::string(home) + "/ns3_g13/g13_project_repo/Final-Year-project/";
    return dir + "lstm_pipeline/lstm_weights_cpp.bin";
}

// =========================================================================
// lstm_make_base_dir():
// Resolves the results_routing base directory the same way routing.cc does,
// so the logger is self-contained and does not depend on the caller passing
// results_dir (which is set after the per-RSU loop in the original code).
// =========================================================================
inline std::string lstm_make_base_dir()
{
    std::string dir =
        "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";
    const char* home = std::getenv("HOME");
    if (home)
        dir = std::string(home) + "/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";
    if (!dir.empty() && dir.back() != '/')
        dir += '/';
    return dir;
}

// =========================================================================
// lstm_logger_init():
// Allocates the previous-cycle slowpath buffer and pre-creates the per-RSU
// output directories so ofstream never fails silently.
// Must be called once after N_RSUs is finalised.
// =========================================================================
inline void lstm_logger_init(uint32_t n_rsus)
{
    if (g_lstm_logger_ready) return;
    g_lstm_prev_slowpath.assign(n_rsus, 0);
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
    // cycle"). Deliberately LOGGING-ONLY in this pass — does NOT feed
    // D_LSTM into is_detected_node[]/mitigation/quarantine. Wiring D_LSTM
    // into the live detection/response path is a separate, much bigger
    // integration decision (it would change TP/FP/mitigation-latency for
    // every existing rule-based result) — flagged in PENDING_FIXES.md
    // Fix 17, not silently done here.
    if (do_inference)
    {
        std::vector<float> raw_feat = {
            (float)obs_delay, (float)lam_PI, (float)U_TCAM,
            (float)zkp_delay_fail, (float)zkp_hop_fail,
            (float)rho_t, (float)v_bar_t
        };
        std::vector<float> norm_feat = mglstm::lstm_normalize_features(g_lstm_model, raw_feat);

        auto& win = g_lstm_rsu_window[r];
        win.push_back(norm_feat);
        if ((int)win.size() > LSTM_WINDOW)
            win.erase(win.begin());  // slide: drop oldest

        if ((int)win.size() == LSTM_WINDOW)
        {
            float score = mglstm::lstm_forward_and_score(g_lstm_model, win);
            bool  d_lstm = mglstm::lstm_detect(g_lstm_model, r, score);
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

    // ── Label (ground truth)
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
    }

    // ── File path: lstm_training/RSU_{r}/A{v}_pct{p}_seed{s}.csv
    // attack_v maps internal variant index (-1=benign→0, 0→1, 1→2, ...) to
    // the proposal's attack number (0=benign, 1–8=attacks).
    int attack_v = (active_attack_variant < 0) ? 0 : (active_attack_variant + 1);
    std::string base = lstm_make_base_dir();
    std::string path = base
        + "lstm_training/RSU_" + std::to_string(r) + "/A"
        + std::to_string(attack_v)
        + "_pct" + std::to_string(attack_percentage)
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
      << "," << escalated
      << "," << label
      << "," << g_lstm_last_score[r]
      << "," << (g_lstm_last_dlstm[r] ? 1 : 0)
      << "\n";
    f.close();
}

#endif // LSTM_LOGGER_H
