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
// CSV columns (7 features + metadata):
//   cycle, rsu_id, delta_t, lambda_PI, U_TCAM,
//   zkp_delay_fail, zkp_hop_fail, rho, v_bar, label
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
#include <string>
#include <vector>
#include <cstdlib>
#include <cmath>

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

// =========================================================================
// lstm_make_base_dir():
// Resolves the results_routing base directory the same way routing.cc does,
// so the logger is self-contained and does not depend on the caller passing
// results_dir (which is set after the per-RSU loop in the original code).
// =========================================================================
inline std::string lstm_make_base_dir()
{
    std::string dir =
        "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
    const char* home = std::getenv("HOME");
    if (home)
        dir = std::string(home) + "/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
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
    g_lstm_logger_ready = true;

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
//   U_TCAM,t     = g_tcam_rule_count[rsu_sim_idx] / TCAM_HW_SIZE (clamped 0–1)
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
    if (!training)              return;
    if (!g_lstm_logger_ready)   return;
    if (r >= g_lstm_prev_slowpath.size()) return;

    const uint32_t rsu_sim_idx = (uint32_t)N_Vehicles + r;
    const int      tcam_hw     = 256; // TCAM_HW_SIZE — same constant as routing.cc

    // ── Feature 2: λ_PI — Δ PACKET_IN slow-path hits since last cycle
    int cur_slow  = g_slowpath_hit_count[rsu_sim_idx];
    double lam_PI = (double)(cur_slow - g_lstm_prev_slowpath[r]);
    if (lam_PI < 0.0) lam_PI = 0.0;    // guard: counter reset between cycles
    g_lstm_prev_slowpath[r] = cur_slow;

    // ── Feature 3: U_TCAM — current rule utilisation (0.0 – 1.0)
    double U_TCAM = (double)g_tcam_rule_count[rsu_sim_idx] / (double)tcam_hw;
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

    // ── Label (ground truth)
    int label = 0;
    if (active_attack_variant >= 0 &&
        active_attack_variant < NUM_ATTACK_VARIANTS)
    {
        label = is_malicious_node[active_attack_variant][rsu_sim_idx] ? 1 : 0;
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

    std::ofstream f(path, std::ios::app);
    if (!f.is_open())
    {
        std::cerr << "[LSTM_LOGGER] WARNING: cannot open " << path << std::endl;
        return;
    }

    // Write header only when the file is newly created (empty).
    if (f.tellp() == 0)
    {
        f << "cycle,rsu_id,delta_t,lambda_PI,U_TCAM,"
          << "zkp_delay_fail,zkp_hop_fail,rho,v_bar,label\n";
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
      << "," << label
      << "\n";
    f.close();
}

#endif // LSTM_LOGGER_H
