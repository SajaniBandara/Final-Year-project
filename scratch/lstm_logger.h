#ifndef LSTM_LOGGER_H
#define LSTM_LOGGER_H

// =========================================================================
// lstm_logger.h — MOBIGUARD Federated LSTM Training Data Logger
//
// Writes one CSV row per RSU per 1-second simulation cycle when
// --training=1 is passed on the command line.
//
// Output path:
//   {HOME}/ns-allinone-3.35/ns-3.35/lstm_training/RSU_{id}/{run_tag}.csv
//
// Row format (300 rows per run at 1 Hz over 300s):
//   timestep, delta_t, lambda_PI, U_TCAM,
//   zkp_delay_fail, zkp_hop_fail, rho, v_bar,
//   label, attack_variant
//
// Called from the existing S1 per-RSU loop in routing.cc immediately
// after s1_update_baseline(), where rho_t and v_bar_t are already computed.
//
// Include order: include AFTER blockchain_sim.h so that
// g_lstm_stark_counts and g_lstm_pkt_counts are visible.
// =========================================================================

#include <fstream>
#include <iomanip>
#include <map>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

// ── Externs — variables defined in routing.cc ─────────────────────────────
extern bool     training;
extern int      attack_percentage;
extern int      active_attack_variant;
extern uint32_t sim_seed;
extern uint32_t N_Vehicles;

// ── Externs — defined in tcam_attack_helper.h / routing.cc ───────────────
extern int g_tcam_rule_count[300];
extern int g_slowpath_hit_count[300];

// ── Externs — defined in crypto_layer.h ──────────────────────────────────
extern std::map<uint32_t, std::pair<uint32_t, uint32_t>> g_lstm_stark_counts;
extern std::map<uint32_t, uint32_t>                       g_lstm_pkt_counts;

// ── TCAM hardware capacity (mirrors TCAM_HW_SIZE in routing.cc) ──────────
static const int LSTM_TCAM_HW_SIZE = 256;

// ── Per-cycle delta tracker for PACKET_IN rate ────────────────────────────
// g_slowpath_hit_count is cumulative; we track the previous value per RSU
// to compute the per-cycle delta (hits/s at 1 Hz).
static int g_lstm_prev_slowpath[300] = {0};

// ── Run tag and base directory — set once in main() ──────────────────────
// Format: "A{variant}_pct{p}_seed{s}"  e.g. "A2_pct40_seed3"
std::string g_lstm_run_tag  = "A0_pct0_seed1";
std::string g_lstm_base_dir = "";

// ── lstm_logger_init ──────────────────────────────────────────────────────
// Call once from main() after cmd.Parse() to resolve the HOME-relative
// output directory.  No-op when training=false.
inline void lstm_logger_init(int variant, int pct, uint32_t seed)
{
    if (!training) return;
    char* home = getenv("HOME");
    std::string base = home
        ? std::string(home) + "/ns-allinone-3.35/ns-3.35/lstm_training"
        : std::string("/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/lstm_training");
    g_lstm_base_dir = base;
    g_lstm_run_tag  = "A" + std::to_string(variant)
                    + "_pct" + std::to_string(pct)
                    + "_seed" + std::to_string(seed);
}

// ── lstm_log_rsu_cycle ────────────────────────────────────────────────────
// Called once per RSU per 1-second data-gathering cycle.
//
//   rsu_idx  : 0-based RSU index  (0 … N_RSUs-1)
//   node_id  : NS-3 node index    (= N_Vehicles + rsu_idx)
//   timestep : Simulator::Now().GetSeconds()
//   delta_t  : obs_delay from S1 baseline update (mean hop-delay this cycle)
//   rho_t    : vehicle density in this RSU's zone
//   v_bar_t  : mean vehicle speed in this RSU's zone (m/s)
//
inline void lstm_log_rsu_cycle(
    uint32_t rsu_idx,
    uint32_t node_id,
    double   timestep,
    double   delta_t,
    double   rho_t,
    double   v_bar_t)
{
    if (!training || g_lstm_base_dir.empty()) return;

    // ── λ_PI: PACKET_IN rate — per-cycle delta at 1 Hz ───────────────────
    int hits_now        = g_slowpath_hit_count[node_id];
    int delta_hits      = hits_now - g_lstm_prev_slowpath[rsu_idx];
    if (delta_hits < 0) delta_hits = 0;
    g_lstm_prev_slowpath[rsu_idx] = hits_now;
    double lambda_pi = static_cast<double>(delta_hits);

    // ── U_TCAM: TCAM utilization clamped to [0, 1] ───────────────────────
    double tcam_util = g_tcam_rule_count[node_id] / static_cast<double>(LSTM_TCAM_HW_SIZE);
    if (tcam_util < 0.0) tcam_util = 0.0;
    if (tcam_util > 1.0) tcam_util = 1.0;

    // ── ZKP failure flags — binary 1 if any failure occurred this cycle ──
    int zkp_delay_fail = 0;
    int zkp_hop_fail   = 0;
    auto it = g_lstm_stark_counts.find(node_id);
    if (it != g_lstm_stark_counts.end()) {
        if (it->second.first  > 0) zkp_delay_fail = 1;
        if (it->second.second > 0) zkp_hop_fail   = 1;
        it->second = {0, 0};   // reset for next cycle
    }
    auto pit = g_lstm_pkt_counts.find(node_id);
    if (pit != g_lstm_pkt_counts.end()) pit->second = 0;

    // ── Label and attack variant ──────────────────────────────────────────
    // attack_variant 0 = benign; 1-8 map to Attacks 1-8 (active_attack_variant + 1)
    int label   = (attack_percentage > 0) ? 1 : 0;
    int variant = (active_attack_variant >= 0) ? (active_attack_variant + 1) : 0;

    // ── Output path: {base}/RSU_{id}/{run_tag}.csv ───────────────────────
    std::string dir  = g_lstm_base_dir + "/RSU_" + std::to_string(rsu_idx);
    mkdir(dir.c_str(), 0755);
    std::string path = dir + "/" + g_lstm_run_tag + ".csv";

    // ── Write CSV header on first open ───────────────────────────────────
    {
        std::ifstream probe(path);
        bool is_new = (!probe.good()) ||
                      (probe.peek() == std::ifstream::traits_type::eof());
        if (is_new) {
            std::ofstream hdr(path, std::ios::out);
            hdr << "timestep,delta_t,lambda_PI,U_TCAM,"
                << "zkp_delay_fail,zkp_hop_fail,rho,v_bar,"
                << "label,attack_variant\n";
        }
    }

    // ── Append data row ───────────────────────────────────────────────────
    std::ofstream fout(path, std::ios::app);
    if (!fout.is_open()) return;

    fout << std::fixed << std::setprecision(6)
         << timestep       << ","
         << delta_t        << ","
         << lambda_pi      << ","
         << tcam_util      << ","
         << zkp_delay_fail << ","
         << zkp_hop_fail   << ","
         << rho_t          << ","
         << v_bar_t        << ","
         << label          << ","
         << variant        << "\n";
}

#endif // LSTM_LOGGER_H
