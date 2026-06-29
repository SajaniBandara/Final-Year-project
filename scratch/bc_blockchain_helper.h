// bc_blockchain_helper.h
// MobiGuard — NS-3 → Blockchain real-time event writer
//
// Writes two CSVs into results_routing/ as the simulation runs:
//   bc_flowmod_log.csv    — one row per TCAM rule install (benign or malicious)
//   bc_trust_updates.csv  — one row per S3/S4 anomaly trust penalty event
//
// The Node.js bridge tails these files in real time and maps each row to
// a mobiguard-cc chaincode call (LogFlowMod, UpdateTrust, etc.).
//
// Include this header from tcam_attack_helper.h (which is included from
// routing.cc at line ~120980, after all NS-3 headers are already pulled in).
//
// §3.4.10 Three-state lifecycle thresholds (matches types.go constants):
//   T_demote = 3000 bp (0.30) — peer demoted to client
//   T_remove = 1000 bp (0.10) — client ejected (writes blocked)
//
// §3.4.10 Anomaly detection triggers (matches sim_params.go):
//   S3: FlowMod install rate > S3_RATE_THRESH/s  (CP TCAM flood)
//   S4: TCAM rule count > S4_RULE_THRESH rules    (DP exhaustion)

#ifndef BC_BLOCKCHAIN_HELPER_H
#define BC_BLOCKCHAIN_HELPER_H

#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <string>

// These globals are defined in tcam_attack_helper.h (same translation unit).
// Forward-declared here so bc_blockchain_helper.h compiles when included
// at the top of tcam_attack_helper.h.
extern int      g_tcam_rule_count[];   // [node_id] → installed rule count
extern uint32_t N_RSUs;
extern uint32_t N_Vehicles;
extern double   simTime;

// ─────────────────────────────────────────────────────────────────────────────
// Thresholds (mirror sim_params.go / SPEC.md values)
// ─────────────────────────────────────────────────────────────────────────────

// S3: control-plane TCAM flood rate threshold (Eq 3.7 / sim_params.go S3LambdaThresh)
static const int    BC_S3_RATE_THRESH   = 10;   // FlowMods per second

// S4: data-plane TCAM exhaustion threshold.
// routing.cc defines TCAM_CAPACITY = 1000; 80% = 800 rules (sim_params.go S4UtcamThresh=80).
// We read the actual capacity from the extern defined in routing.cc.
extern int TCAM_CAPACITY;                        // defined in routing.cc (line ~120984)
static const double BC_S4_UTIL_THRESH   = 0.80; // 80% utilisation triggers penalty

// ─────────────────────────────────────────────────────────────────────────────
// File handles (opened once, flushed after every row for real-time tailing)
// ─────────────────────────────────────────────────────────────────────────────

static std::ofstream g_bc_flowmod_csv;
static std::ofstream g_bc_trust_csv;
static bool          g_bc_files_open = false;

// ─────────────────────────────────────────────────────────────────────────────
// Per-RSU rate tracking for S3 (rolling 1-second window)
// ─────────────────────────────────────────────────────────────────────────────
static std::map<uint32_t, int>    g_bc_s3_count;        // installs in current window
static std::map<uint32_t, double> g_bc_s3_window_start; // window start time (sim seconds)
static std::map<uint32_t, bool>   g_bc_s3_fired;        // guard: fire once per burst window

// Per-RSU S4 guard: fire only on first threshold crossing per RSU
static std::set<uint32_t>         g_bc_s4_reported;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Deterministic 16-hex-char hash from node_id, flow_id, timestamp.
// NS-3 uses this so the bridge can correlate rows; the bridge re-hashes
// with SHA-256 for the actual on-chain FlowMod hash.
static std::string bc_make_hash(uint32_t node_id, uint32_t flow_id, double t_ms)
{
    std::size_t h = std::hash<std::string>{}(
        std::to_string(node_id) + ":" +
        std::to_string(flow_id) + ":" +
        std::to_string(static_cast<long long>(t_ms)));
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << h;
    return oss.str();
}

// Convert a uint32_t IPv4 address to dotted-decimal string.
static std::string bc_ip_str(uint32_t ip)
{
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >>  8) & 0xFF) << "."
        << ( ip        & 0xFF);
    return oss.str();
}

// Open both CSVs with headers (called lazily on first use).
static void bc_open_files()
{
    if (g_bc_files_open) return;

    const std::string dir =
        "/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/";

    // bc_flowmod_log.csv — one row per TCAM rule install
    // Columns match the chaincode LogFlowMod() signature + context fields.
    g_bc_flowmod_csv.open(dir + "bc_flowmod_log.csv", std::ios::trunc);
    if (g_bc_flowmod_csv.is_open())
        g_bc_flowmod_csv
            << "rsu_id,flow_mod_hash,recv_timestamp_ms,"
               "is_malicious,src_ip,dst_ip,src_port,dst_port\n";

    // bc_trust_updates.csv — one row per S3/S4 anomaly penalty
    // Columns match the chaincode UpdateTrust() signature + reason fields.
    g_bc_trust_csv.open(dir + "bc_trust_updates.csv", std::ios::trunc);
    if (g_bc_trust_csv.is_open())
        g_bc_trust_csv
            << "rsu_id,success,timestamp_ms,reason,rule_count,rate_per_s\n";

    g_bc_files_open = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_log_flowmod()
// Called from tcam_install() and tcam_install_malicious() for every TCAM rule.
// Writes one row to bc_flowmod_log.csv and prints [BC-FLOWMOD] to stdout.
// Also maintains the S3 rolling-window counter for this RSU.
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_log_flowmod(uint32_t node_id,
                            uint32_t flow_id,
                            uint32_t src_ip,
                            uint32_t dst_ip,
                            uint16_t src_port,
                            uint16_t dst_port,
                            bool     is_malicious)
{
    bc_open_files();

    double now_s  = Simulator::Now().GetSeconds();
    double now_ms = Simulator::Now().GetMilliSeconds();
    std::string hash = bc_make_hash(node_id, flow_id, now_ms);

    // ── Write CSV row ────────────────────────────────────────────────────────
    if (g_bc_flowmod_csv.is_open()) {
        g_bc_flowmod_csv
            << node_id          << ","
            << hash             << ","
            << static_cast<long long>(now_ms) << ","
            << (is_malicious ? 1 : 0) << ","
            << bc_ip_str(src_ip) << ","
            << bc_ip_str(dst_ip) << ","
            << src_port          << ","
            << dst_port          << "\n";
        g_bc_flowmod_csv.flush(); // real-time: bridge sees row immediately
    }

    // ── NS-3 stdout confirmation line ────────────────────────────────────────
    std::cout << "[BC-FLOWMOD] rsu=" << node_id
              << " hash=" << hash
              << " t=" << std::fixed << std::setprecision(3) << now_s << "s"
              << " malicious=" << (is_malicious ? 1 : 0)
              << std::endl;

    // ── S3 rate tracking (rolling 1-second window per RSU) ───────────────────
    // Initialise window for first-ever event from this RSU.
    if (g_bc_s3_window_start.find(node_id) == g_bc_s3_window_start.end()) {
        g_bc_s3_window_start[node_id] = now_s;
        g_bc_s3_count[node_id]        = 0;
        g_bc_s3_fired[node_id]        = false;
    }

    double elapsed = now_s - g_bc_s3_window_start[node_id];

    if (elapsed >= 1.0) {
        // ── Window expired: evaluate rate ────────────────────────────────────
        double rate = (elapsed > 0.0)
            ? static_cast<double>(g_bc_s3_count[node_id]) / elapsed
            : 0.0;

        if (rate > BC_S3_RATE_THRESH && !g_bc_s3_fired[node_id]) {
            // S3 threshold crossed — emit one trust penalty for this burst.
            if (g_bc_trust_csv.is_open()) {
                g_bc_trust_csv
                    << node_id  << ","
                    << 0        << ","   // success=false → penalty
                    << static_cast<long long>(now_ms) << ","
                    << "S3"     << ","
                    << g_tcam_rule_count[node_id] << ","
                    << std::fixed << std::setprecision(2) << rate << "\n";
                g_bc_trust_csv.flush();
            }
            std::cout << "[BC-S3] rsu=" << node_id
                      << " rate=" << std::fixed << std::setprecision(1)
                      << rate << "/s > thresh=" << BC_S3_RATE_THRESH
                      << " rules=" << g_tcam_rule_count[node_id]
                      << " → trust_penalty t=" << now_s << "s"
                      << std::endl;

            g_bc_s3_fired[node_id] = true;
        }

        // ── Reset window ─────────────────────────────────────────────────────
        g_bc_s3_window_start[node_id] = now_s;
        g_bc_s3_count[node_id]        = 1; // current event is the first of new window
        // Allow S3 to re-fire in next window if attack continues
        if (elapsed >= 2.0) g_bc_s3_fired[node_id] = false;

    } else {
        // Still within the current 1-second window — just count.
        g_bc_s3_count[node_id]++;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_check_s4()
// Called from tcam_snapshot_dump() once per second (after occupancy CSVs written).
// Iterates all RSUs; fires one trust penalty row per RSU whose rule count
// exceeds 80% of TCAM_CAPACITY for the first time.
//
// Note: S4 re-fires every second while the RSU remains above threshold,
// allowing the score to decay toward T_demote and eventually T_remove.
// This mirrors the sustained-penalty model in applyTrustUpdate() (trust.go).
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_check_s4()
{
    bc_open_files();

    double now_ms = Simulator::Now().GetMilliSeconds();
    double now_s  = Simulator::Now().GetSeconds();
    int    thresh = static_cast<int>(TCAM_CAPACITY * BC_S4_UTIL_THRESH); // 800

    for (uint32_t r = 0; r < N_RSUs; r++) {
        uint32_t rsu_idx = N_Vehicles + r;  // sim node index (e.g. 200+r for N_Vehicles=200)
        int      count   = g_tcam_rule_count[rsu_idx];

        if (count > thresh) {
            // Write one penalty row per second while above threshold.
            if (g_bc_trust_csv.is_open()) {
                g_bc_trust_csv
                    << rsu_idx << ","
                    << 0       << ","   // success=false → penalty
                    << static_cast<long long>(now_ms) << ","
                    << "S4"    << ","
                    << count   << ","
                    << 0       << "\n"; // rate=0 (N/A for S4)
                g_bc_trust_csv.flush();
            }

            // Print [BC-S4] only first time to avoid flooding stdout.
            if (g_bc_s4_reported.find(rsu_idx) == g_bc_s4_reported.end()) {
                std::cout << "[BC-S4] rsu=" << rsu_idx
                          << " rules=" << count
                          << " > thresh=" << thresh
                          << " (80% of TCAM_CAPACITY=" << TCAM_CAPACITY << ")"
                          << " → trust_penalty t=" << now_s << "s"
                          << std::endl;
                g_bc_s4_reported.insert(rsu_idx);
            }
        } else {
            // Recovered below threshold — allow [BC-S4] line to print again
            // if it rises above threshold in a future second.
            g_bc_s4_reported.erase(rsu_idx);
        }
    }
}

#endif // BC_BLOCKCHAIN_HELPER_H
