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
#include <vector>
#include <array>

// SHA3-512 output size in bytes. Single authoritative definition for the TU.
static constexpr size_t SHA3_512_BYTES = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Shared blockchain state — one definition per TU (routing.cc).
// FlowMod, detection, and model writes all push hashes here; bc_anchor_to_global
// reads this vector to build the binary Merkle root (eq:anchor_hash).
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<std::array<uint8_t,SHA3_512_BYTES>> g_rsu_commit_hashes;
static int g_bc_global_commit_count = 0;

static std::map<uint32_t, std::array<uint8_t,SHA3_512_BYTES>> g_committed_model_hashes;
static std::map<uint32_t, int> g_model_round;

static std::ofstream g_bc_detection_csv;
static bool          g_bc_detection_open = false;
static std::string   g_bc_detection_path;
static std::ofstream g_bc_model_csv;
static bool          g_bc_model_open     = false;
static std::string   g_bc_model_path;
static std::ofstream g_bc_dkg_csv;
static bool          g_bc_dkg_open       = false;
static std::string   g_bc_dkg_path;
static std::ofstream g_bc_anchor_csv;
static bool          g_bc_anchor_open    = false;
static std::string   g_bc_anchor_path;
static std::ofstream g_bc_tref_csv;
static bool          g_bc_tref_open      = false;
static std::string   g_bc_tref_path;
static int           g_dkg_round         = 0;
static int           g_anchor_seq        = 0;
static int           g_tref_seq          = 0;
static uint8_t       g_prev_anchor_hash[SHA3_512_BYTES] = {};

static const std::string BC_RESULTS_DIR =
    "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";

// Per-run filename suffix ("_Attack{id}_{pct}{delay}[_TAP|_FADE]"), mirrors the
// scheme write_security_metrics_csv() uses for MOBIGUARD_Attack*.csv. Without
// this, every run (and every other process pointed at BC_RESULTS_DIR) writes
// the same bc_*.csv filenames, so concurrent/sequential runs interleave torn
// writes into each other's files — this is what was corrupting
// bc_anchor_log.csv, bc_detection_log.csv, bc_dkg_log.csv and
// bc_flowmod_log.csv (records fused together with missing commas/newlines).
//
// The attack/pct/delay suffix alone is NOT enough: run_std_attacks.py always
// launches the plain MOBIGUARD run and the TAP baseline run for a given Attack
// 2 percentage as two CONCURRENT processes (--enable_tap=1 for the latter),
// and both compute the exact same id/pct/delay, so both opened (and
// std::ios::trunc'd) the identical path at once — confirmed live: the TAP
// run for a percentage crashing before start left that one percentage's
// bc_anchor_log with zero corruption (single writer), while every percentage
// where both processes ran had fused/lost rows. The "_TAP" tag below (same
// convention as the A2_pct<P>..._TAP.log run logs) gives the two processes
// disjoint paths so bc_write_row()'s per-stream fail()/retry logic is no
// longer defeated by a second process truncating the same file underneath it.
//
// run_hf_attacks.py has the identical concurrent-pair pattern for FADE: it
// submits the normal MOBIGUARD run and an isolated FADE run for the same
// (attack, pct) to the same thread pool, and FADE_PARAMS never sets
// enable_tap, so both processes used to collide the same way TAP did before
// the tag above existed. fade_detection_active (true only during an isolated
// FADE run: active_attack_variant in [4,7] with both LRAD flags off) is
// already resolved during one-time setup in main(), before Simulator::Run()
// starts and therefore before any bc_* file is first opened from a scheduled
// event — safe to read here without reordering anything, and needs no launch
// flag of its own.
inline std::string bc_run_suffix() {
    int id = (active_attack_variant >= 0) ? (active_attack_variant + 1) : 0;
    return "_Attack" + std::to_string(id) + "_" + std::to_string(attack_percentage) + g_delay_suffix
           + "_seed" + std::to_string(sim_seed)
           + (enable_tap ? "_TAP" : "")
           + (fade_detection_active ? "_FADE" : "");
}

// ─────────────────────────────────────────────────────────────────────────────
// Flowmod endorsement functions — synchronous BFT path (eq:endorsed_commit).
// FlowModEndorsement and g_flowmod_endorsements are defined in crypto_layer.h
// which is included in routing.cc before this header.
// ─────────────────────────────────────────────────────────────────────────────

// Pre-install audit log — no-op in Fabric mode (bridge's flowmod tailer handles it).
inline bool bc_log_flowmod(const FlowModEndorsement& /*e*/, uint32_t /*rsu_idx*/) {
    return true;
}

// BFT endorsement check per eq:endorsed_commit.
// Returns false → S1 detection signal. On success, appends the commit hash to
// g_rsu_commit_hashes so it feeds the next Merkle root in bc_anchor_to_global().
inline bool bc_commit_flowmod(FlowModEndorsement& e) {
    // f = floor((N_RSUs-1)/3) Byzantine faults tolerated; require f+1 endorsers (eq:endorsed_commit)
    uint32_t f_plus_1 = (N_RSUs > 0) ? ((N_RSUs - 1) / 3) + 1 : 1;
    // AB8-A (enable_endorsement_requirement=false): controller commits unilaterally —
    // quorum check skipped, every FlowMod commits, so bc_query_flowmod() always finds
    // a committed entry and f_unauth (S3/S5 blockchain conjunct) can never fire.
    if (enable_endorsement_requirement &&
        (uint32_t)e.endorsing_rsus.size() < f_plus_1) {
        std::cerr << "[BC-REJECT] FlowMod rejected: endorsers="
                  << e.endorsing_rsus.size() << " < required f+1=" << f_plus_1
                  << " → S1 detection signal\n";
        NS_LOG_WARN("[BC] FlowMod rejected: " << e.endorsing_rsus.size()
            << " < required " << f_plus_1 << " — S1 signal");
        return false;
    }
    double ts = ns3::Simulator::Now().GetSeconds();
    uint8_t buf[SHA3_512_BYTES * 2 + sizeof(double)];
    memcpy(buf,                    e.flowmod_hash,     SHA3_512_BYTES);
    memcpy(buf + SHA3_512_BYTES,   e.endorsement_hash, SHA3_512_BYTES);
    memcpy(buf + SHA3_512_BYTES*2, &ts,                sizeof(double));
    std::array<uint8_t,SHA3_512_BYTES> commit_hash;
    if (!sha3_512_hash(buf, sizeof(buf), commit_hash.data())) return false;
    g_rsu_commit_hashes.push_back(commit_hash);
    e.committed   = true;
    e.commit_time = ts;
    std::cout << "[BC-COMMIT] FlowMod COMMITTED: endorsers="
              << e.endorsing_rsus.size() << "/" << f_plus_1
              << " commit_hash[0..3]=" << _hex4(commit_hash.data())
              << " rsu_chain_len=" << g_rsu_commit_hashes.size() << "\n";
    return true;
}

// Check whether a FlowMod was committed (f+1 endorsed) — used for S3/S5 detection.
inline bool bc_query_flowmod(uint32_t flow_key) {
    auto it = g_flowmod_endorsements.find(flow_key);
    return (it != g_flowmod_endorsements.end()) && it->second.committed;
}

// ─────────────────────────────────────────────────────────────────────────────

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
// routing.cc defines TCAM_CAPACITY (single canonical constant, reconciled
// 2026-07-13 from a disagreeing 256-vs-1000 pair; set to 100 on 2026-07-15);
// 80% gate = 0.8*TCAM_CAPACITY, computed at runtime (S4UtcamThresh=80% fraction,
// unchanged) — it auto-tracks whatever capacity routing.cc sets, so do NOT restate
// the rule count here. We read the actual capacity from the extern in routing.cc.
extern int TCAM_CAPACITY;                        // defined in routing.cc (line ~117453)
static const double BC_S4_UTIL_THRESH   = 0.80; // 80% utilisation triggers penalty

// ─────────────────────────────────────────────────────────────────────────────
// File handles (opened once, flushed after every row for real-time tailing)
// ─────────────────────────────────────────────────────────────────────────────

static std::ofstream g_bc_flowmod_csv;
static std::string   g_bc_flowmod_path;
static std::ofstream g_bc_trust_csv;
static std::string   g_bc_trust_path;
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

// ─────────────────────────────────────────────────────────────────────────────
// bc_write_row() — write one already-newline-terminated CSV row and verify
// it actually landed.
//
// Every bc_*.csv writer in this file used to only check ofstream::is_open()
// before writing, never the stream's state afterward. is_open() stays true
// even after a stream has hit an I/O error and set failbit, and std::ofstream
// does not throw on failure by default — so a single transient write error
// at any point silently kills every later write to that stream for the rest
// of the run, while the unconditional [BC-*] stdout confirmation lines keep
// printing normally (they don't check whether the CSV write succeeded).
//
// This was confirmed on a live run by comparing stdout commit counts against
// on-disk row counts: bc_anchor_log lost 60-75% of its rows, bc_flowmod_log
// lost ~20-25%, bc_tref_log lost a smaller but consistent fraction — every
// single one of the 6 attack_percentage runs, not a one-off. The write calls
// themselves were correct (single-threaded, fresh buffers, flush per row);
// the bug was that nothing ever noticed or reacted when a write failed.
//
// Fix: check the stream after every write; if it failed, clear the error,
// reopen the same path in append mode, retry once, and print a
// [BC-WRITE-ERROR] line so any future recurrence is visible in the log
// instead of silently vanishing again.
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_write_row(std::ofstream& fs, const std::string& path, const std::string& row)
{
    fs << row;
    fs.flush();
    if (fs.fail()) {
        std::cerr << "[BC-WRITE-ERROR] write failed for " << path
                   << " — reopening in append mode and retrying\n";
        fs.clear();
        fs.close();
        fs.open(path, std::ios::app);
        if (fs.is_open()) {
            fs << row;
            fs.flush();
            if (fs.fail())
                std::cerr << "[BC-WRITE-ERROR] retry failed for " << path << " — row lost\n";
        } else {
            std::cerr << "[BC-WRITE-ERROR] reopen failed for " << path << " — row lost\n";
        }
    }
}

// Open both CSVs with headers (called lazily on first use).
static void bc_open_files()
{
    if (g_bc_files_open) return;

    const std::string dir =
        "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";

    // bc_flowmod_log.csv — one row per TCAM rule install
    // Columns match the chaincode LogFlowMod() signature + context fields.
    g_bc_flowmod_path = dir + "bc_flowmod_log" + bc_run_suffix() + ".csv";
    g_bc_flowmod_csv.open(g_bc_flowmod_path, std::ios::trunc);
    if (g_bc_flowmod_csv.is_open())
        bc_write_row(g_bc_flowmod_csv, g_bc_flowmod_path,
                     "rsu_id,flow_mod_hash,recv_timestamp_ms,"
                     "is_malicious,src_ip,dst_ip,src_port,dst_port\n");

    // bc_trust_updates.csv — one row per S3/S4 anomaly penalty
    // Columns match the chaincode UpdateTrust() signature + reason fields.
    g_bc_trust_path = dir + "bc_trust_updates" + bc_run_suffix() + ".csv";
    g_bc_trust_csv.open(g_bc_trust_path, std::ios::trunc);
    if (g_bc_trust_csv.is_open())
        bc_write_row(g_bc_trust_csv, g_bc_trust_path,
                     "rsu_id,success,timestamp_ms,reason,rule_count,rate_per_s\n");

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
        std::string row = std::to_string(node_id) + "," + hash + "," +
                           std::to_string(static_cast<long long>(now_ms)) + "," +
                           std::to_string(is_malicious ? 1 : 0) + "," +
                           bc_ip_str(src_ip) + "," + bc_ip_str(dst_ip) + "," +
                           std::to_string(src_port) + "," + std::to_string(dst_port) + "\n";
        bc_write_row(g_bc_flowmod_csv, g_bc_flowmod_path, row); // real-time: bridge sees row immediately
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
                std::ostringstream rate_oss;
                rate_oss << std::fixed << std::setprecision(2) << rate;
                std::string row = std::to_string(node_id) + ",0," + // success=false → penalty
                                   std::to_string(static_cast<long long>(now_ms)) + ",S3," +
                                   std::to_string(g_tcam_rule_count[node_id]) + "," +
                                   rate_oss.str() + "\n";
                bc_write_row(g_bc_trust_csv, g_bc_trust_path, row);
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
    int    thresh = static_cast<int>(TCAM_CAPACITY * BC_S4_UTIL_THRESH); // 0.8 * current capacity

    for (uint32_t r = 0; r < N_RSUs; r++) {
        uint32_t rsu_idx = N_Vehicles + r;  // sim node index (e.g. 200+r for N_Vehicles=200)
        int      count   = g_tcam_rule_count[rsu_idx];

        if (count > thresh) {
            // Write one penalty row per second while above threshold.
            if (g_bc_trust_csv.is_open()) {
                std::string row = std::to_string(rsu_idx) + ",0," + // success=false → penalty
                                   std::to_string(static_cast<long long>(now_ms)) + ",S4," +
                                   std::to_string(count) + ",0\n"; // rate=0 (N/A for S4)
                bc_write_row(g_bc_trust_csv, g_bc_trust_path, row);
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

// Shared state (g_rsu_commit_hashes, g_bc_global_commit_count,
// g_committed_model_hashes, g_model_round, CSV handles) is defined in
// blockchain_sim.h which is included before this file in routing.cc.

inline bool bc_verify_model_hash(uint32_t rsu_idx, const uint8_t* submitted_hash) {
    auto it = g_committed_model_hashes.find(rsu_idx);
    if (it == g_committed_model_hashes.end()) return false;
    return memcmp(it->second.data(), submitted_hash, SHA3_512_BYTES) == 0;
}

static void bc_open_detection_csv() {
    if (g_bc_detection_open) return;
    g_bc_detection_path = BC_RESULTS_DIR + "bc_detection_log" + bc_run_suffix() + ".csv";
    g_bc_detection_csv.open(g_bc_detection_path, std::ios::trunc);
    if (g_bc_detection_csv.is_open())
        bc_write_row(g_bc_detection_csv, g_bc_detection_path,
                     "rsu_id,suspect_node,signal_idx,timestamp_ms,rsu_sig\n");
    g_bc_detection_open = true;
}
static void bc_open_model_csv() {
    if (g_bc_model_open) return;
    g_bc_model_path = BC_RESULTS_DIR + "bc_model_log" + bc_run_suffix() + ".csv";
    g_bc_model_csv.open(g_bc_model_path, std::ios::trunc);
    if (g_bc_model_csv.is_open())
        bc_write_row(g_bc_model_csv, g_bc_model_path, "rsu_id,round,model_hash,timestamp_ms\n");
    g_bc_model_open = true;
}
static void bc_open_dkg_csv() {
    if (g_bc_dkg_open) return;
    g_bc_dkg_path = BC_RESULTS_DIR + "bc_dkg_log" + bc_run_suffix() + ".csv";
    g_bc_dkg_csv.open(g_bc_dkg_path, std::ios::trunc);
    if (g_bc_dkg_csv.is_open())
        bc_write_row(g_bc_dkg_csv, g_bc_dkg_path,
                     "rsu_id,round,vk_zkp,n_rsus,commitments,timestamp_ms\n");
    g_bc_dkg_open = true;
}
static void bc_open_anchor_csv() {
    if (g_bc_anchor_open) return;
    g_bc_anchor_path = BC_RESULTS_DIR + "bc_anchor_log" + bc_run_suffix() + ".csv";
    g_bc_anchor_csv.open(g_bc_anchor_path, std::ios::trunc);
    if (g_bc_anchor_csv.is_open())
        bc_write_row(g_bc_anchor_csv, g_bc_anchor_path,
                     "rsu_id,seq,anchor_hash,rsu_chain_len,timestamp_ms\n");
    g_bc_anchor_open = true;
}
static void bc_open_tref_csv() {
    if (g_bc_tref_open) return;
    g_bc_tref_path = BC_RESULTS_DIR + "bc_tref_log" + bc_run_suffix() + ".csv";
    g_bc_tref_csv.open(g_bc_tref_path, std::ios::trunc);
    if (g_bc_tref_csv.is_open())
        bc_write_row(g_bc_tref_csv, g_bc_tref_path, "rsu_id,seq,t_ref_value,eps_ref,timestamp_ms\n");
    g_bc_tref_open = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_write_detection_event() — eq:rsu_write
// BC.Write(rk, vs||Si||ts||ML-DSA-87.Sign(sk_rk, H_SHA3-512(vs||Si||ts)))
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_write_detection_event(uint32_t rsu_idx, uint32_t suspect_node,
                                      int signal_idx, double ts)
{
    if (rsu_idx >= (uint32_t)total_size) return;
    // 9 = flag_LSTM (D_LSTM^(k), eq:lstm_detection) — added 2026-07-27 so
    // LSTM-triggered detections get the same blockchain audit trail as
    // S1-S8 (see docs/LSTM_LIVE_INTEGRATION_STATUS.md).
    if (signal_idx < 1 || signal_idx > 9) return;
    if (!g_node_keys[rsu_idx].keys_generated) mldsa87_keygen(rsu_idx);
    OQS_SIG* oqs = get_oqs_ctx();
    if (!oqs) return;

    uint8_t buf[2*sizeof(uint32_t) + sizeof(double)];
    memcpy(buf,                    &suspect_node, sizeof(uint32_t));
    memcpy(buf+sizeof(uint32_t),   &signal_idx,   sizeof(uint32_t));
    memcpy(buf+2*sizeof(uint32_t), &ts,           sizeof(double));
    uint8_t content_hash[SHA3_512_BYTES];
    sha3_512_hash(buf, sizeof(buf), content_hash);

    uint8_t rsu_sig[OQS_SIG_ml_dsa_87_length_signature];
    size_t  rsu_sig_len = OQS_SIG_ml_dsa_87_length_signature;
    if (OQS_SIG_sign(oqs, rsu_sig, &rsu_sig_len,
                     content_hash, SHA3_512_BYTES,
                     g_node_keys[rsu_idx].sk) != OQS_SUCCESS) {
        std::cerr << "[CRYPTO-ERROR] bc_write_detection_event: OQS_SIG_sign failed"
                  << " rsu=" << rsu_idx << " S" << signal_idx
                  << " suspect=" << suspect_node << "\n";
        return;
    }

    std::ostringstream sig_hex;
    for (size_t i = 0; i < rsu_sig_len; ++i)
        sig_hex << std::hex << std::setw(2) << std::setfill('0') << (int)rsu_sig[i];

    bc_open_detection_csv();
    long long ts_ms = (long long)(ts * 1000.0);
    if (g_bc_detection_csv.is_open()) {
        std::string row = std::to_string(rsu_idx) + "," + std::to_string(suspect_node) + "," +
                           std::to_string(signal_idx) + "," + std::to_string(ts_ms) + "," +
                           sig_hex.str() + "\n";
        bc_write_row(g_bc_detection_csv, g_bc_detection_path, row);
    }

    // Append to RSU-chain shadow for Merkle root
    std::array<uint8_t,SHA3_512_BYTES> h;
    memcpy(h.data(), content_hash, SHA3_512_BYTES);
    g_rsu_commit_hashes.push_back(h);

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-DETECT] rsu=" << rsu_idx << " S" << signal_idx
                  << " suspect=" << suspect_node << " t=" << ts
                  << " sig[0..3]=" << _hex4(rsu_sig)
                  << " rsu_chain_len=" << g_rsu_commit_hashes.size() << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_commit_model_hash() — eq:bc_model_verify (CommitModelHash on Fabric)
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_commit_model_hash(uint32_t rsu_idx, const uint8_t* model_hash_64) {
    std::array<uint8_t,SHA3_512_BYTES> arr;
    memcpy(arr.data(), model_hash_64, SHA3_512_BYTES);
    g_committed_model_hashes[rsu_idx] = arr;

    int round = ++g_model_round[rsu_idx];
    uint32_t rsu_node_id = N_Vehicles + (rsu_idx < (uint32_t)N_RSUs ? rsu_idx : 0);

    std::ostringstream hash_hex;
    for (size_t i = 0; i < SHA3_512_BYTES; ++i)
        hash_hex << std::hex << std::setw(2) << std::setfill('0') << (int)model_hash_64[i];

    double ts = Simulator::Now().GetSeconds();
    long long ts_ms = (long long)(ts * 1000.0);

    bc_open_model_csv();
    if (g_bc_model_csv.is_open()) {
        std::string row = std::to_string(rsu_node_id) + "," + std::to_string(round) + "," +
                           hash_hex.str() + "," + std::to_string(ts_ms) + "\n";
        bc_write_row(g_bc_model_csv, g_bc_model_path, row);
    }

    // Append to RSU-chain shadow
    std::array<uint8_t,SHA3_512_BYTES> h;
    memcpy(h.data(), model_hash_64, SHA3_512_BYTES);
    g_rsu_commit_hashes.push_back(h);

    std::cout << "[BC-MODEL] RSU " << rsu_idx << " round=" << round
              << " model hash committed hash[0..3]=" << _hex4(model_hash_64)
              << " t=" << ts << "s\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_commit_dkg() — eq:vk_commit / eq:vk_commit_rotated (CommitDKG on Fabric)
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_commit_dkg(const uint8_t* vk_zkp, const uint8_t com[][SHA3_512_BYTES],
                           uint32_t n_rsus, double ts_setup) {
    int round = ++g_dkg_round;

    std::ostringstream vk_hex;
    for (size_t i = 0; i < SHA3_512_BYTES; ++i)
        vk_hex << std::hex << std::setw(2) << std::setfill('0') << (int)vk_zkp[i];

    long long ts_ms = (long long)(ts_setup * 1000.0);
    uint32_t reporting_rsu = N_Vehicles;

    // Hex-encode per-RSU commitments {Com_j} per eq:vk_commit
    std::ostringstream com_hex;
    for (uint32_t r = 0; r < n_rsus; ++r)
        for (size_t b = 0; b < SHA3_512_BYTES; ++b)
            com_hex << std::hex << std::setw(2) << std::setfill('0') << (int)com[r][b];

    bc_open_dkg_csv();
    if (g_bc_dkg_csv.is_open()) {
        std::string row = std::to_string(reporting_rsu) + "," + std::to_string(round) + "," +
                           vk_hex.str() + "," + std::to_string(n_rsus) + "," +
                           com_hex.str() + "," + std::to_string(ts_ms) + "\n";
        bc_write_row(g_bc_dkg_csv, g_bc_dkg_path, row);
    }

    ++g_bc_global_commit_count;

    std::cout << "[DKG-BC] vk_ZKP committed to global chain (Fabric round=" << round << ")"
              << " t=" << ts_setup << " n_rsus=" << n_rsus
              << " vk_zkp[0..3]=" << _hex4(vk_zkp)
              << " global_chain_len=" << g_bc_global_commit_count << "\n";
    NS_LOG_INFO("[DKG-BC] vk_ZKP committed to global chain at t=" << ts_setup);
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_merkle_root() — binary Merkle tree over g_rsu_commit_hashes
// Odd-length levels: duplicate the last node.
// ─────────────────────────────────────────────────────────────────────────────
static void compute_merkle_root(uint8_t root_out[SHA3_512_BYTES]) {
    if (g_rsu_commit_hashes.empty()) { memset(root_out, 0, SHA3_512_BYTES); return; }

    std::vector<std::array<uint8_t,SHA3_512_BYTES>> level = g_rsu_commit_hashes;

    while (level.size() > 1) {
        if (level.size() & 1) level.push_back(level.back());
        std::vector<std::array<uint8_t,SHA3_512_BYTES>> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            uint8_t pair[2 * SHA3_512_BYTES];
            memcpy(pair,                level[i].data(),   SHA3_512_BYTES);
            memcpy(pair+SHA3_512_BYTES, level[i+1].data(), SHA3_512_BYTES);
            std::array<uint8_t,SHA3_512_BYTES> parent;
            sha3_512_hash(pair, sizeof(pair), parent.data());
            next.push_back(parent);
        }
        level = std::move(next);
    }
    memcpy(root_out, level[0].data(), SHA3_512_BYTES);
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_anchor_to_global() — eq:anchor_hash (AnchorGlobal on Fabric)
// H_anchor^(r) = H(H_root^RSU ‖ ts_anchor ‖ H_prev^global)
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_anchor_to_global() {
    if (g_rsu_commit_hashes.empty()) return;

    double ts = Simulator::Now().GetSeconds();

    uint8_t merkle_root[SHA3_512_BYTES];
    compute_merkle_root(merkle_root);

    static constexpr size_t TS_OFF  = SHA3_512_BYTES;
    static constexpr size_t PRV_OFF = SHA3_512_BYTES + sizeof(double);
    static constexpr size_t BUF_LEN = 2*SHA3_512_BYTES + sizeof(double);
    uint8_t buf[BUF_LEN];
    memcpy(buf,        merkle_root,        SHA3_512_BYTES);
    memcpy(buf+TS_OFF, &ts,                sizeof(double));
    memcpy(buf+PRV_OFF, g_prev_anchor_hash, SHA3_512_BYTES);

    uint8_t anchor_hash[SHA3_512_BYTES];
    sha3_512_hash(buf, BUF_LEN, anchor_hash);
    memcpy(g_prev_anchor_hash, anchor_hash, SHA3_512_BYTES);

    int seq = ++g_anchor_seq;
    ++g_bc_global_commit_count;
    long long ts_ms = (long long)(ts * 1000.0);

    std::ostringstream ah_hex;
    for (size_t i = 0; i < SHA3_512_BYTES; ++i)
        ah_hex << std::hex << std::setw(2) << std::setfill('0') << (int)anchor_hash[i];

    bc_open_anchor_csv();
    if (g_bc_anchor_csv.is_open()) {
        std::string row = std::to_string(N_Vehicles) + "," + std::to_string(seq) + "," +
                           ah_hex.str() + "," +
                           std::to_string(g_rsu_commit_hashes.size()) + "," +
                           std::to_string(ts_ms) + "\n";
        bc_write_row(g_bc_anchor_csv, g_bc_anchor_path, row);
    }

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-ANCHOR] Global anchor committed (Fabric seq=" << seq << ")"
                  << " rsu_chain_len=" << g_rsu_commit_hashes.size()
                  << " global_chain_len=" << g_bc_global_commit_count
                  << " t=" << ts
                  << " anchor_hash[0..3]=" << _hex4(anchor_hash) << "\n";
}

inline void bc_anchor_recurring() {
    bc_anchor_to_global();
    Simulator::Schedule(Seconds(T_SYNC_INTERVAL), &bc_anchor_recurring);
}

// ─────────────────────────────────────────────────────────────────────────────
// bc_commit_tref_to_chain() — sec:time_ref (CommitTRef on Fabric)
// Commits this tick's T_ref(t) = median_j tau_j(t) to the blockchain, per
// main.tex: "T_ref(t) is committed to the blockchain by RSU consensus at
// regular intervals to provide a tamper-evident audit trail for all
// detection decisions." Called directly from update_T_ref() (crypto_layer.h)
// on every T_SYNC_INTERVAL tick — same cadence as bc_anchor_to_global(), no
// separate recurring schedule needed since it always reads a freshly
// computed T_ref/eps_ref rather than risking a stale value from an
// independently-phased timer.
// ─────────────────────────────────────────────────────────────────────────────
inline void bc_commit_tref_to_chain(double t_ref_value, double eps_ref, double ts) {
    int seq = ++g_tref_seq;
    long long ts_ms = (long long)(ts * 1000.0);

    bc_open_tref_csv();
    if (g_bc_tref_csv.is_open()) {
        std::string row = std::to_string(N_Vehicles) + "," + std::to_string(seq) + "," +
                           std::to_string(t_ref_value) + "," + std::to_string(eps_ref) + "," +
                           std::to_string(ts_ms) + "\n";
        bc_write_row(g_bc_tref_csv, g_bc_tref_path, row);
    }

    if (CRYPTO_DEBUG_LOG)
        std::cout << "[BC-TREF] T_ref committed (Fabric seq=" << seq << ")"
                  << " T_ref=" << t_ref_value
                  << " eps_ref=" << eps_ref
                  << " t=" << ts << "\n";
}

#endif // BC_BLOCKCHAIN_HELPER_H
