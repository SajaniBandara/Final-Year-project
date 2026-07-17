#ifndef CRYPTO_EVENT_LOG_H
#define CRYPTO_EVENT_LOG_H

// =========================================================================
// crypto_event_log.h — Per-operation cryptographic timing log
//
// Records wall-clock duration of each crypto operation alongside NS3
// simulation time, enabling supervisors / examiners to verify:
//   (a) each operation fires at the correct simulation moment, and
//   (b) the real wall-clock cost introduced by liboqs / OpenSSL.
//
// Output: results_routing/crypto_timing_log.csv
// Columns:
//   sim_time_s  — NS3 simulation time when the operation was called (s)
//   op          — operation name (sign / verify / stark_hop / stark_timing /
//                 batch_verify / flowmod_endorse / blockchain_write)
//   node_id     — node that performed the operation
//   pkt_id      — packet identifier (0 for non-packet operations)
//   wall_us     — wall-clock duration of the operation (microseconds)
//   result      — "ok" or "fail"
//
// Usage:
//   Include AFTER crypto_layer.h in routing.cc. Then wrap each crypto call:
//
//     auto _t0 = crypto_log_start();
//     bool ok  = mldsa87_sign(...);
//     crypto_log_event("sign", node, pkt, _t0, ok);
//
// Thread safety: single-threaded NS3 simulation — no mutex needed.
// =========================================================================

#include <chrono>
#include <fstream>
#include <string>
#include <cstdlib>   // getenv
#include "ns3/simulator.h"

using namespace ns3;

// ── Internal state ────────────────────────────────────────────────────────

static std::ofstream g_crypto_log_file;
static bool          g_crypto_log_open = false;

// ── Open / init ───────────────────────────────────────────────────────────

inline void crypto_log_init()
{
    if (g_crypto_log_open) return;

    std::string path = "/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/";
    const char* home = getenv("HOME");
    if (home)
        path = std::string(home) + "/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";

    g_crypto_log_file.open(path + "crypto_timing_log.csv",
                           std::ios::out | std::ios::trunc);
    if (!g_crypto_log_file.is_open()) {
        std::cerr << "[CRYPTO-LOG] WARNING: could not open crypto_timing_log.csv at "
                  << path << "\n";
        return;
    }
    g_crypto_log_file << "sim_time_s,op,node_id,pkt_id,wall_us,result\n";
    g_crypto_log_open = true;
}

inline void crypto_log_close()
{
    if (g_crypto_log_open) {
        g_crypto_log_file.flush();
        g_crypto_log_file.close();
        g_crypto_log_open = false;
    }
}

// ── Timing helpers ────────────────────────────────────────────────────────

using CryptoTimePoint = std::chrono::high_resolution_clock::time_point;

inline CryptoTimePoint crypto_log_start()
{
    return std::chrono::high_resolution_clock::now();
}

inline void crypto_log_event(const char*      op,
                              uint32_t         node_id,
                              uint32_t         pkt_id,
                              CryptoTimePoint  t0,
                              bool             result)
{
    if (!g_crypto_log_open) return;

    auto t1      = std::chrono::high_resolution_clock::now();
    double wall_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double sim_t   = Simulator::Now().GetSeconds();

    g_crypto_log_file << sim_t   << ","
                      << op      << ","
                      << node_id << ","
                      << pkt_id  << ","
                      << wall_us << ","
                      << (result ? "ok" : "fail") << "\n";
}

#endif // CRYPTO_EVENT_LOG_H
