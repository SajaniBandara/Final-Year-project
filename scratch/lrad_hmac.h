#ifndef LRAD_HMAC_H
#define LRAD_HMAC_H

// Minimal HMAC tag infrastructure for S2-partial.
// Split from lrad.h so it can be included before the full LRAD engine
// (which has stricter include-order requirements).
// Requires: crypto_layer.h (hmac_sha3_512, g_node_keys, N_Vehicles, Flow_size)

#include <map>
#include <utility>
#include <cstring>

struct HmacTag { uint8_t tag[64]; double ts; uint32_t nonce; bool valid; };
static std::map<std::pair<uint32_t,uint32_t>, HmacTag> g_hmac_tags;

// pkt_id alone does NOT identify a packet: it is a per-cycle slot index that
// restarts at 1 every cycle (routing.cc: packet_id = total_packet_counter + 1,
// with total_packet_counter function-local) and omits the flow entirely.  Two
// concurrent flows through the same node collide on one slot, and a slot
// written in an earlier cycle is still present in a later one.  Compose flow_id
// into the key exactly as crypto_layer.h's crypto_msg_key() already does for
// g_packet_crypto (the FV688 fix) -- same hazard, same remedy.
//
// The write is unconditional: an entry must carry THIS packet's forward
// timestamp, because lrad_s2_partial_check() reads it as ts_recv for the
// (t_now - ts_recv) > Delta_max test of alg:lrad_obu.  A stale ts is a
// guaranteed false positive, since the gap only grows.
inline void lrad_hmac_tag_packet(uint32_t node, uint32_t pkt_id, uint32_t flow_id)
{
    if (node >= (uint32_t)N_Vehicles) return;
    if (pkt_id >= (uint32_t)(Flow_size + 2)) return;
    if (!g_node_keys[node].keys_generated) return;

    // eta_i <- RAND(): fresh per-tag nonce (eq:hmac_light).  Previously every
    // caller passed pkt_id here, so the field duplicated msg_id and carried no
    // entropy.  Uses OQS_randombytes exactly as the full-mode signer does
    // (crypto_layer.h, eq:mldsa_sign) so both modes derive eta the same way.
    uint32_t eta = 0;
    OQS_randombytes(reinterpret_cast<uint8_t*>(&eta), sizeof(eta));

    // eq:hmac_light: HMAC-SHA3-512(k_i, msg_id || ts_i || eta_i) -- 16-byte
    // explicit buffer.  Identical layout to the full-mode 24-byte sign buffer
    // minus nh_i and z_i, which eq:hmac_light omits by design.
    // msg_id = crypto_msg_key(pkt_id, flow_id): pkt_id alone is a per-cycle slot
    // index and does not identify a packet -- see crypto_msg_key's declaration.
    uint32_t msg_id = crypto_msg_key(pkt_id, flow_id);
    double   ts     = ns3::Simulator::Now().GetSeconds();
    uint8_t  msg[16];
    memcpy(msg,    &msg_id, 4);
    memcpy(msg+4,  &ts,     8);
    memcpy(msg+12, &eta,    4);

    HmacTag h{};
    h.ts    = ts;
    h.nonce = eta;
    h.valid = hmac_sha3_512(g_node_keys[node].hmac_key, 64, msg, 16, h.tag);
    g_hmac_tags[{node, msg_id}] = h;
}

#endif // LRAD_HMAC_H
