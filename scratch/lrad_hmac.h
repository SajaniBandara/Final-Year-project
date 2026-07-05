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

inline void lrad_hmac_tag_packet(uint32_t node, uint32_t pkt_id, uint32_t nonce)
{
    if (node >= (uint32_t)N_Vehicles) return;
    if (pkt_id >= (uint32_t)(Flow_size + 2)) return;
    if (!g_node_keys[node].keys_generated) return;

    double  ts = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[16];
    memcpy(msg,    &pkt_id, 4);
    memcpy(msg+4,  &ts,     8);
    memcpy(msg+12, &nonce,  4);

    HmacTag h{};
    h.ts    = ts;
    h.nonce = nonce;
    h.valid = hmac_sha3_512(g_node_keys[node].hmac_key, 64, msg, 16, h.tag);
    g_hmac_tags[{node, pkt_id}] = h;
}

#endif // LRAD_HMAC_H
