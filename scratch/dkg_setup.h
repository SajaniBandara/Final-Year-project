#ifndef DKG_SETUP_H
#define DKG_SETUP_H

inline void dkg_run_ceremony() {
    if (g_dkg.ceremony_done) return;

    // Phase 1: Real ML-DSA-87 keypairs for all RSUs + commitments Com_j = SHA3-512(pk_j)
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t idx = N_Vehicles + r;
        if (!mldsa87_keygen(idx)) {
            NS_LOG_ERROR("[DKG] Key gen failed for RSU " << r);
            continue;
        }
        sha3_512_hash(g_node_keys[idx].pk,
                      OQS_SIG_ml_dsa_87_length_public_key,
                      g_dkg.com[r]);
    }

    // Phase 2: vk_ZKP = SHA3-512(Com_0 ‖ Com_1 ‖ ... ‖ Com_{N_RSUs-1})
    std::vector<uint8_t> combined(N_RSUs * 64);
    for (uint32_t r = 0; r < N_RSUs; ++r)
        memcpy(combined.data() + r * 64, g_dkg.com[r], 64);
    if (!sha3_512_hash(combined.data(), combined.size(), g_dkg.vk_zkp)) {
        NS_LOG_ERROR("[DKG] vk_ZKP computation failed");
        return;
    }

    // Phase 3: Real ML-DSA-87 keypairs for all vehicles
    for (uint32_t v = 0; v < N_Vehicles; ++v)
        mldsa87_keygen(v);

    // Phase 4: HMAC pre-shared keys for OBU (vehicle) mode: hmac_key_v = SHA3-512(v ‖ vk_ZKP)
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        uint8_t seed[68];
        memcpy(seed,   &v,            4);
        memcpy(seed+4, g_dkg.vk_zkp, 64);
        sha3_512_hash(seed, 68, g_node_keys[v].hmac_key);
    }

    g_dkg.ceremony_done = true;
    g_dkg.last_rotation = ns3::Simulator::Now().GetSeconds();
    bc_commit_dkg(g_dkg.vk_zkp, g_dkg.com, N_RSUs, g_dkg.last_rotation);
    NS_LOG_INFO("[DKG] Ceremony complete: " << N_RSUs << " RSUs + "
        << N_Vehicles << " vehicles keyed  vk_zkp[0]=" << (int)g_dkg.vk_zkp[0]);
}

// Triggered by eq:key_rotation_trigger when T_{r_j} < T_min
inline void dkg_rotate_keys(uint32_t revoked_rsu_node_index) {
    std::vector<uint8_t> combined;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t idx = N_Vehicles + r;
        if (idx == revoked_rsu_node_index) continue;
        g_node_keys[idx].keys_generated = false;
        mldsa87_keygen(idx);
        sha3_512_hash(g_node_keys[idx].pk,
                      OQS_SIG_ml_dsa_87_length_public_key,
                      g_dkg.com[r]);
        combined.insert(combined.end(), g_dkg.com[r], g_dkg.com[r] + 64);
    }
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), g_dkg.vk_zkp);
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        g_node_keys[v].keys_generated = false;
        mldsa87_keygen(v);
    }
    g_dkg.last_rotation = ns3::Simulator::Now().GetSeconds();
    bc_commit_dkg(g_dkg.vk_zkp, g_dkg.com, N_RSUs, g_dkg.last_rotation);
    NS_LOG_INFO("[DKG] Key rotation after RSU " << revoked_rsu_node_index
        << " revocation at t=" << g_dkg.last_rotation);
}

#endif // DKG_SETUP_H
