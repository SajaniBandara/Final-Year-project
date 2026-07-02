#ifndef DKG_SETUP_H
#define DKG_SETUP_H

inline void dkg_run_ceremony() {
    if (g_dkg.ceremony_done) return;

    // Phase 1: Real ML-DSA-87 keypairs for all RSUs + commitments Com_j = SHA3-512(pk_j)
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t idx = N_Vehicles + r;
        if (!mldsa87_keygen(idx)) {
            NS_LOG_ERROR("[DKG] Key gen failed for RSU " << r);
            std::cerr << "[DKG-ERROR] ML-DSA-87 keygen failed for RSU r=" << r
                      << " (node idx=" << idx << ")\n";
            continue;
        }
        sha3_512_hash(g_node_keys[idx].pk,
                      OQS_SIG_ml_dsa_87_length_public_key,
                      g_dkg.com[r]);
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[DKG-P1] RSU r=" << r << " (node=" << idx << ")"
                      << " ML-DSA-87 pk_len=" << OQS_SIG_ml_dsa_87_length_public_key
                      << " pk[0..3]=" << _hex4(g_node_keys[idx].pk)
                      << " Com_j[0..3]=" << _hex4(g_dkg.com[r]) << "\n";
    }

    // Phase 2: vk_ZKP = SHA3-512(Com_0 ‖ Com_1 ‖ ... ‖ Com_{N_RSUs-1})
    std::vector<uint8_t> combined(N_RSUs * 64);
    for (uint32_t r = 0; r < N_RSUs; ++r)
        memcpy(combined.data() + r * 64, g_dkg.com[r], 64);
    if (!sha3_512_hash(combined.data(), combined.size(), g_dkg.vk_zkp)) {
        NS_LOG_ERROR("[DKG] vk_ZKP computation failed");
        std::cerr << "[DKG-ERROR] vk_ZKP SHA3-512 failed (n_rsus=" << N_RSUs << ")\n";
        return;
    }
    // Unconditional: vk_ZKP is the root public credential — always show
    std::cout << "[DKG-P2] vk_ZKP = SHA3-512(" << N_RSUs << " Com_j commitments)"
              << " vk_zkp[0..3]=" << _hex4(g_dkg.vk_zkp) << "\n";

    // Phase 3: Real ML-DSA-87 keypairs for all vehicles
    for (uint32_t v = 0; v < N_Vehicles; ++v)
        mldsa87_keygen(v);
    if (CRYPTO_DEBUG_LOG)
        std::cout << "[DKG-P3] " << N_Vehicles << " vehicle ML-DSA-87 keypairs generated"
                  << " (node0 pk[0..3]="
                  << (N_Vehicles > 0 ? _hex4(g_node_keys[0].pk) : "n/a")
                  << ")\n";

    // Phase 4: HMAC pre-shared keys for OBU (vehicle) mode: hmac_key_v = SHA3-512(v ‖ vk_ZKP)
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        uint8_t seed[68];
        memcpy(seed,   &v,            4);
        memcpy(seed+4, g_dkg.vk_zkp, 64);
        sha3_512_hash(seed, 68, g_node_keys[v].hmac_key);
    }
    if (CRYPTO_DEBUG_LOG && N_Vehicles > 0)
        std::cout << "[DKG-P4] HMAC-SHA3-512 keys derived for " << N_Vehicles << " vehicles"
                  << " (v=0 hmac[0..3]=" << _hex4(g_node_keys[0].hmac_key) << ")\n";

    g_dkg.ceremony_done = true;
    g_dkg.last_rotation = ns3::Simulator::Now().GetSeconds();
    bc_commit_dkg(g_dkg.vk_zkp, g_dkg.com, N_RSUs, g_dkg.last_rotation);

    // Unconditional: ceremony completion is a key one-time event
    std::cout << "[DKG] Ceremony COMPLETE: " << N_RSUs << " RSUs + " << N_Vehicles
              << " vehicles keyed | vk_zkp[0..3]=" << _hex4(g_dkg.vk_zkp)
              << " | t=" << g_dkg.last_rotation
              << " | blockchain committed\n";
    NS_LOG_INFO("[DKG] Ceremony complete: " << N_RSUs << " RSUs + "
        << N_Vehicles << " vehicles keyed  vk_zkp[0]=" << (int)g_dkg.vk_zkp[0]);
}

// Triggered by eq:key_rotation_trigger when T_{r_j} < T_min
inline void dkg_rotate_keys(uint32_t revoked_rsu_node_index) {
    std::vector<uint8_t> combined;
    uint32_t rekeyed = 0;
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t idx = N_Vehicles + r;
        if (idx == revoked_rsu_node_index) continue;
        g_node_keys[idx].keys_generated = false;
        mldsa87_keygen(idx);
        sha3_512_hash(g_node_keys[idx].pk,
                      OQS_SIG_ml_dsa_87_length_public_key,
                      g_dkg.com[r]);
        combined.insert(combined.end(), g_dkg.com[r], g_dkg.com[r] + 64);
        ++rekeyed;
        if (CRYPTO_DEBUG_LOG)
            std::cout << "[DKG-ROTATE-P1] RSU r=" << r << " (node=" << idx << ")"
                      << " new pk[0..3]=" << _hex4(g_node_keys[idx].pk)
                      << " new Com_j[0..3]=" << _hex4(g_dkg.com[r]) << "\n";
    }
    if (!combined.empty())
        sha3_512_hash(combined.data(), combined.size(), g_dkg.vk_zkp);
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        g_node_keys[v].keys_generated = false;
        mldsa87_keygen(v);
        // Re-derive HMAC key with updated vk_ZKP (eq:hmac_light: k_v = SHA3-512(v ‖ vk_ZKP))
        uint8_t seed[68];
        memcpy(seed,   &v,            4);
        memcpy(seed+4, g_dkg.vk_zkp, 64);
        sha3_512_hash(seed, 68, g_node_keys[v].hmac_key);
    }
    if (CRYPTO_DEBUG_LOG && N_Vehicles > 0)
        std::cout << "[DKG-ROTATE-P4] HMAC keys re-derived for " << N_Vehicles
                  << " vehicles with new vk_ZKP"
                  << " (v=0 hmac[0..3]=" << _hex4(g_node_keys[0].hmac_key) << ")\n";
    g_dkg.last_rotation = ns3::Simulator::Now().GetSeconds();
    // Pass rekeyed count (excludes revoked RSU) per eq:vk_commit_rotated
    bc_commit_dkg(g_dkg.vk_zkp, g_dkg.com, rekeyed, g_dkg.last_rotation);

    // Unconditional: key rotation is a high-importance security event
    std::cout << "[DKG-ROTATE] Key rotation complete: revoked_rsu=" << revoked_rsu_node_index
              << " rekeyed=" << rekeyed << " RSUs + " << N_Vehicles << " vehicles"
              << " | new vk_zkp[0..3]=" << _hex4(g_dkg.vk_zkp)
              << " | t=" << g_dkg.last_rotation << "\n";
    NS_LOG_INFO("[DKG] Key rotation after RSU " << revoked_rsu_node_index
        << " revocation at t=" << g_dkg.last_rotation);
}

#endif // DKG_SETUP_H
