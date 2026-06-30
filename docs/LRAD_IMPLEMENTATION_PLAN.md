# LRAD Implementation Plan v2 (Corrected)

## Changelog from v1

This revision fixes every issue found reviewing v1 against the actual current
state of `routing.cc`/`crypto_layer.h`/`blockchain_sim.h`/`s1`–`s8_detection.h`
and against `main__10_.tex` (`alg:lrad_obu` lines 1983–2027, `alg:lrad_rsu`
lines 2035–2086, `eq:composite_light` line 1964, `eq:trust_update` line 3033).

Fixed compile-breaking bugs: `t_claimed_packet`/`is_safety_critical_flow`
treated as maps (they're raw arrays), `s1_detect_packet()` called with 3 args
instead of 7, `g_packet_crypto[{...}]` via `operator[]` instead of `.find()`.

Fixed semantic bugs: `escalate_to_rsu()` using the wrong array for vehicle→RSU
lookup, `bc_write_event()`'s parameters misaligned, `lrad_rsu()`'s signature
missing the second node identity (`current_hop`) that S5–S8 require.

Fixed the regression risk: v1's `btmm()` gated behind `D_RSU` would have made
`trust_update_positive()` unreachable and **undone a fix that is already
correctly in place** in the current codebase (`routing.cc:120942–120948`).
v2 keeps that pattern — unconditional per-packet trust update — instead of
replacing it.

Reconciled v1's self-contradiction in Phase 5 (inline flag reimplementation
vs. calling existing functions) by always calling the real `s5_detect()`
through `s8_detect()`, which already correctly implement guards (like S5's
`d' ∉ P(s,d)` check) that the inline formula omitted.

Added: real wiring for the GATE-1 fix (the `sX_detection_active` switches,
currently hardcoded `false` with no enable path anywhere — confirmed still
true as of this revision). Added a real S2-partial (HMAC-based) implementation
instead of reusing the full-mode STARK timing path. Added a non-mutating,
per-RSU S3/S4 snapshot check instead of calling the cycle-level
`ComputeTcamDetection()` sweep per packet. Added `crypto_event_log.h`
instrumentation for every new LRAD function, matching what's already done for
`sign`/`verify`/`stark_hop`.

The vehicle → associated-RSU lookup is now resolved (was left open in the
first draft of this revision): it's `linklifetimeMatrix_dsrc[][]`
(`vector<vector<double>>`, declared `routing.cc:115872`), the existing DSRC
link-lifetime matrix populated from the Gurobi link-lifetime optimizer
(`d_max_dsrc = 270.0`, `routing.cc:147`) and rebuilt each routing-
optimization cycle (`routing.cc:117908`/`118002`). It's already exactly how
the existing code determines "is vehicle v within DSRC range of RSU r" —
confirmed directly at `routing.cc:117443-117444`. `rsu_controller_assignment[]`
is still **not** it (confirmed RSU-indexed → controller-valued).

---

## Phase 0 — Required confirmations before writing any code

Both open items from earlier drafts are now resolved. No blockers remain.

1. **CSV writer function name — CLOSED.** `write_security_metrics_csv()` is
   confirmed at `routing.cc:117100`. The comment at `routing.cc:143305` reads:
   *"write_security_metrics_csv() now runs inside
   calculate_performance_evaluation_metrics and is called once per
   data-gathering cycle — no post-simulation call needed."* Single call site,
   no duplicate post-sim write. Phase 8 can proceed directly.

2. **Vehicle→RSU lookup — CLOSED (Phase 3).** `linklifetimeMatrix_dsrc[][]`
   confirmed at `routing.cc:115872`.

---

## Architecture (corrected)

```
Packet arrives at MacRx()
        │
        ├─ VEHICLE (node_id < N_Vehicles)?
        │     └─ lrad_obu()
        │           ├─ flag_S1  : s1_detect_packet() against the VEHICLE'S
        │           │             CURRENTLY ASSOCIATED RSU's existing
        │           │             s1_delta_bar[]/s1_sigma2[] state — read
        │           │             directly (simulation shortcut; see Phase 2
        │           │             note), not via a simulated broadcast
        │           ├─ flag_S2p : real HMAC.Verify timestamp recovery
        │           │             (Phase 2.5) — NOT the STARK pipeline
        │           ├─ flag_S3/S4 : lightweight per-RSU snapshot read
        │           │             (Phase 2.6), not the full TCAM sweep
        │           ├─ D_OBU = S1 ∨ S2p ∨ S3 ∨ S4
        │           └─ if D_OBU → escalate_to_rsu()
        │
        └─ RSU (N_Vehicles ≤ node_id < N_Vehicles+N_RSUs)?
              └─ lrad_rsu()  [also invoked by process_escalation_at_rsu()]
                    ├─ calls the REAL s2_detect_packet()/s5_detect()/
                    │   s6_detect()/s7_detect()/s8_detect() — not a
                    │   reimplementation — so existing guards (d'∉P(s,d)
                    │   for S5, the W-windowed DUP check for S6, etc.)
                    │   are preserved, not silently dropped
                    ├─ D_RSU = S2f ∨ S5 ∨ S6 ∨ S7 ∨ S8
                    ├─ btmm() — UNCONDITIONAL per verified packet
                    │   (matches existing routing.cc:120942-948 pattern;
                    │   NOT gated behind D_RSU)
                    └─ if D_RSU → bc_write_event() + record_detection_event()
```

---

## Phase 1 — New file: `scratch/lrad.h`

Include after `s8_detection.h` and after `crypto_event_log.h` (both already
present in `routing.cc`'s include order).

### 1.1 / 1.2 — Flag structs (unchanged from v1, correct as written)

```cpp
struct LRADOBUFlags {
    bool flag_S1  = false;
    bool flag_S2p = false;
    bool flag_S3  = false;
    bool flag_S4  = false;
    bool D_OBU    = false;
};

struct LRADRSUFlags {
    bool flag_S2f = false;
    bool flag_S5  = false;
    bool flag_S6  = false;
    bool flag_S7  = false;
    bool flag_S8  = false;
    bool D_RSU    = false;
};
```

### 1.3 — Escalation event struct (unchanged)

```cpp
struct EscalationEvent {
    uint32_t      vehicle_id;
    uint32_t      rsu_id;
    uint32_t      pkt_id;
    uint32_t      flow_id;
    double        t_escalate;
    LRADOBUFlags  obu_flags;
};
static std::map<uint32_t, std::vector<EscalationEvent>> g_escalation_queue;
```

### 1.4 — Counters (relocated reset — see note)

```cpp
static uint32_t g_d_obu_count      = 0;
static uint32_t g_d_rsu_count      = 0;
static uint32_t g_escalation_count = 0;
```

**Correction from v1:** do *not* reset these inside `trust_init_all()` —
that function is defined in `crypto_layer.h`, which is included *before*
`lrad.h`, so it cannot reference these globals (`lrad.h` doesn't exist yet
at that point in the translation unit). Instead add a small
`lrad_reset_state()` function at the bottom of `lrad.h` and call it
explicitly from `routing.cc`'s init sequence, right after the existing
`trust_init_all()` call.

```cpp
inline void lrad_reset_state() {
    g_d_obu_count = g_d_rsu_count = g_escalation_count = 0;
    g_escalation_queue.clear();
}
```

---

## Phase 2 — `lrad_obu()`

```cpp
inline LRADOBUFlags lrad_obu(
    uint32_t vehicle,
    uint32_t prev_sender,           // previous-hop node — used as sender_node_id in S1
    uint32_t pkt_id,
    uint32_t fid,
    bool     is_high_priority,
    double   t_now,
    double   delta_p,
    uint32_t assoc_rsu_local_idx)   // RSU LOCAL index (0..N_RSUs-1) — see Phase 3
{
    LRADOBUFlags flags;
    auto _t0 = crypto_log_start();

    // ── S1 ───────────────────────────────────────────────────────────────
    // Simulation-appropriate simplification: read the associated RSU's
    // EXISTING baseline/variance state directly rather than modelling an
    // RSU→vehicle broadcast of δ̄_r(t)/σ_r(t). The thesis only requires
    // S1 be computable "without controller coordination" — RSU↔vehicle
    // information sharing is in scope; this is a documented simulation
    // shortcut, not a violation of that constraint. If broadcast latency
    // needs to be modelled later, add it here as an explicit delay rather
    // than changing what data is read.
    //
    // IMPORTANT: pass prev_sender (the forwarding RSU that introduced the
    // delay), NOT vehicle (the receiver). s1_detect_packet() forwards
    // sender_node_id straight into record_detection_event() which sets
    // is_detected_node[][] and t_quarantine[]. Passing the receiver would
    // record a FP against the innocent vehicle and miss the malicious RSU.
    if (assoc_rsu_local_idx < (uint32_t)N_RSUs) {
        flags.flag_S1 = s1_detect_packet(
            assoc_rsu_local_idx, delta_p, is_high_priority,
            prev_sender, vehicle /*current_hop*/, pkt_id, fid);
    }

    // ── S2-partial ───────────────────────────────────────────────────────
    flags.flag_S2p = lrad_s2_partial_check(vehicle, pkt_id, t_now);

    // ── S3 / S4 (lightweight per-RSU snapshot, read-only) ───────────────
    if (assoc_rsu_local_idx < (uint32_t)N_RSUs) {
        uint32_t rsu_node_id = N_Vehicles + assoc_rsu_local_idx;
        LRADTcamSnapshot snap = lrad_tcam_snapshot(rsu_node_id);
        flags.flag_S3 = snap.flag_s3;
        flags.flag_S4 = snap.flag_s4;
    }

    flags.D_OBU = flags.flag_S1 || flags.flag_S2p || flags.flag_S3 || flags.flag_S4;

    crypto_log_event("lrad_obu", vehicle, pkt_id, _t0, flags.D_OBU);

    if (flags.D_OBU) {
        g_d_obu_count++;
        escalate_to_rsu(vehicle, pkt_id, fid, flags);
    }
    return flags;
}
```

**Note on `s1_detection_active`:** do **not** use the v1 "flip true, call,
flip false" pattern. `s1_detect_packet()` already checks
`s1_detection_active` internally; that flag should be set **once**, at
init time, via the GATE-1 fix below — not toggled per call. Toggling it
per call makes it permanently-effectively-on whenever `lrad_obu()` runs,
which defeats the entire purpose of having a switchable flag for ablation
studies.

---

## Phase 2.5 — S2-partial: real HMAC implementation (new in v2)

`hmac_sha3_512()` already exists in `crypto_layer.h` and is fully correct
(verified) — it has simply never been called from anywhere. DKG Phase 4
already derives `g_node_keys[v].hmac_key` for every vehicle. This phase
finally uses both.

```cpp
// τ_i = HMAC-SHA3-512(k_i, msg_id ‖ ts_i ‖ η_i)  — eq:hmac_light
struct HmacTag { uint8_t tag[64]; double ts; uint32_t nonce; bool valid; };
static std::map<std::pair<uint32_t,uint32_t>, HmacTag> g_hmac_tags;

inline void lrad_hmac_tag_packet(uint32_t node, uint32_t pkt_id, uint32_t nonce) {
    if (node >= (uint32_t)N_Vehicles) return; // OBU-mode only
    double ts = ns3::Simulator::Now().GetSeconds();
    uint8_t msg[16];
    memcpy(msg,   &pkt_id, 4);
    memcpy(msg+4, &ts,     8);
    memcpy(msg+12,&nonce,  4);
    HmacTag h{};
    h.ts = ts; h.nonce = nonce;
    h.valid = hmac_sha3_512(g_node_keys[node].hmac_key, 64, msg, 16, h.tag);
    g_hmac_tags[{node, pkt_id}] = h;
}

// flag_S2p = (t_now - ts_recv) > Δ_max, where ts_recv is recovered via
// HMAC verification rather than the STARK/full-mode claimed-timestamp path.
inline bool lrad_s2_partial_check(uint32_t vehicle, uint32_t pkt_id, double t_now) {
    auto it = g_hmac_tags.find({vehicle, pkt_id});
    if (it == g_hmac_tags.end() || !it->second.valid) return false;

    // Recompute and compare the tag (HMAC.Verify) before trusting ts_recv.
    uint8_t msg[16];
    memcpy(msg,   &pkt_id,          4);
    memcpy(msg+4, &it->second.ts,   8);
    memcpy(msg+12,&it->second.nonce,4);
    uint8_t recomputed[64];
    if (!hmac_sha3_512(g_node_keys[vehicle].hmac_key, 64, msg, 16, recomputed))
        return false;
    if (memcmp(recomputed, it->second.tag, 64) != 0) return false; // tag invalid

    return (t_now - it->second.ts) > S2_DELTA_MAX;
}
```

`lrad_hmac_tag_packet()` needs to be called at packet-send time (mirroring
where `record_claimed_forward_timestamp()` is already called) — add that
call site alongside it in the existing send path, OBU-side only.

---

## Phase 2.6 — Lightweight S3/S4 snapshot (new in v2, replaces v1's `0.0` placeholders)

`ComputeTcamDetection()` is a full cycle-level sweep across **all** RSUs
that also **mutates** `g_prev_rule_count[]`/`g_prev_slowpath_hits[]` as a
side effect — calling it per packet would be both a performance problem and
would corrupt the baseline counters the periodic metrics cycle depends on.
This is a **read-only**, single-RSU snapshot using the same underlying
state, declared in `lrad.h` (needs `tcam_detection.h` included first):

```cpp
struct LRADTcamSnapshot { bool flag_s3; bool flag_s4; };

inline LRADTcamSnapshot lrad_tcam_snapshot(uint32_t rsu_node_id) {
    LRADTcamSnapshot snap{false, false};
    if (rsu_node_id >= 300) return snap;

    double tcam_util = g_tcam_rule_count[rsu_node_id] / (double)TCAM_HW_SIZE;
    tcam_util = std::min(1.0, std::max(0.0, tcam_util));

    // Use the SAME baseline counters ComputeTcamDetection() owns, but do
    // NOT advance them here — only the periodic cycle function does that.
    int rules_since_baseline = g_tcam_rule_count[rsu_node_id] - g_prev_rule_count[rsu_node_id];
    int hits_since_baseline  = g_slowpath_hit_count[rsu_node_id] - g_prev_slowpath_hits[rsu_node_id];
    double lambda_fm = (rules_since_baseline > 0) ? (double)rules_since_baseline : 0.0;
    double lambda_pi = (hits_since_baseline  > 0) ? (double)hits_since_baseline  : 0.0;

    int malicious_count = 0;
    for (const auto& e : g_tcam_table)
        if (e.node_id == rsu_node_id && e.is_malicious) ++malicious_count;

    double E_lambda_l   = 0.8 + 1.2 * ((double)N_Vehicles / (double)N_Vehicles); // ρ(t) snapshot — see note
    double lambda_hat_a = lambda_fm - E_lambda_l;

    snap.flag_s3 = (lambda_hat_a > 10.0) && (malicious_count > 0);   // λ_thresh = 10.0, matches ComputeTcamDetection's call site
    snap.flag_s4 = (lambda_pi > 15.0) && (tcam_util > 0.80);         // matches existing thresholds
    return snap;
}
```

**Note:** the `ρ(t)` (vehicle density) term needs the same live density value
`ComputeTcamDetection()` is called with at its existing call site
(`routing.cc:117171`, currently `(double)N_Vehicles` as a placeholder for
"active vehicles" — confirm whether a real per-cycle density value is
available and use it here for consistency with the cycle-level numbers).

---

## Phase 3 — `escalate_to_rsu()` (corrected)

```cpp
// Returns RSU local index (0..N_RSUs-1), or N_RSUs as a sentinel meaning
// "no RSU currently within DSRC range." Reuses linklifetimeMatrix_dsrc[][]
// (routing.cc:115872), the same matrix the routing engine already uses to
// determine in-range links, rather than rsu_controller_assignment[] (which
// is RSU-indexed and controller-valued — wrong on both axes for this).
// Picks the RSU with the longest current lifetime as the "nearest/
// strongest-linked" proxy, consistent with how link_lifetime_threshold is
// already used elsewhere (e.g. routing.cc:116254) to gate weak links.
inline uint32_t lookup_vehicle_associated_rsu_local_idx(uint32_t vehicle) {
    uint32_t best_local_idx = N_RSUs; // sentinel: "none in range"
    double   best_lifetime  = 0.0;
    if (vehicle >= linklifetimeMatrix_dsrc.size()) return best_local_idx;

    for (uint32_t r = 0; r < N_RSUs; ++r) {
        uint32_t rsu_node_id = N_Vehicles + r;
        if (rsu_node_id < linklifetimeMatrix_dsrc[vehicle].size() &&
            linklifetimeMatrix_dsrc[vehicle][rsu_node_id] > link_lifetime_threshold &&
            linklifetimeMatrix_dsrc[vehicle][rsu_node_id] > best_lifetime)
        {
            best_lifetime  = linklifetimeMatrix_dsrc[vehicle][rsu_node_id];
            best_local_idx = r;
        }
    }
    return best_local_idx;
}

inline void escalate_to_rsu(
    uint32_t vehicle, uint32_t pkt_id, uint32_t fid, LRADOBUFlags obu_flags)
{
    auto _t0 = crypto_log_start();

    uint32_t rsu_local_idx = lookup_vehicle_associated_rsu_local_idx(vehicle);
    if (rsu_local_idx >= (uint32_t)N_RSUs) {
        // No RSU currently in DSRC range — a real, valid state (vehicle
        // between coverage zones), not an error. Drop rather than escalate
        // to a garbage index.
        crypto_log_event("escalate_to_rsu", vehicle, pkt_id, _t0, false);
        return;
    }
    uint32_t rsu_id = N_Vehicles + rsu_local_idx;

    EscalationEvent ev;
    ev.vehicle_id = vehicle; ev.rsu_id = rsu_id; ev.pkt_id = pkt_id;
    ev.flow_id = fid; ev.t_escalate = ns3::Simulator::Now().GetSeconds();
    ev.obu_flags = obu_flags;

    g_escalation_queue[rsu_id].push_back(ev);
    g_escalation_count++;
    crypto_log_event("escalate_to_rsu", vehicle, pkt_id, _t0, true);

    ns3::Simulator::Schedule(ns3::Seconds(0.001), &process_escalation_at_rsu, rsu_id);
}
```

**Timing note (carried over from the earlier timing-correctness review):**
if multiple escalations to the same RSU happen within the 1 ms window, the
*first* scheduled `process_escalation_at_rsu()` call will drain the whole
queue, including events that haven't reached their own individual 1 ms mark
yet. That's acceptable for now (every event still gets processed exactly
once) but means "1 ms escalation latency" is an upper bound, not a per-event
guarantee — worth a one-line comment in the code so nobody later treats it
as exact in a latency measurement.

---

## Phase 4 — `process_escalation_at_rsu()` (unchanged from v1, correct as written)

```cpp
inline void process_escalation_at_rsu(uint32_t rsu_id)
{
    auto& queue = g_escalation_queue[rsu_id];
    for (auto& ev : queue)
        lrad_rsu(rsu_id, ev.vehicle_id, ev.pkt_id, ev.flow_id,
                 ev.obu_flags, ns3::Simulator::Now().GetSeconds());
    queue.clear();
}
```

---

## Phase 5 — `lrad_rsu()` (corrected)

**Corrected signature** — needs both node identities (matching what
`s5_detect()`–`s8_detect()` actually require), not the single collapsed
`vehicle` parameter from v1:

```cpp
inline LRADRSUFlags lrad_rsu(
    uint32_t     rsu,            // current_hop / eavesdropper / receiving RSU
    uint32_t     prev_sender,    // the suspected sending node
    uint32_t     pkt_id,
    uint32_t     fid,
    LRADOBUFlags obu_flags,
    double       t_now)
{
    LRADRSUFlags flags;
    auto _t0 = crypto_log_start();

    // CORRECTED: .find(), not operator[] — avoids silently default-
    // constructing a "verification failed" entry for packets that were
    // never actually signed/verified.
    auto it = g_packet_crypto.find({prev_sender, pkt_id});
    bool have_crypto = (it != g_packet_crypto.end() && it->second.sig_len > 0);

    // S2-full: call the REAL function, do not reimplement.
    flags.flag_S2f = s2_detect_packet(prev_sender, t_now,
                                       is_safety_critical_flow[fid],
                                       rsu, pkt_id, fid);

    // S5-S8: call the REAL functions — preserves d'∉P(s,d) for S5, the
    // W-windowed DUP check for S6, the volume-window + corroborating
    // volume_check_anomaly() OR for S7, etc. recv_flow_id is approximated
    // as fid here since LRAD doesn't carry the raw tagged flow id with the
    // 0xDEAD0000 marker through escalation — fine, since these functions
    // already prefer the real g_packet_crypto evidence over the marker
    // whenever a crypto record exists (confirmed in the current code).
    uint32_t base_fid = fid & 0xFFFFu;
    flags.flag_S5 = s5_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S6 = s6_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S7 = s7_detect(fid, prev_sender, rsu, pkt_id, base_fid);
    flags.flag_S8 = s8_detect(fid, prev_sender, rsu, pkt_id, base_fid);

    flags.D_RSU = flags.flag_S2f || flags.flag_S5 || flags.flag_S6 ||
                  flags.flag_S7 || flags.flag_S8;

    // btmm() — CORRECTED: unconditional, matching the pattern already
    // correctly in place at routing.cc:120942-948. Do NOT gate behind
    // D_RSU (that makes the positive branch unreachable — see Changelog).
    if (have_crypto)
        btmm(prev_sender, it->second.sig_valid, it->second.stark_hop_ok,
             !flags.flag_S2f /* timing_ok */);

    if (flags.D_RSU) {
        g_d_rsu_count++;
        // CORRECTED parameter order: (rsu_idx, event_type, node, ts).
        // event_type 6 = "lrad_composite_detection" (new code; document
        // alongside the existing 2=da,3=T_ref,4=nfa,5=model convention).
        bc_write_event(rsu, /*event_type=*/6, prev_sender, t_now);
        // record_detection_event() is already called internally by
        // whichever of s2_detect_packet/s5_detect/.../s8_detect fired —
        // do NOT call it again here, that would double-count.
    }

    crypto_log_event("lrad_rsu", prev_sender, pkt_id, _t0, flags.D_RSU);
    return flags;
}
```

**Important correction from v1:** the individual `s2_detect_packet()`/
`s5_detect()`–`s8_detect()` calls already call `record_detection_event()`
themselves on a positive trigger (confirmed in the current source). v1's
plan to *also* call it again from `lrad_rsu()` would double-record the same
event. Removed.

**Also corrected:** v1 invented `s6_dup_check()`, which doesn't exist —
not needed, since `s6_detect()` already does that check internally and is
now called directly instead of being reimplemented.

**GATE-1, properly fixed (replaces v1's temporary-flag hack):**
`s5_detection_active`...`s8_detection_active` and `s1_detection_active`/
`s2_detection_active` should be set **once**, at init time, not toggled per
call. Two changes needed:

1. In `declare_attack_states()` (`attack_declaration.h`), add cases tying
   each flag to its corresponding `attack_number`, mirroring how TCAM
   detection is already gated by `active_attack_variant`:
   ```cpp
   case (1): present_selective_delay_cp_attack = true; active_attack_variant = 0;
             s1_detection_active = true; break;
   case (2): present_selective_delay_attack_nodes = true; active_attack_variant = 1;
             s2_detection_active = true; break;
   // ... case 5 -> s5_detection_active = true; etc. for 6,7,8
   ```
2. Additionally expose each as a CLI override in `crypto_register_cli_params()`
   so a researcher can run e.g. `--attack_number=5 --s5_detection_active=0`
   for an ablation study (measuring detection contribution per signature)
   without editing source.

---

## Phase 6 — `btmm()` (corrected)

```cpp
inline void btmm(uint32_t node, bool b_batch, bool b_hop, bool timing_ok)
{
    if (b_batch && b_hop && timing_ok)
        trust_update_positive(node);
    else
        trust_update_negative(node);
}
```

This matches the logic already correctly running at `routing.cc:120942–948`.
**Do not remove that existing block per v1's Phase 6 instruction** — either
leave it exactly as-is (simplest, zero risk), or if architectural
consistency is wanted, replace it with a call to `btmm()` at that exact
spot, called unconditionally inside the existing `if (sig_ok)` block,
**not** moved into `lrad_rsu()` behind `D_RSU`.

**Known remaining gap, not introduced by this plan:** the existing
`if (sig_ok)` gate conflates "this packet wasn't addressed to me" (broadcast
noise, correctly skipped) with "this packet was addressed to me and the
signature is invalid" (a real failure that should penalize trust per
`eq:trust_update`'s `BatchVerify=0` branch, currently doesn't). Fixing this
needs `mldsa87_verify()` to expose that distinction to its caller — out of
scope for LRAD itself, but worth a follow-up ticket.

---

## Phase 7 — Wire into `MacRx()`

### 7.1 Insertion point

Same as v1 — after the existing ML-DSA-87 verify + STARK block
(`routing.cc:120917–120951`). **Leave that block in place** (Phase 6 above).

### 7.2 Dispatcher (corrected)

```cpp
// ── LRAD: unified detection engine (alg:lrad_obu / alg:lrad_rsu) ──────────
{
    bool _is_vehicle = (current_hop < (uint32_t)N_Vehicles);
    bool _is_rsu     = (!_is_vehicle && current_hop < (uint32_t)(N_Vehicles + N_RSUs));
    uint32_t _prev   = tagmodified_routing.Getprevious_senderId();

    if (_is_vehicle) {
        // CORRECTED: raw array indexing, not .count()/.at() — neither
        // t_claimed_packet nor is_safety_critical_flow is a map.
        double _t_claimed = (_prev < (uint32_t)total_size && packet_ID < (uint32_t)(Flow_size+2))
                             ? t_claimed_packet[_prev][packet_ID] : 0.0;
        double _delta_p = (_t_claimed > 0.0) ? (Now().GetSeconds() - _t_claimed) : 0.0;
        bool   _hi_pri  = is_safety_critical_flow[fid];

        uint32_t _assoc_rsu = lookup_vehicle_associated_rsu_local_idx(current_hop); // Phase 3

        lrad_obu(current_hop, _prev, packet_ID, fid, _hi_pri,
                 Now().GetSeconds(), _delta_p, _assoc_rsu);
    }

    if (_is_rsu) {
        LRADOBUFlags _empty_obu_flags;
        lrad_rsu(current_hop, _prev, packet_ID, fid,
                 _empty_obu_flags, Now().GetSeconds());
    }
}
// ── END LRAD ──────────────────────────────────────────────────────────────
```

### 7.3 Removing old standalone calls

v1 only mentioned removing S5–S8's old standalone calls and missed S1/S2.
**Corrected list:** once `lrad_rsu()` calls `s2_detect_packet()`/`s5_detect()`
.../`s8_detect()` internally, remove **all six** of their old standalone
call sites in `MacRx()` (S1's existing RSU-only call site, S2's existing
call site at `routing.cc:120908–120914`, S5 at `routing.cc:120879`,
S6 at `120881`, S7 at `120833`, S8 at `120834`) — leaving both in place
would double-fire and double-count every one of these signatures, not just S5–S8.

Keep in place (logging helpers, not detectors, as v1 correctly noted):
`s6_log_recv()`, `volume_record_delivery()`, and the new
`lrad_hmac_tag_packet()` call site added in Phase 2.5.

---

## Phase 8 — CSV columns (Phase 0 confirmed: target is `write_security_metrics_csv()` at routing.cc:117100)

```cpp
fout << "...,d_obu_count,d_rsu_count,escalation_count\n";
...
fout << "..." << g_d_obu_count << "," << g_d_rsu_count << "," << g_escalation_count << "\n";
```

Reset via `lrad_reset_state()` (Phase 1.4), not `trust_init_all()`.

---

## Phase 9 — Includes

```cpp
#include "lrad.h"   // after s8_detection.h; crypto_event_log.h already included above
```

---

## Phase 10 — File change summary (corrected)

| File | Change |
|---|---|
| `scratch/lrad.h` | **NEW** — structs, `lrad_obu()`, `lrad_rsu()`, `escalate_to_rsu()`, `process_escalation_at_rsu()`, `btmm()`, `lrad_hmac_tag_packet()`/`lrad_s2_partial_check()`, `lrad_tcam_snapshot()`, `lrad_reset_state()`, counters |
| `scratch/routing.cc` | Add `#include "lrad.h"`; add LRAD dispatcher in `MacRx()`; remove **all six** old standalone `s1`/`s2`/`s5`–`s8` detect call sites (S1@~120987, S2@120908–120914, S5@120879, S6@120881, S7@120833, S8@120834); add `lrad_hmac_tag_packet()` call at send time; add 3 CSV columns; call `lrad_reset_state()` after `trust_init_all()`. Existing trust-update block at ~120942–948 stays, untouched or relocated into `btmm()` called from the same spot — never moved behind `D_RSU`. |
| `attack_declaration.h` | Add `sX_detection_active = true` cases to `declare_attack_states()`, tied to `attack_number` (GATE-1 fix). |
| `crypto_layer.h` | Add CLI overrides for the 6 detection-active flags in `crypto_register_cli_params()`. No change to existing trust-update logic. |
| `s1`–`s8_detection.h` | **No structural changes** — called directly with real parameters now, not reimplemented or temporarily-flag-toggled. |
| `tcam_detection.h` | No change — `ComputeTcamDetection()` stays as the periodic cycle-level function; `lrad_tcam_snapshot()` in `lrad.h` is a separate read-only path over the same globals. |

---

## Phase 11 — Implementation order (revised)

1. GATE-1 fix (`declare_attack_states()` + CLI overrides) — do this **first**, independent of the rest, so S1/S2/S5–S8 are at least reachable for testing immediately.
3. `lrad.h` skeleton (structs, `lrad_reset_state()`) — compile-only check.
4. Phase 2.5 (HMAC/S2-partial) and Phase 2.6 (TCAM snapshot) — these are self-contained and testable in isolation before touching `MacRx()`.
5. `lrad_obu()`, `escalate_to_rsu()`, `process_escalation_at_rsu()`.
6. `lrad_rsu()`, `btmm()` (verify against the existing `routing.cc:120942–948` pattern, do not regress it).
7. Wire dispatcher into `MacRx()`; remove all six old standalone detect calls (S1, S2, S5–S8).
8. CSV columns.
9. Build, fix compile errors.
10. Baseline run (no attack): confirm `d_obu=0`, `d_rsu=0`, `escalation_count=0`, and confirm average trust score stays near 1.0 over the run (regression check on the already-working trust loop).
11. Attack sweep (Phase 12 below).

---

## Phase 12 — Baseline testing checklist (corrected)

| Scenario | Attack variant | Expected firing |
|---|---|---|
| Baseline | none | `D_OBU=0`, `D_RSU=0`, `escalation_count=0`, mean trust ≈ 1.0 |
| Attack 1 (Selective Delay CP) | 0 | `flag_S1=1` at vehicles → `D_OBU=1` → escalation |
| Attack 2 (Selective Delay DP) | 1 | `flag_S2p=1` (HMAC path) at vehicles → escalation → `flag_S2f=1` (STARK path) at RSU → `D_RSU=1` |
| Attack 3 (TCAM CP) | 2 | `flag_S3=1` via `lrad_tcam_snapshot()` at vehicles → `D_OBU=1` |
| Attack 4 (TCAM DP) | 3 | `flag_S4=1` via `lrad_tcam_snapshot()` → `D_OBU=1` |
| Attack 5 (Active HF CP) | 4 | `flag_S5=1` at RSU (via real `s5_detect()`) → `D_RSU=1`. **Note:** still depends on `bc_query_flowmod()`'s underlying FlowMod pipeline being fixed (blockchain teammate's item) for full equation fidelity — `s5_detect()` will still fire correctly via its ground-truth gate + crypto evidence in the meantime. |
| Attack 6 (Active HF DP) | 5 | `flag_S6=1` → `D_RSU=1` |
| Attack 7 (Passive HF CP) | 6 | `flag_S7=1` → `D_RSU=1` |
| Attack 8 (Passive HF DP) | 7 | `flag_S8=1` → `D_RSU=1` |

For each: confirm `record_detection_event()` fires exactly once per
detection (not twice — see Phase 5's double-count fix), confirm
`is_detected_node[][]` is set, confirm `crypto_timing_log.csv` shows
`lrad_obu`/`lrad_rsu`/`escalate_to_rsu` entries with sane `wall_us` values,
and confirm detection latency (`t_detection - t_attack_event`, computable
from that CSV) is bounded by roughly one `escalate_to_rsu` cycle (~1 ms) for
OBU-tier signatures plus whatever the RSU-tier evaluation costs.

---

## Known gaps / open questions (trimmed to genuinely open items)

| Item | Status |
|---|---|
| CSV writer function name (Phase 0) | **CLOSED.** Confirmed `write_security_metrics_csv()` at routing.cc:117100, single call site per cycle per routing.cc:143305. |
| `bc_query_flowmod(fid)`'s underlying data | Still depends on the blockchain teammate's fix to the FlowMod-endorsement pipeline (the `fid=0` stub) for full fidelity on S5/S3 — not blocking LRAD itself, since `s5_detect()` still fires via its other conjuncts in the meantime. |
| `sig_ok=false` not penalizing trust (real failures vs. broadcast noise) | Pre-existing gap in `mldsa87_verify()`'s caller contract, independent of LRAD — flag separately. |
| ρ(t) density value passed into `lrad_tcam_snapshot()` | Currently mirrors the existing placeholder at `ComputeTcamDetection()`'s call site (`routing.cc:117171`); replace both together if/when a real per-cycle density value becomes available. |