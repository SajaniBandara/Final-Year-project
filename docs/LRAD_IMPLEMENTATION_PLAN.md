# LRAD Implementation Plan

## Context

The thesis defines a two-stage hierarchical detection engine called **LRAD** (Lightweight Rule-based
Attack Detection). It is the missing glue between the post-quantum crypto layer (ML-DSA-87 + STARK)
and the S1–S8 MOBIGUARD signatures. Without LRAD, the `s*_detection_active` booleans are permanently
`false` and none of S1–S8 ever fire.

This plan covers every file, every function, and every data structure needed.

---

## Architecture

```
Packet arrives at MacRx()
        │
        ├─ node is VEHICLE (node_id < N_Vehicles)?
        │         └─ call lrad_obu()
        │                   ├─ evaluates S1, S2-partial, S3, S4
        │                   ├─ D_OBU = S1 ∨ S2p ∨ S3 ∨ S4
        │                   └─ if D_OBU → escalate_to_rsu() → queues event at nearest RSU
        │
        └─ node is RSU (node_id ≥ N_Vehicles)?
                  └─ call lrad_rsu()  [also triggered by process_escalation_at_rsu()]
                            ├─ reads g_packet_crypto (sig_valid, stark_hop_ok) already set by MacRx
                            ├─ evaluates S2-full, S5, S6, S7, S8
                            ├─ D_RSU = S2f ∨ S5 ∨ S6 ∨ S7 ∨ S8
                            ├─ if D_RSU → BC.Write()
                            └─ if D_RSU → BTMM() (trust penalty + quarantine)
```

**Thesis algorithms implemented here:**
- `alg:lrad_obu` (thesis lines 1983–2027)
- `alg:lrad_rsu` (thesis lines 2035–2086)

---

## Phase 1 — New file: `scratch/lrad.h`

Create a new header `scratch/lrad.h`. Include it in `routing.cc` **after** all detection headers
(`s8_detection.h`) and after `crypto_event_log.h`.

### 1.1 OBU flag struct

```cpp
struct LRADOBUFlags {
    bool flag_S1   = false;  // Selective delay CP: δp > δ̄ + k·σr ∧ HIGH priority
    bool flag_S2p  = false;  // S2-partial: (t_now - ts_recv) > Δmax
    bool flag_S3   = false;  // TCAM exhaustion CP: λ̂a > λthresh ∧ U_TCAM > U_thresh
    bool flag_S4   = false;  // TCAM exhaustion DP: λPI > λPI,thresh ∧ U_TCAM > U_thresh
    bool D_OBU     = false;  // S1 ∨ S2p ∨ S3 ∨ S4
};
```

### 1.2 RSU flag struct

```cpp
struct LRADRSUFlags {
    bool flag_S2f  = false;  // S2-full: STARK delay proof fails
    bool flag_S5   = false;  // Active HF CP: ¬b_batch ∧ FlowMod ∉ BC.Query
    bool flag_S6   = false;  // Active HF DP: ¬b_batch ∧ DUP(msg_id, W)
    bool flag_S7   = false;  // Passive HF CP: vol > εvol ∧ b_hop=0
    bool flag_S8   = false;  // Passive HF DP: b_batch ∧ b_hop=0
    bool D_RSU     = false;  // S2f ∨ S5 ∨ S6 ∨ S7 ∨ S8
};
```

### 1.3 Escalation event struct

```cpp
struct EscalationEvent {
    uint32_t      vehicle_id;
    uint32_t      rsu_id;
    uint32_t      pkt_id;
    uint32_t      flow_id;
    double        t_escalate;
    LRADOBUFlags  obu_flags;
};

// Per-RSU pending escalation queue (flushed by process_escalation_at_rsu)
static std::map<uint32_t, std::vector<EscalationEvent>> g_escalation_queue;
```

### 1.4 Global counters (added to CSV)

```cpp
static uint32_t g_d_obu_count      = 0;
static uint32_t g_d_rsu_count      = 0;
static uint32_t g_escalation_count = 0;
```

Reset these three in `trust_init_all()` between runs.

---

## Phase 2 — Implement `lrad_obu()` (in `lrad.h`)

**Signature:**
```cpp
inline LRADOBUFlags lrad_obu(
    uint32_t vehicle,
    uint32_t pkt_id,
    uint32_t fid,
    bool     is_high_priority,
    double   t_now,
    double   delta_p,        // measured forwarding delay at this hop (seconds)
    double   lambda_obs,     // observed FlowMod rate (from S3 TCAM state)
    double   lambda_PI,      // packet injection rate (from S4 state)
    double   u_tcam          // TCAM utilisation fraction [0,1]
);
```

**Steps:**

| Step | Thesis line | Implementation |
|---|---|---|
| Compute `δ̄ = δ0 + αρ·ρ + αv·v̄⁻¹` | Line 1 | Read `s1_delta0`, `s1_alpha_rho`, `s1_alpha_v`, RSU density / speed state |
| Compute `σr = EWMA(δr, β)` | Line 2 | Read `s1_rsu_obs_sum`, `s1_beta` (existing in s1_detection.h) |
| Compute `λ̂a = λ_obs − E[λl|ρ]` | Line 3 | From existing S3 TCAM rate tracking |
| `flag_S1 = (δp > δ̄ + k·σr) ∧ is_high_priority` | Line 4 | Call existing `s1_detect_packet()` with `s1_detection_active=true` temporarily |
| `flag_S2p = (t_now − ts_recv) > Δmax` | Line 6 | `delta_p > S2_DELTA_MAX` (already computed as `timing_ok` in MacRx) |
| `flag_S3 = (λ̂a > λthresh) ∧ (u_tcam > U_thresh)` | Line 7 | Call existing S3 check |
| `flag_S4 = (λPI > λPI_thresh) ∧ (u_tcam > U_thresh)` | Line 8 | Call existing S4 check |
| `D_OBU = flag_S1 ∨ flag_S2p ∨ flag_S3 ∨ flag_S4` | Line 9 | Combine flags |
| If `D_OBU`: call `escalate_to_rsu(...)` | Line 10 | Schedule with 1 ms NS3 delay |
| Increment `g_d_obu_count` if `D_OBU` | — | Counter update |

**How to enable S1–S4 detectors inside LRAD without changing their guard:**

```cpp
// Temporarily enable detector, call it, restore flag
s1_detection_active = true;
flags.flag_S1 = s1_detect_packet(delta_p, is_high_priority, vehicle);
s1_detection_active = false;
```

Apply the same pattern for S3 and S4.

---

## Phase 3 — Implement `escalate_to_rsu()` (in `lrad.h`)

```cpp
inline void escalate_to_rsu(
    uint32_t vehicle,
    uint32_t pkt_id,
    uint32_t fid,
    LRADOBUFlags obu_flags)
{
    // Find nearest RSU from existing assignment map
    uint32_t rsu_id = rsu_controller_assignment[vehicle];

    EscalationEvent ev;
    ev.vehicle_id = vehicle;
    ev.rsu_id     = rsu_id;
    ev.pkt_id     = pkt_id;
    ev.flow_id    = fid;
    ev.t_escalate = Simulator::Now().GetSeconds();
    ev.obu_flags  = obu_flags;

    g_escalation_queue[rsu_id].push_back(ev);
    g_escalation_count++;

    // Model OBU→RSU escalation latency (~1 ms)
    Simulator::Schedule(Seconds(0.001), &process_escalation_at_rsu, rsu_id);
}
```

**RSU assignment:** Use `rsu_controller_assignment[vehicle]` which already maps each vehicle to its
controller RSU. If that map does not cover all vehicles, fall back to zone-based lookup via
`crypto_zone_id(vehicle)`.

---

## Phase 4 — Implement `process_escalation_at_rsu()` (in `lrad.h`)

```cpp
inline void process_escalation_at_rsu(uint32_t rsu_id)
{
    auto& queue = g_escalation_queue[rsu_id];
    for (auto& ev : queue) {
        lrad_rsu(rsu_id, ev.vehicle_id, ev.pkt_id,
                 ev.flow_id, ev.obu_flags,
                 Simulator::Now().GetSeconds());
    }
    queue.clear();
}
```

---

## Phase 5 — Implement `lrad_rsu()` (in `lrad.h`)

**Signature:**
```cpp
inline LRADRSUFlags lrad_rsu(
    uint32_t     rsu,
    uint32_t     vehicle,       // suspected sender / attacker
    uint32_t     pkt_id,
    uint32_t     fid,
    LRADOBUFlags obu_flags,     // from escalation (may be empty for direct RSU paths)
    double       t_now
);
```

**Steps:**

| Step | Thesis line | Source in existing code |
|---|---|---|
| Look up `auto& meta = g_packet_crypto[{vehicle, pkt_id}]` | — | Populated by `mldsa87_verify()` and `stark_update_meta()` before LRAD is called |
| `flag_S2f = !meta.stark_timing_ok` | Line 1 | `meta.stark_timing_ok` set by `stark_update_meta()` |
| `b_batch = meta.sig_valid` | Lines 2–3 | Per-packet proxy for batch verify result |
| `b_hop = meta.stark_hop_ok` | Line 4 | Set by `stark_update_meta()` |
| `flag_S5 = !b_batch ∧ !bc_query_flowmod(fid)` | Line 5 | `bc_query_flowmod()` from blockchain_sim.h |
| `flag_S6 = !b_batch ∧ s6_dup_check(fid, pkt_id)` | Line 6 | Read `s6_msg_recv_log` (already populated by `s6_log_recv()`) |
| `flag_S7 = volume_check_anomaly(vehicle) ∧ !b_hop` | Line 7 | `volume_check_anomaly()` from crypto_layer.h |
| `flag_S8 = b_batch ∧ !b_hop` | Line 8 | Direct use of `b_batch` and `b_hop` |
| `D_RSU = flag_S2f ∨ flag_S5 ∨ flag_S6 ∨ flag_S7 ∨ flag_S8` | Line 9 | Combine flags |
| If `D_RSU`: `bc_write_event(rsu, vehicle, D_RSU, t_now)` | Line 10 | `bc_write_event()` from blockchain_sim.h |
| If `D_RSU`: `btmm(vehicle, b_batch, b_hop, !flag_S2f)` | Line 11 | See Phase 6 below |
| If `D_RSU`: `record_detection_event(active_attack_variant, vehicle)` | — | Drives `is_detected_node[][]` for CSV |
| Increment `g_d_rsu_count` if `D_RSU` | — | Counter update |

**S5–S8 enablement inside lrad_rsu() (same temporary-flag pattern):**

```cpp
s5_detection_active = true;
flags.flag_S5 = s5_detect(fid, prev_sender, current_hop, pkt_id, base_fid);
s5_detection_active = false;
// ... repeat for S6, S7, S8
```

---

## Phase 6 — Implement `btmm()` (in `lrad.h`)

Replace the current unconditional trust calls in MacRx with a gated version that only fires on
confirmed detection:

```cpp
inline void btmm(uint32_t node, bool b_batch, bool b_hop, bool timing_ok)
{
    if (b_batch && b_hop && timing_ok)
        trust_update_positive(node);
    else {
        trust_update_negative(node);
        // future: write penalty event to blockchain log
    }
}
```

**Remove** the trust update block added earlier in routing.cc (the one at ~line 120940 inside the
`if (sig_ok)` block) — BTMM now lives entirely inside `lrad_rsu()`.

---

## Phase 7 — Wire LRAD into `MacRx()` in `routing.cc`

### 7.1 Insertion point

After the existing ML-DSA-87 verify + STARK block (approximately lines 120909–120935), add the LRAD
dispatcher. The ML-DSA-87 and STARK results are already stored in `g_packet_crypto` by this point,
so `lrad_rsu()` can read them directly.

### 7.2 LRAD dispatcher block

```cpp
// ── LRAD: unified detection engine (alg:lrad_obu / alg:lrad_rsu) ──────────
{
    bool _is_vehicle = (current_hop < (uint32_t)N_Vehicles);
    bool _is_rsu     = (!_is_vehicle &&
                        current_hop < (uint32_t)(N_Vehicles + N_RSUs));
    uint32_t _prev   = tagmodified_routing.Getprevious_senderId();

    if (_is_vehicle) {
        double _delta_p = Now().GetSeconds()
                          - (t_claimed_packet[_prev].count(packet_ID)
                             ? t_claimed_packet[_prev][packet_ID] : 0.0);
        bool _hi_pri = is_safety_critical_flow.count(fid) &&
                       is_safety_critical_flow.at(fid);
        lrad_obu(current_hop, packet_ID, fid, _hi_pri,
                 Now().GetSeconds(), _delta_p,
                 /* lambda_obs */ 0.0,   // replace with actual S3 state
                 /* lambda_PI  */ 0.0,   // replace with actual S4 state
                 /* u_tcam     */ 0.0);  // replace with actual TCAM util
    }

    if (_is_rsu) {
        LRADOBUFlags _empty_obu_flags;
        lrad_rsu(current_hop, _prev, packet_ID, fid,
                 _empty_obu_flags, Now().GetSeconds());
    }
}
// ── END LRAD ──────────────────────────────────────────────────────────────
```

> **Note:** The `lambda_obs`, `lambda_PI`, and `u_tcam` parameters must be filled in with the
> actual state variables from S3/S4 detection headers once those are audited. Use `0.0` as a safe
> placeholder that disables S3/S4 triggering initially.

### 7.3 Remove or comment out the old scattered detection calls

The individual `s5_detect()`, `s6_detect()`, `s7_detect()`, `s8_detect()` calls currently scattered
in MacRx are now called from inside `lrad_rsu()`. To avoid double-firing:

- Remove (or `#if 0`) the old standalone calls from the MacRx body.
- Keep `s6_log_recv()` calls in place — they are logging helpers, not detectors.
- Keep `volume_record_delivery()` call in place — it feeds `volume_check_anomaly()`.

---

## Phase 8 — Add new CSV columns

In `write_security_metrics_csv()` (or equivalent CSV-write function in routing.cc):

**Header:**
```cpp
fout << "...,d_obu_count,d_rsu_count,escalation_count\n";
```

**Data row:**
```cpp
fout << "...,"
     << g_d_obu_count      << ","
     << g_d_rsu_count      << ","
     << g_escalation_count << "\n";
```

Reset in `trust_init_all()`:
```cpp
g_d_obu_count = g_d_rsu_count = g_escalation_count = 0;
```

---

## Phase 9 — Include `lrad.h` in `routing.cc`

Add after the last detection header include (after `s8_detection.h`) and after `crypto_event_log.h`:

```cpp
#include "lrad.h"
```

Order matters: `lrad.h` calls into `s1`–`s8` detection functions and reads `g_packet_crypto`, so it
must come after all of those.

---

## Phase 10 — File change summary

| File | Change |
|---|---|
| `scratch/lrad.h` | **NEW** — all structs, `lrad_obu()`, `lrad_rsu()`, `escalate_to_rsu()`, `process_escalation_at_rsu()`, `btmm()`, counters |
| `scratch/routing.cc` | Add `#include "lrad.h"`; add LRAD dispatcher block in MacRx(); remove old scattered `s*_detect()` calls; remove unconditional trust update; add 3 CSV columns; reset counters in `trust_init_all()` |
| `scratch/crypto_layer.h` | Remove the `trust_update_positive/negative` calls added at ~line 120940 (now inside `btmm()` in lrad.h) |
| `scratch/s1_detection.h` – `s8_detection.h` | No structural changes — LRAD calls them via temporary-flag enable |

---

## Phase 11 — Implementation order

1. Create `lrad.h` with structs and function stubs (compile-only check)
2. Implement `lrad_obu()` — wire S1 and S2p first; leave S3/S4 as `false` stubs
3. Implement `escalate_to_rsu()` + `process_escalation_at_rsu()`
4. Implement `lrad_rsu()` — wire S5, S6, S7, S8
5. Implement `btmm()`, remove old unconditional trust calls from routing.cc
6. Wire LRAD dispatcher into MacRx(); remove old standalone `s*_detect()` calls
7. Add CSV columns and counter resets
8. Build (`./waf build`) — fix any compile errors
9. Run baseline (no attack) — verify `d_obu=0`, `d_rsu=0`, `escalation=0`
10. Run attack sweep — verify D_OBU / D_RSU fire for correct attack variants

---

## Phase 12 — Baseline testing checklist

| Scenario | Attack variant | Expected firing |
|---|---|---|
| Baseline | none | `D_OBU=0`, `D_RSU=0`, `escalation_count=0` |
| Attack 1 (Selective Delay CP) | 0 | `flag_S1=1` at vehicles → D_OBU=1 → escalation |
| Attack 2 (Selective Delay DP) | 1 | `flag_S2p=1` at vehicles → escalation → `flag_S2f=1` at RSU → D_RSU=1 |
| Attack 3 (TCAM CP) | 2 | `flag_S3=1` at vehicles → D_OBU=1 |
| Attack 4 (TCAM DP) | 3 | `flag_S4=1` at vehicles → D_OBU=1 |
| Attack 5 (Active HF CP) | 4 | `flag_S5=1` at RSU → D_RSU=1 |
| Attack 6 (Active HF DP) | 5 | `flag_S6=1` at RSU → D_RSU=1 |
| Attack 7 (Passive HF CP) | 6 | `flag_S7=1` at RSU → D_RSU=1 |
| Attack 8 (Passive HF DP) | 7 | `flag_S8=1` at RSU → D_RSU=1 |

For each attack: confirm `record_detection_event()` fires, confirm `is_detected_node[][]` is set,
confirm detection rate in CSV is > 0.

---

## Known gaps / open questions

| Item | Status |
|---|---|
| S3/S4 TCAM state variables (`lambda_obs`, `lambda_PI`, `u_tcam`) | Need to audit s3/s4 detection headers for the exact variable names before wiring into `lrad_obu()` |
| `bc_query_flowmod(fid)` function signature | Confirm it exists in blockchain_sim.h or stub it |
| `rsu_controller_assignment` map population | Confirm it is populated before first MacRx call |
| `t_claimed_packet[prev][pkt]` availability | Confirm this timestamp map exists and is populated at the correct MacRx site |
| `is_safety_critical_flow` map | Confirm its name and population point |
