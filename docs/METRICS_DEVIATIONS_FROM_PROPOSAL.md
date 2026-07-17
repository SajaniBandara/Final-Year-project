# Performance Metrics — Deviations From Proposal (Fresh Audit)
**Date:** 2026-07-07
**Scope:** Independent re-verification of all 12 performance metrics (docs/main.tex §4.6) against
the current state of the codebase (scratch/routing.cc, scratch/crypto_layer.h,
scratch/bc_blockchain_helper.h, lstm_pipeline/src/). This audit re-checks both pre-existing code and
everything implemented earlier in this session (M5, M7, M8, M9, M11, M12), specifically hunting for
bugs, silent wiring gaps, and deviations that a status-tracking summary (docs/METRICS_VERIFICATION_REPORT.md)
would not surface on its own.

**This file supersedes METRICS_VERIFICATION_REPORT.md's correctness claims wherever they conflict.**
The other report tracked *implementation progress*; this one re-verifies *actual runtime behavior*.

---

## Critical Finding: M2 (TVR) is non-functional — counters are never incremented — FIXED (2026-07-07)

**Severity: Critical. Pre-existing bug, not introduced this session, not caught by the earlier report.**

**Fix applied:** added the increment site at `routing.cc`, immediately after `timing_ok` is computed
(same location `S2_DELTA_MAX` is already checked for S2 detection):
```cpp
if (is_safety_critical_flow[fid] &&
    current_hop >= (uint32_t)N_Vehicles &&
    current_hop <  (uint32_t)(N_Vehicles + N_RSUs) &&
    t_fwd_claimed > 0.0) {
    g_tvr_crit_total++;
    if (!timing_ok) g_tvr_violated++;
}
```
Scoped to safety-critical flows, at RSU receive points, only when a claimed forward timestamp
exists. The "never forwarded → δ_p=∞" sub-case (eq:nfwd_detect) is deliberately **not** folded into
this fix — it remains a separate, still-open enhancement (see the open-items list below) rather than
risk conflating two different semantics in one change. Runs unconditionally (not gated on `sig_ok`)
since TVR measures delay, not signature validity. **Build verification pending.**

`calculate_tvr_metric()` (routing.cc) reads two counters:

```cpp
uint64_t g_tvr_crit_total  = 0;   // distinct safety-critical RSU-hop observations
uint64_t g_tvr_violated    = 0;   // of those: hop_delay > Δ_max (S2_DELTA_MAX)
...
void calculate_tvr_metric() {
    double denom = (g_tvr_crit_total > 0) ? (double)g_tvr_crit_total : 1.0;
    current_TVR = (double)g_tvr_violated / denom;
    ...
}
```

**Neither `g_tvr_crit_total` nor `g_tvr_violated` is ever incremented anywhere in the codebase.**
Verified with an exhaustive search (`g_tvr_crit_total++`, `g_tvr_violated++`, `+=` on either name) —
zero matches outside their declaration and the read-only `calculate_tvr_metric()` function itself.
Both stay at their zero-initialized value for the entire simulation.

**Consequence:** `current_TVR` is **always exactly 0** (`0 / 1.0`), regardless of attack intensity,
attack variant, or whether Selective Time Delay Variants 1–4 are active at all. The comment above the
declaration (`routing.cc:114663-114667`) claims "Counters ... are incremented inside MacRx at every
RSU receive point (see TVR block above)" — **no such increment site exists anywhere in the file.**
This is either a stale comment describing intended-but-never-implemented behavior, or the increment
code was removed at some point without updating the comment.

**Why the earlier METRICS_VERIFICATION_REPORT.md missed this:** that report's Step 1 fix added
`cur_TVR, avg_TVR` to the CSV header/row and confirmed the *computation function* runs and the
*column exists*. It never checked whether the inputs to that computation were themselves populated.
Exporting a metric that always evaluates to zero does not fix it — it just makes the zero visible.

**The raw ingredients for a correct fix already exist** — they are just never connected:
- `is_safety_critical_flow[fid]` (HIGH-priority packet flag) — already read elsewhere
  (`routing.cc:121228`, LRAD-OBU block: `bool _hi_pri = is_safety_critical_flow[fid];`)
- Per-hop delay vs. `S2_DELTA_MAX` (50 ms) comparison — already computed at every RSU receive point
  (`routing.cc:121239`: `bool timing_ok = ... <= S2_DELTA_MAX;`), but this result feeds S2 detection
  and STARK/trust bookkeeping only — it is never used to increment `g_tvr_crit_total`/`g_tvr_violated`.

**Fix scope:** at the same site that computes `timing_ok` (routing.cc:121239, inside the RSU receive
path), for HIGH-priority packets: `g_tvr_crit_total++;` always, and `if (!timing_ok) g_tvr_violated++;`.
This is a small, contained fix — the hard part (identifying the correct hook point and threshold) is
already done by the existing S2 timing check; TVR just never tapped into it.

**Impact on evaluation:** every M2 result in every table this project has produced or will produce
from the current codebase (Tables 5.1–5.5 in the proposal's evaluation plan) reads **0% TVR across
every run, every variant, every attack percentage** — the metric carries no information until fixed.

---

## High: M5 (Controller Failover Latency) — `g_failover_max_ms` reset race under overlapping revocations — FIXED (2026-07-07)

**Severity: High. Introduced this session (M5 implementation). Affects specifically the "2
compromised controllers" scenario the proposal explicitly requires evaluating (main.tex M5:
"Evaluated across 0, 1, and 2 compromised controller scenarios").**

**Fix applied:** removed the `g_failover_max_ms = 0.0;` per-event reset inside `ctrl_reassign_rsus()`.
`g_failover_max_ms` is now a monotonic running max across the entire simulation — it only ever grows,
never resets mid-run — so overlapping revocation events can no longer clobber each other's
in-flight latency measurements. This reports "the worst L_failover observed by any revocation event
so far in the run" instead of "the most recent event's max," which trades a small amount of
per-event granularity for eliminating the race entirely; it still directly answers the proposal's
target-bound question (does L_failover stay ≤ 100 ms across every event in the run). The one-time,
full-run reset at simulation start (inside `trust_init_all()`) is untouched. **Build verification
pending.**

```cpp
inline void ctrl_reassign_rsus(uint32_t revoked_ctrl) {
    ...
    double t_revoke = ns3::Simulator::Now().GetSeconds();
    g_failover_max_ms = 0.0;      // <-- resets on EVERY revocation event
    ++g_failover_events;
    ...
    for (uint32_t r = 0; r < N_RSUs; ++r) {
        ...
        ns3::Simulator::Schedule(ns3::Seconds(delay_ms / 1000.0),
                                 &ctrl_complete_rsu_reassign,
                                 r, best, revoked_ctrl, t_revoke);
    }
}
```

`ctrl_reassign_rsus()` is called from `ctrl_trust_update_negative()` every time **any** controller's
trust score crosses `TRUST_T_MIN_CTRL`. If a second controller is revoked while RSU-reassignment
completions from a **first, still-in-flight** revocation are pending (a realistic scenario: broadcast
completion delay defaults to only 10 ms base + 1 ms/zone, so any two revocations within tens of
milliseconds of each other overlap):

1. Controller A revoked at `t_revoke=T1`. `g_failover_max_ms` reset to 0. N completions scheduled
   with closure-captured `t_revoke=T1`.
2. Some of A's completions fire, correctly updating `g_failover_max_ms` relative to `T1`.
3. Controller B revoked at `t_revoke=T2` (before all of A's completions have fired).
   `g_failover_max_ms` is **reset to 0 again**, discarding A's already-recorded latencies.
4. A's remaining pending completions still fire using their captured `T1` — they compute
   `lat_ms = now - T1` (correctly, for A), but this now updates a `g_failover_max_ms` that was reset
   for B's event, mixing two unrelated revocation events' latencies into one "max" value.

**Consequence:** in exactly the scenario the proposal calls out by name (2 compromised controllers),
`ctrl_failover_max_ms` in the CSV can under- or over-report the true worst-case latency for either
event, depending on interleaving timing. The metric is not simply "noisy" — it is **structurally
wrong** whenever two revocations overlap in time, which is the realistic case this scenario is
designed to stress.

This per-event-reset design is fundamentally incompatible with concurrent revocations — see "Fix
applied" above for the resolution (monotonic running max, never reset mid-run).

---

## Medium: M11 (UFCR) injection pollutes M7's `rsu_chain_len` when endorsement is disabled — FIXED (2026-07-07)

**Severity: Medium. Introduced this session (M11 implementation). Cross-metric contamination, not a
standalone correctness bug in M11 itself.**

**Fix applied:** `ufcr_attempt_unauthorized_flowmod()` now records `g_rsu_commit_hashes.size()`
immediately before calling `bc_commit_flowmod()`, and if the call succeeded *and* actually grew the
chain, pops that one entry back off:
```cpp
size_t chain_len_before = g_rsu_commit_hashes.size();
bool committed = bc_commit_flowmod(fake_e);
if (committed && g_rsu_commit_hashes.size() > chain_len_before)
    g_rsu_commit_hashes.pop_back();
```
This surgically undoes only the side effect of the synthetic injection, without touching
`bc_commit_flowmod()` itself — the legitimate per-cycle FlowMod path (`transmit_delta_values()`) is
completely unaffected, since it's a separate call site with its own (real) `FlowModEndorsement`.
`rsu_chain_len` now reflects only genuine FlowMod traffic in both AB8-A and AB8-B runs, making M7
comparable across both endorsement configurations. **Build verification pending.**

**Root cause (before the fix):** `ufcr_attempt_unauthorized_flowmod()` calls `bc_commit_flowmod(fake_e)`
once per second while a control-plane variant is active. When `enable_endorsement_requirement=false`
(AB8-A), this call **succeeds** (by design — that is what UFCR is measuring) and, as a side effect of
`bc_commit_flowmod()`'s existing logic, pushed a hash onto the shared `g_rsu_commit_hashes` vector —
the same vector `write_security_metrics_csv()` reports as `rsu_chain_len` for M7's consensus-overhead
tracking, inflating it by ~1/second beyond legitimate FlowMod traffic and making AB8-A/AB8-B runs of
the same attack variant not directly comparable on that column. The fix above eliminates this.

---

## Low: `fed_aggregator.py` Krum filter rejects a lone eligible RSU (boundary edge case) — FIXED (2026-07-07)

**Severity: Low. Introduced this session (M8 implementation). Only manifests at very small RSU
counts (K≤2 after trust-gating), never triggered by the proposal's actual 64-RSU configuration.**

**Fix applied:** `krum_filter()` now guards `len(flat_weights) < 2` at the top and auto-accepts the
sole candidate (mask=`[True]`) rather than computing a degenerate `gamma=0` threshold that would
reject it. Krum's geometric-outlier test is mathematically undefined with fewer than 2 points — there
is nothing to compare a single model against — so auto-accepting is the correct behavior, not a
weakening of the filter. **Syntax-checked; end-to-end pipeline run still pending** (same as the rest
of M8).

`krum_filter()` computes `gamma = median(dists) + gamma_factor * dists.std()`. If exactly one RSU
survives the trust gate (Step 1) and is passed into `krum_filter()` alone, its distance to "the
median" (of a single-element set) is trivially `0`, so `dists.std() == 0` and `gamma == 0`. The
mask condition `dists < gamma` then evaluates `0 < 0 == False` — **the sole eligible RSU is rejected
by its own Krum filter**, even though it was the only honest participant.

**Consequence (before the fix):** in a degenerate scenario with very few total RSUs and aggressive
trust-gating (not the paper's actual 64-RSU setup, but reachable in a small synthetic smoke test),
`run_aggregation()` would have silently produced a global model aggregated from **zero** accepted
RSUs (`weighted_fedavg` with an all-`False` mask divides by `total=0`), raising a `ZeroDivisionError`
rather than a clear diagnostic. The guard described above eliminates this path entirely.

---

## New Feature: Real `T_ref(t)` clock-skew anchoring for M2/M6 (eq:delay_updated, eq:time_consensus) — IMPLEMENTED (2026-07-07)

**Not a bug fix — a genuine capability addition.** During this audit it was found that the codebase's
existing "T_ref anchoring" pattern (used in LRAD-OBU's S1 delay computation) was **mathematically a
no-op**: `(Now() − g_T_ref) − (t_claimed − g_T_ref)` cancels `g_T_ref` algebraically, producing the
identical value as `Now() − t_claimed` with no correction at all. The reason: every node in this
simulation reads the same single global `Simulator::Now()` clock, so there was no actual per-node
clock disagreement for the equation's correction term to remove. Main.tex §"Distributed Trusted Time
Reference" (sec:time_ref, main.tex:1958-1988, Chapter 3 Methodology → §3.4 Proposed Solution)
specifies this defends against a compromised RSU lying about its own clock to disguise a real delay
— a threat this simulation didn't model at all prior to this change.

**What was built (12 steps, spanning ns-3/C++, Fabric chaincode/Go, the Node.js bridge, and tests):**

| Layer | Change |
|---|---|
| ns-3 (`crypto_layer.h`) | `node_clock_offset(node)`/`node_local_time(node)` — a stateless, continuously-evaluable per-RSU clock model reusing M9's existing `TIME_REF_F_BAD`/`TIME_REF_DELTA_ATTACK` (single source of truth for "which RSUs are Byzantine" across M9, M2, and M6 now) |
| ns-3 (`crypto_layer.h`) | `update_T_ref()` refactored to call `node_local_time()` per RSU instead of its own separate inline offset loop |
| ns-3 (`routing.cc`) | `record_claimed_forward_timestamp()` now stores `node_local_time(node)` (the sender's own, possibly-wrong clock reading) instead of the raw shared clock |
| ns-3 (`routing.cc`) | S2/TVR timing check and the NFA witness-alert delay report now correct the sender's claim via `t_fwd_claimed - node_clock_offset(prev_sender)` before comparing to the receiver's ground truth |
| ns-3 (`routing.cc`) | S1's existing no-op anchoring pattern replaced with the same real correction |
| ns-3 (`routing.cc`) | M6 (L_e2e): `routing_packet_initial_timestamp`/`routing_packet_final_timestamp` now record each endpoint's own local time; `calculate_average_latency_routing()` corrects both the flow's source and destination offsets before subtracting |
| ns-3 (`crypto_layer.h` + `bc_blockchain_helper.h`) | `bc_commit_tref_to_chain()` — writes `bc_tref_log.csv` every `T_SYNC_INTERVAL` tick, called directly from `update_T_ref()` (forward-declared, same pattern as `bc_commit_dkg`) |
| Chaincode (`types.go`) | New `TRefCommit` struct + `keyPrefixTRef` (Asset 9), mirroring `GlobalAnchor` exactly |
| Chaincode (`tref.go`, new file) | `CommitTRef(seq, tRefValue, epsRef, committedAt)` / `GetTRef(seq)`, mirroring `anchor.go`'s `AnchorGlobal`/`GetAnchor` exactly (RSU-only write, duplicate-seq-safe, no verify step) — realizes main.tex:1985-1988's "committed to the blockchain... tamper-evident audit trail" |
| Bridge (`tailers/tref.js`, new file) | Tails `bc_tref_log.csv`, submits `CommitTRef`, mirroring `tailers/anchor.js` exactly |
| Bridge (`index.js`) | Wires the new tailer into startup/shutdown alongside the existing five |
| Test (`test_synthetic.sh`) | New "§9. T_ref commit" section: commit, query, and duplicate-seq rejection, mirroring the Model Hash Commit test shape |

**Design rationale — why not just subtract `g_T_ref` at read time (still a no-op)?** `g_T_ref` is a
periodically-resynced snapshot (every `T_SYNC_INTERVAL`, default 1s); using it for correction would
either cancel out identically (if read once, same value both sides) or collapse timing resolution to
1-second buckets (if read at two different sync ticks) — breaking S2's 50ms-resolution detection
either way. `node_clock_offset()` is a deterministic, continuously-evaluable function of
`(node, TIME_REF_F_BAD, TIME_REF_DELTA_ATTACK)`, so it can correct a specific node's known bias at
full timestamp precision without waiting for or depending on sync-tick granularity — mathematically
equivalent to what an auditor with the blockchain-committed history could reconstruct, without
needing to actually replay that history for every delay check.

**Regression safety:** with the default `TIME_REF_F_BAD=0`, every `node_clock_offset()` call returns
`0.0`, making every corrected quantity numerically identical to the pre-existing (uncorrected)
behavior — this change is a strict no-op unless M9's Byzantine-clock sweep flags are explicitly set.

**Scope acknowledgment:** this closes the gap to the level of detail the equations specify. A fully
airtight version would also need the blockchain commit itself to be consumed by an on-chain
verification step (not just written) so that a compromised RSU literally cannot submit a claim
inconsistent with its own committed history — the current implementation provides the commit/audit
trail infrastructure but the ns-3 delay-correction logic uses direct oracle knowledge of
`node_clock_offset()` rather than reading back its own on-chain commits. This is the same
oracle-vs-inferred-from-history simplification the codebase already uses elsewhere (e.g. ground-truth
`*_malicious_nodes[]` arrays for detection), and is consistent with the level of chain-plumbing this
codebase implements for its other committed assets.

**Verification status:** ns-3/C++ changes require `./waf build`; chaincode changes require the Fabric
toolchain (`go build`, no local Go available in this session) and `test_synthetic.sh` against a live
test-network; bridge JS changes are syntax-checked clean (`node --check`). All pending user
verification on the appropriate hosts.

### Follow-up re-audit of this feature — three bugs found and fixed (2026-07-07)

Immediately after implementing the above, a second pass specifically hunting for other consumers of
the now-changed `t_claimed_packet`/`routing_packet_*_timestamp` arrays found three real gaps the
initial implementation missed:

1. **`s2_detect_packet()` (`s2_detection.h`) was missing the anchoring correction entirely.** This is
   MOBIGUARD's *actual* S2 signature detector — the one that drives `record_detection_event()` for
   M1's real confusion matrix — not the duplicate inline timing check in `routing.cc`'s MacRx block
   that was fixed first. It read `t_claimed_packet[sender][id]` (now storing `node_local_time()`,
   i.e. potentially inflated by the sender's own offset) and computed
   `hop_delay = t_recv_now - t_fwd_by_sender` with no correction — meaning a Byzantine-compromised
   sender's inflated claim would make MOBIGUARD's *own* S2 detector *more* evadable under M9's clock
   scenario, the opposite of what eq:delay_updated is supposed to achieve. **Fixed** by anchoring
   `t_fwd_by_sender` via `node_clock_offset(sender_sim_index)` before computing `hop_delay`, mirroring
   the correction already applied to the other call site.

2. **The STARK proof check immediately below it used the unanchored value**, creating an internal
   inconsistency: `delay_exceeds` (conjunct 1) would use the corrected delay per item 1's fix, but
   `stark_prove_timing`/`stark_verify_timing` (conjunct 2) would independently re-derive their own
   pass/fail from the *uncorrected* interval — meaning the two conjuncts of S2's AND condition could
   disagree under a compromised clock, potentially suppressing S2 detection even when the anchored
   delay correctly identified a violation. **Fixed** by passing the same anchored timestamp to both
   STARK calls.

3. **M6 (L_e2e)'s delivery guard in `calculate_average_latency_routing()` compared *raw* (unanchored)
   timestamps** (`final > initial`) before computing the anchored delay inside the `if` block. Under
   M9's scenario, a large destination-RSU offset relative to a small real one-hop delay could make a
   genuinely-delivered packet's raw final timestamp appear ≤ its raw initial timestamp, silently
   dropping it from `delivered_packet_counter`/`total_latency` — a false negative in the delivery
   check itself, not just an imprecise delay value. **Fixed** by computing the anchored send/receive
   times *before* the guard and comparing those instead.

**Deliberately left unfixed (out of scope, not one of the 12 metrics):** `calculate_average_packet_delivery_ratio_routing()`'s
own delivery check (PDR) has the *same* raw-comparison pattern as item 3 and is subject to the same
theoretical false-negative risk under M9's scenario. PDR is not one of the proposal's 12 official
metrics (see the "Non-conformance note" below — it's a pre-revision metric superseded by UCR), so
this was not fixed to avoid expanding scope into a metric outside main.tex §4.6's list. Flagged here
for completeness in case PDR is used for any other purpose later.

**Lesson for future changes to shared timestamp arrays:** any array feeding more than one metric or
detector needs an exhaustive consumer search (not just "fix the call site you were looking at") —
this is exactly the kind of gap a targeted fix can introduce while looking correct in isolation.

---

## Confirmed correct (no deviation found) — re-verified this session

| Metric | What was re-checked | Result |
|---|---|---|
| **M1 formula** | `MCC = (TP·TN-FP·FN)/√(...)` with epsilon-smoothing | Matches Eq. 4.1 exactly; epsilon guards div-by-zero, not a deviation |
| **M3 (UCR) counter wiring** | `fade_eavesdrop_counter` increment sites | Genuinely incremented at `routing.cc:121149` and `:121194` — unlike TVR, UCR's underlying data is real |
| **M4 (t_onset/t_quarantine) wiring** | `record_attack_onset()`/`record_detection_event()` | Both correctly stamp `t_onset[n]`/`t_quarantine[n]`; `trust_update_negative()`'s quarantine branch also stamps `t_quarantine[n]` independently. M4 is genuinely wired, confirming the earlier report's "already wired" claim. |
| **M7 counters (O_crypto/T_batch/T_consensus)** | All `g_m7_*` increment sites | Correctly incremented, never reset mid-run (only at `trust_init_all()`, a full-run reset) — no concurrency issue like M5's |
| **M9 boundary behavior** | Median-index math for `f_bad` sweep | Confirmed: for `f_bad < N_RSUs/2`, median always lands on an honest (0-offset) entry; at `f_bad = N_RSUs/2` exactly, lands on first compromised entry. Reproduces the proposal's claimed bound exactly, no off-by-one. |
| **M11 CP-variant gating** | `is_cp_variant` check against Attacks 1/3/5/7 | Correctly matches `active_attack_variant ∈ {0,2,4,6}` (0-indexed); function is a no-op outside those variants |
| **M12 one-shot counting guard** | `g_witness_threshold_fired` per-node dedup | Correctly prevents re-counting on repeated pool growth for the same node; TP_W/FP_W classification against `passive_hf_malicious_nodes[]` is correctly scoped |
| **CSV column alignment** | Full header vs. data-row column count, both fixed and TCAM-conditional blocks | Recounted by hand: 21 fixed + 9 conditional (TCAM) + 30 always-appended = matches on both sides exactly. No silent column-shift bug from the many incremental edits this session. |
| **M8 BRFA-v2 structure** | All 4 algorithm steps present and correctly composed | Trust-gate → hash-verify → Krum → weighted aggregation, composed via `final_mask`; index alignment between `rsu_ids`/`flat_list`/`n_list` verified correct throughout `run_aggregation()` |

---

## Already-documented, still-open items (confirmed unchanged, not re-litigated in depth here)

These were correctly identified in the earlier METRICS_VERIFICATION_REPORT.md; one has since been
resolved (see the new "Real T_ref(t) clock-skew anchoring" section above), the rest remain open and
are listed here for completeness:

- ~~M2/M6 — no `T_ref(t)` normalization~~ — **RESOLVED 2026-07-07.** See "New Feature: Real T_ref(t)
  clock-skew anchoring" above.
- **M2 — packets never forwarded are not assigned `δ_p = ∞`.** Moot until the Critical TVR fix above
  lands, since the whole counter is currently non-functional regardless; worth revisiting together.
- **M1 — no mobility-density/speed binning** (`MCC_s[ρ_b, v̄_b]`, Eq. mobility_baseline). Requires
  post-processing SUMO trace data against simulation timestamps; not a runtime code gap.
- **M12 — no vehicle-density binning** for the `R_W` feasibility claim (~3.1 vehicles/RSU cell).
  Same category as above — a post-processing/analysis task, not a missing counter.

---

## Non-conformance note: extra CSV columns not in the proposal's 12 metrics

`write_security_metrics_csv()` exports `cur_PDR, avg_PDR` (Packet Delivery Ratio) and, for TCAM
variants, 9 columns of TCAM utilization/rate data (`max_tcam_util`, `s3_fired_count`, etc.). Neither
is one of the current 12 official metrics (M1–M12) in main.tex §4.6 — PDR was the *pre-revision*
M5 (superseded by UCR, per the commented-out old metric list at main.tex:4037-4043), and the TCAM
columns are FADE-baseline-specific instrumentation, not part of MOBIGUARD's own metric set. This
isn't a "bug," but it means the CSV schema is **wider than the proposal's metric list** — worth
knowing before treating "the CSV" as a 1:1 mirror of Section 4.6. (A prior attempt to remove these
columns was raised and not pursued — noted here for visibility, not re-proposed.)

---

## Summary

| Finding | Severity | Introduced when | Status |
|---|---|---|---|
| TVR counters never incremented — metric always reports 0% | **Critical** | Pre-existing, before this session | ✅ **Fixed 2026-07-07** (build pending) |
| M5 `g_failover_max_ms` reset race on overlapping controller revocations | **High** | This session (M5 implementation) | ✅ **Fixed 2026-07-07** (build pending) |
| M11 injector inflates M7's `rsu_chain_len` under AB8-A + CP attacks | **Medium** | This session (M11 implementation) | ✅ **Fixed 2026-07-07** (build pending) |
| Krum filter rejects a lone surviving RSU (small-K edge case) | **Low** | This session (M8 implementation) | ✅ **Fixed 2026-07-07** (syntax-checked) |
| Extra CSV columns (PDR, TCAM) outside the 12-metric list | **Informational** | Pre-existing | No action required |

**Net assessment: all four code-level findings from this audit have been fixed.** Nothing identified
in this pass remains open at the code level. The one item deliberately left unaddressed —
`T_ref(t)` distributed-time anchoring for M2/M6 (they currently use `Simulator::Now().GetSeconds()`
directly instead of the codebase's own existing `Now().GetSeconds() - g_T_ref` convention, already
used elsewhere for LRAD-OBU's delay computation) — is a design-scope question, not a bug: it's a
genuine equation-fidelity gap versus eq:delay_updated, well-defined and fixable using the exact
pattern already established in the code, but changes what "delay" means for two metrics at once and
was not part of what was asked to be fixed this round. Flagged here explicitly in case full
equation-for-equation fidelity is wanted next.

**Verification commands (after `./waf build` succeeds):**
```bash
# TVR: run a Selective Time Delay variant, check cur_TVR/avg_TVR are no longer always 0
./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=40"
# Look for non-zero cur_TVR in MOBIGUARD_Attack1_40.csv once delay exceeds 50ms

# M5: run a scenario with 2 compromised controllers (attack_percentage=100 on Attack 1
# compromises multiple controllers per declare_attackers()'s ladder), check
# ctrl_failover_max_ms reflects a stable, non-conflated worst-case value
./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=100"
```
