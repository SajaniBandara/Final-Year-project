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

**Fix scope:** track max-latency per revoked controller (e.g. `std::map<uint32_t,double>
g_failover_max_ms_by_ctrl`) instead of a single scalar, or track a single monotonic running max
across the whole run (never reset) rather than "most recent event only" — the latter is simpler and
still answers the proposal's question (worst-case latency observed), just not scoped to "most recent
event" the way the current single-event design intends. Either avoids the overwrite-on-overlap bug;
the current per-event-reset design is fundamentally incompatible with concurrent revocations.

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

`ufcr_attempt_unauthorized_flowmod()` calls `bc_commit_flowmod(fake_e)` once per second while a
control-plane variant is active. When `enable_endorsement_requirement=false` (AB8-A), this call
**succeeds** (by design — that is what UFCR is measuring) and, as a side effect of
`bc_commit_flowmod()`'s existing logic, pushes a hash onto the shared `g_rsu_commit_hashes` vector —
the same vector `write_security_metrics_csv()` reports as `rsu_chain_len` for M7's consensus-overhead
tracking.

**Consequence:** any run combining a control-plane attack variant with `enable_endorsement_requirement=false`
(i.e., AB8-A configuration under Attacks 1, 3, 5, or 7) will show an `rsu_chain_len` inflated by
~1 per second of simulation time beyond what the legitimate per-cycle FlowMod traffic alone would
produce. This is arguably *correct* behavior in isolation (an unauthorized commit that bypassed
endorsement legitimately did get written to the chain — that is the point of AB8-A), but it means
**M7's `rsu_chain_len` is not directly comparable between AB8-A and AB8-B runs of the same attack
variant** without accounting for this known, fixed-rate contribution. Not documented anywhere before
this audit.

**Fix scope (optional — could also just be documented as expected behavior):** track the injected
commits in a separate counter (`g_ufcr_injected_commits`) and either exclude them from
`rsu_chain_len` or report both figures side by side.

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

**Consequence:** in a degenerate scenario with very few total RSUs and aggressive trust-gating (not
the paper's actual 64-RSU setup, but reachable if someone runs the pipeline with a small synthetic
RSU count for a quick smoke test), `run_aggregation()` would silently produce a global model
aggregated from **zero** accepted RSUs (`weighted_fedavg` with an all-`False` mask divides by
`total=0`), raising a `ZeroDivisionError` rather than a clear diagnostic.

**Fix scope:** guard `krum_filter()` (or `run_aggregation()`) for `len(flat_weights) < 2` and either
auto-accept the single candidate or raise a descriptive error instead of silently computing a
degenerate threshold. Low priority given the target configuration is 64 RSUs, but worth a one-line
guard since `poison_sweep.py`'s trust-gate + high `rho_mal` combinations could plausibly shrink the
eligible set this far in an aggressive sweep.

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

These were correctly identified in the earlier METRICS_VERIFICATION_REPORT.md and remain open;
listed here only for completeness so this audit is a complete picture on its own:

- **M2/M6 — no `T_ref(t)` normalization.** Both TVR (once fixed per the Critical finding above) and
  L_e2e use `Simulator::Now().GetSeconds()` (absolute wall-clock) rather than the distributed time
  reference `T_ref(t)` the proposal's equations specify. Low practical impact unless RSU clocks are
  deliberately desynchronized (M9 scenario), but not equation-faithful as written.
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
