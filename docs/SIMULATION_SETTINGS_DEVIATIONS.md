# Deviations Found — Careful Linear Read of Simulation Settings, Results, Timeline
**Date:** 2026-07-08
**Scope:** main.tex lines 4965-5513 (§Simulation Settings through §Conclusion), read
sequentially line-by-line rather than via targeted search. This is a direct response to
discovering that earlier verification (this session) used keyword searches that missed
hedge-language the document actually uses ("modelled" vs the searched-for "simulated/stub").
This file documents what a full linear read of *this specific range* surfaced.

**This is not yet a complete line-by-line audit of the whole document.** The Methodology
chapter (main.tex ~1132-3435, ~2300 lines covering the threat model, attack signatures,
crypto layer, blockchain architecture, and federated LSTM) has been extensively verified
this session, but via targeted deep-dives on specific mechanisms (S1/S2, STARK, T_ref,
witness, DKG, metrics) rather than a fresh, complete linear read start-to-finish. Given the
pattern established below — a careful read of ~550 lines surfaced 6 new findings that
targeted searches missed — the Methodology chapter likely has more. See "Scope and next
step" at the end.

---

## Finding 1: Attacker allocation uses stochastic draws, not the specified deterministic count — FIXED (2026-07-08)

**Fix applied:** `declare_attackers()` in `scratch/attack_declaration.h` now computes
`n_atk = floor(0.01 * attack_percentage * var)` and selects exactly that many nodes via a
seeded Fisher-Yates shuffle (`ShuffleNodeIndices()`, new helper added in `routing.cc` right
after `GetBooleanWithProbability()`, using the same `RngSeedManager`-governed RNG
infrastructure). The count is now deterministic per `attack_percentage`; only *which* nodes
are selected varies per seed, matching the proposal's "5 fixed pseudorandom seeds per
configuration" methodology. Original analysis retained below for reference.

**Proposal (main.tex:5296-5298, simulation_table):**
> "Attacker allocation (vehicles/RSUs): `⌊0.01p × 264⌋` nodes; plane-specific per attack variant"

This specifies a **deterministic count**: at a given `attack_percentage p`, exactly
`floor(0.01 × p × 264)` nodes should be attackers (264 = 200 vehicles + 64 RSUs).

**Code (`routing.cc:115178-115186`, `GetBooleanWithProbability`):**
```cpp
bool GetBooleanWithProbability(double probabilityPercent, int /*nodeID*/) {
    static Ptr<UniformRandomVariable> rng = ...;
    return rng->GetValue() < probabilityPercent;
}
```
Used in `declare_attackers()` (`attack_declaration.h:172`) as an **independent Bernoulli draw
per node**: `attacking_state = GetBooleanWithProbability(attack_percentage, i)` for each of
the 264 candidate nodes.

**Why this matters:** an independent per-node draw gives the *expected* count
`0.01×p×264` on average, but the *actual* count in any single run is Binomially distributed
around that expectation. At `p=40%`: expected ≈105.6 attackers, standard deviation
≈ √(264×0.4×0.6) ≈ 7.96 — meaning a typical run could have anywhere from ~98 to ~114 actual
attackers, a ±7-8% swing. Since the proposal treats `attack_percentage` as a controlled
independent variable across "5 fixed pseudorandom seeds" per configuration (main.tex:5305),
this randomness in the *count itself* (not just *which* nodes are picked) adds uncontrolled
variance the deterministic formula was presumably designed to eliminate — each seed should
give the same attacker *count*, differing only in *which* nodes are selected.

**Note:** an earlier read of this session characterized a commented-out block in
`routing.cc` (~115215-115234, using `attacker_candidates[]` scaled by
`num_attackers_local = (uint32_t)(8 * attack_percentage / 100.0)`) as superseded by the more
general `declare_attackers()` mechanism. That characterization should be revisited — the
commented-out approach was actually closer to the table's deterministic-count formula (fixed
count, indices selected in order) than the current stochastic implementation is.

**Fix scope:** replace the per-node Bernoulli draw with: shuffle the candidate node index
list (seeded, reproducible), take the first `floor(0.01 × attack_percentage × 264)` as
attackers. This guarantees exact-count reproducibility while keeping *which* nodes are
selected randomized per seed — matching the proposal's stated methodology.

**Severity:** Medium — doesn't break detection logic, but affects experimental precision:
`attack_percentage` isn't as tightly controlled a variable as the proposal specifies, adding
noise to any regression/threshold analysis run against it (e.g., the S1 calibration sweep,
FPR-vs-percentage curves in the evaluation tables).

---

## Finding 2: Controller-compromise ladder has an undocumented extra bucket, contradicting the table — FIXED (2026-07-08)

**Fix applied:** in `declare_attackers()` (`scratch/attack_declaration.h`), the ladder's first
branch changed from `attack_percentage < 10 -> step 0` to `attack_percentage == 0 -> step 0`,
so `[1,33)` now correctly maps to `step 1` (1 controller compromised), matching the table's
`<33%:1` exactly, while still leaving `p=0` (no attack) at zero compromise. This also brings
Attack 1's ladder into agreement with Attack 3's own controller-compromise ladder
(`routing.cc:115032-115036`), which already implemented the table correctly
(`p==0->0, p==100->4, >=66->3, >=33->2, else->1`) — confirming the fixed boundary is the
right one, not a new invention. Original analysis retained below for reference.

**Proposal (main.tex:5300-5302, simulation_table):**
> "Attacker allocation (controllers): `<33%: 1; 33–66%: 2; ≥66%: 3; 100%: 4`"

Three thresholds (33%, 66%, 100%), four resulting bucket values (1,2,3,4 controllers).

**Code (`attack_declaration.h:210-222`, `declare_attackers()`):**
```cpp
uint32_t step;
if (attack_percentage < 10)       step = 0;
else if (attack_percentage < 33)  step = 1;
else if (attack_percentage < 66)  step = 2;
else                              step = 3;
uint32_t num_to_compromise = (step * max_compromisable) / 3;
```
With `N_Controllers=4`, `max_compromisable=3` (non-100% case): this produces
`p<10%→0 compromised`, `10≤p<33%→1`, `33≤p<66%→2`, `p≥66%→3` (plus the separately-handled
`p=100%→4` override).

**The mismatch:** for `attack_percentage ∈ [0%, 10%)`, the code compromises **zero**
controllers, but the proposal's table says `<33%` should give **1**. I searched the full
document for any more-detailed prose specification that might justify the code's extra
`<10%` bucket (grepped for "10%", "num_controllers_compromised", "threshold ladder",
"compromise ladder") and found **no other specification of this ladder anywhere in
main.tex** — the simulation_table entry is the only place this is defined, and the code
doesn't match it.

**Severity:** Medium — affects the low end of the attack-percentage sweep (0-10%) for
Attack 1 (CP) specifically: at very low attack intensities, the code produces a "no attack"
condition where the proposal's own table specifies there should already be one controller
compromised. This could make the low-percentage end of any CP-attack evaluation curve show
artificially clean (0-compromise) behavior for a wider percentage range than the proposal
intends.

**Fix scope:** either (a) remove the `<10%→0` bucket so the ladder matches the table exactly
(`<33%→1, <66%→2, else→3`, `100%→4`), or (b) if the `<10%→0` bucket is intentional (e.g., to
give a true "no attack, percentage low but nonzero" baseline point), add that as an explicit,
documented deviation with justification — right now it's silently undocumented.

---

## Finding 3: "268 peers" in the blockchain table is arithmetically inconsistent

**Proposal (main.tex:5349, simulation_table):**
> "Blockchain audit trail & Permissioned, PBFT consensus, **268 peers** (4 controllers + 64
> RSUs), 1s block interval, ≤50 tx/block"

`4 + 64 = 68`, not `268`. `268` is the figure used elsewhere in the same table for **total
network nodes** (main.tex:5272: "Number of nodes & 268 (200 vehicles, 64 RSUs, 4
controllers)"). Vehicles are not blockchain peers per the architecture (only RSUs and
controllers hold Fabric identities per `blockchain/mobiguard-cc/access_control.go`'s
`rsuOrgMSP`/`controllerOrgMSP`), so "268 peers" appears to be a copy-paste error from the
node-count row — the correct figure should be 68.

**Verified:** searched the entire `blockchain/` directory for the literal string "268" —
zero matches. This confirms the error is confined to the proposal document; the actual
chaincode/test-network configuration doesn't hardcode the wrong number anywhere.

**Severity:** Low — documentation-only fix, main.tex line 5349. No code impact.

---

## Finding 4: Simulation Results section — "Variant 7" cited under an "Attack 8, Data Plane" heading

**Proposal (main.tex:5425-5447):**

Section header and figure caption both say **"Passive Hidden Forwarding Attack on the data
plane"** / **"Attack 8"** (main.tex:5425-5434) — per the established numbering, Data Plane
Passive HF is Attack 8 (S8), while Control Plane Passive HF is Attack 7 (S7). But the
analysis paragraph immediately after says:

> "**Variant 7** achieves an MCC of 0 with one false negative, reflecting the passive nature
> of the attack..." (main.tex:5444-5445)

This is an internal inconsistency in the proposal's own narrative — either the section is
mislabeled (should be describing Attack 7/CP, not Attack 8/DP), or the results paragraph
should say "Variant 8," or the two are describing genuinely different runs that got
conflated during writing. Not something I can resolve from the code side — this is a
proposal-document authoring issue worth flagging to whoever wrote this results paragraph.

**Severity:** Low (documentation clarity) but worth fixing before this becomes a real
evaluation-chapter table, since it currently describes an experiment that doesn't cleanly
map to either variant as written.

---

## Finding 5: Reported MCC=0 with a false negative, alongside a stated "50ms mitigation latency" — possibly contradictory

**Proposal (main.tex:5444-5447):**
> "Variant 7 achieves an MCC of 0 with one false negative, reflecting the passive nature of
> the attack where no observable network degradation occurs, **with an average mitigation
> latency of 50ms**."

If the described run had exactly one attack instance and it was a false negative (missed
detection), there should be **no successful quarantine event** to produce a "mitigation
latency" figure at all — M4 (`L_mit = t_quarantine - t_onset`) requires a quarantine to
actually fire. Reporting both "MCC=0, FN=1" (nothing detected) and "avg mitigation latency
=50ms" (something got quarantined, and quickly) for what reads as the same scenario is
internally inconsistent as written.

**Two ways this could be legitimate, not a bug:** (a) if the test run had multiple attack
instances/nodes and only some were missed (mixed outcome), the single-sentence summary may
be conflating separate sub-results; (b) if `t_quarantine` was set via a *different* detection
path (e.g., the general trust-degradation quarantine mechanism, independent of S7's own
confusion-matrix outcome) — the M4 mitigation-latency mechanism doesn't require S7 itself to
have fired correctly, since `trust_update_negative()`'s own quarantine branch is a separate
trigger. This is plausible given this session's earlier finding that M4 is genuinely wired
via two independent paths.

**Severity:** Low/informational — can't resolve definitively without access to the original
run's raw logs (this describes a past result, not something re-run in this session). Flagging
for the author's awareness; if this exact test network scenario gets re-run post this
session's fixes (T_ref anchoring, TVR wiring, M5 race fix), the new output should be checked
against this narrative for consistency.

---

## Finding 6: M7 overhead gaps — FIXED (2026-07-08)

Originally: `crypto_layer.h`'s O_crypto computation used a 64-byte SHA3-512 commitment for
`π_delay` (and 0 bytes for `π_hop`, treated as "embedded" in the ML-DSA-87 signature), while
main.tex:5342/5124 (same table / §Simulation Settings ZKP scheme item) explicitly specifies
"ZKP proof size ≤100KB per proof (FRI-STARK, SHA3-512; conservative blowup)" — and no
simulated proof-generation wall-clock overhead existed anywhere despite main.tex:5123
modeling "Proof generation overhead... ≤10ms per packet."

**Fix applied:**
- `g_m7_crypto_bytes_sum` (`crypto_layer.h`, inside `mldsa87_sign()`) now adds
  `sig_len + 2 * STARK_PROOF_SIZE_MODELED_BYTES` (a new named constant = 100KB, main.tex:5124)
  instead of the ad-hoc `+ 64.0` — accounting for both `π_delay` and `π_hop` at the
  proposal's own conservative bound, per eq:overhead_full. This brings the reported
  O_crypto from ~4.7KB to ~204.5KB per hop, matching eq:overhead_full's own worked example
  ("≈200KB per hop") almost exactly.
- A new M7 instrumentation pair (`g_m7_stark_wall_us_sum`, `g_m7_stark_calls`) measures the
  real wall-clock cost of `stark_prove_timing()`/`stark_verify_timing()`/`stark_verify_hop()`
  via `std::chrono`, exported as a new `t_stark_ms_avg` CSV column — a characterization metric
  comparable against the proposal's "≤10ms modelled" bound, deliberately **not** injected as
  an artificial `Simulator::Schedule` delay into the packet-forwarding pipeline (which would
  have changed M2/M6/S1/S2 detection outcomes network-wide rather than just reporting
  overhead — same reasoning the existing `g_m7_batch_wall_us_sum`/`g_m7_consensus_wall_us_sum`
  metrics already use).
- `scripts/verify_metrics.py`'s `COLUMNS_NO_TCAM`/`COLUMNS_TCAM` (now 52/61 columns, was
  51/60) and `m7_overhead()`'s expected-value check updated to match.

---

## Summary table

| # | Finding | Severity | Fix scope |
|---|---|---|---|
| 1 | Attacker allocation: stochastic draw vs deterministic `⌊0.01p×264⌋` count | Medium | **FIXED** — shuffle+select (`ShuffleNodeIndices`) replaces per-node Bernoulli |
| 2 | Controller ladder: undocumented `<10%→0` bucket contradicts table's `<33%→1` | Medium | **FIXED** — `==0` replaces `<10` boundary |
| 3 | "268 peers" should be "68 peers" (4 controllers + 64 RSUs) | Low | Doc fix only — main.tex:5349 |
| 4 | "Variant 7" cited under an "Attack 8, Data Plane" section | Low | Doc fix only — main.tex:5444, author clarification needed |
| 5 | MCC=0/FN=1 alongside "50ms mitigation latency" — possibly contradictory | Low/informational | Needs author clarification or a fresh re-run to verify |
| 6 | M7 O_crypto/T_STARK gaps vs "≤100KB"/"≤10ms" modeled overhead | Medium | **FIXED** — O_crypto uses modeled 100KB/proof bound; new t_stark_ms_avg column added |

---

## Scope and next step

This document covers a genuine, careful linear read of main.tex:4965-5513 (~550 lines:
Simulation Settings, Simulation Results, Timeline, Resources, Conclusion). It does **not**
yet cover a fresh line-by-line read of:

- Chapter 1 (Introduction, main.tex:363-648) — low technical/code-checkable content expected
- Chapter 2 (Literature Review, main.tex:649-1131) — covered by earlier
  `SECTION_VERIFICATION_REPORT.md` work, not re-verified today
- **Chapter 3 (Methodology, main.tex:1132-3435, ~2300 lines)** — the highest-risk remaining
  section. Covered extensively this session via targeted deep-dives (S1/S2 signatures, STARK
  proof mechanics, T_ref/eq:delay_updated, witness mechanism, DKG, blockchain trust/
  quarantine equations, federated LSTM) — but *not* via a single continuous linear read.
  Given that today's linear read of a much shorter section (550 lines) surfaced 6 findings a
  targeted-search approach had missed, this chapter likely has more waiting to be found the
  same way.
- Chapter 4 §Performance Metrics/Ablation/Benchmarking (main.tex:3440-4964) — the metrics
  themselves are covered in depth by `docs/METRICS_VERIFICATION_REPORT.md` and
  `docs/METRICS_DEVIATIONS_FROM_PROPOSAL.md`; the Ablation (§4124-4614) and Benchmarking
  (§4615-4964) study *descriptions* have not had the same careful linear-read treatment.

**Recommended next step:** apply the same method here (continuous read, no keyword search) to
Chapter 3 next, since it's the largest concentration of equations/algorithms with concrete,
checkable code correspondences.
