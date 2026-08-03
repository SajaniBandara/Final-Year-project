# Fresh-Run Fix Priority List (evidence from 2026-07-29 sweep)

**Source run:** `results_routing/` (fresh, mtimes 2026-07-29 13:52-13:54) — 8 attacks ×
6 percentages, seed 1, produced by `scripts/run_rule_based_sweep.py`.
**Logs read in full:** `logs/task8_verification/{equation_audit.log, functional_verification.log,
timing_report.log}`, all 48 `logs/rule_based_sweep/A*_pct*_seed1.log` (grepped for
crash/error markers; sizes up to 217 MB), and the 5 available
`logs/rule_based_sweep/A*_pct80_seed1_timing_report.log` deep-timing reports (A1, A2, A4, A5, A8).
**Also directly inspected** (not just derived reports): every `crypto_timing_log_V{0-7}_pct60_s1*.csv`
(all 8 attack variants at 60%) row-by-row for schema validity, monotonic timestamps, NaN/negative
values, and per-`(op,result)` breakdown; `crypto_timing_log_V4_pct*.csv` across all 6 percentages
once an anomaly was found at pct60; and every `results_routing/*.csv` file for empty/header-only
outputs. **Second pass, all remaining CSV types at pct60 for all 8 attacks:**
`MOBIGUARD_Attack*_60*.csv`, `bc_anchor_log`, `bc_detection_log`, `bc_dkg_log`, `bc_flowmod_log`,
`bc_tref_log`, `rsu_density`, `lambda_l_true`, `tcam_occupancy`, `tcam_snapshots` — parsed every
row of every file (script-driven: field-count/schema checks, monotonicity where expected —
blockchain chain length, DKG round, cycle index — non-negativity, and NaN/Inf scanning).
**Cross-referenced against:** `docs/main.tex` (sole spec reference), `docs/PENDING_FIXES.md`
(prior fix history), `docs/METRICS_VERIFICATION_REPORT.md`.

**Scorecard for this run:** equation/algorithm presence audit **107 PASS, 0 FAIL** (every
`eq:`/`alg:` label in main.tex resolves to code, negative-control self-test 87/87). Functional
verification **619 PASS, 11 FAIL, 107 WARN** (WARNs are coverage gaps by the checker's own
definition, not defects — see guide §5). Zero crashes/segfaults/aborts across all 48 sweep logs.
Below is every FAIL/anomaly found, in priority order, with the evidence and — where traceable —
the root cause in code. **Methodology note on finding #0:** an anomaly (`flowmod_endorsement_rate
=0.0000` for Attack 5 only) was found by reading the raw `crypto_timing_log_*.csv` files directly
(not covered by the 11-FAIL summary, since the checker only range-validates that field). It was
initially — incorrectly — reported as a live consensus breakdown; tracing it into `routing.cc`
and the raw NS-3 run log before finalizing this document showed it's a deliberate, documented
ground-truth substitution, not a defect. Kept in the document, corrected, because it surfaces a
real (different) issue: the metric name is misleading and the underlying modeling gap it works
around isn't disclosed in the thesis. This is a reminder that a raw-log anomaly needs to be
traced to source before being reported as a bug — see finding #0 for the full correction.
**Findings #9–#12 are a different kind of check**, added after a direct main.tex-vs-code
cross-reference (not sourced from the fresh run's logs/CSVs at all) — they cover mechanisms
main.tex describes that have no corresponding code, found by grepping for the exact terms each
equation names and checking `scripts/audit_equations.py`'s own `[INFO]`/paper-only
classifications against main.tex directly rather than trusting the label. Integrated into the
same priority ordering as the rest of this document.

---

## P0 — Critical (contradicts the thesis's own headline numbers, affects every attack)

### 0. `flowmod_endorsement_rate=0.0000` for Attack 5 is a documented ground-truth substitution, NOT a real breakdown — but it exposes a genuine, undisclosed modeling deviation from main.tex, and the metric is dangerously misleading as written

**Correction note:** an earlier pass of this document reported this as "Attack 5's blockchain
consensus completely breaks down" — a P0 correctness bug. That was **wrong**, caught by tracing
the finding into `scratch/routing.cc` and cross-checking the raw NS-3 run log
(`logs/rule_based_sweep/A5_pct60_seed1.log`) before finalizing. Corrected finding below.

**What's actually happening.** `routing.cc:118524` contains a deliberate, extensively-commented
override:
```cpp
if (present_active_hf_attack && active_attack_variant == 4)
{
    e.committed = false;
    _committed  = false;
}
```
The surrounding comment (routing.cc:118500-118523) explains why: `flowmod_endorse()`'s simulated
RSU quorum has no real independent per-RSU content-verification step (its params are the RSU's
own index, not real route content), so it **unconditionally endorses whatever flow id it's
given** — including Attack 5's poisoned flow, which rides the same `flow_id=0` as legitimate
traffic. Without this override, `bc_query_flowmod(0)` would permanently read "committed=true,"
which gates S5's detector shut at its very first conjunction (`s5_detection.h:123`:
`if (bc_query_flowmod(base_flow_id)) return false;`) — the comment records this was **empirically
confirmed** as the reason S5 fired 0/48 times in an earlier debugging session. The override is a
ground-truth substitute for the missing independent-verification model, scoped tightly to variant
4, so that S5 can fire at all.

**Verified this doesn't affect the real blockchain layer:** grepped
`logs/rule_based_sweep/A5_pct60_seed1.log` for the actual commit path
(`[BC-COMMIT] FlowMod COMMITTED: endorsers=640/22 ... rsu_chain_len=178`) at cycles *after*
attack onset (t=10s+) — it fires normally, on schedule, every cycle, with the RSU chain still
growing (matches `functional_verification.log`'s own FV417: "RSU chain grows monotonically...
52 -> 4464"). The per-second `[UFCR] unauthorized FlowMod attempt ... blocked_total=N/N` lines
that also appear in this log are a *separate*, always-on synthetic canary probe (fires
identically from t=1 to t=28, attack-independent) — unrelated to either the override above or to
finding #2 below; it is exactly what M11/UFCR is designed to measure and is working correctly
(100% blocked, confirmed by FV415/416 PASS).

**What this analysis is worth keeping, revised:**
1. **`flowmod_endorsement_rate` in the CSV/verification log is a misleading name for what's
   actually plumbed for Attack 5 specifically** — it reads 0.0000 not because endorsement failed,
   but because this one metric field is deliberately overridden as a detector ground-truth signal.
   A reader (including a viva examiner) looking at `MOBIGUARD_Attack5_*.csv` or FV414's printed
   line has no way to know this without reading the routing.cc comment — main.tex's own
   `eq:endorsed_commit` describes a real per-RSU independent-verification guarantee, and this
   simulation doesn't implement that guarantee; it substitutes ground truth instead. Per
   [[main_tex_reference]], this is exactly the kind of implementation-vs-thesis deviation that
   should be stated explicitly in the thesis text near M11/eq:endorsed_commit, not left implicit
   in a code comment.
2. **The `consensus` op's `result=fail` field in `crypto_timing_log_V4_*.csv` inherits this same
   override** (it logs `_committed`, the same variable) — so a reader of the raw crypto log sees
   an unexplained 19/28 "fail" streak with sentinel `pkt_id=0, flow_id=4294967295` and no
   indication it's intentional. Worth a one-line comment in the CSV-adjacent code or a distinct
   `result` value (e.g. `ground_truth_override`) instead of reusing `fail`, so this doesn't get
   mistaken for a real defect again (as it was here, initially).
3. **`functional_verification.py`'s FV414 check** (`flowmod_endorsement_rate within [0,1]`)
   passing on a 0.0000 value for one specific attack is still worth tightening — not because
   this particular 0.0000 is a bug, but because the check currently can't distinguish this
   documented case from a genuine future regression in the same field for a different attack.
   Recommend a comment/exception in the checker referencing this override, or a dedicated
   assertion that A5's 0.0000 is expected while every other attack's should stay near 1.0.

**Not yet resolved by this correction:** the underlying gap this override works around — no real
per-RSU independent FlowMod content verification in the simulation — is itself worth a line in
the thesis's limitations/deviations section, separate from any code fix. Per
[[debugging_methodology]], this is a **design/modeling boundary**, not an implementation bug: the
override is a reasonable, well-documented stand-in given that constraint, not something to "fix"
by writing more simulation code. Flag to supervisor if eq:endorsed_commit's real-verification
guarantee needs to be demonstrated more rigorously than a ground-truth flag for the thesis's
claims.

---

### 1. M4 Mitigation Latency is 17×–61× over the main.tex target, on all 8 attacks

**Evidence:** `functional_verification.log` FV29/116/202/289/375/462/549/635 — `eq:l_mit`,
FAIL on every one of the 8 attack sweeps (A1–A8), `avg_mit_ms` ranging **1771 ms to 6106 ms**
against main.tex's own target of **≤100 ms** (`docs/main.tex:4277`, `eq:l_mit`). For comparison,
main.tex's own narrative text (line 6150) claims "*an average mitigation latency of 50 ms*" —
the fresh run is **35×–120× worse** than that claimed figure.

| Attack | avg_mit_ms |
|---|---|
| A1 | 1771.27 |
| A2 | 2737.15 |
| A3 | 6106.05 |
| A4 | 5932.11 |
| A5 | 2184.17 |
| A6 | 2208.06 |
| A7 | 2654.63 |
| A8 | 3079.42 |

**Context:** `docs/METRICS_VERIFICATION_REPORT.md`'s Fix-12 note (2026-07-14) confirmed the
M4 *pipeline* is wired correctly (`t_quarantine` set via `record_detection_event()` +
`trust_update_negative()`) and was producing a plausible `M4_L_mit_ms=1117.59` at that time.
This fresh run shows the pipeline still fires (WARN-free, values non-zero) but the *magnitude*
has gotten worse, not better, and is universally >17× the target — this is not a "never fires"
bug like the old ones documented in `PENDING_FIXES.md`; it is a **magnitude** problem.

**Action:**
1. Instrument the gap between `t_onset` (first attack-conforming packet) and `t_quarantine`
   (`SC.Quarantine(v)` execution) to find where the 1.7–6 s actually accumulates — split into
   (a) detection→trust-update, (b) trust-update→blockchain endorsement/commit
   (`bc_commit_flowmod`, f+1 quorum), (c) DKG/key-rotation overhead if `trust_update_negative()`
   triggers `dkg_rotate_keys()` on the same path (per `PENDING_FIXES.md` AB11 gate description).
   `bc_dkg_log`/`bc_anchor_log`/`bc_flowmod_log` CSVs in `results_routing/` already carry
   per-round timestamps for this — they weren't cross-referenced against `t_quarantine` in this
   pass.
2. Per [[debugging_methodology]]: once the dominant contributor is isolated, decide whether it's
   an **implementation bug** (fix directly — e.g. an unnecessary serialization/wait in the
   commit path) or a **design cost** (blockchain consensus/BFT propagation genuinely takes
   seconds at this scale) — the latter needs a supervisor conversation about whether the 100 ms
   target in main.tex is achievable with the current blockchain-anchored design, not a code patch.
3. **Likely viva question:** *"Your own Table/Eq. l_mit target is 100 ms — your measured
   mitigation latency is 1.7–6 s. Why, and is the target wrong or the implementation slow?"*
   Have the component breakdown from step 1 ready before the viva, not just "it's slow."

---

### 2. S5/S6/S7 (Hidden-Forwarding signatures) false-positive rate is 3×–37× over the calibrated 1% target

**Evidence:** `functional_verification.log` FV383/470/557 — `eq:rule_s1` label (see finding #5,
this is a labeling artifact; the underlying data is each sweep's own primary signature), FAIL
on A5/A6/A7, PASS/not-flagged on A1–A4 and A8:

| Attack | Signature | avg_FPR | Target |
|---|---|---|---|
| A5 (Active HF, CP) | S5 | **37.16%** | ≤1% |
| A6 (Active HF, DP) | S6 | 2.86% | ≤1% |
| A7 (Passive HF, CP) | S7 | **35.84%** | ≤1% |
| A8 (Passive HF, DP) | S8 | not flagged | ≤1% |

**Root cause found for S7:** `scratch/s7_detection.h:78-81` — the volume-rate threshold is a
hardcoded, **explicitly not-yet-calibrated** constant:
```cpp
// Pending calibration from SUMO traces once baseline PDR profiles are available.
static const double S7_EPSILON_VOL = 0.1; // pkt/s
```
This is the same class of gap that `rule_calibrator.py` already closed for S1 (Fix 10,
per-packet σ² granularity) and S3/S4 (Fix 3, TCAM threshold 0.80→0.054688 from benign p99) —
S7 was simply never put through that calibration pass.

**S5 has no equivalent hardcoded threshold** (its detection is a pure crypto/hop conjunction:
`mldsa_fails && b_hop_fails && d_prime_unauthorized`, `scratch/s5_detection.h:214`) — its 37%
FPR needs code-level tracing, not a threshold tweak. Top suspects, in order of plausibility:
- The documented `mldsa87_verify_copy_content()` pkt_id-reuse staleness caveat
  (`PENDING_FIXES.md` HF-1 section: shared `(signer, pkt_id)` record can read a
  later-overwritten record) — previously measured at ~5.6% staleness, but that was said to be
  "directionally safe: missed detections only, never false positives," so if it *is* the cause
  here, the "never false positives" claim needs re-verification.
  - `d_prime_unauthorized` firing on some legitimate multi-hop forwarding pattern not accounted
  for in the conjunction.

**Action:**
1. Run S7 through the same calibration procedure as S1/S3/S4 (`rule_calibrator.py`, benign-only
   population, target FPR ≤1%) and hardcode the resulting `S7_EPSILON_VOL`.
2. Trace S5's `mldsa_fails`/`b_hop_fails`/`d_prime_unauthorized` individually on a benign-only
   A5 run to find which conjunct is firing spuriously; re-verify the "never false positives"
   staleness claim against this fresh evidence.
3. This is not yet documented anywhere in `PENDING_FIXES.md` — worth adding as a new numbered
   Fix entry once root-caused, so it doesn't get lost.

---

## P1 — High (real, reproducible defects; not yet in PENDING_FIXES.md)

### 3. Witness-alert causal-order violations on Hidden-Forwarding runs (13%–21% of DA alerts)

**Evidence:** `logs/rule_based_sweep/A5_pct80_seed1_timing_report.log` and
`A8_pct80_seed1_timing_report.log`, GROUP F ("Witness Alert Timing"):
- A5: **1935 / 14376 (13.5%)** duplication alerts have `t_alert < t_verify` (witness signed its
  alert *before* the packet's own verify record exists) — check **FAILS**.
- A8: **324 / 1552 (20.9%)** — same failure.
- A1/A2/A4 (non-HF) show 0 alerts or clean timing (this check doesn't apply/passes).

Example logged violation: `VIOLATION: alert at t=28.711 but verify at t=28.75 for pkt=2`
(A8) — the alert timestamp is *earlier* than the verify timestamp it's supposed to follow.

**Likely same root cause as finding #2's S5 suspect** — `g_packet_crypto` keyed only by
`(signer, pkt_id)` with small, cycle-reused `pkt_id` values means a witness alert can reference
a crypto record that's already been overwritten by a later packet reusing the same id
(`PENDING_FIXES.md` HF-1 section documents this exact sharing problem for
`mldsa87_verify_copy_content()`, measured there at ~5.6%). **This fresh evidence shows the rate
is far higher for witness timing specifically (13–21%, not ~5.6%)** — worth re-measuring rather
than assuming it's the same bug at the same magnitude.

**Action:** trace whether `witness_submit_duplication_alert()` reads its `t_verify` comparand
from the same shared-by-`(signer,pkt_id)` record, and if so, prioritize the per-instance (not
per-key) crypto record fix that `PENDING_FIXES.md` flagged as "a materially bigger change" and
deferred — this fresh evidence (13-21% vs the earlier 5.6% estimate) suggests it's a bigger
problem than previously scoped.

---

### 4. Batch cryptographic-verification ticks fail sporadically in every sampled run (not attack-onset-correlated)

**Evidence:** all 5 available deep timing reports show `[FAIL] All N batch ticks report
passed=1 (g_batch_passed=true)`:

| Run | passed=0 count | rate |
|---|---|---|
| A1_pct80 | 2/289 | 0.7% |
| A2_pct80 | 5/397 | 1.3% |
| A4_pct80 | 2/289 | 0.7% |
| A5_pct80 | 28/275 | **10.2%** |
| A8_pct80 | 16/188 | **8.5%** |

Checked whether this correlates with tick `elapsed` time exceeding the 50 ms budget — it does
not; failing ticks have `elapsed` as low as 0.005–0.044 s, well under budget, and are **not**
clustered at the attack's onset (`attack_start_time≈10s`) — e.g. A1's two failures are at
t=11.3s and t=17.25s, A2's five are scattered from t=3.5s to t=22.65s (some *before* the attack
even starts). This rules out the "correctly-flagged-a-delayed/attack-packet" explanation that
applies to a separate, adjacent finding (A2's STARK `timing_ok` FAIL is annotated by the report
itself as expected: *"STARK correctly flagged delayed packet — proof is working"* — that one is
not a bug, see note below).

**Action:** find what `g_batch_passed` actually asserts (likely a batch-level ML-DSA-87 batch
signature check distinct from per-packet STARK timing) and why 0.7–10% of batches fail it even
on ticks with no timing pressure and outside the attack window. The much higher rate on
A5/A8 (Hidden Forwarding) vs A1/A2/A4 suggests HF duplicate-packet traffic is contributing,
but the mechanism isn't yet traced.

---

### 5. TCAM-exhaustion attacks (A3/A4) essentially never trigger key rotation, unlike the other 6 attacks (found in the `bc_dkg_log` second pass)

**Evidence:** `bc_dkg_log_Attack{N}_60*.csv`, all 8 attacks, pct60:

| Attack | DKG rounds in this run | `n_rsus` sequence |
|---|---|---|
| A1 | 3 | 64 → 63 (drops once, stays) |
| A2 | 8 | 64 → 63 |
| **A3** | **1** | **64 (never drops — no re-keying happens at all)** |
| **A4** | **1** | **64 (same)** |
| A5 | 42 | 64 → 63 |
| A6 | 46 | 64 → 63 |
| A7 | 33 | 64 → 63 |
| A8 | 27 | 64 → 63 |

For the 6 non-TCAM attacks, DKG round 1 is the t=0 bootstrap ceremony (`n_rsus=64`); every
subsequent round drops to and holds at exactly `n_rsus=63` — one RSU is quarantined and excluded
from all future re-keying, and this fires repeatedly (3 to 46 times per 40 s run) as
`trust_update_negative()` re-triggers `dkg_rotate_keys()` (per `PENDING_FIXES.md`'s AB11
description of this call path). **For A3 and A4, only the single bootstrap round (t=0,
`n_rsus=64`) exists in the entire run** — the quarantine/re-keying path that fires 3–46 times for
every other attack never fires once for the two TCAM-exhaustion attacks, despite both being
under active attack at pct60 with `bc_trust_updates_Attack{3,4}_60.csv` confirming penalty events
*are* being recorded (33 and 158 rows respectively — see finding #6 in `PENDING_FIXES.md`'s
scoping note).

**Checked whether this explains finding #1's M4 latency pattern — it doesn't, and runs the
opposite direction:** A3/A4 have the *worst* M4 latency (6106 ms, 5932 ms) despite having the
*least* DKG/quarantine activity (zero re-keying), while A5/A6 (42/46 rounds of rapid re-keying)
have comparatively *better* M4 latency (2184 ms, 2208 ms) among the 8. So heavy DKG churn is not
the M4 bottleneck for the attacks that have it — if anything this suggests the opposite question:
**for A3/A4, does the quarantine mechanism actually reach the point of revoking/excluding the
offending RSU at all**, given `bc_trust_updates` shows penalty events but `bc_dkg_log` shows no
resulting re-keying? A quarantine that logs a "penalty" but never triggers the same
exclusion-from-DKG consequence the other 6 attacks show would be a real gap in the TCAM-attack
mitigation path specifically, and could be a better lead for A3/A4's outsized M4 numbers than
anything in finding #1's original action list.

**Action:** trace whether `trust_update_negative()`'s `dkg_rotate_keys()` call is reachable from
the S3/S4 (TCAM) detection path the same way it's reachable from S1/S2/S5-S8 — if TCAM-attack
penalties go through a different code path that skips key rotation, that's a real, fixable gap
worth closing (and worth checking against finding #1 before concluding the two are unrelated).

---

### 5b. `cur_TVR`/`avg_TVR` is completely dead (exactly 0.0000, every cycle) for Attack 3 specifically — its own data-plane sibling Attack 4 shows nonzero TVR, ruling out "TCAM attacks just don't cause forwarding delay"

**Found via a "dead code by dead metric" scan** — pulled every column of every attack's
`MOBIGUARD_Attack{N}_60*.csv` and flagged any column that never leaves its initial value across
all 28 cycles. Most of the ~15 dead-looking columns per attack turned out to be correctly scoped
(UFCR is CP-only, `WAP_precision`/`witness_TP_W` are passive-HF-only, `stark_timing_fail_count`
is S2-only per the AB4 ablation result already in `PENDING_FIXES.md`, `eps_ref_s` defaults to 0
by design, `ctrl_failover_*` is scoped to the S1/S3 CP-conflict and S5/S6 eavesdrop call sites
documented in `METHODOLOGY_CHAPTER_DEVIATIONS.md`). **`cur_TVR` on Attack 3 is the one exception
that isn't explained by any of those scoping rules.**

**Evidence — full per-cycle `cur_TVR` trace, Attacks 1–4 (all Selective-Time-Delay variants,
the only 4 TVR is scoped to per `METRICS_VERIFICATION_REPORT.md`):**
```
A1: 0 0 0 0 0 0 0 0 0 0.30 1.01 1.55 2.99 3.47 3.88 ... 5.16   (rises after cycle 9, attack onset)
A2: 6.73 10.75 11.67 ... 16.81                                (nonzero from cycle 1)
A3: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0    (exactly 0, all 28 cycles)
A4: 0 0 ... 0 (cycles 1-20) 0.04 0.08 0.11 0.22 0.21 0.20 0.20 0.33   (rises after cycle 20)
```
A1, A2, and A4 all eventually show nonzero TVR — A4 in particular is Attack 3's own sibling
(same TCAM-exhaustion mechanism, data-plane instead of control-plane) and clearly does register
safety-critical delay violations, just later and smaller in magnitude than A1/A2. **Attack 3 is
the only one of the four where TVR never leaves exactly zero, for the entire run.** This rules
out the simplest innocent explanation ("TCAM exhaustion doesn't cause forwarding delay, so TVR
correctly stays 0") — A4 disproves that directly, using the same underlying attack mechanism.

**Why this is worth flagging alongside finding #5:** this is the second TCAM-attack-specific
measurement pathway found dead for Attack 3 in this pass (the first being DKG re-keying/
quarantine exclusion, finding #5 above) — and Attack 3 is also the single worst attack for M4
mitigation latency (6106 ms, finding #1). Three independent signals now point the same
direction: Attack 3's specific code path (control-plane TCAM exhaustion) appears to under-exercise
detection/measurement machinery that fires correctly for every other variant, including its own
data-plane sibling.

**Action:** trace whether `is_safety_critical_flow[fid]`/`t_fwd_claimed` (the two conditions
gating the TVR increment site, per `METRICS_DEVIATIONS_FROM_PROPOSAL.md`'s original TVR fix) are
ever populated on Attack 3's specific packet path — control-plane TCAM exhaustion works by a
compromised controller flooding malicious FlowMods (`cp_attack_tick()`,
`tcam_attack_helper.h`), which may not route through the same per-packet claimed-forward-timestamp
bookkeeping that direct-injection delay (A1/A2) and data-plane TCAM flooding (A4) both hit. Worth
resolving together with finding #5's DKG-rotation gap, since both may share the same root cause
(a control-plane-specific code path bypassing per-packet instrumentation the other variants use).

---

### 9. `HOLD_FORWARD` local quarantine (`eq:local_quarantine`, part of `alg:lrad_obu`) is not implemented — OBU detection never actually pauses forwarding

**Not found in the logs — found by cross-referencing main.tex against the code directly**
(user request: check for unimplemented parts of the proposal). Grepped the whole codebase for
`HOLD_FORWARD`, `fwd_state`, `T_hold`, `RSU.Confirm` — **zero hits anywhere.**

**What main.tex specifies** (`eq:local_quarantine`, immediately following `alg:lrad_obu`'s
pseudocode): on OBU detection (`D_OBU=1`), the vehicle should suspend forwarding of flows
matching the flagged signature (`fwd_state(v) = Hold`) until either the RSU confirms
(`RSU.Confirm(v,r)`) or a timeout `T_hold` elapses — explicitly "to prevent an OBU from
continuing to forward potentially attack-affected traffic before the RSU completes full-mode
analysis."

**What the code actually does** (`scratch/lrad.h`): on `D_OBU=1`, `escalate_to_rsu()` queues
the event; 1ms later `process_escalation_at_rsu()` runs `lrad_rsu()`. There is no hold/pause
logic anywhere in that path — packets matching the flagged flow keep forwarding normally for
the entire escalation window (and indefinitely if the RSU never confirms), exactly the failure
mode the equation is meant to prevent.

**Why this matters:** `alg:lrad_obu` is a named Algorithm the thesis presents as implemented —
this isn't a peripheral equation, it's half of the dual-mode architecture's own stated
detection-response behavior, and it's absent for all 8 attack variants (every one dispatches
through `lrad_obu()`). It doesn't corrupt any currently-reported metric (M4 measures RSU-level
`SC.Quarantine`, not this local OBU-level hold), so it hasn't shown up as a numeric anomaly
anywhere in this run's data — it's a missing *behavior*, not a wrong *number*, which is exactly
why a log/CSV-only audit pass would never catch it.

**Action:** implement `fwd_state` tracking per (vehicle, flow-signature) with a `T_hold` timer
in `lrad.h`'s OBU path, gated the same way `escalate_to_rsu()` already is; or, if this was a
deliberate scope cut, document it explicitly in the thesis's implementation/limitations section
rather than leaving `alg:lrad_obu` presented as fully realized.
**Likely viva question:** *"Walk me through what happens to in-flight packets on the flagged
flow between OBU detection and RSU confirmation"* — the honest current answer is "they keep
forwarding normally," which contradicts the algorithm as written.

---

### 10. Controller delay-evidence channel (`eq:delay_evidence`) is not implemented — controller trust only reacts to unauthorized FlowMods, never to S1 timing evidence

**Also found by main.tex cross-reference, not the logs.** `scripts/audit_equations.py` itself
already documents this honestly (it's why this label is `[INFO]`/paper-only in the equation
audit rather than a silent gap): *"the controller-trust evidence channel is realised through
unauthorised-FlowMod conflict evidence... not by tallying per-RSU f_S1 outcomes."* Confirmed by
grep — `E_delay`, `delay_evidence`, and any per-controller accumulation of `f_S1(r_k,t)` outcomes
are absent from `scratch/*.h`/`*.cc`; `ctrl_trust_update_negative()` is reachable only from the
conflict-evidence path.

**What main.tex specifies** (`eq:delay_evidence`, feeding `eq:ctrl_trust_update`): controller
trust should be driven by **two independent evidence channels** — conflict evidence
(unauthorized FlowMods, implemented) and delay evidence (a count of independent RSUs assigned to
controller $c_i$ that detect S1 timing anomalies attributable to it, gated at an f+1 threshold
for BFT safety). Only the first channel exists in code.

**Why this matters:** Attack 1 (Selective Time Delay, Control Plane) is exactly the attack whose
own detection signature (S1) is supposed to feed this second channel — a CP-compromised
controller injecting timing delays should accumulate delay evidence toward revocation via
`eq:ctrl_trust_update`'s second branch, and currently cannot, at all. The controller can still be
revoked via the conflict-evidence channel if it also issues unauthorized FlowMods, but the
timing-anomaly-specific pathway the equation names is entirely absent.

**Action:** implement `E_delay(c_i,t)` — accumulate `f_S1(r_k,t)=1` events per RSU grouped by
`rsu_controller_assignment[r_k]`, gate at `f+1` independent RSUs (mirroring the BFT-threshold
pattern already used for witness alerts, `WITNESS_F+1`), and wire it into
`ctrl_trust_update_negative()`'s trigger condition alongside the existing conflict-evidence
check. If descoped deliberately, this should be stated in the thesis rather than left as an
equation with no corresponding code.

---

## P2 — Medium (verification-script accuracy issues — mislead a reader, not code defects)

### 6. `functional_verification.py` GROUP D reuses the `eq:sig_s1`/`eq:rule_s1` label for every attack's primary-signature check

**Evidence:** FV381–383 print `eq:sig_s1`/`eq:rule_s1` while the GROUP header itself correctly
says `[A5 Hidden Forwarding: Active, Control Plane]` — the underlying data is S5's own
confusion matrix (CSV only ever exports `selected_variant`, confirmed correct design per
`METRICS_VERIFICATION_REPORT.md` Critical Issue #1), but the printed equation tag doesn't
change per sweep. This is what made finding #2 read, at first glance, like "S1 is broken on
Attack 5" rather than "S5 is broken on Attack 5" — worth fixing so the log is self-explanatory
(and so a viva examiner skimming it doesn't draw the wrong conclusion).

**Action:** parameterize GROUP D's printed label by `active_attack_variant`'s own signature
name, the same way the GROUP header text already is.

### 7. GROUP K's `eq:trust_update` WARN fires for every non-TCAM attack sweep — expected, but worth silencing

**Evidence:** FV77/164/... — "`bc_trust_updates: N file(s) present but header-only`" WARNs on
A1, A2, A5–A8. Verified this is **not a bug**: `scratch/bc_blockchain_helper.h:6` documents
`bc_trust_updates.csv` as "one row per S3/S4 anomaly trust penalty event" — scoped to the two
TCAM attacks only. Confirmed A3/A4's own files are correctly populated at pct>0 (e.g.
`bc_trust_updates_Attack4_100.csv` has 273 rows) and correctly empty at pct=0 (no attack, no
penalty). The check just doesn't know this file is TCAM-scoped and flags every other attack the
same way.

**Action:** low priority — scope this WARN to A3/A4 sweeps only in the checker, or rename the
check description to make clear it's TCAM-specific.

### 8. `tcam_snapshots_attack1.csv` has 10 corrupted rows out of 311,904 — filename isn't seed/pct-disambiguated, vulnerable to concurrent-writer interleaving

**Evidence:** field-count check (expected 13 columns) on all 7 available `tcam_snapshots_attack{N}.csv`
files found malformed rows **only** in attack1's file (10/311904, all clustered in a ~1,100-row
window early in the file); attacks 2,4,5,6,7,8 (and `tcam_occupancy_*`/`lambda_l_true_*` for all
attacks) are clean. Example corrupted row:
`5,62,2,3.0.0.145,3.0.0.140,44628,26488,17,1.241158,3.758842,2,1500.0.0.163,3.0.0.48,1716,...` —
the `bytes` field (`1500`) is directly fused to the start of what looks like a *different* row's
`dst_ip` (`.0.0.163,...`), the classic signature of two processes' unbuffered/unlocked appends to
the same file interleaving mid-line.

**Root cause (plausible, matches an existing documented caution):** unlike
`MOBIGUARD_Attack{N}_{pct}_seed{S}.csv`, this filename has no `_pct`/`_seed` suffix — every
percentage point (and every seed) of Attack 1's sweep opens and appends to the **same**
`tcam_snapshots_attack1.csv`. `scratch/tcam_attack_helper.h` already has a comment acknowledging
exactly this hazard for the sibling `lambda_l_true_*.csv` file ("two concurrent sims collided
here even with distinct seeds") — this is the same class of bug, just caught in a different
sibling file this time, and only 10 rows out of 300K+ (rare — `--workers` parallelism has to line
up two writes at almost exactly the same instant to interleave mid-line).

**Action:** low priority given the rarity, but the fix is straightforward and matches the
existing MOBIGUARD-file convention: add `_pct{P}_seed{S}` to `tcam_snapshots_*.csv` and
`tcam_occupancy_*.csv`'s filenames (`tcam_attack_helper.h`) so concurrent sweep workers never
target the same file. Also worth adding a schema/field-count check for this file type to
`functional_verification.py`'s GROUP A (which currently only validates the MOBIGUARD CSV schema),
so future corruption like this surfaces automatically instead of needing a manual pass.

### 11. Experiment 4 / AOEI stealthiness sweep (`eq:aoei`, `eq:aoei_points`, main.tex §5499–5583) has no implementation at all

**Found by main.tex cross-reference, not the logs — this is missing evaluation infrastructure,
not a defect in anything currently running**, which is why it's ranked here rather than in P0/P1:
it doesn't corrupt any of the 8-attacks×6-percentages data already collected, it's simply an
entire experiment from the evaluation plan that hasn't been started.

**What main.tex specifies:** AOEI is a composite benchmarking x-variable combining an attacker
targeting-selectivity ratio (`n_targeted/n_eligible`) and a copy-destination hop-divergence term
(`d_div`), swept across 4 defined operating points (AOEI = 0.25/0.50/0.75/1.0, each with
specific targeting-fraction and divergence values given in the text) and evaluated on
M1/M2/M3/M4/M12.

**What exists in code:** nothing. Grepped for `n_targeted`, `n_eligible`, `d_div`,
`copy_destination`, `divergence`, `selectivity` (the last only matches S1's unrelated detector
selectivity conjunct, not this) — no code anywhere controls attacker targeting fraction or
copy-destination placement as tunable experiment parameters, and no `scripts/run_*.py` sweep
references AOEI at all. `scripts/audit_equations.py` correctly declares this paper-only (the
*formula* is legitimately an experimental-design choice, not a runtime quantity), but that
classification says nothing about whether the *experiment itself* — 4 configured simulation runs
— has ever been executed. It appears not to have been.

**Action:** implement the two missing knobs (a CLI flag or config to select which fraction of
eligible packets/flows the attacker targets, and one to place the unauthorized copy destination
at a controlled hop-distance from the authorized path), then build a dedicated sweep script
(mirroring `run_ablation_sweep.py`'s pattern) for the 4 AOEI operating points main.tex specifies
verbatim. This is new implementation work, not a bug fix — flagging it here so it doesn't get
missed before the benchmarking chapter is written.
**Coverage note:** `docs/METHODOLOGY_CHAPTER_DEVIATIONS.md` already flags that main.tex's
Ablation (§4124–4614) and Benchmarking (§4615–4964) study *descriptions* have never had a full
line-by-line read (only the metrics themselves were checked) — this finding came from exactly
that unreviewed region, which suggests there may be more experiment-level gaps like it still
there.

### 12. Per-packet blockchain receipt log (`eq:packet_receipt_log`) is replaced by a coarser witness/detection-event log — working substitute, but an undisclosed deviation

**Found by main.tex cross-reference.** main.tex specifies every RSU logs **every** packet
reception to the chain (`BC.LogReceipt(H(p), dst, r_k, ts_recv, verify_result)`), with a
`BC.QueryReceipt` lookup enabling cross-RSU duplicate detection for S6–S8 **without requiring
direct RSU-to-RSU communication channels.** `scripts/audit_equations.py` already documents the
actual implementation choice: *"this build records witness alerts and detection events on chain
(bc_write_detection_event) instead of a receipt per delivered packet."*

**Why this is a deviation worth stating, not just noting:** S6–S8 detection does work correctly
(confirmed extensively elsewhere in this document and in `METHODOLOGY_CHAPTER_DEVIATIONS.md`) —
but via local/ground-truth checks at the point of detection, not via the cross-RSU blockchain
query mechanism main.tex describes as the reason this logging exists in the first place. The
capability the equation motivates (RSU A learning about a packet RSU B observed, purely from
chain state, with no direct channel between them) isn't actually exercised by anything in the
current detection pipeline.

**Action:** no code fix needed if the current detection mechanism is accepted as sufficient —
but this should be stated explicitly in the thesis wherever `eq:packet_receipt_log`/S6–S8's
detection mechanism is described, rather than left implicit in a source comment only visible to
someone reading `scripts/audit_equations.py`.

---

## P3 — Confirmed non-issues (checked, no action needed)

- **`fade_results_V*.csv` header-only on all 48 files.** Expected: this run used
  `run_rule_based_sweep.py` (MOBIGUARD-only, no baseline), not `run_hf_attacks.py`
  (which pairs each HF attack with an isolated FADE run per `PENDING_FIXES.md` Fix 9). GROUP O's
  WARN correctly reflects this as a coverage gap, not a defect, per
  `docs/task8_verification/FUNCTIONAL_VERIFICATION_GUIDE.md` §7 note 3. Only actionable if a
  fresh FADE-comparison sweep is wanted for the thesis's benchmarking chapter.
- **A2's STARK `timing_ok` "FAIL"** (1904/2196 pass) is the checker correctly observing that a
  Selective-Time-Delay attack causes some packets to genuinely exceed `STARK_DELTA_MAX` — the
  report's own annotation confirms this is the proof *working*, not failing. No action.
- **No crashes.** Grepped all 48 `logs/rule_based_sweep/*.log` (up to 217 MB each) for
  segfault/abort/exception markers — zero hits across all 8 attacks × 6 percentages.
- **Causal ordering is clean everywhere sampled:** DKG-before-sign, sign-before-verify (3330/3330
  A1 packets checked), T_ref-sync-before-packet-window (29/29 windows), STARK-at-verify-time
  (2399/2399 A1 packets) all PASS with zero exceptions in every timing report read.
- **Equation/algorithm presence audit is fully clean:** 107/107 PASS, 0 FAIL, negative-control
  self-test (87/87) confirms no check passes vacuously — every `eq:`/`alg:` label in
  `docs/main.tex` (90 equations + 5 algorithms) resolves to a real symbol in the source tree.
- **All 8 attacks' `MOBIGUARD`, `bc_anchor_log`, `bc_tref_log`, `rsu_density`, `lambda_l_true`,
  and (except the one file in finding #8) `tcam_occupancy`/`tcam_snapshots` CSVs at pct60 are
  structurally clean:** no NaN/Inf, no unparseable rows, no negative values in fields that must be
  non-negative, `bc_anchor_log`'s per-RSU chain length monotonically non-decreasing with strictly
  increasing timestamps, `bc_tref_log`'s `t_ref_value` exactly equal to `seq` and `eps_ref` exactly
  `0.0000` in every one of the 232 rows checked (consistent with the default `f_bad=0`).
  `bc_flowmod_log`'s `is_malicious` flag is 0 in every row for the 6 non-TCAM attacks and nonzero
  (72%/91%) for A3/A4 — consistent with `bc_trust_updates`' documented TCAM-only scoping (finding
  #7), not a bug.
- **`eq:evasion_probability`, `eq:bhattacharyya`, `eq:l_priv` are correctly not implemented as
  code.** Checked each against main.tex directly: the first two are analytical/motivational
  equations in the Ch. 3 threat-model rationale (never meant to be runtime quantities), and
  `eq:l_priv` (M10) is defined by main.tex itself as an architectural/qualitative metric, not a
  runtime measurement. `scripts/audit_equations.py`'s `[INFO]`/paper-only classification for all
  three is correct — unlike findings #9–#12, these are not gaps.
- **Dead-metric scan (all 52/61 MOBIGUARD CSV columns × all 8 attacks at pct60) found ~15
  "always-0" columns per attack — all but one (finding #5b) are correctly scoped, not dead code.**
  `UFCR`/`ufcr_*` dead on every data-plane variant (2,4,6,8), alive on every control-plane variant
  (1,3,5,7) — matches main.tex's own CP-only UFCR scoping exactly. `witness_TP_W`/`WAP_precision`/
  `WAP_recall` dead on A1–A6, alive only on A7/A8 — matches the documented "Variants 7-8 specific"
  scope for WAP-R exactly. `stark_timing_fail_count` dead everywhere except A2 — matches the
  already-documented AB4 ablation finding that only S2's detection conjunct reads it.
  `ctrl_failover_*` dead on A2,A4,A7,A8, alive on A1,A3,A5,A6 — matches the two documented call
  sites (`routing.cc:118169` for CP FlowMod-endorsement failures, `routing.cc:121249` for S5/S6's
  eavesdrop path specifically, not S7/S8) exactly. `eps_ref_s`/`time_ref_f_bad` dead everywhere —
  expected, default `TIME_REF_F_BAD=0`. `o_crypto_bytes_pkt` constant everywhere — expected, a
  fixed-formula value, not a counter. None of these needed further investigation once traced
  against already-documented scoping; only finding #5b (Attack 3's fully-dead TVR) didn't fit any
  known scoping rule and is tracked above as a real, open finding.

---

## Suggested order of work

1. Fix #1 (M4 latency breakdown) and #2 (S5/S7 FPR) — both P0, both block honest presentation of
   M1/M4 results in the thesis. #2 has a concrete one-line fix available for S7 (calibrate
   `S7_EPSILON_VOL`) that can be done immediately while #1's tracing is set up.
2. Finding #0 — cheap documentation fixes (rename the CSV `result` value, add a thesis-text note
   near eq:endorsed_commit) can happen any time; the underlying "no real per-RSU independent
   verification" modeling gap is a supervisor conversation, not a code task, and isn't blocking.
3. Findings #5 and #5b (A3/A4 never trigger key rotation; Attack 3's TVR is completely dead) —
   trace together alongside #1, since between them they're the strongest available lead for *why*
   Attack 3 specifically has the worst M4 number of all 8 attacks, and may share one root cause
   (a control-plane-TCAM-specific code path bypassing per-packet instrumentation the other
   variants use); do this before concluding #1's root cause is fully understood.
4. Fix #3 (witness causal-order) and #4 (batch-tick failures) — both point at the same class of
   shared-keyed-crypto-record problem already flagged as future work in `PENDING_FIXES.md`; worth
   tracing together since the fix is likely shared.
5. Findings #9 (`HOLD_FORWARD`) and #10 (controller delay-evidence channel) — both are missing
   *behavior*, not wrong *numbers*, so they're not blocking any currently-collected result the
   way #1/#2 are, but both are named mechanisms (`alg:lrad_obu`, `eq:delay_evidence`) a viva panel
   could directly ask to see running — implement or explicitly scope out in the thesis before that
   conversation happens, whichever is decided, rather than leaving them silently absent.
6. Fixes #6/#7 — cheap, improves trustworthiness of the verification log for anyone (including
   a viva panel) reading it directly. Fix #8 (filename disambiguation) — cheap, low urgency given
   how rare the corruption is, but should be done before it silently corrupts a more consequential
   file.
7. Findings #11 (Experiment 4/AOEI) and #12 (packet-receipt-log substitution) — #11 is genuinely
   new implementation work (two experiment-control knobs plus a sweep script), not a small fix;
   start it early given how much lead time it needs relative to everything else on this list. #12
   is a documentation-only action (state the substitution explicitly in the thesis) and can happen
   any time.
8. No action on the P3 items — re-verify only if scope changes (e.g. a FADE-comparison sweep is
   added later).
