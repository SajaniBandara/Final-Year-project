# Draft reply — supervisor round 7 (2026-09-05)

Status against the five items, what is genuinely still missing, and the questions
we cannot answer ourselves. Everything below was re-verified against the working
tree today; where a claim rests on a measurement, the measurement is cited.

---

## 0. Status board

| # | item | state | what is actually left |
|---|---|---|---|
| 1 | Vehicle-attacker enforcement | **partly already done — but the gap is not where expected** | A1 and A2 have **no guard at all**; A4's fix landed but was never validated |
| 2 | UCR fix + reach | **done**; audit complete | one residual (LRAD tautology); A5–A7 re-verification not written up |
| 3 | Global-scalar feature | **feasibility answered: NOT recomputable** | full regeneration + full retrain needed; two spec rulings block the fix |
| 4 | Latch reset boundary | **not started** | `hf_truth_latch_clear()` has zero callers |
| 5 | M4 two-number format | counts exported; format **not implemented** | derived pair + reporting change + default flip |

---

## 1. Vehicle-attacker enforcement — the map is different from the one we expected

You asked us to confirm rather than assume. We did, and the assumption does not hold.

### 1.1 Current enforcement state, all eight variants

| variant | plane | attacker node | guard present | does it bite | evidence |
|---|---|---|---|---|---|
| A1 | CP | RSU | **NO GUARD** | — | `selective_time_delay.h` and both call sites (`routing.cc:121560`, `:125075`) contain no quarantine test |
| A2 | DP | vehicle *or* RSU | **NO GUARD** | — | same two sites |
| A3 | CP | RSU | yes — `tcam_attack_helper.h:784` | yes | installs 25,234 → 25,176 |
| A4 | DP | vehicle | yes | **fix landed, unvalidated** | `7cd6b5a` (2026-08-31) |
| A5 | CP | RSU | yes — `routing.cc:121655` | yes | post-quarantine fires → 0 |
| A6 | DP | vehicle | yes + covering-RSU term | **yes — fixed 2026-08-30** | post-quarantine fires 50 → 0 |
| A7 | CP | RSU | yes — `routing.cc:121751` | yes | post-quarantine fires → 0 |
| A8 | DP | vehicle | yes + covering-RSU term | **yes** | fires 137 → 0; intentional sends 9,950 → 89 (99.1%, 5 seeds) |

**A6 and A8 are not inert.** They were closed on 2026-08-30, before your message,
by guarding `hf_gt_attribution_node(current_hop)` alongside `current_hop` — the
covering RSU of the attacking vehicle. That second term is what makes the DP
hidden-forwarding variants respond, and the A/B is in
`docs/ITEM11_P1_A8_RISE_FALL_2026-08-31.md`.

**A4 needed a different fix and got one.** Guarding was never the problem there —
the guard already checked the attacking vehicle. Nothing decremented that
vehicle's trust, so `quarantine_blocks(attacker)` was permanently false. `7cd6b5a`
feeds `v_atk = argmax_v λ_PI(v,r,t)` (already computed for a log line) into
`trust_update_negative()` on every S4 fire, closing the loop. Detection attribution
is unchanged — S3/S4 still fire at the observing RSU.

**The genuine gap is A1 and A2.** Neither Selective Time Delay injection site
consults quarantine in any form. This is the one place where "the guard is inert"
understates it: there is no guard. Note this pulls **A1, a control-plane variant,**
into item 1's scope — A1's attacker is always the RSU holding the poisoned FlowMod,
so a guard there would bite immediately, exactly as A3's does.

### 1.2 What is left to do

1. Add the guard at both A1/A2 injection sites (`check_and_transmit` path and the
   retransmit path), mirroring the HF construction: test the injecting node **and**
   `hf_gt_attribution_node()` of it, since A2's attacker pool spans the full node
   space and can be a vehicle.
2. Run the A4 post-fix A/B that was never run. `logs/a4_quarantine/` is empty — the
   directory survived, the runs did not. Until that exists, A4 is "fix written",
   not "fix validated", and we should not report it as closed.
3. Re-run the same A/B for A1/A2 once guarded.

Validation protocol, identical to A3's: `--simTime=90 --sim_seed=1
--attack_percentage=60 --enable_quarantine_enforcement={0,1}`, compare
attack-conforming action counts on quarantined nodes before and after
`t_quarantine`.

---

## 2. UCR — fix confirmed, reach audited

### 2.1 Does the slot ID appear as a uniqueness key elsewhere?

Yes, in five other places. We audited every consumer on 2026-08-31; the audit is
complete and four of five were already safe:

| consumer | status |
|---|---|
| crypto `g_packet_crypto` | **fixed** — keyed `{signer, crypto_msg_key(pkt_id, flow_id)}` (12+12 bits). This was the FV688 causal-order bug |
| S2 / TAP `claimed_forward_timestamp()` | **fixed** — voids flow_id/packet_id entirely; identity now comes from the packet tag with an ownership check |
| S6 `s6_msg_recv_log` | **OK** — keyed on the pair but expires entries older than `S6_WINDOW_S = 30 s` before insertion, so it is window-scoped by construction |
| S1 | **unaffected** — takes packet_id/flow_id for logging only |
| LRAD `g_hmac_tags` | **partly fixed** — see below |

**One residual, and it is a reporting matter, not a code defect.** The LRAD key
originally omitted `flow_id`, so concurrent flows collided on one slot. Adding it
shifted `flag_S2p` fires 2,197 → 2,272 (+3.4%, `miss` bit-identical at 6,625 —
systematic, not noise); the collision was **masking** detections, not fabricating
them. That part is fixed.

`lrad_s2_partial_check()` does recompute the HMAC from the entry's own stored
timestamp and nonce, so the `memcmp` can never fail. **We are no longer proposing
to change this, and an earlier draft of this reply was wrong to call it unfixed.**
It is a deliberate, already-documented modelling choice: HMAC authenticates
*origin*, not truthfulness, and in S2 the malicious node is the forwarder itself,
which can sign a false timestamp perfectly validly. `alg:lrad_obu` (main.tex:2342)
annotates S2-partial *"threshold only, no ZKP"* for exactly this reason, and no
variant models impersonation, so the forgery this check would reject never occurs.
Recorded in `docs/CRYPTO_IMPLMENTATION.md` §2.5 and in its audit table.

**What it does require is a sentence in the paper.** `flag_S2p = HMAC.Verify ∧
(t_now − ts_recv) > Δ_max` reduces in practice to the threshold term alone, so
S2-partial must not be described as performing integrity verification. Tag
*generation* is real (OpenSSL, and its CPU cost is genuinely measured in
`crypto_timing_log`); verification is modelled.

### 2.2 Is the UCR fix A8-specific?

No. UCR is a single metric function with one dedup set
(`fade_eavesdropped_packets`, now keyed on H(p) per main.tex:1306); there is no
per-variant code path. The fix applies to A5–A8 identically with no further code
change. Corrected UCR figures exist for all four
(`output/hf/Figure_UCR_HF_AllAttacks.png`), but only A8 has been written up
against the old caption at 20% and 60%. Re-verification for A5–A7 is a reporting
task, not a code task.

### 2.3 The 76% number

Agreed, and it will go in plainly: **scheduling-only enforcement leaves ~76% of
interception intact** (eavesdropper receptions 168,097 → 127,203, −24.3%, 5 seeds),
against a 99.1% reduction in intentional duplicate sends. The gap is that a
quarantined RSU still forwards legitimate traffic that reaches the eavesdropper.
Receives-per-intentional-send goes 17:1 (off) → 1,011:1 (on), which makes it
unambiguous.

Two things still diverge from `eq:ucr` and we have not touched them:

- **Off-path predicate.** Spec tests `d' ∉ P(s_p, d_p)`, the blockchain-committed
  policy (`eq:policy_commit`). Code tests `is_eavesdropper_node` — the attack's own
  designated set. The metric is currently defined by attack configuration, not by
  policy.
- **Window.** Spec has `R(d', W)`. Code clears the dedup set once per run, so
  W = the whole run. S6 by contrast does implement a 30 s window.

Both are in the questions list below.

---

## 3. Global-scalar feature — feasibility check complete

**Verdict: the correct per-RSU values cannot be recomputed from anything we have
logged. Regeneration is required.** Four independent reasons, any one of which is
sufficient:

1. **The CSV schema never carried it.** The per-RSU training row is
   `cycle, rsu_id, delta_t, lambda_PI, U_TCAM, zkp_delay_fail, zkp_hop_fail, rho,
   v_bar, d_div, a_tp, r_anom, delta_exceed, escalated, label,
   lstm_anomaly_score, d_lstm, hf_send_gt`. The `d_div`/`a_tp` columns hold the
   **already-collapsed global scalar**. No per-RSU destination set, no per-RSU
   delivery count, no per-RSU byte counts.
2. **The nearest per-RSU quantity is the wrong shape.** `r_anom` is incremented on
   the *same source lines* as the `d_div` accumulators, already attributed via
   `hf_gt_attribution_node()` — but it is an event **count**, and `D_div`'s
   numerator is a **set cardinality**. A count cannot be inverted to a set. `A_tp`
   additionally needs a per-RSU denominator (`total_delivery`) that was never
   accumulated per RSU at all.
3. **The raw stdout does not carry it either.** The only candidate is eFADE's
   per-node `recv=/fwd=` debug line (`efade_detection.h:489`). It does not appear
   in the HF logs at all (`grep -c` on `logs/A6_pct40_seed1.log` returns 0), and it
   is path-scoped and cumulative rather than per-RSU per-cycle, so it would not
   suffice even where present.
4. **The A5–A8 training set is not on this machine.** `results_routing/lstm_training/`
   here holds Attack 0–4 only. The 1,372,800-row analysis was run on the
   LSTM-dataset machine. Reasons 1–3 apply equally there — this is a schema limit,
   not a missing-file problem.

### 3.1 The fix itself is small

One line per site. `g_lstm_flow0_dest_set` / `g_lstm_flow0_total_delivery_count` /
`g_lstm_flow0_legit_count` (`crypto_layer.h:868-869`) become RSU-keyed maps, and
the three `MacRx` accumulation sites (`routing.cc:122191, :122266, :122303`) key
them by `hf_gt_attribution_node(prev_sender)` — the value already computed on the
adjacent line for `g_lstm_ranom_count`. The attribution machinery is entirely in
place; only the container shape is wrong.

### 3.2 Regeneration cost estimate

A5–A8 × pct {20, 60, 100} × seeds 1–5 = 60 runs at 300 s. At the measured
3.93 wall-s/sim-s (`optimized`, `-O3` confirmed) that is ~20 min/run ≈ **20 core-hours**,
or roughly 2.5 h on 8 workers. Benign (Attack 0) rows are unaffected and need not
be regenerated. Plus the retrain.

### 3.3 Retrain scope — we agree with your read

Budgeting for a **full retrain including the encoder**, not a frozen fine-tune.
The unfrozen-encoder test earlier this session moved macro-MCC 0.3142 → 0.6781 and
A2 DR 37.1% → 85.1%, which established that the frozen latent — not head capacity —
was the binding constraint. A latent trained to treat a broadcast constant as
meaningful will not transfer once that input becomes per-node.

### 3.4 What blocks us from just doing it

Two rulings, both in the questions list. In short: the spec-correct per-RSU `D_div`
appears to collapse to a near-binary quantity, and `eq:feat_atp` does not define
who is credited with an authorized delivery. Details in Q3 and Q4.

Agreed on the freeze: **no Q1–Q6 grid until this lands.** Every A5–A8 number from
prior rounds is marked provisional in our tables.

### 3.5 The five zero-variance features, sorted as requested

**Group A — correct by spec; scaler handling only, no feature change.**

| feature | why zero benign variance is correct | handling needed |
|---|---|---|
| `zkp_delay_fail` | binary {0,1}; fires only on a STARK timing-proof failure, an attack-only event | exempt binary indicators from z-scoring **explicitly**, not by accident via the `std=1.0` fallback |
| `zkp_hop_fail` | same, hop-proof failure | same |
| `r_anom` | unauthorized receptions do not occur benignly. **Genuinely per-RSU** — cross-RSU agreement 3.0%, within-stratum AUC 0.69–0.74 | it is an unbounded **count**, so `std=1.0` leaves it unnormalised at raw post-`log1p` scale beside z-scored features. Needs a real scale (attack-inclusive scaler fit, or a stated fixed divisor) |

**Group B — zero benign variance is also correct, but broken under attack for the
d_div/a_tp reason.**

`d_div`, `a_tp`. Benign 1.0 is the correct resting value; the defect is
**cross-RSU constancy under attack** (100.0% of cycles have all 32 sampled RSUs
identical; within-stratum AUC exactly 0.500). Fixed by §3.1.

**So: none of the three Group A features are zero-variance for the broken reason.**
The broadcast defect is confined to the two already identified. `r_anom`'s
scaler treatment is a real problem, but it is a normalisation bug, not a feature
bug — worth noting because `d_div` currently contributes 1.498 mean |z| on
false-positive rows while `r_anom`, which perfectly localises the attack (0.000 on
every negative row, infinite margin), contributes 0.876.

---

## 4. Latch reset boundary — not started, and the conditional may be moot

`hf_truth_latch_clear(rsu_local_idx)` exists at `crypto_layer.h:823` and has
**zero callers**. It is a hook and nothing more.

Implementing your conditional exposes something worth flagging before we build it:
**the latch is HF-only.** `g_hf_activity_latch` covers A5–A8; A3/A4 use
`--tcam_truth_live` instead, and A1/A2 have their own event gate. So the
per-variant matrix has only four cells — and per §1, **all four HF variants have
confirmed working enforcement.** The conditional is implementable exactly as you
describe, but at present no variant sits on the end-of-run side of it.

We will build it as a per-variant setting anyway, defaulting reset-at-quarantine
for A5–A8, so that the structure is in place if A1/A2 latching is ever added and
so the distinction is explicit in code rather than implicit.

One caveat that bears on whether A6/A8 should really be on the "confirmed" side:
their enforcement bites via the **covering RSU**, not the attacking vehicle.
Vehicles still never cross the trust threshold in HF runs. See Q1.

---

## 5. M4 — understood, and here is what is already in place

The two raw counts are already exported per commit `865d4ad`:
`lmit_scored_n` (nodes averaged into the mean) and `lmit_blocked_before_acting`
(quarantined having never acted), both columns in the MOBIGUARD CSV.

Three small things remain, none of them blocked:

1. Derive and export the pair explicitly —
   prevention rate = `blocked_before_acting / (blocked_before_acting + scored_n)`,
   mean latency over `scored_n` only.
2. Make the pair the reporting unit in the plot/summary scripts. Right now nothing
   downstream computes it; the mean is still quotable alone, which is exactly the
   failure mode (58 of 67 quarantined nodes fell into the excluded bucket last run,
   leaving a "latency" that was the mean over the 9 slowest survivors).
3. Decide whether `enable_corrected_lmit` flips to default 1. It currently
   defaults 0 = legacy, which reproduces the inverted metric.

Parked until item 1 closes, as instructed.

---

## 6. Still missing, outside your five — these bear on the sweep you want to authorise

- **The S5–S8 oracle gate is still unruled.** All four HF signatures early-return
  unless `active_/passive_hf_malicious_nodes[prev_sender]` — the attacker-assignment
  array written by the injector. `eq:sig_s5`'s five conjunctions do not include it.
  Consequence: S5–S8 **cannot** produce a false accusation, so their precision is an
  identity rather than a measurement, and `score_primary` is attacker-identity-aware
  and is not an achievable ceiling. Raised 2026-09-01, unanswered. This caps what
  any post-fix A5–A8 number can claim.
- **M-numbering conflict.** main.tex and `evaluator.py` disagree on M2/M3/M5/M7/M8;
  "M8" means poisoning resistance in one and UCR in the other. Open since 08-31.
- **Canonical M1 is unreproducible.** `scripts/m1_from_detector_windows.py` requires
  `python3 -m metrics.run_metrics`; that package exists on no host here and was never
  in git history. Every M1 quoted in the last three weeks comes from
  `scripts/m1_local.py`, a re-implementation — deltas valid, absolute levels not
  comparable to the historical 0.2721.
- **`LSTM_HC_MULT` is broken under the classifier head.** `high_conf = score > 2.0 × θ`,
  but P(attack) ≤ 1.0 and θ median 0.940 ⇒ bar 1.88, unreachable for 44 of 64 RSUs.
  The multiplicative test was designed for the autoencoder's unbounded reconstruction
  error; it needs an additive or percentile form.
- **`W` contradicts itself in main.tex.** `[tbd: {5, 10, 15} s]` against a stated
  "≤ 9 s zone residence bound" — two of three candidates exceed the bound,
  **including the current default of 10.0**.
- **A1/A2 have an unexplained recall decay** (DR 96% → 74% and 88% → 74% across a
  300 s run). Not the TCAM latch; none of the September corrections address it.

---

## 7. Questions we cannot answer ourselves

Numbered for reply. Q3 and Q4 block item 3; Q5 caps what item 3's result can claim.

**Q1 — Is proxy attribution acceptable for the DP hidden-forwarding variants?**
A6/A8 enforcement works by guarding the attacking vehicle's **covering RSU**, since
vehicles never cross the trust threshold. That over-blocks: every vehicle under a
quarantined RSU is denied the action, not only the attacker. The alternative is to
give vehicles their own trust path, as A4 now has via S4's `v_atk` attribution.
Which do you want, and does the paper need to state the proxy?

**Q2 — Should A1 be in item 1's scope?** You scoped item 1 to the data-plane
variants, but A1 is control-plane and has no enforcement guard at all. Its attacker
is always an RSU, so a guard would bite immediately. We propose including it; confirm.

**Q3 — Per-RSU `D_div` looks like it collapses to a binary.**
`passive_hf_rsu_to_eavesdropper` maps one eavesdropper per malicious node, and the
legitimate-delivery site inserts exactly one destination. So a per-RSU destination
set has cardinality ∈ {1, 2}, making
`D_div_per_rsu = 1 + 1[r_anom > 0]` — a deterministic function of `r_anom`. The fix
would therefore **remove broadcast noise without adding independent signal.** Is
that the intended outcome, or should `D_div`'s destination space be redefined
(e.g. over all off-path receivers, or over the policy set of `eq:policy_commit`)
so it carries graded information?

**Q4 — `eq:feat_atp` does not define per-RSU attribution of authorized deliveries.**
The "authorized" event fires only at flow 0's single destination node, which is not
an RSU. Three options: (i) credit the covering RSU of the destination;
(ii) use per-RSU directional byte counts as main.tex's wording implies
("per-flow directional byte rate logs") — `fade_forwarded_count`/`fade_received_count`
already exist per node and could be promoted; (iii) drop `A_tp` as unspecifiable
per-RSU. This decides whether `A_tp` survives the fix at all, so we need it before
regenerating.

**Q5 — Does the S5–S8 oracle gate stay?** If deliberate ("compromise identified
out-of-band"), it must be stated in the paper because it changes what S5–S8 claim
to do. If not, S5–S8 need the gate removed and every HF precision number re-measured.
Open since 2026-09-01.

**Q6 — Which M-numbering convention?** main.tex or `evaluator.py`. One of them has
to give, and every table depends on the answer.

**Q7 — Canonical M1: recover `metrics/`, or bless the re-implementation?** If the
package is genuinely gone, `m1_local.py` should be adopted formally and 0.2721
retired as an incomparable historical figure, stated as such.

**Q8 — UCR's off-path predicate and window.** Code tests the attack's eavesdropper
set; `eq:ucr` tests the blockchain-committed policy set. Code's window is the whole
run; the spec has an explicit `W`. Fix the code to spec, or amend the spec? Note
that under the spec reading, counting relay traffic that reaches an off-path
receiver is **correct**, which is what makes 24% the honest containment number.

**Q9 — `W = 10.0` exceeds the stated ≤ 9 s residence bound.** Either only W = 5 is
admissible and the default is invalid, or the bound is context rather than a
constraint. This decides whether a `W` sweep is worth running at all.

**Q10 — Should `enable_corrected_lmit` default to 1?** Leaving it at 0 means any run
that forgets the flag reproduces the inverted M4.

**Q11 — OBU rows in M1.** Raised three times, still open, and it has a concrete
consequence: **S1 cannot affect M1 at all.** `dw_mark_obu()` writes OBU rows; M1
scores RSU rows only. Confirmed empirically — after the S1 variance-floor fix, S1
fired 2.7× more often and M1 was byte-identical. A1's M1 is carried entirely by S2.
Either M1 incorporates OBU rows, or S1 is reported separately and the paper says so.

---

## Appendix — how M1 can be computed, and what each choice costs

Nine independent axes. They compose, which is why "M1" has meant at least four
different numbers in this project's history. Each row below is a real choice
someone has to make, not a hypothetical.

### A. Unit of classification

| | **per-RSU × 10 s deduplicated block** (`eq:eval_dedup`) | **per-node, whole run** (simulator's inline print) |
|---|---|---|
| **Pros** | It is what main.tex specifies. Each block scored independently, so a later threshold change genuinely retracts earlier false positives. Dedup removes the 42% overlap inflation the paper itself calls "materially affecting all figures". Supports `eq:mcc_variant` and `eq:mcc_mobility` stratification. | Cheap, computed live, no post-processing. Gives per-component attribution via `record_detection_event(..., DSRC_*)` → `[SECURITY-SRC]` — this is how we established the LSTM contributed 828 FPs against 65 TPs. Required for M4's `t_onset`/`t_quarantine`. |
| **Cons** | Needs ≥ 90 s runs (30 s warm-up exclusion removes a 30 s run entirely). Non-stationary — see axis I. The canonical scorer does not exist on any host (Q7). | `is_detected_node[][]` is a **sticky latch**: warm-up FPs are permanent and no later threshold change can retract them. Run-length dependent — 55.6% precision at 20 s vs 26.6% at 90 s, same config. **Defined nowhere in main.tex.** |
| **Verdict** | Report this as M1. | Keep as a diagnostic. Never label it MCC or M1 in a results table. |

### B. Attribution column — `score` vs `score_primary`

They differ in **two** ways at once — detector set *and* attribution node — which
is a confound that produced three separate wrong conclusions in one session.

- **`score` (D_RSU, observer-attributed).** Pro: it is the deployed decision — D_RSU
  is what actually drives BC.Write, BTMM and quarantine, so it is the honest
  system number. Con: `dw_mark_rsu()` marks the RSU *processing* the packet, so a
  node is penalised for correctly detecting a malicious neighbour. 44.7% of A5–A8
  false positives are true non-attackers.
- **`score_primary` (primary signatures, suspect-attributed).** Pro: correct
  attribution — non-attacker FP share falls to 0–4.9%; M1 0.3836 → 0.6187. Con: it
  is variant-aware **and**, via the S5–S8 oracle gate (Q5), attacker-identity-aware.
  **It is not an achievable deployment ceiling** and must not be presented as one.
- **Recommended: `score` with `--dw_mark_suspect`.** Full deployed detector set,
  correct attribution, measurement-only (`dw_mark_rsu()` writes only
  `g_dw_rsu_fired[]`; D_RSU and every enforcement path are untouched). This is the
  column behind the 0.7477 figure.

### C. Persistence M — a window counts positive only if the detector fired in ≥ M of its cycles

Pros: free — `detector_windows.h` already emits `score_cycles`, nothing rebuilds.
M = 3 is the best global compromise (`score` pooled 0.3836 → 0.4831).

Cons, and they are serious:
- **Pooled MCC is not decomposable across strata.** M = 8 maximises the *pooled*
  number while collapsing A1–A4 from 0.5818 to 0.3988 and leaving one variant at
  10% DR. The pooled figure cannot show you that. **Never use M = 8.**
- The families want opposite values — A1–A4 peak at M = 1, A5–A8 at ≈ 8 — so any
  single global M is a compromise by construction.
- **M's value should shrink once the truth latch lands, and may reverse.** M was
  empirically reconstructing the activity gate from firing density (dormant median
  2–3 cycles vs active 4–6). Latching the truth does that job properly, so the two
  do **not** stack. Re-measure M after item 4, do not assume additivity.

### D. Aggregation — pooled vs macro

- **Pooled** (one confusion matrix over all variants). Pro: single number, direct
  from `eq:mcc`. Con: hides a collapsed variant — A3 at −0.007 barely moves it.
- **Macro** (mean of per-variant MCC). Pro: `eq:mcc_variant` explicitly asks for
  per-variant scores "to prevent strong variants masking weak ones in aggregate
  figures" — macro is closer to the paper's stated intent. Con: undefined and zero
  cells make ablation monotonicity ill-posed (Q3 macro −0.020, Q4 exactly 0.000
  everywhere, because most variants have no value in an LSTM-only or witness-only
  arm). Still unresolved after three raisings.

### E. Time-averaged per-cycle MCC vs cumulative-matrix MCC

- **Per-cycle average** (what `avg_MCC` was in the TAP/MOBIGUARD CSVs). Pro: shows
  temporal behaviour. Con: an average of ratios is not the ratio of averages; a
  cycle with one event weighs the same as one with a thousand; undefined cycles
  score 0 and drag the mean down.
- **Cumulative matrix** (`mcc_matrix`, commit `7af0755`). Pro: one denominator,
  comparable across baselines — FADE and SFTO already reported it, so TAP/MOBIGUARD
  were not comparable to them until this landed. Con: discards the temporal story,
  which for this system is real information (axis I).

### F. Detector scope — LSTM alone vs the full composite

The 0.895 table came from `lstm_pipeline/src/evaluator.py`: the LSTM alone,
offline, warm-up-adapted per-RSU θ, deduplicated. Pro: the right unit for an
ablation *about the LSTM*. Con: it is not the system. `D_RSU = S2f ∨ S5 ∨ S6 ∨ S7 ∨
S8 ∨ flag_LSTM`, and OR-ing detectors monotonically increases false positives — so
composite FPR is 40–86% where LSTM-alone is 0.00–1.00%. DR is comparable
(80–99% vs 84–93%); only FPR diverges. **Quoting 0.895 as a system number is the
specific mistake that cost a full session.** Also note its FPR 0.000 for A5–A7 has
TN = 0 under the latched `y_indep` label — there are no negatives to be false about.

### G. Truth semantics — event-gated vs latched

| | A5–A8 MCC | DR | FPR | FP |
|---|---|---|---|---|
| event-gated (a dormant compromised RSU is a negative) | 0.5928 | 98.6% | 38.9% | 1,621 |
| latched (positive until contained) | **0.7674** | 87.7% | **8.5%** | 189 |

73.8% of all remaining false positives are this one question. Argument for latched:
`preprocessor.py:229` already applies exactly this latch to `y_indep`'s HF term with
prior approval, so today's mixed state is the inconsistency. **Report as a
measurement alignment, never as a detector improvement.**

The general rule, which this project had never stated: **truth and detector must be
evaluated on the same time semantics.** Three separate "detector failures" turned
out to be one defect — A5–A8's 1,432 spurious FPs (event truth vs latched detector),
A3/A4's 298 spurious FNs (latched truth vs live detector), and the two families
answering the same question oppositely.

### H. OBU rows in or out

Out, currently, and correctly per `eq:eval_dedup` — every quantity in the paper's
evaluation is indexed by the RSU, and the OBU that fires is the *victim*, not the
suspect, so there is nothing coherent to score there. **But the consequence is that
S1 contributes nothing to M1** (Q11). This is a reporting decision with a real cost
either way.

### I. Run length — not a choice, but it conditions every number above

M1 is **not stationary**. Pooled per 10 s window across a 300 s run:

| window | M1 | DR | FPR | FN |
|---|---|---|---|---|
| 40–50 s | **0.6958** (peak) | 98.3% | 30.5% | 4 |
| 110–120 s | 0.5480 | 85.0% | 28.8% | 30 |
| 270–280 s | 0.5139 | 84.3% | 32.5% | 34 |

The decay is **pure recall** — FPR is flat (23–33%, no trend) while FN grows 8.5×.
**Any M1 quoted from a short run is inflated**, and a 90 s run samples only the
favourable early window. Always state run length beside an M1 figure. The A3
component of this decay is fully explained and fixed (`--tcam_truth_live` takes A3
to DR 100.0%); the A1/A2 component is not (§6).

### Proposed reporting convention

Macro of per-variant MCC, on the `score` column with `--dw_mark_suspect`, latched
truth, M re-measured after the latch, ≥ 300 s runs, run length always stated, and
`score_primary` shown beside it as a **labelled attribution diagnostic, explicitly
not a ceiling**. Conditional on Q5, Q6, Q7 and Q11.

---

## Appendix B — what was implemented this session (2026-09-05)

Every change is behind a **default-off flag**, so all previously reported numbers
reproduce bit-identically until a flag is explicitly set. That is deliberate: it
lets each fix be measured as a clean A/B on one binary rather than landing as an
untracked shift in the results.

| # | change | flag | default |
|---|---|---|---|
| 1 | A1/A2 quarantine guard at both Selective Time Delay injection sites | `--enable_quarantine_enforcement` (existing) | off |
| 3 | Per-RSU `D_div`/`A_tp` accumulators + logger | `--lstm_ddiv_atp_per_rsu` | off |
| 4 | HF latch released at quarantine time, per attacker type | `--hf_latch_reset_rsu_attacker`, `--hf_latch_reset_vehicle_attacker` | both off |
| 5 | M4 reported as a pair; `lmit_prevention_rate` derived and exported | (always on — additive only) | n/a |

### Item 1 — `scratch/selective_time_delay.h`

New `std_delay_quarantine_blocks(injector)`, tested inside each of the four
attack branches (DP and CP, in both `calculate_unified_selective_delay()` and
`schedule_unified_selective_delay_attack()`). It tests the injector **and**
`hf_gt_attribution_node(injector)`, mirroring the A6/A8 construction, because
A2's injector can be a vehicle and vehicles never cross the trust threshold.
`hf_gt_attribution_node()` maps an RSU to itself, so A1 needs no special case.

Placed inside the branches rather than at function entry so the covering-RSU
lookup is paid only on packets an attack would actually fire on.

### Item 3 — `crypto_layer.h`, `routing.cc`, `lstm_logger.h`

Three RSU-keyed maps parallel to the existing globals, populated at the same
three `MacRx` sites using the `hf_gt_attribution_node()` value already computed
on the adjacent line for `g_lstm_ranom_count`. The globals are untouched, so the
off path is unchanged.

**The attribution rule we had to choose is Q4 and we have made it explicit in
code rather than silently:** authorized deliveries are credited to the covering
RSU of the packet's last-hop sender — each RSU accounts for the flow-0 traffic it
actually relayed — which is the reading that matches main.tex's "per-flow
directional byte rate logs". If you rule differently, one function changes.

This is written but **not run**: turning it on requires the regeneration we are
waiting on your approval for.

### Item 4 — `crypto_layer.h`

`hf_truth_latch_clear()` now has a caller, inside `trust_update_negative()` at
the point quarantine fires. Split by attacker type per your instruction:
`hf_latch_reset_rsu_attacker` covers A5/A7, `hf_latch_reset_vehicle_attacker`
covers A6/A8.

One implementation detail worth surfacing. For a vehicle attacker the latch sits
on the **covering RSU**, which may also cover other attacking vehicles that are
still active. Clearing it unconditionally would blank the truth for attackers
that have not been contained — the mirror image of the guard's over-block. So the
latch is released only once no non-quarantined HF attacker still attributes to
that RSU. Logged as `[HF-LATCH-CLEAR]` so the boundary is auditable.

### Item 5 — `routing.cc`

`g_lmit_prevention_rate = blocked_before_acting / (blocked_before_acting +
scored_n)`, exported as a new `lmit_prevention_rate` CSV column and printed on
**one line** with the latency and both population sizes:

```
[SECURITY] M4 prevented=86.6% (58/67 stopped before acting)  |  latency=2697 ms over n=9 that acted first
```

Printing them together is the point — neither half can now be quoted alone.

### Not changed, and why — a correction to §2.1 above

The LRAD HMAC "tautology" is **not** a defect and we withdraw the earlier
characterisation. It is a documented modelling choice (`CRYPTO_IMPLMENTATION.md`
§2.5): HMAC authenticates origin, not truthfulness; the S2 attacker is the
forwarder itself and can sign a false timestamp validly; no variant models
impersonation. `alg:lrad_obu` annotates S2-partial *"threshold only, no ZKP"* for
precisely this reason. What it needs is a sentence in the paper — that
`flag_S2p` reduces to its threshold term — not a code change.
