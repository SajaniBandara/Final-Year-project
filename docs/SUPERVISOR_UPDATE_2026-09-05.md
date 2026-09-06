# Supervisor update — round 7 (2026-09-05)

Subject: Items 1, 4 and 5 measured. Item 4 does not work as specified, and the
reason matters. Item 3's feasibility check is answered: regeneration is required.

All measurements below: seed 1, 60%, 90 s, `optimized`/`-O3` build, error gate
(`Solution not found` / link-lifetime) **0 on all 14 runs**. Every change is
behind a default-off flag, so nothing previously reported has moved.

---

## 1. Item 1 — vehicle-attacker enforcement. Done, and the map was not what we expected

You asked us to confirm rather than assume. The assumption did not hold.

**A6 and A8 were already fixed** on 2026-08-30, before your message, by guarding
`hf_gt_attribution_node(current_hop)` — the covering RSU — alongside the node
itself. Post-quarantine fires went 50→0 and 137→0.

**The real gap was A1 and A2**, which had no enforcement guard of any kind. Not an
inert guard — an absent one. This pulls **A1, a control-plane variant**, into the
scope your message set as "the four data-plane variants".

We added the same two-term guard to both Selective Time Delay injection sites.
Measured A/B, only `--enable_quarantine_enforcement` varied:

| variant | attacker | actions OFF | actions ON | change | quarantined (of which vehicles) |
|---|---|---|---|---|---|
| A1 | RSU | 834 | 159 | **−80.9%** | 25 (0) |
| A2 | vehicle | 7,249 | 1,985 | **−72.6%** | 93 (76) |
| A4 | vehicle | 49,689 | 44,392 | −10.7% | 142 (122) |

**Post-quarantine actions: 0 of 44,171.** Across 236 quarantined-and-acting nodes,
not one attack action after its own `t_quarantine`. That is your validation
criterion met exactly, on all three.

**A4's fix is now validated** — the A/B that had never been run. 122 vehicles reach
quarantine, against the original finding of **zero**. The trust-decrement fix works.
A4's smaller reduction is timing, not leakage: quarantine lands at t=18–41 s, after
the worst attacker has already installed 559 rules.

**One correction to our own earlier report.** We wrote that vehicles never cross the
trust threshold. That is TCAM-path-specific. In A2, 76 vehicles quarantine without
any covering-RSU proxy, because the S2/LRAD path already decrements vehicle trust.

---

## 2. Item 4 — implemented, exercised, and it makes things worse. Please read this one

The hook is wired and provably fires. `hf_truth_latch_clear()` went from zero
callers to firing on quarantine, split by attacker type as you specified:

| variant | attacker | latch clears (reset off → on) | quarantines |
|---|---|---|---|
| A5 | CP/RSU | 0 → 64 | 64 |
| A6 | DP/veh | 0 → 52 | 167 |
| A7 | CP/RSU | 0 → 66 | 68 |
| A8 | DP/veh | 0 → 45 | 164 |

Truth-positive windows fall as intended: A5 35→20, A6 130→30, A7 65→15, A8 142→56.

**But M1 falls on every variant, on both score columns:**

| variant | `score` Δ | `score_primary` Δ |
|---|---|---|
| A5 | −0.031 | −0.103 |
| A6 | −0.178 | **−0.326** |
| A7 | −0.109 | −0.209 |
| A8 | −0.164 | −0.195 |

**Diagnosis.** In A6/A8's treatment arm, **72–76% of the new false positives are
declared attackers firing in windows that begin after their own quarantine.** True
positives convert to false positives roughly one-for-one while true negatives
barely move.

Truth's boundary moved to quarantine. **The detector's did not.** S5–S8 contain no
quarantine awareness at all — none of the four files mentions it — so a contained
node keeps being accused forever. The drop being *larger* on `score_primary` rules
out the observer-attribution artefact; this is a genuine detector-side latch.

This is the same defect class as our §2 "one defect, three faces" finding,
reproduced in the mirror direction. Your reasoning — *"once enforcement lands the
compromised state genuinely ends at quarantine, so truth and detector agree by
construction"* — holds for truth. It does not hold for the detector, which was
never taught to stop.

**We are leaving it default-off and recommend not enabling it** until S5–S8 also
stop asserting on a quarantined node. That is a change to detection logic, not
measurement, so we are not making it without your instruction — and it collides
with the still-unanswered oracle-gate question (Q4 below).

---

## 3. Item 3 — feasibility answered: not recomputable, regeneration required

Four independent blockers, any one sufficient:

1. The per-RSU training row carries only the **already-collapsed global scalar** in
   its `d_div`/`a_tp` columns. No per-RSU destination set, no per-RSU delivery count.
2. `r_anom` is incremented on the *same source lines* with the right attribution,
   but it is an event **count**; `D_div`'s numerator is a **set cardinality**, and
   `A_tp` needs a per-RSU denominator that was never accumulated.
3. Raw stdout has no per-RSU per-cycle delivery record for HF runs. The only
   candidate line does not appear in HF logs at all.
4. The A5–A8 training set is not on this machine; it lives on the LSTM-dataset
   machine, where the same schema limits apply.

**Cost:** ≈60 runs × 300 s ≈ 20 core-hours, ≈2.5 h on 8 workers. Benign rows are
unaffected and need not be regenerated.

**We agree with your read on retrain scope** and are budgeting a full retrain
including the encoder. The unfrozen-encoder test (macro-MCC 0.3142 → 0.6781, A2 DR
37.1% → 85.1%) already established that the frozen latent was the binding
constraint; a latent trained to treat a broadcast constant as meaningful will not
transfer once that input becomes per-node.

The code is written and behind `--lstm_ddiv_atp_per_rsu`, so regeneration can start
the moment you approve, with no implementation lag.

### The five zero-variance features, sorted as you asked

**Group A — correct by spec. Scaler handling only, no feature change.**

| feature | why zero benign variance is correct | what it needs |
|---|---|---|
| `zkp_delay_fail` | binary {0,1}; fires only on a STARK timing-proof failure, an attack-only event | exempt binary indicators from z-scoring *explicitly*, not by accident via the `std=1.0` fallback |
| `zkp_hop_fail` | same, hop-proof failure | same |
| `r_anom` | unauthorized receptions do not occur benignly. **Genuinely per-RSU** — cross-RSU agreement 3.0%, within-stratum AUC 0.69–0.74 | it is an unbounded **count**, so the `std=1.0` fallback leaves it unnormalised beside z-scored features. Needs a real scale, and the choice stated |

**Group B — broken for the d_div reason:** `d_div`, `a_tp` only.

**So none of Group A is zero-variance for the broken reason.** The defect is confined
to the two already identified. Worth noting the cost: `d_div` contributes 1.498 mean
|z| on false-positive rows, while `r_anom` — which perfectly localises the attack,
exactly 0 on every negative row — contributes 0.876. The model is being told the
wrong thing, loudly.

---

## 4. Item 5 — M4 pair implemented, and it immediately shows the inversion

Both numbers now print on one line and export as CSV columns, so neither can be
quoted alone:

```
[SECURITY] M4 prevented=32.6% (46/141 stopped before acting)  |  latency=… ms over n=95 that acted first
```

Measured on A4:

| arm | acted-then-caught | stopped before acting | prevention rate |
|---|---|---|---|
| enforcement OFF | 50 | 46 | 0.479 |
| enforcement ON | 118 | 49 | **0.293** |

The *rate* falls while enforcement is on — because the denominator more than
doubled, not because prevention worsened (absolute prevented rose 46→49). That is
precisely the effect the pairing exists to expose, and a single number would have
hidden it.

---

## 5. Item 2 — UCR reach, closed

The per-cycle slot ID was audited across all six consumers on 2026-08-31: crypto
`g_packet_crypto` fixed, S2/TAP `claimed_forward_timestamp()` fixed, S6 safe by its
30 s window, S1 unaffected, LRAD's key fixed (collision was *masking* detections,
`flag_S2p` 2,197→2,272). **No other counter is inflated or deflated by it.**

The UCR fix is not variant-specific — one metric function, one dedup set now keyed
on H(p). A5–A8 are covered identically; only the A5–A7 write-up against the old
caption remains, which is reporting, not code.

**We withdraw one claim from our earlier draft.** We had listed the LRAD HMAC
verification as an unfixed defect. It is not — it is a documented modelling choice
(`CRYPTO_IMPLMENTATION.md` §2.5): HMAC authenticates origin, not truthfulness; the
S2 attacker is the forwarder itself and signs a false timestamp validly; no variant
models impersonation. What it needs is a sentence in the paper — that `flag_S2p`
reduces to its threshold term and S2-partial does not perform integrity
verification — not a code change.

The 76% residual interception figure will go in plainly as an honest limitation of
scheduling-only enforcement, as you directed.

---

# QUESTIONS

Q1–Q3 block work. The rest are reporting decisions we cannot make for you.

**Q1. Item 4's detector-side reset — do we make it?**
Moving truth's latch to quarantine without moving the detector's makes M1 worse on
all four HF variants (above). Fixing it means S5–S8 stop asserting on a quarantined
node. That is detection logic, not measurement. Do we proceed, and if so should the
detector's state clear at quarantine, or should quarantined nodes be excluded from
scoring altogether?

**Q2. Per-RSU `D_div` collapses to a near-binary. Accept it?**
`passive_hf_rsu_to_eavesdropper` maps one eavesdropper per malicious node, so a
per-RSU destination set has cardinality at most 2. Per-RSU `D_div` is therefore
close to `1 + 1[r_anom > 0]` — largely a function of `r_anom`. The fix **removes a
broadcast false signal; it does not add an independent one.** Still correct, but the
paper should not claim new discriminative power from it. Accept, or redefine
`D_div`'s destination space?

**Q3. `eq:feat_atp` does not define per-RSU attribution of an authorized delivery.**
That event fires at flow 0's single destination node, which is not an RSU. We have
implemented: credit the covering RSU of the last-hop sender, i.e. each RSU accounts
for the flow-0 traffic it actually relayed — the reading matching "per-flow
directional byte rate logs". Alternatives: credit the destination's covering RSU;
or drop `A_tp` as unspecifiable per-RSU. **This decides whether `A_tp` survives the
fix**, so we need it before regenerating.

**Q4. Does the S5–S8 oracle gate stay?** (Open since 2026-09-01.)
All four HF signatures early-return unless the node is in the attacker-assignment
array; `eq:sig_s5`'s five conjunctions do not include it. Consequence: S5–S8
**cannot** produce a false accusation, so their precision is an identity, not a
measurement, and `score_primary` is attacker-identity-aware and is not an achievable
ceiling. This caps what any post-fix A5–A8 number can claim, and it interacts with
Q1.

**Q5. Which M-numbering?** main.tex and `evaluator.py` conflict on M2/M3/M5/M7/M8 —
"M8" means poisoning resistance in one and UCR in the other. Every table depends on
the answer.

**Q6. Canonical M1 — recover `metrics/`, or bless the re-implementation?**
The package exists on no host here and was never in git history. Every M1 quoted in
the last three weeks comes from `scripts/m1_local.py`, a re-implementation: deltas
valid, absolute levels not comparable to the historical 0.2721. If it is genuinely
gone, we propose adopting the re-implementation formally and retiring 0.2721 as an
incomparable historical figure, stated as such.

**Q7. UCR's off-path predicate and window.** Code tests the attack's own eavesdropper
set; `eq:ucr` tests the blockchain-committed policy set. Code's window is the whole
run; the spec has an explicit `W`. Fix code to spec, or amend spec? Under the spec
reading, counting relay traffic reaching an off-path receiver is *correct*, which is
what makes 24% the honest containment number.

**Q8. `W = 10.0` exceeds the stated ≤ 9 s residence bound.** main.tex offers
`{5, 10, 15}` against that bound, so two of three candidates — including the current
default — are inadmissible. Is only W=5 valid, or is the bound context?

**Q9. Should `enable_corrected_lmit` default to 1?** At 0, any run that forgets the
flag reproduces the inverted M4.

**Q10. OBU rows in M1 — decided how?** Raised three times. Concrete consequence:
**S1 cannot affect M1 at all.** `dw_mark_obu()` writes OBU rows; M1 scores RSU rows
only. Confirmed empirically — after the S1 variance-floor fix, S1 fired 2.7× more
often and M1 was byte-identical. A1's M1 is carried entirely by S2. Either M1
incorporates OBU rows, or S1 is reported separately and the paper says so.

---

# APPENDIX — WHICH MCC WE REPORT, AND WHAT EACH CHOICE COSTS US

"M1" has meant at least four different numbers in this project. These are not
competing estimates of one quantity; they answer different questions. Nine
independent axes, each with what it has actually cost or gained **us**, measured.

## A. Unit of classification

**Per-RSU 10 s deduplicated blocks (`eq:eval_dedup`) — this is M1.**
*Good for us:* it is what main.tex specifies. Each block is scored independently, so
a later threshold change genuinely retracts earlier false positives. Deduplication
removes the 42% overlap the paper itself says "materially affects all figures". It
supports the per-variant and per-mobility stratification `eq:mcc_variant` requires.
*Costs us:* needs ≥90 s runs — a 30 s run has nothing left after the 30 s warm-up
exclusion. And it is non-stationary (axis I).

**Per-node, whole-run (the simulator's inline print).**
*Good for us:* cheap, live, and it carries per-component attribution via
`[SECURITY-SRC]` — that is how we established the LSTM contributed 828 false
positives against 65 true positives, the single most useful diagnostic we have. It
is also required for M4's `t_onset`/`t_quarantine`.
*Costs us:* `is_detected_node[][]` is a **sticky latch**, so warm-up false positives
are permanent and no later threshold change can retract them. It is run-length
dependent — the *same config* scored 55.6% precision at 20 s and 26.6% at 90 s. And
it is defined nowhere in main.tex.
**Verdict: keep as a diagnostic, never label it MCC or M1 in a results table.**

## B. Attribution column — `score` vs `score_primary`

These differ in **two** ways at once, detector set *and* attribution node. That
single confound produced three of six wrong conclusions in one session.

**`score` (D_RSU, observer-attributed).** *Good:* it is the deployed decision —
D_RSU is what actually drives BC.Write, BTMM and quarantine, so it is the honest
system number. *Costs:* `dw_mark_rsu()` marks the RSU *processing* the packet, so a
node is penalised for correctly detecting a malicious neighbour. 44.7% of A5–A8
false positives are true non-attackers.

**`score_primary` (suspect-attributed).** *Good:* correct attribution — non-attacker
FP share falls to 0–4.9%, M1 0.3836 → 0.6187. *Costs:* it is variant-aware **and**,
via the oracle gate (Q4), attacker-identity-aware. **It is not an achievable
deployment ceiling and must never be presented as one.**

**This axis is not academic for us — it produced today's most misleading number.**
With enforcement on, A1's `score` MCC read **−0.0966**, worse than random. All 53 of
its false negatives had `score_primary = 1`: the detector fired on every one. What
failed was observer attribution — a quarantined attacker stops forwarding, so it
stops observing its own attack traffic, and the observer-attributed column loses the
signal. Enforcement did not break detection; it amplified a defect we already knew
about. On `score_primary`, enforcement is neutral to positive (−0.047 to +0.027).

**Recommended: `score` with `--dw_mark_suspect`** — full deployed detector set,
correct attribution, measurement-only (`dw_mark_rsu()` writes only
`g_dw_rsu_fired[]`; D_RSU and every enforcement path are untouched). This is the
column behind our 0.7477.

## C. Persistence M (window positive iff detector fired in ≥ M cycles)

*Good:* free — `score_cycles` is already emitted, nothing rebuilds. M=3 is the best
global compromise (`score` pooled 0.3836 → 0.4831).
*Costs:* **pooled MCC is not decomposable across strata.** M=8 maximises the pooled
number while collapsing A1–A4 from 0.5818 to 0.3988 and leaving one variant at 10%
DR — the pooled figure cannot show you that. **Never M=8.** The families want
opposite values (A1–A4 peak at M=1, A5–A8 at ≈8), so any single global M is a
compromise by construction. And **M's value should shrink once the truth latch
lands, possibly reverse** — M was empirically reconstructing the activity gate from
firing density, a job the latch does properly. Do not stack them assuming they add.

## D. Aggregation — pooled vs macro

*Pooled:* one number, direct from `eq:mcc`. But it hides a collapsed variant — A3 at
−0.007 barely moves it.
*Macro:* `eq:mcc_variant` explicitly asks for per-variant scores "to prevent strong
variants masking weak ones", so macro is closer to the paper's stated intent. But
undefined and zero cells make ablation monotonicity ill-posed — Q3 macro −0.020, Q4
exactly 0.000 everywhere, because most variants have no value in an LSTM-only or
witness-only arm. Unresolved after three raisings.

## E. Per-cycle time-average vs cumulative-matrix MCC

*Per-cycle average* (what `avg_MCC` was in our TAP/MOBIGUARD CSVs): shows temporal
behaviour, but an average of ratios is not the ratio of averages — a cycle with one
event weighs the same as one with a thousand, and undefined cycles score 0 and drag
the mean.
*Cumulative matrix* (`mcc_matrix`, commit `7af0755`): one denominator, comparable
across baselines. **This mattered concretely: FADE and SFTO already reported matrix
MCC while TAP and MOBIGUARD reported the time-average, so our baseline comparison
was not apples-to-apples until this landed.** TAP's matrix MCC is A1 −0.13..−0.24,
A2 0.08..0.36. Cost: it discards the temporal story, which for us is real (axis I).

## F. Detector scope — LSTM alone vs full composite

The 0.895 table is `evaluator.py`: the LSTM alone, offline, warm-up-adapted per-RSU
θ, deduplicated. *Good:* the right unit for an ablation **about the LSTM**.
*Costs:* it is not the system. `D_RSU = S2f ∨ S5 ∨ S6 ∨ S7 ∨ S8 ∨ flag_LSTM`, and
OR-ing detectors monotonically increases false positives — composite FPR runs 40–86%
where LSTM-alone is 0.00–1.00%. **Quoting 0.895 as a system number is the mistake
that cost us a full session.** Its FPR 0.000 for A5–A7 also has TN = 0 under the
latched label: there are no negatives to be false about.

The three numbers, reconciled: **0.895** = LSTM alone; **0.272** = full-system
composite, *this is M1*; **0.264 / 0.219** = per-node diagnostic, not M1.

## G. Truth semantics — event-gated vs latched

| | A5–A8 MCC | DR | FPR | FP |
|---|---|---|---|---|
| event (a dormant compromised RSU is a negative) | 0.5928 | 98.6% | 38.9% | 1,621 |
| latched (positive until contained) | **0.7674** | 87.7% | **8.5%** | 189 |

73.8% of all remaining false positives are this one question. `preprocessor.py:229`
already applies this latch to `y_indep` with your prior approval, so today's mixed
state is the inconsistency. **Report as a measurement alignment, never as a detector
improvement.**

The general rule, which this project had never written down: **truth and detector
must be evaluated on the same time semantics.** Three separate "detector failures"
were one defect — A5–A8's 1,432 spurious FPs, A3/A4's 298 spurious FNs, and the two
families answering the same question oppositely. **Item 4 is the fourth face of it**,
and it is why that change fails today.

## H. OBU rows in or out

Out, currently, and correctly per `eq:eval_dedup` — every quantity in the paper's
evaluation is indexed by RSU, and the OBU that fires is the *victim*, not the
suspect. **Cost to us: S1 contributes nothing to M1** (Q10). A real decision with a
real price either way.

## I. Run length — not a choice, but it conditions everything above

M1 is **not stationary**. Pooled per 10 s window across a 300 s run:

| window | M1 | DR | FPR | FN |
|---|---|---|---|---|
| 40–50 s | **0.6958** (peak) | 98.3% | 30.5% | 4 |
| 110–120 s | 0.5480 | 85.0% | 28.8% | 30 |
| 270–280 s | 0.5139 | 84.3% | 32.5% | 34 |

The decay is **pure recall** — FPR is flat (23–33%, no trend) while FN grows 8.5×.
**Any M1 from a short run is inflated**, and a 90 s run samples only the favourable
early window — which is why every figure in this message is quoted as an off-vs-on
*delta*, with both arms inside the same window, rather than as an absolute level.
The A3 component of this decay is explained and fixed (`--tcam_truth_live` takes A3
to DR 100.0%); the A1/A2 component is not.

## Proposed convention

Macro of per-variant MCC, on the `score` column with `--dw_mark_suspect`, latched
truth, M re-measured after the latch, ≥300 s runs, run length always stated, and
`score_primary` shown beside it as a **labelled attribution diagnostic, explicitly
not a ceiling**. Conditional on Q4, Q5, Q6 and Q10.
