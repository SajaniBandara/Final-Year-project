# Draft reply — round 10 (re-measurement delivered; a second metric-side defect found)

Status: draft for sending. Send everything below the rule.
Evidence: 24 runs at 300 s (all rc=0), 8 enforcement runs at 90 s (all rc=0).

---

Understood on all counts, and you were right that the last message diagnosed
rather than delivered. The re-measurement is done and is below, first, as asked.

It comes with a caveat that I want stated before the numbers rather than after,
because it changes how two rows should be read: while producing this table we
found a second defect, on the metric side rather than the detector side, that
silently discards a large fraction of true detections. It is pre-existing, it is
not the S5 fix, and it makes A5 and A6 unreportable in the tables below. Details
in §2.

## 1. The re-measurement — Q5 and item 4, on the S5-fixed build

24 runs: 3 arms × 8 variants, `simTime=300` (reportable), 60 %, seed 1, all
rc=0. Both S5 fixes on in every arm. Column is `score_primary`, the per-variant
primary detector.

**Q5 — what the oracle gate was worth:**

| variant | gate OFF (honest) | gate ON (legacy) | inflation |
|---|---|---|---|
| A1 | 0.6095 | 0.6095 | 0 |
| A2 | 0.9719 | 0.9719 | 0 |
| A3 | 0.5531 | 0.5531 | 0 |
| A4 | 0.5418 | 0.5418 | 0 |
| A5 | 0.0000 † | 0.0000 † | — |
| A6 | −0.0089 † | 0.4200 | **+0.4289** |
| A7 | 0.0633 | 0.3313 | **+0.2680** |
| A8 | 0.1398 | 0.5206 | **+0.3808** |
| **macro** | **0.3588** | **0.4935** | **+0.1347** |
| pooled | 0.3622 | 0.4796 | +0.1174 |

The gate was inflating the macro headline by **0.135**, and a single variant by
up to **0.43**. A1–A4 are identical across arms, which is the control: the flag
touches only S5–S8.

**Item 4 — the latch reset, finally at a length where it is measurable:**

| variant | reset OFF | reset ON | Δ |
|---|---|---|---|
| A5 | 0.0000 † | 0.0000 † | — |
| A6 | −0.0089 † | −0.0064 † | — |
| A7 | 0.0633 | 0.0374 | −0.0259 |
| A8 | 0.1398 | 0.0288 | **−0.1110** |
| **macro** | **0.3588** | **0.3420** | **−0.0168** |
| pooled | 0.3622 | 0.3871 | +0.0249 |

So the number you have been chasing since round 7: **the latch reset costs
−0.0168 on the macro headline, concentrated almost entirely on A8.** Not −0.326,
and not the "no positive class survives" degeneracy that 90 s produced — at
300 s there are enough windows for this to be a measurement. A1–A4 are unchanged,
confirming the latch is HF-only by construction.

Note that macro and pooled **disagree in sign** here (−0.0168 vs +0.0249). That
is a concrete argument for your macro-as-headline instruction: pooled is carried
by whichever variants contribute the most rows, and on this A/B that reverses the
conclusion.

## 2. The second defect — M1 discards detections that accuse a vehicle

`lrad.h:583` records the primary detector against the **accused node**:

```
dw_mark_rsu_primary(prev_sender, _prim);
```

and `detector_windows.h:124` drops anything below the vehicle boundary:

```
if (rsu < (uint32_t)N_Vehicles) return;
```

When the accused forwarder is a vehicle there is no RSU row to write to, so the
detection disappears from the metric. Measured on the 300 s runs, by counting
accusations whose `prev_sender` is a vehicle:

| variant | dropped (vehicle) | recorded (RSU) | share lost |
|---|---|---|---|
| A5, after t=27 s | 315 | 1 | **99.7 %** |
| A6 | 340,307 | 1,829 | **99.5 %** |
| A8 | 89,238 | 30,662 | 74 % |
| A7 | 20,940 | 36,641 | 36 % |

This fully accounts for the two † rows. A5's S5 fires **361 times spanning
t=1–298 s** with 262 RSU-*receiver* fires after t=27 s, and the attack delivers
duplicates from t=10.1 to t=290.5 — yet only 22 windows carry
`score_primary=1`, every one of them inside the 30 s warm-up, so A5 scores
0.0000. A6 is the same mechanism at 99.5 %.

**The detectors were working. The metric could not see them.** This is
pre-existing and independent of the S5 fix — `score_primary` hardcodes
`prev_sender` regardless of `--dw_mark_suspect`, which only affects the `score`
column.

Consequences for §1, stated plainly:

- A5 and A6 rows are artefacts in every arm; both macro figures are **understated**.
- The Q5 inflation of +0.1347 is a **floor, not the value** — A5 contributes zero
  to both sides, and A6's honest arm is suppressed while its gated arm is not.
- The item 4 result of −0.0168 **stands**, because A7 and A8 carry it and both
  record a majority of their accusations.

The fix is one line: attribute vehicle accusations to the covering RSU via
`hf_gt_attribution_node(prev_sender)`, the same proxy already used for the truth
latch, the LSTM counters and item 1's quarantine guard. We have **not** made it.
It is a measurement change that would move every HF number in the thesis upward,
and it is the same class of decision as option (b). It also lands exactly on your
paper item *"correct suspect attribution as the reported column"*, which suggests
you already suspected something here — we do not think you knew it was zeroing
two variants outright. **We would like a ruling before touching it.**

## 3. A6's silent-S5 quarantine, and the same trace on S7/S8

Runs with S5 silent (both fixes on), **90 s — diagnostic length, not
reportable**, 60 %, seed 1. Accusations landing on nodes **never declared
attackers** in that run, at the 10 s window level:

| run | primary fired | never-declared | share |
|---|---|---|---|
| A5 | 23 | **0** | 0.0 % |
| A6 | 181 | 21 | 11.6 % |
| A7 | 746 | 166 | **22.3 %** |
| A8 | 590 | 70 | 11.9 % |

Grouping firings by sender, message and timestamp — the same grouping that
exposed S5's overhearing problem — multiple nodes do accuse the same event
(same 90 s runs):

| signature | distinct events | max accusers on one event |
|---|---|---|
| S6 | 14,405 | **27** |
| S7 | 8,162 | 10 |
| S8 | 5,333 | **24** |

So your suspicion was right: **the variant guards kept this class of problem from
surfacing rather than ruling it out.** It is milder than S5, which fired on
90.2 % of benign windows, but it is real, and S7 is the worst affected at 22.3 %.

One methodological caveat on our own numbers here: our first pass at this grouping
omitted the timestamp and reported "up to 228 accusers". That conflated distinct
events across time and was wrong. The table above includes time and is the
corrected version.

On the quarantine itself: A6 quarantines 248 of 268 nodes with S5 firing zero
times, so that is S6's own behaviour and it remains **unexplained**. We have not
closed it. What we can now say is that it is not an S5 artefact.

## 4. A1/A2/A4 enforcement validation

A3's protocol, unchanged: **90 s — diagnostic length, not reportable**, 60 %,
seed 1, only `--enable_quarantine_enforcement` varied, run on the S5-fixed build.

| variant | actions OFF | actions ON | reduction | round 8 reported |
|---|---|---|---|---|
| A1 | 766 | 150 | **−80.4 %** | 834 → 159, −80.9 % |
| A2 | 7,273 | 1,734 | **−76.2 %** | 7,249 → 1,985, −72.6 % |
| A4 | 49,689 | 44,392 | **−10.7 %** | 49,689 → 44,392, −10.7 % |

**All three fixes confirmed working.** A4 reproduces round 8 digit for digit.

We also ran the A1 pair with the S5 fix **off**, to check whether round 8's
numbers had been inflated by the false-positive quarantine storm:

| arm | actions | quarantined | of which vehicles | S5 fires |
|---|---|---|---|---|
| A1 off, fixed | 766 | 18 | **0** | 0 |
| A1 on, fixed | 150 | 26 | **0** | 0 |
| A1 off, no fix | 766 | 218 | **162** | 10,054 |
| A1 on, no fix | **47** | 215 | 161 | 7,246 |

Two things. The storm **does** inflate the apparent effect — −93.9 % against the
true −80.4 %, i.e. enforcement getting credit for containment that spurious
detections caused. And on the unfixed build an A1 run, whose attackers are
*RSUs*, was quarantining **162 vehicles** off the back of 10,054 S5 fires. On the
fixed build: zero vehicles.

One loose end we cannot account for: round 8's published −80.9 % matches the
*clean* value (−80.4 %), not our reproduction of the condition it was measured
under (−93.9 %). That figure of ours stands, but we cannot explain why it does
not match the build state it was measured on, and we would rather say so than
leave it.

## 5. NEXUS — it is the latter, and it is wider than the S5 guard

`active_attack_variant` is a single `int` (`routing.cc:114733`), assigned in a
`switch` on `attack_number` with `break` in every case
(`attack_declaration.h:102-140`). No bitmask, no set, no joint mode anywhere in
the tree. **Exactly one variant can be armed per run.**

Three things follow:

1. The S5 guard would suppress S5 in any joint run unless
   `active_attack_variant == 4`. That is a genuine defect in what we wrote.
2. **It is not confined to our change.** S6/S7/S8 have carried the identical
   construction since long before this session, so N1–N3 would already have been
   wrong for those three. Our guard makes S5 consistent with a pattern that was
   already broken for joint experiments.
3. The generalization is small: replace `active_attack_variant != N` with a
   `variant_active(N)` predicate backed by a set, in all four files at once.

We have not written it, because it changes S6/S7/S8 behaviour. Say the word and
it is a short change.

## 6. The two items you say never came back

Both are in the repo, committed 2026-09-09 in the same squash as the round 8
work — this is the fourth crossing in a row, so we are simply re-sending rather
than arguing about it:

- **D_div smoke test** — `--ddiv_smoke_test`, all three criteria pass on A5–A8:
  non-constant across all 64 RSUs in 100 % of attack cycles; exactly zero under
  benign (max 0 across 3,712 samples); correlation with R_anom 0.78–0.81, i.e.
  meaningfully below 1. Full write-up in `CHANGES_ROUND8_2026-09-09.md` §3.
  **So the richer D_div is confirmed safe to build the regeneration around.**
- **A1/A2 recall-decay time buckets** — `A1A2_RECALL_DECAY_2026-09-07.md`.

It may be worth agreeing that documents land before the message that discusses
them, since this keeps happening.

## 7. Paper reconciliation — started; one defect in the "just confirm" list, and `W` is worse than described

You asked us to confirm `eq:lstm_gate`, `eq:theta_adapt`, the A4
temporal-asymmetry note and `eq:eval_dedup` are cleanly present with no stale
duplicates. Three are clean; **`eq:theta_adapt` is not.**

**`eq:theta_adapt` is defined twice, with two different equations**, both live:

| line | definition |
|---|---|
| 3445 | θ_adapted = **max**(θ, μ_warmup + z·σ_warmup) — the k·σ form |
| 5404 | θ_adapted = **pct₉₉**(𝒜_benign ∪ 𝒜_warmup) — the percentile form |

LaTeX resolves duplicate labels to the last, so all five `\ref`s — including the
two at lines 3438 and 3447 sitting directly beside the k·σ equation — point at
the percentile form. A reader at §3445 sees one definition; every cross-reference
means the other. It emits a "multiply defined labels" warning on every build.
This looks like residue from the threshold-calibration work: both approaches were
written in and neither removed.

Separately, on your own list item for `W` — it is not the wording problem you
described. **`W` contradicts the code by 3×.** The paper (§5516) states *"Observation window
W (Eq. dup_alert_cond): W = 10 s"*. The code is `S6_WINDOW_S = 30.0`
(`s6_detection.h:82`), and every `[S6]` log line in today's runs prints
`W=30.000s`. The stated
**value** is wrong, and every S6 duplicate detection in the thesis was produced
with a 30 s window. One ambiguity we cannot resolve from the source: there are
two distinct W's in this project, the M1 evaluation window (10 s, correct) and
this S6 detection window (30 s). It is possible §5516 was written about the
evaluation window and mislabelled with `eq:dup_alert_cond`. Either way it is a
defect, but which one determines the fix, and that is your call.

Clean, confirmed present exactly once: `eq:lstm_gate`, `eq:eval_dedup`,
`eq:sig_s5`, `eq:feat_ddiv`, `eq:feat_atp`, `eq:quarantine`, `eq:feat_ndiv`, the
A4 temporal-asymmetry note, the Q1 covering-RSU limitation, and the Q2
S2-partial/HMAC-origin note (lines 2349–2351 — already added in round 8, so that
item on your list is done). `eq:ucr`'s second copy is fully commented out, so it
is stale text but not a build problem.

**Section 4's methodology subsection does not exist**, and five of its six points
appear nowhere in the document: macro-averaged, pooled, suspect attribution,
diagnostic ceiling, and run length all return zero matches; only de-duplication
is present. So that item is greenfield rather than an edit — worth knowing when
you scope the LaTeX patch.

**M4's paired prevention-rate** is in the code and the CSV from round 8 but not in
the paper, consistent with your list.

We also found that **`m1_local.py` could not produce the headline you asked
for** — it computed pooled only. We have added a macro row, which excludes
degenerate variants (TP+FN=0) rather than averaging in `mcc()`'s zero-denominator
fallback, and prints which variants it excluded so the exclusion is never
invisible. Every "ALL" figure in previous messages was pooled; the tables in §1
give both.

## 8. Regeneration, and what we need from you

The 60-run regeneration has **not** been started and will not be until you clear
it.

Blocking on your ruling:

1. **The vehicle-accusation fix (§2)** — the one that currently zeroes A5 and A6.
   This is the biggest item; nothing about the HF numbers is trustworthy until it
   is settled.
2. **The `variant_active()` generalization (§5)** — needed before N1–N3, and it
   touches S6/S7/S8, not just S5.
3. **`W` (§7)** — whether the paper's 10 s or the code's 30 s is correct.
4. **Option (b)**, still open from round 9. Benign quarantine is now 0, so for the
   first time there is a regime in which it can be validated.

Not blocking, in progress: the rest of the paper reconciliation.

All 300 s figures above are from single-seed runs (seed 1). Multi-seed will change
the absolute values; the arm-to-arm deltas are what we would stand behind.
`m1_local.py` remains a local re-implementation of M1, so its absolute level
should not be compared against the canonical 0.2721 — every comparison here is
arm-to-arm within the same binary.
