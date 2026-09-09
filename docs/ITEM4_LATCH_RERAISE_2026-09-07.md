# Item 4 (the truth latch) — re-raising an approval that was given without the data

**Date:** 2026-09-07 · **Status:** needs a ruling · **Flags:** default-off, unchanged

## Why we are re-opening an item you already approved

In round 8 you approved item 4 "as built, including the fix for the shared
covering RSU over-release case." That approval crossed with
`SUPERVISOR_UPDATE_2026-09-05.md`, which carried the measurement showing the
latch **makes M1 worse on all four HF variants**. We do not think you had that
measurement in front of you when you approved, so we are putting it back to you
rather than shipping against an approval we believe was uninformed.

The flags remain default-off. Nothing has been enabled on the strength of the
approval.

## What the latch does, and the part that works

`hf_truth_latch_clear()` moves the *ground-truth* boundary: a node stops counting
as compromised at the moment it is quarantined, rather than staying compromised
for the rest of the run. The hook is wired and provably fires — it went from zero
callers to firing on every quarantine:

| variant | attacker | latch clears (off → on) | quarantines |
|---|---|---|---|
| A5 | CP / RSU | 0 → 64 | 64 |
| A6 | DP / vehicle | 0 → 52 | 167 |
| A7 | CP / RSU | 0 → 66 | 68 |
| A8 | DP / vehicle | 0 → 45 | 164 |

Truth-positive windows fall exactly as intended: A5 35→20, A6 130→30,
A7 65→15, A8 142→56. The mechanism does what it was designed to do.

## The problem: M1 falls on every variant, on both score columns

| variant | `score` Δ | `score_primary` Δ |
|---|---|---|
| A5 | −0.031 | −0.103 |
| A6 | **−0.178** | **−0.326** |
| A7 | −0.109 | −0.209 |
| A8 | −0.164 | −0.195 |

## Diagnosis

In A6/A8's treatment arm, **72–76% of the new false positives are declared
attackers firing in windows that begin after their own quarantine.** True
positives convert to false positives close to one-for-one; true negatives barely
move.

The cause is a boundary mismatch. **Truth's boundary moved to quarantine. The
detector's did not.** S5–S8 contain no quarantine awareness whatsoever — none of
the four files mentions it — so a contained node keeps being accused for the rest
of the run, and every one of those accusations is now scored as a false positive
against a truth signal that has correctly stopped.

Your reasoning — *"once enforcement lands the compromised state genuinely ends at
quarantine, so truth and detector agree by construction"* — holds for truth. It
does not hold for the detector, which was never taught to stop.

That the drop is **larger on `score_primary`** rules out the observer-attribution
artefact we documented elsewhere. This is a genuine detector-side latch, not a
measurement artefact.

## Consequence if enabled as approved

Enabling the latch as it stands would publish an M1 that is **worse by up to
0.326** than the current figure, and worse for a reason that has nothing to do
with detection quality — it would be measuring the detector's failure to
de-assert, not its ability to detect. The number would be wrong in a way that
looks like a real regression.

## The Q5 interaction — now resolved, and it changes the picture

When we last wrote, we flagged that this collided with the then-open oracle-gate
question. **The gate is now removed** (committed 2026-09-07). This matters here
because the gate was part of why S5–S8 keep asserting: it forced every evaluation
through the attack injector's assignment array, so a declared attacker passed the
first conjunct forever, quarantined or not.

Q5 A/B, 60%, seed 1, **90 s — diagnostic length, not reportable** under your
own convention:

| variant | gate ON (legacy) | gate OFF (honest) | false positives |
|---|---|---|---|
| A5 | P 1.0000 · R 0.9327 · F1 0.9652 | P 0.7335 · R 0.9615 · F1 0.8322 | **0 → 218** |
| A6 | P 1.0000 · R 0.8798 · F1 0.9360 | P 0.8127 · R 0.9249 · F1 0.8652 | **0 → 156** |
| A7 | P 0.9529 · R 0.9071 · F1 0.9294 | P 0.7383 · R 0.9631 · F1 0.8359 | 28 → 213 |
| A8 | P 1.0000 · R 0.8115 · F1 0.8959 | P 0.8471 · R 0.8702 · F1 0.8585 | **0 → 115** |

All four variants complete, error gate 0 on all eight runs.

Your prediction was right on both counts. **Three of the four — A5, A6 and A8 —
had exactly zero false positives with the gate on** — precision 1.0000 was an identity, not a
measurement. And recall *improves* in all four once the gate is out, so the gate
was never buying detection capability; it only suppressed the denominator of
precision.

Because the gate removal changes when and where S5–S8 fire, **the latch
measurement above predates the current detector and may no longer hold.** We
propose to re-measure the latch on top of the gate-removed build before anyone
acts on it.

## What we are asking for

1. **Confirm the approval still stands** now that you have seen the −0.326.
2. **Rule on the fix**, which is a change to detection logic and therefore not
   ours to make unilaterally. Three options:
   - **(a)** Leave the latch off; document the boundary mismatch as a known
     limitation. Cheapest, no code change, but truth stays wrong after quarantine.
   - **(b)** Teach S5–S8 to stop asserting on a quarantined node — moves the
     detector's boundary to match truth's. Correct in principle; it is a
     detection-logic change and would need its own validation.
   - **(c)** Exclude quarantined nodes from scoring entirely, on the grounds that
     a contained node is out of scope for detection.

We recommend deferring the choice until the post-Q5 re-measurement lands, in case
the gate removal has already narrowed the gap.

## Status of the flags

Default-off, unchanged, and we will not enable them without an instruction that
accounts for the numbers above.
