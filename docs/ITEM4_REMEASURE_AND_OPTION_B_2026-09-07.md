# Item 4 — the re-measurement, and our recommendation on option (b)

**Runs:** gate-removed build, `--enable_quarantine_enforcement=1`,
`--hf_truth_latched=1`, reset flag off vs on. 90 s, 60%, seed 1, error gate 0 on
all 8. **90 s is diagnostic length**, not reportable.

## Headline: the −0.326 does not reproduce, and not for a good reason

| variant | `score` Δ | r7 Δ | `score_primary` Δ | r7 Δ |
|---|---|---|---|---|
| A5 | **−0.0997** | −0.031 | **0.0000** | −0.103 |
| A6 | −0.0061 | −0.178 | **0.0000** | **−0.326** |
| A7 | −0.0545 | −0.109 | **0.0000** | −0.209 |
| A8 | 0.0000 | −0.164 | **0.0000** | −0.195 |

**Every `score_primary` delta is exactly zero, structurally.** The latch writes
`truth`; it never touches `truth_declared`, which `score_primary` is scored
against — measured, `truth_declared` is identical in both arms on all four
variants (624→624, 732→732). The −0.326 was a `score_primary` number, so
whatever produced it in round 7, this configuration cannot reproduce it. We
would not trust the r7 `score_primary` deltas without knowing what config
produced them.

The latch itself fired hard (clears 0→242, 0→166, 0→218, 0→154).

## The much larger problem the re-measurement exposed

Absolute MCC on the `score` column, enforcement on:

| variant | reset OFF | reset ON |
|---|---|---|
| A5 | 0.1068 | 0.0071 |
| A6 | **−0.2509** | **−0.2570** |
| A7 | 0.0842 | 0.0297 |
| A8 | **−0.3250** | **−0.3250** |

**A6 and A8 are negative — anti-correlated with truth, worse than random.** The
latch delta is noise next to this. Turning enforcement on is what causes it: the
same runs without enforcement scored 0.4658 / 0.0147 / 0.4695 / 0.0085.

## Answering your question on option (b)

**How big is the change?** Genuinely small. The four sites are structurally
identical (`s5_detection.h:137`, `s6:159`, `s7:136`, `s8:106`), `crypto_layer.h`
symbols are already in scope, and `quarantine_blocks()` already exists
(`crypto_layer.h:623`). One guard per file.

Two traps that make the naive version wrong, both avoidable:
1. `quarantine_blocks()` returns false unconditionally when
   `enable_quarantine_enforcement` is off, so the guard would be silently inert
   in default runs.
2. Truth's latch is indexed by **RSU local index**
   (`hf_truth_latch_clear`, `crypto_layer.h:823`) while the detector accuses
   `prev_sender`. For the DP variants those are different entities.

**Will it behave unexpectedly on a variant we haven't discussed? Yes — it
inverts between the two families.** Truth-positive rate and detector firing
rate, by time bucket, enforcement on, reset on:

| | t=0–20s | 20–40s | 40–60s | 60–80s |
|---|---|---|---|---|
| **A5** truth+ | 0.9% | 0.4% | 0.4% | 0.4% |
| **A5** detector fires | 34.0% | 35.0% | 29.5% | 28.6% |
| **A6** truth+ | 43.7% | 44.0% | 43.6% | 43.6% |
| **A6** detector fires | 32.9% | 36.4% | 30.4% | 29.0% |
| **A8** truth+ | 43.1% | 43.4% | 43.6% | 43.6% |

- **A5/A7 (RSU attackers):** quarantine genuinely ends the compromised state —
  truth collapses to ~0.4% — while the detector keeps firing ~30%. Almost every
  one of those fires is a false positive. **Option (b) aligns detector with
  truth and should improve these substantially.**
- **A6/A8 (vehicle attackers):** truth stays flat at **43.6% for the entire
  run**. The compromised state does *not* end at quarantine. Option (b) would
  silence a detector that is firing on genuinely-still-compromised nodes, cost
  recall, and make things worse.

## Recommendation

**Adopt option (b), scoped to A5/A7 only — not applied uniformly.**

There is direct precedent: the latch reset is *already* split by attacker type
across two flags (`hf_latch_reset_rsu_attacker` /
`hf_latch_reset_vehicle_attacker`) for exactly this reason. Option (b) should be
gated the same way and paired 1:1 with the latch flag it mirrors, so the
detector's boundary moves if and only if truth's does. That keeps the two
boundaries in lockstep by construction rather than by coincidence.

We do **not** recommend option (c). Your concern was right, and stronger than
you framed it: at 93% of nodes quarantined by t≈20 s, scoring would run on ~7%
of the network.

Option (a) is not needed for A5/A7. It remains the honest interim for A6/A8.

## The upstream finding, which we think outranks item 4

For A6/A8, truth stays at 43.6% *after* enforcement quarantines the network.
**Enforcement is not containing vehicle attackers.** That sits badly beside item
1's "post-quarantine leak 0 of 44,171", and one of the two is measuring
something other than what its name suggests. A related premise has already been
falsified: `crypto_layer.h:841` justified the covering-RSU proxy with "vehicles
never cross the trust threshold" — measured, 199/200 do in A5/A6, 167–173 in
A7/A8. Comment corrected 2026-09-07.

We think this should be resolved before item 4 is closed, because option (b)'s
A6/A8 half depends on it.
