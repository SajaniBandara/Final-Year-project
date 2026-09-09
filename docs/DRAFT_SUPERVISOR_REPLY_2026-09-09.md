# Draft reply — round 9 (item 4 re-measurement + the S5 defect it exposed)

Status: draft for sending. Evidence: `docs/S5_SOUNDNESS_FIX_2026-09-09.md`.
Code: commit `73a0258`, both new flags default-off.

---

Thank you — and the sequencing instruction turned out to matter more than
either of us expected. We did the re-measurement first, as you asked, and it
did not give any of the three answers you offered. Chasing why produced
something larger, so this message is in four parts: the number you asked for,
what was underneath it, a correction to something you read as good news, and
our recommendation on (b).

One process note first. This reply crosses with
`ITEM4_REMEASURE_AND_OPTION_B_2026-09-07.md`, which we had already sent — the
third crossing in a row. Everything below supersedes it, including two errors
in that document which we correct at the end.

## 1. The re-measurement: the −0.326 does not reproduce

Gate-removed build, enforcement on, `--hf_truth_latched=1`, latch reset off vs
on. 90 s, 60 %, seed 1, all eight runs exited rc=0. M1 is RSU rows,
de-duplicated 10 s blocks, 30 s warm-up.

| variant | `score` OFF → ON | `score_primary` OFF → ON |
|---|---|---|
| A5 | 0.0982 → 0.0000 † | 0.0000 → 0.0000 † |
| A6 | 0.0091 → −0.0130 | −0.0367 → **−0.0302** |
| A7 | 0.0568 → 0.0000 † | 0.1308 → 0.0000 † |
| A8 | 0.0000 → 0.0000 | 0.0192 → 0.0192 |

† is not a score. In those cells TP + FN = 0 — after warm-up and de-duplication
there is no positive class left at all, so DR prints as `nan` and MCC is a
zero-denominator fallback rather than a measurement.

So: it does not shrink, stay, or get worse. **A6 — the variant that carried the
−0.326 — moves in the opposite direction, by +0.0065.** The largest
`score_primary` delta anywhere is A7's −0.1308, and that is one of the
degenerate cells.

The underlying counts show why:

| variant | truth=1 OFF → ON | truth_declared | score | score_primary |
|---|---|---|---|---|
| A5 | 48 → 6 | 624 (both) | 755 (both) | 183 (both) |
| A6 | 48 → 38 | 732 | 756 | 196 |
| A7 | 16 → 2 | 624 | 890 | 587 |
| A8 | 25 → 25 | 732 | 854 | 515 |

The detector's predictions are byte-identical in both arms on all four
variants — the latch is truth-only, exactly as designed. On A8 the flag does
nothing whatsoever: the entire output file is byte-identical off versus on.

We would not report any of these as a latch effect, because of part 2.

## 2. What was underneath: M1 was being scored on an already-quarantined network

With enforcement on, at 60 %:

| variant | quarantined by t=20 s | by t=30 s | total | of which vehicles |
|---|---|---|---|---|
| A5 | 234 | 248 | 252 (94 % of 268) | 200 / 200 |
| A6 | 225 | 247 | 253 (94 %) | 200 / 200 |
| A7 | 148 | 165 | 218 (81 %) | 160 |
| A8 | 141 | 175 | 217 (81 %) | 161 |

M1's warm-up is 30 s. **Scoring therefore begins after 98 % of all quarantines
have already happened** (A5: 248 of 252). That is why every enforcement-on MCC
in the table above sits between −0.04 and +0.13 — the metric is being computed
on a network that is already almost entirely contained.

We then checked whether that containment was actually attack-driven. It is not.
Same configuration at 20 %, plus a benign control with enforcement on and no
`--attack_number` at all:

| run | attackers | quarantined | % of 268 | vehicles |
|---|---|---|---|---|
| **benign** | **none** | **212** | **79.1 %** | **157 / 200** |
| A5 @ 20 % | 40 | 250 | 93.2 % | 200 / 200 |
| A6 @ 20 % | 40 | 253 | 94.4 % | 200 / 200 |
| A7 @ 20 % | 40 | 230 | 85.8 % | 171 |
| A8 @ 20 % | 40 | 225 | 83.9 % | 167 |

Tripling the attacker fraction moves quarantine by under 5 %, and on A7/A8 it
moves the wrong way. A network with **no attacker at all** still loses 79 % of
its nodes.

The cause is a defect in S5, in two parts.

**S5 never had the variant guard its siblings have.** `s6_detection.h:145`,
`s7:122` and `s8:92` each open with an executable
`if (active_attack_variant != N) return false;`. `s5_detect()` has no such line.
Its own header documents conjunction 1 as `active_attack_variant == 4`, but
nothing implements it — and the `variant=4` that appears in its log output is a
compile-time constant, `S5_HOME_VARIANT`, not a read of the live variable. The
log looked correct while the guard was absent.

`attack_declaration.h:97` states the assumption the design rested on: signatures
are left always-on because *"each sX_detect() gates on its own attack-specific
ground truth internally (e.g. s5_detect() checks
active_hf_malicious_nodes[prev_sender])"*. That array is the oracle gate. Q5
removed it. S6/S7/S8 were unaffected because each has a real guard; S5 was the
one signature where the gate was the only thing holding it back.
`routing.cc:122593` carries the same, now-false, invariant: *"S5–S8 return false
for non-eavesdropped packets — no false positives."*

Measured — S5 firing in runs where Attack 5 is not injected:

| run | S5 | S6 | S7 | S8 |
|---|---|---|---|---|
| **benign** | **7,389** | 0 | 0 | 0 |
| A6 @ 60 % | **57,618** | 95,916 | 0 | 0 |
| A7 @ 60 % | **9,045** | 0 | 11,136 | 0 |
| A8 @ 60 % | **22,774** | 0 | 0 | 31,578 |

S6/S7/S8 fire zero times outside their own variant. S5 fires everywhere.

**Second, S5 cannot distinguish an attack from ordinary broadcast overhearing.**
`b_hop_fails` is true for every neighbour that is not the signed next hop, and
`d_prime_unauthorized` excludes only the flow's *final destination* — so every
intermediate relay and every passive overhearer satisfies both. In benign runs
all three printed conjuncts are identical to a real attack's. Grouping benign
`[S5]` lines by (sender, packet, flow, timestamp):

| receivers firing on one transmission | transmissions |
|---|---|
| 1 | 2,972 |
| 2 | 1,409 |
| 3 | 497 |
| 4 | 45 |

Up to four different nodes accuse the same sender for the same frame. Those
accusations feed `trust_update_negative()` → quarantine, which is what empties
the network before scoring starts.

## 3. A correction on the Q5 result you read as good news

You wrote that zero false positives on A5 and A8 were confirmed pure artefact,
and that recall improving once the gate was gone showed the shortcut was never
buying detection capability. The first half is right. The second half we now
have to qualify, and we would rather say so than let it stand.

The post-Q5 false-positive figures we reported — A7 `28 → 213`, A8 `0 → 115` —
**include S5 fires from an attack that was never injected in those runs.** They
are not honest measured precision loss; a component of them is structurally
impossible. The gate removal was still the right call: it exposed this rather
than caused it, and it is the reason we found it at all. But no post-Q5 number
is trustworthy until the fix below is in, and we are not asking you to draw
conclusions from the round 8 table in the meantime.

## 4. The fix, and what it measures

Both changes are behind default-off flags, per the usual convention. The
regression arm is exact: a benign run on the new binary with both flags off
produces 7,389 S5 fires, identical to the old binary. Every previously reported
number reproduces bit-identically.

`--s5_variant_guard` is the one line S6/S7/S8 already have. Worth being explicit
about why this is not the oracle gate returning: it consults *which experiment
is configured*, never *which node is guilty*. It cannot make a node look
innocent, so it cannot manufacture precision. It removes cross-variant
contamination only, and does nothing for false positives inside Attack 5's own
run.

`--s5_require_addressed` is the genuinely missing conjunct: was this frame
addressed to me? Nothing in the simulation carried that, so the MAC destination
is now a field on the packet tag, set at all four transmit sites and read at the
receive site. This is also not an oracle, and the reason is the interesting
part: `intended_recipient` is independent of `signed_next_hop`, because a
hidden-forwarding duplicate is addressed to d′ while still carrying the
*original* signed next hop. So d′ legitimately observes "addressed to me **and**
b_hop(u) = 0", while a passive overhearer sees "not addressed to me" and drops
out. No attack-injector state is consulted.

| measure | before | guard only | addressing only | both |
|---|---|---|---|---|
| benign S5 fires | 7,389 | 0 | 37 | **0** |
| benign RSU window FPR | 90.2 % | 0.8 % | 6.1 % | **0.8 %** |
| benign nodes quarantined | 212 | — | — | **0** |

Attack 5's own run:

| | off | both |
|---|---|---|
| M1 (`score`) | 0.0982 | **0.3702** |
| TP / FP | 13 / 197 | **77 / 98** |
| DR / FPR | 86.7 % / 64.6 % | 83.7 % / **43.0 %** |
| nodes quarantined | 252 (200 veh) | **70 (26 veh)** |
| hidden duplicates delivered | 4 | **31** |

**That MCC must not be quoted as a 3.8× improvement, and we want to flag it
before anyone does.** It is not a like-for-like detector comparison. Unfixed,
the false-positive storm quarantined the network — the attacker included —
within seconds, so the attack only ever delivered 4 duplicates; fixed, it
delivers 31. Part of the true-positive gain is simply that the attack now runs.
The defensible claim is that the fix makes A5 *measurable*, and that on the
measurable run detection is substantially better.

The other three variants keep their own signatures, and two improve because
their attackers are no longer quarantined early by S5's false positives:

| run | S5 (was) | own signature (was) |
|---|---|---|
| A6 | 0 (57,618) | S6 96,912 (95,916) |
| A7 | 0 (9,045) | S7 16,351 (11,136) |
| A8 | 0 (22,774) | S8 34,049 (31,578) |

## 5. Option (b): size, side effects, and our recommendation

**How large is it?** Small, and we checked rather than estimated. The four call
sites are structurally identical, so it is one guard line each. Two details make
it five files rather than four: the helper cannot live beside its precedent,
because `selective_time_delay.h` is included *after* S5–S8 in `routing.cc`, so
it belongs in `crypto_layer.h` where `quarantine_blocks()` and
`hf_gt_attribution_node()` already are. And the guard must test the accused
**and** its attribution node — mirroring item 1's `std_delay_quarantine_blocks()`
— because for the data-plane variants the accused is a vehicle while truth's
latch clears on the covering RSU. Testing `prev_sender` alone would leave the
two boundaries misaligned on exactly the variants the mismatch was found on.
About 20 lines across 5 files. There is direct in-repo precedent for the
construction, which is the strongest argument that it is low-risk.

**Could it behave unexpectedly on a variant we haven't discussed?** Yes, and in
a way that has changed since our 09-07 note. That note recommended adopting (b)
scoped to A5/A7, on evidence that quarantine genuinely ends the compromised
state for RSU attackers but not for vehicle attackers. We now think that
recommendation was made in a regime where it could not be validated: with 81–94 %
of the network quarantined before scoring opened, (b) would have silenced the
detector on nearly every node, both boundaries would have collapsed together,
and the result would have been not a better M1 but no M1 — which is precisely
what the † cells in part 1 already show. On A8 there was nothing for it to be in
lockstep with, since the latch flag changes nothing there at all.

**Our recommendation, concretely.** Option (b) is small and clean, and we do
think it is the right fix in principle, for the reason you gave — it makes the
detector and truth agree rather than hiding the disagreement. But we recommend
sequencing it rather than approving it now:

1. Merge the S5 fix (default-off flags, already committed).
2. Re-measure the Q5 A/B **and** the item 4 latch A/B on the fixed build. Benign
   quarantine is now 0, so for the first time in this thread there is a regime
   in which those numbers mean something.
3. Decide (b) against those numbers. We expect it to become both smaller in
   effect and easier to justify, but we would rather show you that than assert
   it.

If you would prefer not to wait, the fallback we would accept is approving (b)
as written but keeping it default-off until step 2 reports — the code is
harmless while the flag is off, and it removes a round trip.

**On option (c)** — your concern was right, and stronger than you framed it. It
is not only that the metric gets easier as more nodes are quarantined; at 94 %
quarantined, scoring would have run on roughly 6 % of the network. We do not
recommend it, and we do not think it needs revisiting.

**On option (a)** — not needed if the above sequence works. It stays available
as the honest interim if step 2 shows the boundaries still disagree.

## 6. Two corrections to our own 09-07 document

Both matter because you may have read it before this arrived.

1. Its explanation that "every `score_primary` delta is exactly zero,
   structurally — the latch never touches `truth_declared`, which
   `score_primary` is scored against" is wrong on the mechanism. In
   `m1_local.py`, `--score-col` selects a *prediction* column; the truth column
   is chosen independently and defaults to `truth`. Both columns score against
   the same truth, and the deltas are not all zero.
2. Its absolute A6/A8 figures (−0.2509, −0.3250) do not reproduce. Measured
   here: +0.0091 and 0.0000.

## 7. Status, and what we are asking for

Flags remain off. The two new S5 flags are also default-off, and the regression
arm proves the tree is bit-identical with them off, so nothing you have
previously seen has moved.

Three things left open deliberately, none of which we have patched around:

- 37 residual benign S5 fires under the addressing conjunct alone, all
  vehicle → RSU, correctly addressed but still failing `b_hop`. Consistent with
  RSU handoff in flight. That is a hypothesis from 37 samples, not a finding.
  The variant guard conceals it in benign runs; it remains live inside Attack
  5's own run.
- A6 still quarantines 248 nodes with S5 silent, so that is S6's own behaviour
  and currently unexplained.
- Option (b), pending your ruling on the sequencing above.

What we need from you: a ruling on the sequencing in §5, and whether you want
the Q5 round 8 table formally withdrawn and re-measured, or annotated in place.

All numbers here are 90 s diagnostic runs — not reportable length under your own
convention. `m1_local.py` is a local re-implementation of M1, so its absolute
level should not be compared against the canonical 0.2721; every comparison in
this message is arm-to-arm within the same binary, where any constant offset
cancels.
