# S5 soundness — the two defects Q5 exposed, and the item 4 re-measurement

**Date:** 2026-09-09 · **Flags:** both new flags default-off · **Branch:** A30

Covers three things, in dependency order: the item 4 re-measurement the round 8
reply asked for, the root-cause defect the re-measurement exposed, and the fix.
The middle one outranks the other two — until it lands, no post-Q5 number is
trustworthy, including the ones reported as good news in
`CHANGES_ROUND8_2026-09-09.md`.

All runs below: `optimized` build, `-O3` confirmed on `CXXFLAGS`, 90 s
(**diagnostic length, not reportable**), seed 1, `--enable_detector_windows=1
--enable_quarantine_enforcement=1 --hf_truth_latched=1`. Error gate 0 on all 14
runs. `simTime=90`, `attack_percentage=60` unless stated.

**Environment note.** The gate-removed build had never been compiled on this
host — the binary was from 2026-09-02 and contained none of the round 8 flags
(`hf_oracle_gate`, `ddiv_smoke_test`, `lstm_ddiv_atp_per_rsu`,
`hf_latch_reset_*` all absent from `strings`), and no result CSV anywhere under
`$HOME` was newer than 09-05. Everything here was rebuilt and re-run locally, so
these numbers are reproducible on this machine rather than cited from a doc
whose artefacts are not present.

---

## 1. Item 4 re-measurement — the −0.326 does not reproduce

Gate-removed build, `--hf_latch_reset_{rsu,vehicle}_attacker` off vs on.

M1 (RSU, deduped 10 s blocks, warm-up 30 s), via `scripts/m1_local.py`:

| variant | `score` OFF | ON | `score_primary` OFF | ON |
|---|---|---|---|---|
| A5 | 0.0982 | 0.0000 † | 0.0000 | 0.0000 † |
| A6 | 0.0091 | −0.0130 | −0.0367 | **−0.0302** |
| A7 | 0.0568 | 0.0000 † | 0.1308 | 0.0000 † |
| A8 | 0.0000 | 0.0000 | 0.0192 | 0.0192 |

† **Not a score.** TP+FN = 0 — no positive class survives warm-up and dedup.
`m1_local.py` returns 0.0 for a zero denominator and prints DR as `nan%`.

**The answer to "does it shrink, stay, or get worse" is none of those.** A6 —
the variant that carried the −0.326 — moves *up* by 0.0065. The largest
`score_primary` delta anywhere is A7's −0.1308, and that is one of the
degenerate cells.

Raw grid counts (RSU rows, unfiltered):

| variant | truth=1 OFF → ON | truth_declared | score | score_primary |
|---|---|---|---|---|
| A5 | 48 → **6** | 624 (both) | 755 (both) | 183 (both) |
| A6 | 48 → 38 | 732 | 756 | 196 |
| A7 | 16 → **2** | 624 | 890 | 587 |
| A8 | 25 → **25** | 732 | 854 | 515 |

Detector predictions are **identical in both arms on all four variants** — the
latch is truth-only, as designed. A8's entire CSV is byte-identical off vs on:
the flag does nothing there.

### Two corrections to `ITEM4_REMEASURE_AND_OPTION_B_2026-09-07.md`

1. Its mechanism claim — "every `score_primary` delta is exactly zero,
   structurally… the latch never touches `truth_declared`, which
   `score_primary` is scored against" — misreads `m1_local.py`. `--score-col`
   selects a **prediction** column; the truth column is selected independently
   by `--truth-semantics`, which defaults to `event` (= `truth`). Both columns
   score against the same truth, and the deltas are **not** all zero.
2. Its absolute A6/A8 figures (−0.2509, −0.3250) do not reproduce. Measured
   here: +0.0091 and 0.0000.

---

## 2. Why every enforcement-on M1 was ~0 — and the defect underneath

Quarantine with enforcement on, 60%, seed 1:

| variant | by t=20 s | by t=30 s | total | of which vehicles |
|---|---|---|---|---|
| A5 | 234 | 248 | 252 (94% of 268) | 200/200 |
| A6 | 225 | 247 | 253 (94%) | 200/200 |
| A7 | 148 | 165 | 218 (81%) | 160 |
| A8 | 141 | 175 | 217 (81%) | 161 |

M1's warm-up is 30 s, so **scoring begins after 98% of all quarantines have
already happened** (A5: 248 of 252). Every enforcement-on M1 in this thread is
computed on an already-contained network.

It is not attack-driven. Same config at 20%, plus a **benign control** with
enforcement on and no `--attack_number` at all:

| run | attackers | quarantined | % of 268 | vehicles | S5 fires |
|---|---|---|---|---|---|
| **benign** | **none** | **212** | **79.1%** | **157/200** | **7,389** |
| A5 @20% | 40 | 250 | 93.2% | 200/200 | 18,451 |
| A6 @20% | 40 | 253 | 94.4% | 200/200 | 29,150 |
| A7 @20% | 40 | 230 | 85.8% | 171 | 7,723 |
| A8 @20% | 40 | 225 | 83.9% | 167 | 11,658 |

Tripling the attacker fraction (20% → 60%) moves quarantine by under 5%, and in
A7/A8 it moves the *wrong way*. A network with no attacker still loses 79% of
its nodes.

### Defect 1 — `s5_detect()` has no `active_attack_variant` guard

`s6_detection.h:145`, `s7:122` and `s8:92` each open with an executable
`if (active_attack_variant != N) return false;`. **`s5_detect()` has no such
line.** Its own header documents conjunction 1 as `active_attack_variant == 4`,
but nothing implements it, and the `variant=4` in its log output is the constant
`S5_HOME_VARIANT` (`s5_detection.h:287`), not a read of the live variable — so
the log looks correct while the guard is absent.

`attack_declaration.h:97` states the assumption the design rested on:

> "Each sX_detect() function already gates on its own attack-specific ground
> truth internally (**e.g. s5_detect() checks
> active_hf_malicious_nodes[prev_sender]**), so leaving every signature
> always-on is safe: a detector with no matching attacker present in this run
> simply never fires."

That array *is* the oracle gate. Q5 removed it. S6/S7/S8 were unaffected because
each has its own real guard; S5 was the one signature where the gate was the
only thing holding it back. `routing.cc:122593` carries the same now-false
invariant: *"S5–S8 return false for non-eavesdropped packets — no false
positives."*

Measured, S5 fires in every run including ones where Attack 5 is not injected:

| run | S5 | S6 | S7 | S8 |
|---|---|---|---|---|
| **benign** | **7,389** | 0 | 0 | 0 |
| A5 @60% | 36,179 | 0 | 0 | 0 |
| A6 @60% | **57,618** | 95,916 | 0 | 0 |
| A7 @60% | **9,045** | 0 | 11,136 | 0 |
| A8 @60% | **22,774** | 0 | 0 | 31,578 |

### Defect 2 — S5 cannot separate an attack from broadcast overhearing

`d_prime_unauthorized` (`s5_detection.h:210-217`) is true unless `current_hop`
is the flow's **final destination**, so every intermediate relay and every
passive overhearer satisfies it. `b_hop_fails` is true for every neighbour that
is not the signed next hop. Both therefore hold for ordinary traffic, and in
benign runs all three printed conjuncts are identical to an attack's
(`mldsa_fails=1 b_hop_fails=1 d_prime_unauthorized=1`, 7,389 of 7,461 lines).

Broadcast is the mechanism. Grouping benign `[S5]` lines by
(sender, packet, flow, timestamp):

| receivers firing per single transmission | transmissions |
|---|---|
| 1 | 2,972 |
| 2 | 1,409 |
| 3 | 497 |
| 4 | 45 |

Up to four different nodes accuse the same sender for the same frame.

### Consequence for Q5's reported numbers

The FP increases in `CHANGES_ROUND8_2026-09-09.md` (A7 `28 → 213`, A8
`0 → 115`) contain S5 fires from an attack that was never injected. Those are
structurally impossible, not measured precision loss. The gate removal was still
correct — it exposed this rather than caused it — but the post-Q5 figures need
re-measuring on the fixed build.

---

## 3. The fix

**Files:** `s5_detection.h`, `crypto_layer.h`, `routing.cc`. Both flags default
**false**, so every previously reported number reproduces bit-identically.

### `--s5_variant_guard`

One line in `s5_detect()`, matching S6/S7/S8:

```cpp
if (s5_variant_guard && active_attack_variant != 4) return false;
```

It consults **which experiment is configured**, never **which node is guilty**.
That is the distinction from the oracle gate: it cannot manufacture precision,
because it cannot make a node look innocent. It removes cross-variant
contamination only — it does nothing for false positives inside Attack 5's own
run.

### `--s5_require_addressed`

The genuinely missing conjunct: *was this frame addressed to me?* Nothing
carried that information, so it is now plumbed:

- new `intended_recipient` field on `CustomDataUnicastTag_ModifiedRouting`
  (+ `Serialize`/`Deserialize`/`GetSerializedSize`; ctor defaults `UINT32_MAX`)
- set at all four live transmit sites: normal relay (`hop`), hidden copy
  (`spy_node_id`), active-HF duplicate (`eavesdropper_index`), source injection
  (`final_next_hop`)
- published at the MacRx tag peek into `g_s5_rx_intended_recipient`, read by
  `s5_detect()`

**This is not an oracle.** `intended_recipient` is independent of
`signed_next_hop`: a hidden-forwarding duplicate is addressed to d′ while still
carrying the *original* signed next hop, so d′ legitimately observes "addressed
to me **and** b_hop(u) = 0", while a passive overhearer sees "not addressed to
me" and drops out. No attack-injector state is consulted. An unset tag
(`UINT32_MAX`) is treated as "cannot tell" and falls through to legacy
behaviour rather than inventing a fire.

---

## 4. Measured

### Regression arm — flags off is bit-neutral

| | S5 fires |
|---|---|
| benign, pre-change binary | 7,389 |
| benign, post-change binary, both flags off | **7,389** |

The tag field, the serialization change and the receive-site hook perturb
nothing.

### Benign — false positives eliminated

| config | S5 fires | RSU windows firing | FPR | nodes quarantined |
|---|---|---|---|---|
| off | 7,389 | 924 / 1024 | 90.2% | 212 (157 veh) |
| `--s5_variant_guard` | 0 | 8 / 1024 | 0.8% | — |
| `--s5_require_addressed` | 37 | 62 / 1024 | 6.1% | — |
| **both** | **0** | **8 / 1024** | **0.8%** | **0** |

A benign network now stays completely uncontained. The addressing conjunct alone
accounts for ~99.5% of the reduction, which is the load-bearing result: it is
the non-oracle fix.

### Attack 5 — detection improved, not suppressed

| | off | both |
|---|---|---|
| **M1 (`score`)** | 0.0982 | **0.3702** |
| TP / FP | 13 / 197 | **77 / 98** |
| DR / FPR | 86.7% / 64.6% | 83.7% / **43.0%** |
| S5 fires | 36,179 | 128 |
| nodes quarantined | 252 (200 veh) | **70 (26 veh)** |
| hidden duplicates delivered | 4 | **31** |

**Read the MCC with the caveat.** This is not a like-for-like detector
comparison. Unfixed, the false-positive storm quarantined the network — the
attacker included — within seconds, so the attack only ever delivered 4
duplicates; fixed, it delivers 31. Part of the TP gain is that the attack
actually runs. The defensible claim is that the fix makes A5 **measurable**, and
that on the measurable run detection is substantially better — not that MCC
improved 3.8× under identical conditions.

### Other variants — contamination gone, own signatures unharmed

| run | S5 (was) | own signature (was) | quarantined (was) |
|---|---|---|---|
| A6 | **0** (57,618) | S6 96,912 (95,916) | 248 (253) |
| A7 | **0** (9,045) | S7 16,351 (11,136) | 143 (218) |
| A8 | **0** (22,774) | S8 34,049 (31,578) | 176 (217) |

S7 and S8 detect *more* than before: their attackers are no longer prematurely
quarantined by S5's false positives.

---

## 5. Open, and deliberately not fixed here

1. **37 residual benign fires under `--s5_require_addressed` alone.** All are
   vehicle senders → RSU receivers, correctly addressed but still failing
   `b_hop`. Consistent with **RSU handoff in flight** — the vehicle signs a next
   hop, the frame is addressed to it, but association moves before delivery
   (cf. `handoff_tracker.h`, which already models this for S1). Hypothesis from
   37 samples, not a conclusion. The variant guard conceals it in benign runs,
   but it stays live inside Attack 5's own run.
2. **A6 still quarantines 248 nodes** with S5 silent. That is S6's own
   behaviour, untouched by this work and unexplained.
3. **Option (b)** (teaching S5–S8 not to assert on a quarantined node) is
   ~20 lines across 5 files — the helper must live in `crypto_layer.h`, not
   beside its `std_delay_quarantine_blocks()` precedent, because
   `selective_time_delay.h` is included *after* S5–S8. It must test the accused
   **and** `hf_gt_attribution_node(accused)`, mirroring item 1. Not adopted:
   the 09-07 recommendation to scope it to A5/A7 was made when 81–94% of the
   network was quarantined before scoring opened, which left no regime to
   validate it in. **Re-evaluate now that benign quarantine is 0.**

---

## 6. Reproduce

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
env -u CXXFLAGS ./waf build

C="--N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 \
   --maxspeed=150 --use_sumo_mobility=1 --architecture=3 --simTime=90 \
   --sim_seed=1 --enable_detector_windows=1 \
   --enable_quarantine_enforcement=1 --hf_truth_latched=1"

# benign control — omit --attack_number entirely
./waf --run-no-build "scratch/routing/routing $C --attack_percentage=0 \
    --run_tag=bn_off"
./waf --run-no-build "scratch/routing/routing $C --attack_percentage=0 \
    --s5_variant_guard=1 --s5_require_addressed=1 --run_tag=bn_both"

# Attack 5, before and after
./waf --run-no-build "scratch/routing/routing $C --attack_number=5 \
    --attack_percentage=60 --run_tag=a5_off"
./waf --run-no-build "scratch/routing/routing $C --attack_number=5 \
    --attack_percentage=60 --s5_variant_guard=1 --s5_require_addressed=1 \
    --run_tag=a5_both"

# score
python3 scripts/m1_local.py \
    --results-dir ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing \
    --tag a5_both --score-col score
```

S5 fire counts come from `grep -c 'SIGNATURE S5 TRIGGERED'` on the run log;
quarantine counts from
`grep -oE "TRUST-QUARANTINE\] node=[0-9]+" | sort -u`.

`m1_local.py` is a local re-implementation — its absolute level must not be
compared against the canonical 0.2721, only arm-to-arm within the same binary.
Every comparison in this document is arm-to-arm.
