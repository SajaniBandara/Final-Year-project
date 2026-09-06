# Round 8 triage — status of every item (2026-09-06)

Source: `docs/supervisor_message_2026-09-06_round8.md`.

**Crossover note.** This message replies to `DRAFT_SUPERVISOR_REPLY_2026-09-05.md`.
It crossed with `SUPERVISOR_UPDATE_2026-09-05.md`, which already reports measured
results for item 1's A/B runs and item 4's outcome. Items marked **ALREADY DONE**
below need reporting, not work.

Legend: **DONE** · **BLOCKED** (needs a ruling) · **READY** (can start now) ·
**STOP** (finding contradicts the instruction — decision needed)

---

## Item 1 — enforcement · **DONE**

> *"Confirm A2, A6, A8 don't share A4's specific defect… before assuming the fix
> generalizes cleanly."*

Measured 2026-09-05/06, quarantined-node census per variant:

| variant | quarantined | vehicles | RSUs | shares A4's defect? |
|---|---|---|---|---|
| A1 | 25 | 0 | 25 | **N/A** — attacker is always an RSU by construction |
| A2 | 93 | **76** | 17 | **No** — vehicle trust is decremented (S2/LRAD path) |
| A4 | 142 | **122** | 20 | **Was yes; now fixed** (0 → 122 vehicles) |
| A5 | 64 | 20 | 44 | **No** |
| A6 | 167 | **122** | 45 | **No** |
| A7 | 68 | 26 | 42 | **No** |
| A8 | 164 | **121** | 43 | **No** |

**A4 was genuinely unique.** Only the TCAM path lacked a trust-decrement for the
attacker; every other variant already had one. A1's zero is correct by
construction, not a defect.

A1 approved into scope — **already implemented and validated** (see round 7):
A1 −80.9%, A2 −72.6%, A4 −10.7% attack actions, and **post-quarantine leak 0 of
44,171 actions** across 236 quarantined-and-acting nodes.

**Remaining:** nothing. Report the round-7 numbers.

---

## Item 2 — UCR · **READY** (documentation only)

Two writing tasks, no code:
1. One sentence in the paper: `flag_S2p` reduces to its threshold term in
   practice; S2-partial does not perform integrity verification.
2. Write up A5–A7 against the corrected UCR metric, as already done for A8.

---

## Item 3 — the richer D_div · **GO — all three criteria pass**

**Superseded.** An earlier revision of this file recorded a STOP here, on the
basis of a log-derived estimate that the feature would degenerate. **That estimate
was wrong and the live smoke test overturned it.**

Measured 2026-09-06, `--ddiv_smoke_test` (instrumentation only, no feature
changed), 60 s, seed 1, 60%, error gate 0 on all five runs:

| variant | max | nonzero | RSUs disagree | corr(feature, `R_anom`) |
|---|---|---|---|---|
| A5 | 5 | 21.4% | 48/48 (100%) | 0.783 |
| A6 | 7 | 40.6% | 48/48 (100%) | 0.793 |
| A7 | 5 | 21.3% | 48/48 (100%) | 0.811 |
| A8 | 5 | 29.4% | 48/48 (100%) | 0.788 |
| **benign** | **0** | **0.00%** | 0/48 | — |

- **(a) non-constant across the 64 RSUs:** yes, in 100% of attack cycles, all four
  variants. Not a silent collapse.
- **(b) exactly zero under benign traffic:** yes — max 0 across 3,712 samples.
- **(c) correlation with `R_anom` below 1:** yes, 0.78–0.81. This is the
  load-bearing number. The *simple* per-RSU form sits at ≈1.0 by construction
  (it reduces to `1 + 1[r_anom > 0]`); the richer form counts how many distinct
  sources misbehave where `R_anom` counts how many events occur, so one loud
  attacker and five quiet ones are different states `R_anom` conflates.

**Why the earlier estimate was wrong, recorded so it is not repeated.** The log
analysis counted distinct *flows per forwarder*; the feature counts distinct
*source vehicles per covering RSU*. Different quantities — and the
vehicle→covering-RSU aggregation exists only at runtime, so no amount of log
post-processing could have reached it. This feature's behaviour must not be
predicted from logs.

**Consequence:** per the supervisor's instruction ("if all three hold, go straight
into the regeneration and retrain already planned"), the regeneration is
**unblocked**, bundled with the oracle-gate removal since both need fresh runs.

**Paper:** `eq:feat_ddiv` was already indexed $(v,r,t)$ — per source, per RSU — so
the spec was never the problem; the aggregation step to a single per-RSU model
input was left implicit and got implemented as a network-wide scalar. Corrected in
`main.tex` with a new `eq:feat_ndiv` stating the aggregate explicitly, its
relationship to `eq:feat_ddiv` (aggregation only, $D_{div}$ unchanged), and why it
is not a restatement of `R_anom`.

**A_tp (Q4, option two) — READY, unaffected.** Promote `fade_forwarded_count` /
`fade_received_count` to RSU-keyed via the same attribution. `eq:feat_atp` is
already per $(v,r,t)$, so this is an implementation fix, not a spec change.

---

## Q5 — the oracle gate · **READY, highest priority**

Approved for removal, bundled with the item 3 regeneration. Agreed with the
reasoning: precision guaranteed by construction is not a measurement, and this is
the same class as label leakage — found late only because it lived in C++ control
flow rather than a training script.

Both outcomes are publishable; the current number is not.

---

## Item 4 — the latch · **STOP — approved, but the measurement says otherwise**

Approved "as built". **The supervisor had not seen the round-7 measurement when
they wrote this.** Enabling it drops M1 on all four HF variants, on both score
columns:

| variant | `score` Δ | `score_primary` Δ |
|---|---|---|
| A5 | −0.031 | −0.103 |
| A6 | −0.178 | **−0.326** |
| A7 | −0.109 | −0.209 |
| A8 | −0.164 | −0.195 |

Cause: truth's boundary moved to quarantine, the detector's did not. 72–76% of the
new false positives are declared attackers firing after their own quarantine.
S5–S8 have no quarantine awareness at all.

**Flags stay default-off.** This needs re-raising explicitly — the approval was
given without the data. Note it may resolve itself once the oracle gate comes out,
since that gate is part of why S5–S8 keep asserting; **re-measure after Q5 rather
than fixing the detector separately.**

---

## Q1 — covering-RSU proxy · **READY** (documentation only)

Approved as-is; do not build per-vehicle trust paths. Add one limitations sentence
stating the over-block plainly, with individual vehicle trust paths as future work.

---

## Item 5 — M4 · **DONE**, unblocks now

Implemented and verified on real data. Item 1 is closed, so this is unblocked.

---

## Q6 — metric numbering · **READY**

Paper is canonical; conform every script. Flag genuine paper errors back rather
than silently picking a side.

---

## Q7 — canonical M1 script · **READY, today**

Bless `scripts/m1_local.py` formally and **commit it today**. Retire 0.2721
explicitly as a number from an unrecoverable script.
⚠ Blocked in practice by the path-swap hazard — see Blockers below.

---

## Q8 — UCR predicate/window · **READY** (one check, then document)

Accept the implementation; document rather than change code. Check first that a
duplicate always arrives within a short bounded time of its original, well under
any candidate `W`. If so the whole-run vs windowed distinction is moot.

---

## Q9 — `W` vs residence bound · **READY** (rewording)

Reword rather than sweep. Supervisor offered to reverse if we prefer the sweep;
we do not — the reframing is accurate and the sweep would not change the default.

---

## Q10 — M4 default · **READY, immediate**

Flip `enable_corrected_lmit` to default 1.

---

## Q11 — OBU rows · **READY**

Separate explicit OBU-stage table; do not blend into the RSU headline. Resolves
the "S1 cannot affect M1" problem without a new aggregation scheme.

---

## Confidence multiplier (`LSTM_HC_MULT`) · **READY**

Recalibrate as a percentile cut on the validation split at a stricter operating
point. No offset patch.

---

## A1/A2 recall decay · **READY, analysis only**

Per time bucket, report **both** ground-truth event count and caught count.
Distinguishes a dormant-window artefact from real degradation. Send the breakdown
before proposing anything.

---

# Blockers

**The repo cannot be committed as-is.** `routing.cc` shows 1145 changed lines;
**1083 are the local-only path swap** (`sdvn_hidden_attacks` → `nipuni`) that must
never reach the repo. Real session work is ~55–62 lines. Six other touched files
are pure path swaps. This blocks Q7's "commit it today" instruction until the
isolation is done.

# Proposed order

1. **Isolate and commit** — unblocks Q7 and protects the session's work.
2. **Q10** (one-line default flip) and **Q1/Q9/Q2** documentation — minutes each.
3. **A6/A8 instrumentation smoke test** — settles item 3's open half cheaply.
4. **Oracle gate removal (Q5)** — highest scientific priority.
5. **A1/A2 recall-decay breakdown** and **HC_MULT recalibration** — parallel, no
   dependency on the regeneration.
6. Regeneration + retrain, bundling item 3 and Q5. **No ablation grid before this.**
