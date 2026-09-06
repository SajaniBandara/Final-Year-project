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

## Item 3 — the richer D_div · **STOP — pre-build check does not support it**

The supervisor asked for exactly this confirmation before building:

> *"does the simulation already model multiple concurrent attacking source
> vehicles routing through a shared RSU at the percentages you're testing… I don't
> want you building on an assumption I haven't verified."*

**Measured. The expectation is not borne out.** Per-cycle (1 s) distinct attacked
flows per malicious forwarder — this is the value the proposed feature would take:

| variant | active cells | cells with >1 flow | % | max | mean |
|---|---|---|---|---|---|
| A5 | 7 | **0** | **0.00%** | **1** | 1.000 |
| A7 | 17 | **0** | **0.00%** | **1** | 1.000 |
| A6 | 49 | 5 | 10.20% | 2 | 1.102 |
| A8 | 57 | 6 | 10.53% | 2 | 1.105 |

**The proposed feature never exceeds 2 anywhere, and for A5/A7 it is identically
1** — exactly as degenerate as the simple version it was meant to replace.

**Confidence split, stated honestly:**

- **A5/A7 — definitive.** Their forwarders *are* RSUs (7 and 13 RSU forwarders,
  0 vehicles), so forwarder-level measurement **is** RSU-level measurement. The
  feature cannot carry information here. No further check will change this.
- **A6/A8 — not yet resolved.** Their forwarders are mostly vehicles (32 and 35),
  and several vehicles can share one covering RSU, which would aggregate upward.
  The logs do not carry the covering-RSU attribution (it is computed at runtime
  from link lifetimes), so this cannot be settled from existing data.
  **Indirect evidence that sharing is real:** our latch-clear guard only releases
  when no other non-quarantined attacker attributes to that RSU, and on A6 it
  released just 52 times against 122 vehicle quarantines — ~70 suppressions, each
  one an instance of two attackers sharing a covering RSU.

**Also confirmed, and it matters regardless of the outcome:** attacks span **4–7
distinct flows** (A5:4, A6:6, A7:6, A8:7) while the current accumulator is gated on
`fid == 0` alone. The single-flow hardcoding the supervisor identified is real and
discards most of the attack surface. Generalising to all flows is warranted on its
own merits, independent of whether the per-source-vehicle count survives.

**Recommendation:** run the smoke test as *instrumentation only* — log the
per-RSU count under the real `hf_gt_attribution_node()` attribution without
changing the feature — on a 60 s A6/A8 sample. That settles A6/A8 for the cost of
one short run and no feature commitment. If it confirms ≤2 there too, take the
supervisor's own fallback: the straightforward per-RSU fix, D_div characterised as
a corroborating indicator.

**A_tp (Q4, option two) — READY, unaffected.** Promote `fade_forwarded_count` /
`fade_received_count` to RSU-keyed via the same attribution. Independent of the
D_div question.

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
