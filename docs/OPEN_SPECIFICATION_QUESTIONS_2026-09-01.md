# Open specification questions, and remaining MCC levers (2026-09-01)

Two distinct lists. **Part A needs a decision** — these are not bugs, and no
amount of measurement resolves them; someone has to choose, and the choice
should be stated in the paper. **Part B is engineering** — defects with known or
estimable value.

---

# PART A — Specification questions

## A1. Does a persistently compromised but momentarily quiet RSU count as a positive?
**Status: implemented behind `--hf_truth_latched`, awaiting the decision.**

A5–A8 truth is gated per-cycle on `hf_send_gt`'s delta (EVENT). S5–S8 fire on
latched compromise state (STATE). Opposite semantics, scored across the gap.

| | A5–A8 MCC | DR | FPR | FP |
|---|---|---|---|---|
| event (today) | 0.5928 | 98.6% | 38.9% | 1621 |
| **state / latched** | **0.7674** | 87.7% | **8.5%** | 189 |

**73.8% of ALL remaining false positives** (1,595 / 2,161 in arm D) are this one
question. Argument for latched: `preprocessor.py:229` already applies exactly
this latch to `y_indep`'s HF term **with supervisor approval**, so today's state
is the inconsistency. Report as a measurement alignment, never as a detector
improvement.

## A2. Where does the latch reset?
End-of-run is correct **only** because quarantine currently does not enforce.
With `enable_quarantine_enforcement` on, a contained attacker would count as a
positive forever. Must move to quarantine time per `eq:local_quarantine`.
`hf_truth_latch_clear()` is the hook; wire it when enforcement lands.

## A3. Is the S5–S8 oracle gate a modelling assumption or a shortcut?
All four HF signatures early-return unless
`active_/passive_hf_malicious_nodes[prev_sender]` — the **attacker-assignment
array** written by the injector. `eq:sig_s5`'s five conjunctions do **not**
include it.

Consequences until resolved: S5–S8 **cannot** produce a false accusation, so
their precision is an identity, not a measurement; `score_primary` is
attacker-identity-aware and is not an achievable ceiling. **Do not report HF
precision as a detector property.** If the gate is deliberate ("compromise
identified out-of-band"), it must be stated in the paper, because it changes
what S5–S8 claim to do.

## A4. Should A3/A4 have an activity gate at all?
They currently have none (`act = 1` always), justified as "TCAM exhaustion
persists across cycles rather than firing discretely." That is **the same
argument as A1, resolved the opposite way.** The project should answer A1 and A4
consistently, or state why the families differ.

## A5. `W` (witness observation window) — the paper contradicts itself
`[tbd: {5, 10, 15} s]` with a stated "≤ 9 s zone residence bound". Two of three
candidates exceed the bound, **including the current default of 10.0**. Either
only W=5 is admissible and the default is invalid, or the bound is context.
Resolve before spending sweep runs.

## A6. `T_hold` — accept an empirical value?
Now **measured**: floor exactly 1 ms (= the RSU.Confirm RTT), recommended
**0.01 s** (10× margin, 9.74 ms mean hold vs the old default's 99.78 ms for
identical containment). Question: is an empirically-selected value reported with
its selection criterion acceptable, or does main.tex need a fixed number?

## A7. Which M-numbering?
main.tex and `evaluator.py` **conflict** on M2/M3/M5/M7/M8 (thesis M2=TVR vs
pipeline M2=DR, etc.). "M8" means poisoning resistance in one and UCR in the
other. Pick one convention for all reporting.

## A8. How is canonical M1 reproduced?
`scripts/m1_from_detector_windows.py` requires `python3 -m metrics.run_metrics`.
**That package does not exist anywhere on this host** and was never in git.
`scripts/m1_local.py` was written to close the gap, but it is a
re-implementation — absolute values are not comparable to the historical
M1 = 0.2721. Either recover the package or bless a re-implementation.

---

# PART B — Remaining MCC levers

Baseline 0.3836 → **0.5556** (arm D, attribution). Arm E (scoped) and arm F
(+ latched truth) pending.

## B1. Finish the two in flight
- **arm E** — attribution scoped to exclude A3/A4 (they regressed 0.5278→0.4392
  and 0.6490→0.6272 because their detectors accuse the *victim*, not the sender)
- **arm F** — arm E + `--hf_truth_latched`. Projected A5–A8 ≈ 0.77.

## B2. A1's S2f precision — **the largest genuine FP source left**
179 of A1's 264 FPs (67.8%) are true non-attackers — real false accusations, not
semantics. After A1 is settled this is the biggest remaining *detector* defect.

## B3. A3/A4 — both precision and recall genuinely broken
- A3: 144 FPs, **100% true non-attackers**; DR stuck at 57.7%, flat across every M
- A4: DR 70.8%, but FPR already 1.3%
- Worth **+0.1108** pooled if recall is recovered at unchanged FPR
- **Blocker: A1–A4 emit zero `tcam_*` diagnostic files** — the snapshot dumper is
  scheduled only on `first_ever` from `tcam_install`/the passive path, never from
  `tcam_install_malicious`. Fix that first; three hypotheses have already been
  tested and rejected without it.

## B4. Re-measure persistence M *after* the latch
M was empirically reconstructing the activity gate from firing density (dormant
median 2–3 cycles vs active 4–6). Once the truth is latched, that job disappears
— **M's value should shrink, and may reverse.** Do not stack the two assuming
they add. Use M=3 if it still helps; never M=8 (it collapses A1–A4 to 0.3988 and
leaves a variant at 10% DR).

## B5. LSTM-side work — real, but small for M1
Arm C settled the magnitude: gating the LSTM out of `D_RSU` moved M1 by **+0.007**.
The signature OR dominates. So these all matter for the LSTM's own metrics and
very little for full-system M1:
- **in-sim `cls_theta`** — fitted; benign firing 6.85% → 0.87%
- **end-to-end head** — offline macro-MCC 0.3142 → **0.6781**, the biggest
  offline gain of the session; confirms the frozen latent was the binding
  constraint. Deviates from the supervisor's "do not touch the encoder", so
  present it, don't ship it.
- **`d_div`/`a_tp` broadcast removal** — confirmed defect (100% cross-RSU
  agreement, AUC 0.500 within stratum)
- **`is_spike` contamination** → `y_binary` → `hparams.json`. `y_indep` is clean.

## B6. `LSTM_HC_MULT` is broken under the classifier head
`high_conf = score > 2.0 × theta_used`. With P(attack) ≤ 1.0 and θ median 0.940,
the bar is 1.88 — **unreachable for 44/64 RSUs (69%)**. The multiplicative test
was designed for the autoencoder's unbounded reconstruction error. Needs an
additive or percentile form if the high-confidence tier is to mean anything under
the classifier.

## Dead ends — measured, do not revisit
| lever | result |
|---|---|
| per-RSU M (FPR-target) | 0.3344 |
| per-RSU M (MCC-optimal ceiling, same-data fit) | 0.4224 — still below global 0.5539 |
| longer warm-up | FPR flat across the run (61%→53%) |
| classifier head as calibrated | −0.003 on M1 |
