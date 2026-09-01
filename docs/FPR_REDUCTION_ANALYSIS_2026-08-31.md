# How to reduce FPR — evidence and ranked fixes (2026-08-31)

M1's loss is entirely false-positive-driven: recall is already fine (DR 92.6%),
precision is not (FPR 53.3%). So every fix below targets precision, and none
should be judged on DR.

Measured with `scripts/m1_local.py` on the stashed Q6 grids
(`prior_Q6_stash_2026-08-31_2313/`, 8 variants). Absolute levels are from a
local re-implementation and a stash of unknown config — **read the deltas, not
the levels**.

## The central measurement

`detector_windows.h` emits two scores per window. `score` is the deployed
OR-composite `D_RSU`; `score_primary` is the variant's primary detector, which
**excludes `flag_LSTM` for every variant** ([`lrad.h`](../scratch/lrad.h) primary
switch: A1/A2→`S2f`, A5/A6→`S5|S6`, A7/A8→`S7|S8`).

| | MCC | DR | FPR | FP |
|---|---|---|---|---|
| `score` (OR-composite, **includes LSTM**) | 0.4350 | 92.6% | **53.3%** | 3781 |
| `score_primary` (**excludes LSTM**) | **0.5654** | 71.2% | **15.3%** | 1087 |

**2694 of 3781 false positives — 71% — come from the disjuncts outside the
primary detector.** Dropping them *raises* MCC from 0.435 to 0.565 despite
losing 21 points of DR. The OR-composite is currently net-harmful.

Per variant, the damage is concentrated in Hidden Forwarding:

| variant | MCC `score` | MCC `primary` | FPR `score` | FPR `primary` |
|---|---|---|---|---|
| A5 | 0.2866 | **0.7278** | 82.1% | 26.7% |
| A6 | 0.3278 | **0.8149** | 82.0% | 19.2% |
| A7 | 0.3495 | **0.7305** | 74.6% | 26.3% |
| A8 | 0.4027 | **0.8389** | 73.0% | 14.8% |

A5–A8 fire at DR 100% / FPR 73–82% under the OR — the detector is close to
"always on", which is why MCC collapses. Their primary detectors are strong
(0.73–0.84). The LSTM is destroying signal that S5–S8 already provide.

---

## Fix 1 — stop soft LSTM hits reaching the window score (highest value, smallest change)

`D_RSU` keys on `flag_LSTM` alone:

```cpp
// lrad.h:451
flags.D_RSU = flags.flag_S2f || flags.flag_S5 || flags.flag_S6 ||
              flags.flag_S7 || flags.flag_S8 || flags.flag_LSTM;
if (flags.D_RSU) dw_mark_rsu(rsu);   // ← feeds M1
```

But `flag_LSTM_high_conf` already exists and the codebase **already treats soft
LSTM-only hits as untrustworthy in two other places**:

- `lrad.h:571-574` — a soft LSTM-only trigger is blocked from opening the BTMM
  trust gate at all
- `lrad.h:628` — only high-confidence LSTM hits are latched into the per-node
  confusion matrix

So the project has twice decided a soft LSTM-only hit is not strong enough
evidence to act on — and then lets it into the very score M1 reports. That is an
inconsistency, not a design choice.

**Change:** use `flag_LSTM_high_conf` in the `D_RSU` disjunction (or require
`flag_LSTM && (flag_LSTM_high_conf || any_signature)`). Cheap, one line,
consistent with existing policy, and needs no retraining.

## Fix 2 — persistence M (free: no new runs needed)

`detector_windows.h` (item 7, 2026-08-30) emits `score_cycles` and
`score_primary_cycles`: how many distinct cycles inside the 10 s window the
detector fired in. Its own rationale — *"emitting the count lets the persistence
threshold M be swept offline from a SINGLE run per configuration, instead of one
90-minute run per candidate M."*

**This lever appears never to have been swept.** A window is positive under
persistence-M iff `*_cycles >= M`; M=1 is today's behaviour.

Evidence it will bite: in the smoke run (A5 @60%), the RSU window distribution is

| firing cycles | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|---|
| windows | 34 | **39** | 11 | 11 | 12 | 14 | 7 |

**39 windows fire in exactly one cycle out of ten.** A genuine hidden-forwarding
compromise is persistent state (S5's conjunctions are latched; the FlowMod stays
unendorsed), so a single-cycle blip is far more consistent with noise than
attack. M=2 erases all 39 at minimal DR cost.

`scripts/m1_local.py --persistence M` sweeps this offline on any grid from the
current binary. Do M=1..5 the moment tonight's runs land.

## Fix 3 — per-variant / per-RSU LSTM thresholds (§6b, already done offline)

Cuts the LSTM's FP rate at source rather than downstream: A6 FPR 75.3% → 4.1%
window-level. Blocked in-sim: `lstm_logger.h:539` loads `hf_theta.json` as a
**single scalar**, and the scalar collapse forfeits most of the gain
(mean MCC 0.303 per-RSU → 0.226 scalar). Needs a per-RSU HF lookup in
`lstm_logger.h`.

## Fix 4 — classifier head at FPR≤1% (§6a, running tonight)

`cls_theta.json` thresholds are calibrated per-RSU at FPR≤1%, versus the
autoencoder's reconstruction-error threshold. This is the arm currently under
test.

## Fix 5 — A3 is a separate problem, do not fold it in

A3's *primary* detector scores MCC **0.0382** at FPR 22.0% — it carries almost no
information, matching the recorded diagnosis "A3 at DR≈FPR≈50.8% (MCC=0.000) =
detector carrying no information". A3 is the one variant where `score_primary`
FPR (22.0%) is *worse* than the OR (20.0%). No amount of LSTM gating helps here;
S3/S4's rule needs its own review.

---

## What NOT to do

**Do not simply deploy `score_primary`.** It selects the detector using
`active_attack_variant` — the ground-truth attack label. That is variant-aware at
inference and not deployable; it is a diagnostic upper bound, not a system. Its
15.3% FPR is therefore optimistic. The deployable equivalent is "`D_RSU` with the
LSTM term gated" (Fixes 1–4), whose true FPR lies between 15.3% and 53.3%.

**Measure that gap before choosing.** Q5 is *not* a clean isolation — it disables
the witness mechanism and BTMM trust alongside the LSTM. The clean measurement is
the LSTM-only ablation the code already documents at `lrad.h:464-484`, which found
the LSTM "entirely responsible" for the FP explosion on A3/A4 (FP 2 → 413) while
witness-only and BTMM-only matched baseline byte-for-byte.

## Suggested order

1. Sweep persistence M offline on tonight's grids — zero cost, zero risk
2. Gate `D_RSU` on `flag_LSTM_high_conf` — one line, already-endorsed policy
3. Land §6a/§6b thresholds
4. Review S3/S4 separately for A3
