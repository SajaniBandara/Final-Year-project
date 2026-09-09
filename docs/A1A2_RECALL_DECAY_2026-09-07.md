# A1/A2 recall decay — the per-bucket breakdown you asked for

**Requested:** round 8, *"Break true positives into time buckets across the run
and for each bucket report both how many genuine events existed as ground truth
and how many were caught… Send the breakdown before proposing anything."*

**Run:** 60%, `d80ms`, seed 1, **90 s — diagnostic length, not reportable.**
Enforcement-OFF arm (`r7a1e0` / `r7a2e0`) so quarantine does not confound the
decay signal. Error gate 0. S1/S2 are untouched by the Q5 oracle-gate removal,
which was S5–S8 only, so these numbers are unaffected by that change.

## Attack 1

| bucket | `score` GT | caught | recall | | `score_primary` GT | caught | recall |
|---|---|---|---|---|---|---|---|
| 0–10s | 30 | 15 | 0.5000 | | 64 | 38 | 0.5938 |
| 10–20s | 40 | 35 | 0.8750 | | 64 | 45 | 0.7031 |
| 20–30s | 34 | 23 | 0.6765 | | 64 | 38 | 0.5938 |
| 30–40s | 34 | 33 | 0.9706 | | 64 | 38 | 0.5938 |
| 40–50s | 32 | 32 | 1.0000 | | 64 | 37 | 0.5781 |
| 50–60s | 31 | 30 | 0.9677 | | 64 | 36 | 0.5625 |
| 60–70s | 27 | 25 | 0.9259 | | 64 | 34 | 0.5312 |
| 70–80s | 25 | 25 | 1.0000 | | 64 | 36 | 0.5625 |

## Attack 2

| bucket | `score` GT | caught | recall | | `score_primary` GT | caught | recall |
|---|---|---|---|---|---|---|---|
| 0–10s | 193 | 186 | 0.9637 | | 107 | 78 | 0.7290 |
| 10–20s | 237 | 221 | 0.9325 | | 107 | 77 | 0.7196 |
| 20–30s | 271 | 264 | 0.9742 | | 106 | 79 | 0.7453 |
| 30–40s | 287 | 285 | 0.9930 | | 106 | 76 | 0.7170 |
| 40–50s | 287 | 285 | 0.9930 | | 104 | 67 | 0.6442 |
| 50–60s | 289 | 279 | 0.9654 | | 100 | 63 | 0.6300 |
| 60–70s | 289 | 285 | 0.9862 | | 100 | 60 | 0.6000 |
| 70–80s | 286 | 283 | 0.9895 | | 96 | 56 | 0.5833 |

## What the data says

**There is no recall decay on `score` for either variant.** This is the headline
correction. A1's `score` recall *rises* across the run (0.50 → 1.00); the low
first bucket is warm-up, not decay, and it recovers by 30 s and stays high. A2's
`score` recall is flat and high throughout (0.93–0.99) while ground-truth events
*increase* 193 → 287 and then plateau. Neither matches the pattern that prompted
the question.

**A2 `score_primary` is real degradation, and it is the one finding here that
needs action.** Applying your own test: ground truth stays essentially steady
(107 → 96, −10%) while recall falls 0.7290 → 0.5833, a 20% relative drop. Genuine
events are not tapering off — they are increasingly missed. This is not the
dormant-window pattern and does not get the limitation treatment.

**A1 `score_primary` is a mild version of the same thing.** Ground truth is
*exactly* constant at 64 per bucket — one declared-truth window per RSU per
bucket — while recall drifts 0.594 → 0.563. Small, monotone after the warm-up
bump, and consistent in direction with A2.

**A1 `score` ground truth does taper** (30 → 25, −17%) but recall rises against
it, so the taper is not costing detections.

## Consequence

The two `score_primary` columns are the real finding: a detector-side decline
against steady ground truth, strongest on A2. Per your instruction we are sending
the breakdown before proposing a fix, and are not touching code.

One caveat on scope: at 90 s the last bucket is 70–80 s, so this characterises
early-run behaviour only. If the decay continues past 80 s the 300 s reporting
runs will show it far more clearly, and we would want to re-cut this table at
300 s before drawing a conclusion about the shape of the decline.
