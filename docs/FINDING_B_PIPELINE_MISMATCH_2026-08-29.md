# Finding (b): Two pipelines, two different answers

A fresh, controlled test (this session) shows negative windows present at every
attack percentage tested — 20%, 40%, and 60% — for A5. That includes the exact
case (A5 @60%) that the supervisor report cites as TN=0. Both numbers are
real. They come from two different pipelines.

## The two paths

**Path 1 — what I tested this session:**

```
routing.cc (live sim, seed 1, A5/A6/A7 x 20%/40%/60%)
  -> detector_windows.csv
       truth = lstm_rsu_ground_truth_label() AND per-cycle activity gate
  -> results_table.py (window-grid scorer)
       RSU rows, score_primary column = rule-based S5-S8
  -> RESULT: TN healthy at every percentage, incl. 60% (MCC 0.86-1.00)
```

**Path 2 — what finding (b)'s original numbers came from:**

```
many pooled runs (many seeds x percentages, run_training_attacks.py)
  -> results_routing/lstm_training/RSU_*/Attack{5,6,7}_*.csv
  -> preprocessor.py -> test_meta.npy / test_y_indep.npy
       y_indep built from hf_send_gt
  -> evaluator.py
       LSTM classification head (A5-A8 have NO rule-based fallback --
       TCAM_RULE_BASED_VARIANTS = {3, 4} only)
  -> evaluation_results.json
  -> REPORTED: TN=0 for A5, A6, A7 (MCC = 0.000)
```

Both paths start from the same underlying ground-truth logic, but diverge on
three things. Only one of the three is confirmed so far.

## The three candidate explanations

**1. Different detector entirely — CONFIRMED REAL**
Mine scores the rule-based S5-S8 signatures. Finding (b) scores the LSTM
autoencoder's own anomaly threshold. Confirmed in code:
`TCAM_RULE_BASED_VARIANTS = {3, 4}` in `evaluator.py` — A5/A6/A7 never get a
rule-based fallback, only the LSTM head. A rule detector and a learned
threshold don't have to agree with each other.

**2. Different ground truth — UNCONFIRMED**
Mine uses the window grid's `truth` column (the ground-truth function ANDed
with the activity gate item 9 found is bugged). Finding (b) uses `y_indep`,
built from `hf_send_gt`. Likely correlated, not proven identical.

**3. Pooled test set vs. one run — UNCONFIRMED, BLOCKED LOCALLY**
The LSTM test split pools rows across many historical seeds/percentages. If
A5-A7's slice of that pool happens to only include high-percentage or
already-saturated runs, TN=0 could be correct *for that pooled set* without
contradicting a healthy single 60% run. I tried to check this directly:
`test_meta.npy` on this machine has **zero rows** for A5/A6/A7 — this
machine's cache can't settle it.

## What to ask your friend to check on HPC

In order of how directly each one settles the question. The first two need no
new compute — just reading files that already exist wherever the real
pipeline ran.

1. **Percentage/seed distribution in the real test split.** In
   `lstm_pipeline/preprocessed/test_meta.npy`, filter column 1 (attack_v) to
   5, 6, 7, then check column 2 (pct)'s distribution for those rows.
   - All high-percentage -> genuine saturation is plausible (candidate 3); my
     finding would then only apply to single runs, not the pooled set.
   - Mixed/low percentages present too -> pooling isn't the explanation,
     points back to candidate 1 or 2.

2. **Confirm `evaluator.py` isn't stale.** Re-run it fresh against the
   current model/data and diff the A5/A6/A7 rows against the committed
   `evaluation_results.json`. If they've already changed since Aug 28, the
   report's numbers may already be outdated.

3. **Direct ground-truth comparison (candidate 2).** For one matched run
   (same attack, percentage, seed), pull both the window grid's `truth`
   column and the raw `hf_send_gt` counter side by side. If they disagree
   meaningfully, that answers it on its own.

4. **If 1-3 don't settle it: send the raw training CSVs.**
   `results_routing/lstm_training/RSU_*/Attack{5,6,7}_*.csv` — with those on
   this machine, all three candidates become minutes of local checking
   instead of guesswork.

## Meanwhile — proceeding in parallel

None of these four depend on finding (b) or item 7 landing:

- **Item 9** — A5-A8 activity-gate repoint (`g_ranom_flag_last` ->
  `hf_send_gt` delta), then rerun A5 in full. **Built, verification run in
  progress.**
- **Item 5** — real witness + R_anom config for A7/A8's first ladder rung,
  replacing the Q4 stand-in. Queued next.
- **Item 1** — one-sentence methodology note: S1 computed at the OBU, scored
  against RSU-attributed ground truth, and why. Queued next.
- **Finding (a)** — tcam_send_gt collection sweep for A3/A4, closing the same
  leak-free-label gap Fix 2 closed for A1/A2. Queued next.

---
Sources: `docs/SUPERVISOR_FULL_REPORT_2026-08-28.md`,
`lstm_pipeline/evaluation_results.json`, this session's
`logs/findingb_pilot/*.log` (seed 1).
