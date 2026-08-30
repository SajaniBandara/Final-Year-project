# Session README — 2026-08-29

Master tracker for this session's work: the supervisor's original 11-item
request, their follow-up decisions, the open follow-up question, and where
every item actually stands right now. Full source documents are linked at the
bottom rather than reproduced in full.

## 1. Supervisor's original request (11 items)

Sent as one message, organized in four groups:

**Approved, implement now**
1. M1 scores OBU rows, not just RSU rows (S1 currently earns credit nowhere)
2. Recall reported two ways: declared-attacker set and acted-attacker set
3. Per-node whole-run matrix: diagnostic only, never a results-table number
4. Fix WAP-R denominator to match Fix 1's covering-RSU attribution
5. Restructure monotonicity to per-variant applicable ladders
6. Run the Fix 2 data collection sweep, then rescore A1/A2 (leak-free ground truth)

**Needs one specific verification before closing**
7. S1 threshold: replace Gaussian k·sigma with a non-parametric percentile —
   build it, run a fresh zero-attack baseline, report the resulting FPR

**Diagnose first, no code changes yet (three separate questions)**
8. A3's Q1 score of 0.318 — f_unauth is supposed to be near-deterministic
9. Three residual A5 nodes (220, 225, 233) still firing 58/58 windows
10. A2 node-vs-window gap — S2 is 100% node-precision but window M1 is 0.431

**New analysis, additional to the ablation table**
11. Temporal performance curve for the full deployed system (mean +/- sd
    across 5 seeds vs. simulation time)

Full text: see conversation history / `docs/SUPERVISOR_FULL_REPORT_2026-08-28.md`'s
own framing of these items.

## 2. What the team reported back (2026-08-28)

`docs/SUPERVISOR_FULL_REPORT_2026-08-28.md` — all 11 items answered, plus
three unplanned findings:

- (a) A3/A4 have no leak-free ground truth either (same gap Fix 2 closed for
  A1/A2) — `tcam_send_gt` built, needs a collection sweep
- (b) Per-variant MCC is degenerate for A5, A6, A7 (TN=0 zeroes the MCC
  denominator, so A6 shows MCC=0.000 despite 86.2% detection at 0% FP)
- (c) A1's percentage sweep has 4 distinct operating points, not 6 (controller
  count banding)

Six decisions were requested back from the supervisor at the end of that report.

## 3. Supervisor's decisions on all six (2026-08-29)

| # | Item | Decision |
|---|---|---|
| 1 | Item 1 substitute | **Approved as built.** A2's 0.921 stands. A1's drop to 0.637 is item 7's threshold problem surfacing, not a regression — report A1 as provisional until item 7 lands. Add one methodology sentence: S1 computed at the OBU, scored against RSU-attributed ground truth, and why. |
| 2 | Item 5 (A7/A8 ladder) | **Build the real witness+R_anom config.** Do not keep Q4 as a permanent stand-in — both components already exist and are independently verified. |
| 3 | Item 7 (threshold fix) | **Approved to build, not yet approved as done.** One check first: best-effort and high-priority traffic may not share the same baseline delay shape (preferential queueing). Send mean/median/p99 of both populations from the same clean baseline, side by side, plus the resulting FPR/recall once live. |
| 4 | Item 9 (gate fix) | **Approved, implement now.** Clear implementation bug. Fix it, then rerun A5 in full to confirm no similar residuals surface elsewhere. |
| 5 | Finding (b) | **Most important item — needs one more check before deciding how to fix.** Rerun A5/A6/A7 at 20% or 40%. Two branches: negative windows reappear -> genuine saturation, report DR/FPR directly for zero-negative runs. Negative windows still absent -> scoping bug in window-truth computation, diagnose that instead. **Do not report any MCC for A5/A6/A7 anywhere until this comes back.** |
| 6 | Item 11 (temporal curve) | **Accepted, one clarification.** Confirm A2's "ceiling from the first window" starts at/after attack onset (t=10s), not before — the zero-attack baseline showed zero S2 firings, so early detection would contradict that. |

Supervisor also asked: **"Why don't you get any negative classes for A5, A6,
and A7?"** — this is finding (b) restated as a direct question. See section 5.

Priority instruction: **item 7's distribution comparison and finding (b)'s
low-percentage rerun must come back before touching anything else on those
two.** Everything else can proceed in parallel.

## 4. Progress as of now

| Item | Status |
|---|---|
| Item 1 methodology sentence | **Done.** Paragraph added to `docs/main.tex` after eq:mcc_variant: S1 evaluated at the OBU, scored against the covering RSU, and why (A1's OBU truth vector is identically zero by construction). |
| Item 5 (real witness+R_anom config) | **Built, not yet run.** R_anom was gated by `g_disable_s7_s8`, so no config could express the rung. Added tri-state `g_disable_ranom` (`crypto_layer.h`, default -1 = follow `g_disable_s7_s8`) so **every existing Q1-Q6 run stays bit-identical unless the flag is passed**, plus config `Q4R` in `run_q1q6_ablation.py`. Verified via `--table`. NB `g_ranom_rule_fired_this_pkt` deliberately left on the ungated value -- it drives Q3's LSTM suppression and has never been gated. |
| **Item 7** (threshold fix) | **ROOT CAUSE FOUND 2026-08-30; candidate fix under validation.** The two percentile arms are still correctly reported as negative results (see `docs/SUPERVISOR_UPDATE_2026-08-30.md` sec.7 -- best-effort costs A1 6.3 / A2 18.7 points of recall and was recommended against). What changed is the diagnosis of WHY. Measured on the zero-attack 300s baseline, **94.8% of all 2,676 false positives fall in the 50-300 ms band -- exactly `S1_HANDOFF_JITTER_MIN_S`..`MAX_S`** (median firing delay 246.9 ms). `s1_detect_packet()` adds a 50-300 ms draw whenever `handoff_just_occurred(vehicle_id)` and then tests that inflated value, so S1 fires on the confounder it injects itself. No threshold can separate them because the confounder is LARGER than the signal: A1/A2 inject 80 ms, while 1.25% of benign high-priority packets already exceed the ~85 ms an attacked packet reaches. Window-level OR-aggregation over ~15 high-priority packets per 10 s window turns 1.25% into 1-(1-0.0125)^15 = 17%, matching the 17.11% observed -- and it is why best-effort (threshold ~151 ms, ABOVE the 85 ms signal) rejected jitter and true detections alike. **Fix** (`--s1_suppress_handoff_fp`, commit `1448111`, default OFF so all prior results stay bit-identical): do not accuse on a packet the detector already knows carries handoff jitter. Measured seed 1: zero-attack window FPR **18.86% -> 0.03%** (3 firings), A1@60% 80ms recall **95.55%** at FPR **6.48%** (vs k*sigma 99.13% / 23.56%) -- strictly dominates the best-effort arm on both axes and is the first arm to clear the <=1% target. **NOT YET VALIDATED**: single seed, A1 only; 5-seed FPR + A2 recall running. **Limitation to report**: suppressing during handoff cycles creates an evasion window for an attacker timing delays to coincide with handoffs (handoffs are controller-mediated so cannot be manufactured at will, but the exposure is real and is the source of the 3.6-point recall cost). Not proposed for adoption until validated and signed off. |
| **Item 9** (gate fix) | **Gate fix correct; residual is SYSTEMIC, not 3 nodes.** Send-side repoint compiles and runs clean, and TP now equals truth-positive windows for 220/225/233 with zero false negatives -- the wrong-signal failure mode is gone. But a full sweep (`scripts/item9_granularity.py`) over every node with S5 activity on A5@60% found **39 nodes** show the residual, several worse than the three originally reported (node 236: 166 residual cycles vs node 220's 119). Root cause: `hf_send_gt` is nonzero in ~10% of cycles while S5 fires in ~45-53% -- the send-side counter's granularity does not match the detector's firing condition at all, for most attacking nodes, not just three. Needs the supervisor's call on what the correct send-side truth signal should be before changing the gate further. |
| **Finding (b)** (negative-window rerun) | **RESOLVED.** Root cause found and verified against the actual test split -- see section 5 below. It is the supervisor's branch 2 (scoping bug in window-truth computation via the wrong label, `test_y.npy`'s spike-based `y_bin` instead of leak-free `y_indep`), not saturation. The local window-grid rerun (A5/A6/A7 at 20/40/60%, all showing healthy TN) was never in conflict with the reported TN=0 -- they were measuring different things (rule-based S5-S8 vs the LSTM classification head). `docs/FINDING_B_PIPELINE_MISMATCH_2026-08-29.md`'s "needs HPC access" framing is superseded; no HPC data was actually needed. |
| Item 11 clarification | **Answered.** Confirmed via code trace (not a new run): the reported "t=2" data point is a window *start* label; the window's content (1.998s-11.998s) already spans past the actual attack onset at t=10s, and window truth is content-based, not start-label-based. Not a contradiction of the zero-attack baseline. |
| Finding (a) (tcam_send_gt sweep) | **Already DONE -- this row was stale.** Verified against the data 2026-08-29: A3/A4 training CSVs carry the `tcam_send_gt` column (20-col header vs A5-A8's 18) and it is populated -- nonzero in 32.7% of A3 rows and 30.6% of A4 rows (seed-5 split). A1/A2 likewise carry `std_send_gt`, nonzero in 24.0%/32.2% of rows at pct100. The collection was done by commit `e34f353` on 2026-08-28, and `lstm_training_pre_tcamgt_20260828/` is the pre-collection backup. `preprocessor.py:119` backfills zeros for the A5-A8 files that lack the column (deliberate, and it prints a warning), so the mixed 18/19/20-col schema is handled. All three injection counters now feed `y_indep` via `_inj = max(hfgt, stdgt, tcamgt)`. |

## 5. RESOLVED (2026-08-29, later same day): the negative-class question

**"Why don't you get any negative classes for A5, A6, and A7?"**

**Answered, with a verified code-level root cause. It is the supervisor's
branch 2 (scoping bug in window-truth computation), not saturation. No HPC
data was needed** -- two premises in the earlier write-up were wrong:

- `lstm_training/` **does** hold A5/A6/A7 raw data locally (1600 files each).
  The "zero rows" observed earlier was the *preprocessed cache*, not the
  source CSVs.
- The local reruns were never contradicting the pooled-split result. They
  were measuring the same thing from the other side.

**Mechanism.** `evaluator.py:predict_test()` loads `test_y.npy` -- the
*spike-based* label `y_bin`, not the leak-free `y_indep`. In
`lstm_pipeline/src/preprocessor.py:355`, `is_spike` for A5-A8 includes

    ddiv_spike = df["attack_v"].isin(HF_VARIANTS) & (df["d_div"] > 1)

`d_div > 1` holds in ~92-96% of ALL rows in an HF run, dormant cycles
included -- the code's own comment at preprocessor.py:294 says so ("85-92% of
'quiet' cycles ... already have d_div elevated"). Window truth is
`max()` over a 10-cycle window, so a signal present in ~92% of rows makes
essentially EVERY window positive. The negative class is annihilated before
scoring, which zeroes the MCC denominator.

**Measured on the actual test split (seed 5), and it predicts the observed
table variant-for-variant:**

| variant | rows `d_div>1` | windows positive by that leg ALONE | observed TN |
|---|---|---|---|
| A5 | 91.7% | **100.0%** | 0 |
| A6 | 96.4% | **100.0%** | 0 |
| A7 | 91.9% | **100.0%** | 0 |
| A8 | 54.1% | 92.6% | 173 |

A8 is the control: its lower `d_div` rate leaves 7.4% of windows able to be
negative, which is exactly why it alone has a nonzero TN. A6 is the sharpest
consequence -- 86.2% DR at 0% FP reported as MCC=0.000 purely because its
negatives never reach the confusion matrix.

**Fix candidate (NOT applied -- needs the supervisor's call, since it moves
every HF number):** score A5-A8 against `y_indep`, the leak-free
injection-based label the pipeline already computes and saves as
`test_y_indep.npy`. Relabelled that way the same test split carries **57-72%
negative windows** (A5 13,062 / A6 10,476 / A7 13,115 of 18,240).

The supervisor's standing instruction is unchanged and still binding: **do not
report any MCC for A5/A6/A7** until he has ruled on the fix.

`docs/FINDING_B_PIPELINE_MISMATCH_2026-08-29.md` predates this and its "needs
HPC access" checklist is superseded by the above.

## 6. Workflow gotcha found this session

**Always re-run `scripts/local_path_swap.sh local` immediately after any
`... hpc` revert, before launching another simulation.** Caught the hard way:
reverted to HPC paths to commit item 7/item 9 cleanly, then launched the item
7 baseline run without switching back. The compiled binary itself was
unaffected (`SCR` in `routing.cc` is baked in at compile time and was still
correct), but `scratch/optimization.py`/`optimization_lifetime.py` are
interpreted fresh from disk on every `system()` call — they picked up the
reverted `SCRATCH` HPC path, silently failed to find their own input CSV
every cycle (`Unexpected error in link lifetime optimization: ... No such
file or directory`), and the link-lifetime optimization degraded on every
cycle for the whole 300s run. That directly affects routing paths and
per-hop delay, i.e. exactly what S1 measures — the first baseline run's
numbers were discarded, not reported, and rerun after fixing paths.

Check for this specifically with:
```bash
grep -c "Solution not found\|Unexpected error in link lifetime" <run.log>
```
Zero is the only acceptable count. A nonzero count invalidates the run's
delay/routing-dependent metrics even if the simulation completes without
crashing.

## 7. Related documents

- `docs/SUPERVISOR_FULL_REPORT_2026-08-28.md` — the full 11-item report
- `docs/FINDING_B_PIPELINE_MISMATCH_2026-08-29.md` — the pipeline-mismatch
  diagnosis and HPC checklist
- `logs/findingb_pilot/` — A5/A6/A7 percentage-sweep run logs, this session
- `logs/item9_verify/` — item 9 verification run log
- `logs/item7_verify/` — item 7 baseline validation run log
