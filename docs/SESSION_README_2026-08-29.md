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
| Item 1 methodology sentence | Not started |
| Item 5 (real witness+R_anom config) | Not started |
| **Item 7** (threshold fix) | **Code built** (best-effort-calibrated percentile, clean A/B against the old path, diagnostics export). **Not yet run** — needs a zero-attack baseline for the mean/median/p99 comparison + FPR number. |
| **Item 9** (gate fix) | **Code built and verified.** Send-side gate repoint compiles and runs clean. Rerun on A5@60%/300s: TP now equals truth-positive windows exactly for nodes 220/225/233 with zero false negatives (real improvement — the old wrong-signal failure mode is gone). But all three nodes still fire in 58/58 windows regardless of the corrected gate, leaving 19-24 residual FP per node. **Not fully closed** — points to a second, narrower issue: whether `g_lstm_hf_sendgt_count`'s increment granularity actually matches how often S5's own firing condition is true for these high-activity nodes. Needs its own follow-up diagnosis. |
| **Finding (b)** (negative-window rerun) | **Partially done, and the result complicates the picture.** A5 rerun at 20%/40%/60% (window-grid scorer): negative windows present at every percentage, including 60% — this contradicts a simple "saturation at 60%" explanation. A6/A7 also rerun at 20%/40%, all show healthy TN. Full writeup + 3 candidate explanations + HPC checklist: `docs/FINDING_B_PIPELINE_MISMATCH_2026-08-29.md`. **The original TN=0 numbers still stand as real** — they come from a different pipeline (LSTM classification head on a pooled historical test split) than what was reproduced locally (rule-based window grid, single runs). Not resolved; needs HPC data. |
| Item 11 clarification | **Answered.** Confirmed via code trace (not a new run): the reported "t=2" data point is a window *start* label; the window's content (1.998s-11.998s) already spans past the actual attack onset at t=10s, and window truth is content-based, not start-label-based. Not a contradiction of the zero-attack baseline. |
| Finding (a) (tcam_send_gt sweep) | Not started |

## 5. Open question needing HPC data

**"Why don't you get any negative classes for A5, A6, and A7?"**

Full detail, diagram-in-prose, and a concrete checklist for what to check on
HPC: `docs/FINDING_B_PIPELINE_MISMATCH_2026-08-29.md`.

Short version: local reproduction (window-grid scorer, single runs) shows
healthy negative windows at every tested percentage, contradicting the
"genuine saturation at 60%" branch the supervisor set up. The three candidate
explanations (different detector / different ground truth / pooled test set
vs. one run) are not fully distinguished — the local machine's LSTM
preprocessed cache has **zero rows** for A5/A6/A7, so the actual pooled test
split's composition can't be inspected here. That file has the exact
checklist for whoever has HPC access.

## 6. Related documents

- `docs/SUPERVISOR_FULL_REPORT_2026-08-28.md` — the full 11-item report
- `docs/FINDING_B_PIPELINE_MISMATCH_2026-08-29.md` — the pipeline-mismatch
  diagnosis and HPC checklist
- `logs/findingb_pilot/` — A5/A6/A7 percentage-sweep run logs, this session
- `logs/item9_verify/` — item 9 verification run log
