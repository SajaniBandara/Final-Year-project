# State and next steps — 2026-08-30

Single pickup document. Covers the supervisor's latest instructions, every
diagnostic answered since, all measured numbers, and exactly what to run next.
Written so work can move entirely to the machine holding the LSTM dataset.

Companion docs (still valid, not superseded):
- `HANDOFF_OTHER_MACHINE_2026-08-30.md` — **path setup, read first on a new machine**
- `SUPERVISOR_ROUND3_ANSWERS_2026-08-30.md` — code-level answers to items 5, 9, finding (b)
- `SESSION_README_2026-08-29.md` — the running item-by-item tracker

---

## 1. Status at a glance

| Item | State |
|---|---|
| Item 1 — methodology sentence | **DONE**, in `main.tex` |
| Item 5 — witness+R_anom (Q4R) | **DONE**; scored against the simulator's own confusion matrix, NOT the pipeline finding (b) broke, so trustworthy as-is |
| Item 7 — persistence sweep | **DONE** — full FPR + A1/A2 recall tables, §3 |
| Item 7 — handoff-jitter root cause | **FOUND + FIXED behind a flag**; A1 measured, **A2 and 5-seed still missing** |
| Item 9 — S5 vs gate granularity | **DIAGNOSED + remedy validated on real data**; awaiting sign-off to implement |
| Item 11 — temporal curve | **DONE** (earlier round) |
| Finding (a) — A3/A4 leak-free label | **Already done** (commit `e34f353`), no sweep needed |
| Finding (b) — degenerate MCC | **ROOT CAUSE FOUND + cross-check returned**; verdict: fix jointly with item 9 |
| Q3–Q6 grid | **BLOCKED — do not run** (supervisor instruction) |

---

## 2. What the supervisor asked (round 3) and what happened

| Ask | Outcome |
|---|---|
| Item 5: confirm what A7's 0.963 is scored against | **Answered.** `run_q1q6_ablation.py` reads TP/FP/TN/FN from the MOBIGUARD CSV, written by `routing.cc` from `is_malicious_node[]`/`is_detected_node[]`. It contains **zero** references to `is_spike`/`y_bin`/`test_y.npy`. Different pipeline entirely — needs no re-scrutiny when finding (b) is fixed. |
| Finding (b): how is the cleaner label built, at what granularity | **Answered.** `y_indep` = `max(hf_send_gt, std_send_gt, tcam_send_gt)` over the 10-cycle window, positive iff `> 0` (`preprocessor.py:235-238`). A **per-cycle EVENT counter OR-ed across the window**, not a state flag. |
| Finding (b): A5 cross-check vs S5's 45–53% | **Answered on the LSTM machine.** See §5 — lands on the **65% branch**. |
| Item 9: which S5 condition is actually true | **Answered from code, then confirmed by data.** See §6. |
| Item 7: build within-window persistence and sweep M | **Done.** See §3. |
| Do not run Q3–Q6 | Respected. |

---

## 3. Item 7 — persistence sweep results (the direct answer)

Default k·σ threshold, 300 s, seed 1, `--enable_detector_windows=1`.
A window counts positive under persistence-M iff the detector fired in **≥ M
distinct cycles** of that window's ten. M=1 is exactly today's OR behaviour.

### Validation — three independent anchors reproduce at M=1
This is what makes the rest trustworthy:

| anchor | expected (published) | measured at M=1 |
|---|---|---|
| zero-attack window FPR | 18.86% | **18.86%** |
| A1 @60% | TP 802 / FP 684 / FN 7 / TN 2219, recall 99.13%, FPR 23.56% | **identical** |
| A2 @60% | recall 99.94%, FPR 7.21% | **identical** |

### False alarm rate — zero attack, OBU windows

| M | FP windows | window FPR |
|---|---|---|
| 1 (today) | 2188 | 18.86% |
| 2 | 186 | 1.60% |
| 3 | 7 | **0.06%** |
| 4+ | 0 | 0.00% |

Benign false positives are **88.8% single-cycle** — which is why persistence
works at all, and confirms the supervisor's breadth diagnosis.

### Recall — un-deduplicated (matches the published A1/A2 table, n=3712)

| M | A1 recall | A1 FPR | A1 MCC | A2 recall | A2 FPR | A2 MCC |
|---|---|---|---|---|---|---|
| 1 (today) | 99.13% | 23.56% | 0.6368 | **99.94%** | 7.21% | **0.9207** |
| 2 | 89.86% | 12.44% | 0.7023 | 93.64% | 2.77% | 0.9118 |
| 3 | 79.11% | 6.44% | **0.7210** | 87.89% | 1.43% | 0.8785 |
| 4 | 66.13% | 3.82% | 0.6785 | 81.16% | 0.72% | 0.8321 |
| 5 | 52.90% | 1.69% | 0.6319 | 72.76% | 0.38% | 0.7698 |
| 6 | 41.78% | 0.83% | 0.5699 | 61.70% | 0.14% | 0.6877 |

Deduplicated (`eq:eval_dedup`, n=1856) agrees to within ~1 point throughout.

### The finding that matters
**A1 and A2 disagree about the best M.** A1's MCC *improves* with persistence
(0.637 → 0.721 at M=3); A2's *degrades monotonically* (0.921 → 0.879). A2 is
already healthy at M=1 because item 1's RSU-primary attribution fixed it, so
persistence there only discards true detections. A1 is sick at M=1 because of
the handoff-jitter false positives (§4), which persistence partially masks.

Since the ablation grid runs **one** config for all variants, **no single M
serves both**: A2 wants M=1, A1 wants M=3.

---

## 4. Item 7 — the handoff-jitter root cause (separate from persistence)

**Why both earlier percentile arms failed.** `s1_detect_packet()` adds a
50–300 ms draw whenever `handoff_just_occurred(vehicle_id)`, then tests that
inflated value — S1 fires on a confounder it injects itself. Measured on the
zero-attack baseline: **94.8% of all false positives land in the 50–300 ms
band**, median firing delay 246.9 ms.

The confounder is **larger than the signal** (A1/A2 inject 80 ms), so no
threshold can separate them: 1.25% of benign high-priority packets already
exceed the ~85 ms an attacked packet reaches, and OR-aggregation over ~15
packets per window turns that into ~17%, matching the 17.11% observed. The
best-effort arm pushed the threshold to ~151 ms — *above* the 85 ms signal —
which is why it rejected jitter and true detections alike.

**Fix:** `--s1_suppress_handoff_fp` (default OFF, so all prior results are
bit-identical). Do not accuse on a packet already known to carry handoff
jitter — the serving RSU participates in the handoff, so this is runtime
information, not oracle knowledge.

### Measured, seed 1, vs the alternatives on A1

| approach | zero-attack FPR | A1 recall | A1 MCC |
|---|---|---|---|
| baseline k·σ (M=1) | 18.86% | 99.13% | 0.637 |
| persistence M=3 | 0.06% | 79.11% | 0.721 |
| **handoff fix** | **0.03%** | **95.55%** | **0.840** |

Wins on all three axes and needs no per-variant tuning — it removes the
*cause*, persistence filters the *symptom*.

**Limitation to report:** suppressing during handoff cycles creates an evasion
window for an attacker timing delays to coincide with handoffs. Handoffs are
controller-mediated so cannot be manufactured at will, but the exposure is
real and is the source of the 3.6-point recall cost.

**MISSING — this is the top run priority:** the handoff fix has **no A2
measurement** and **no 5-seed FPR**. That queue was killed mid-run by a path
swap (see §8) and discarded rather than trusted.

---

## 5. Finding (b) — resolved, and the cross-check verdict

**Root cause:** `evaluator.py` scores against `test_y.npy` (the spike-based
label), not the leak-free `y_indep`. For HF variants that label includes
`d_div > 1`, true in 92–96% of ALL rows including dormant cycles. Window truth
is `max()` over 10 cycles, so nearly every window is positive, TN and FP
collapse to 0, and the MCC denominator is zero. A8 is the control: its lower
54.1% rate leaves 7.4% of windows able to stay negative, which is exactly why
it alone has nonzero TN.

**Cross-check result (measured on the LSTM machine, A5 @60%, five seeds):**

| quantity | all 64 RSUs | attacker RSUs only |
|---|---|---|
| per-cycle `hf_send_gt` firing (booleanised) | 6.7 – 7.5% | 11.3 – 12.6% |
| independence prediction, W=10 | ~52% | ~71% |
| **measured `y_indep` window rate** | **30.3 – 33.7%** | **51.1 – 55.9%** |
| S5 per-cycle firing | 45 – 53% | — |

Two corrections that came out of this: `hf_send_gt` is a **count (0–5), not a
0/1 flag** (the earlier 8.85% was mean events per cycle, not the fraction of
cycles firing); and the windowing replication reproduces the stored `y_indep`
to within 0.4 points, so the pipeline is being measured faithfully.

**Verdict: the 65% branch, not the 100% branch.** Measured lands ~2× short of
S5, so the window-level OR does **not** launder item 9's coarseness. Per the
supervisor's own decision rule: **one defect at two granularities → fix
jointly with item 9.**

Worth noting the measured rate is *below* even the independence prediction,
which means duplicate-send events are **clustered** (a burst in one cycle,
then silence) rather than independent. Independence would have narrowed the
gap; bursting preserves it.

---

## 6. Item 9 — diagnosis confirmed, remedy validated

**From code:** `s5_detect()`'s conjunctions 1–2 are both *persistent* —
FlowMod never endorsed, and `active_hf_malicious_nodes[]` assigned once in
`hf_declare_malicious_rsus()` and never cleared. So S5 fires on an **ongoing
compromised state**, while `hf_send_gt` marks only the instant a duplicate is
scheduled. **S5 firing more often is correct detection, not a bug** — exactly
the supervisor's working guess.

**Validated on real data (LSTM machine), applying the proposed latch
("has this RSU ever scheduled a duplicate up to now") to existing A5 @60% data:**

| | per-event OR (today) | latched |
|---|---|---|
| attacker RSUs | 52.0% | **93.0%** |
| benign RSUs | 0.0% | **0.0%** |

Latching lifts attacker-RSU windows to where S5 sits, **without disturbing
benign RSUs at all**. Also confirmed: S5 records against `prev_sender`
(`s5_detection.h:276`) — the same node `hf_send_gt` marks — so there is **no
sender/receiver attribution mismatch**.

**Status: ready to build, not built.** It changes every A5–A8 window-truth
number, so it needs the supervisor's sign-off.

---

## 7. New problem found: attacker set saturates at high intensity

The ever-firing set tracks the malicious set cleanly at low/mid intensity but
not at high:

| attack % | RSUs ever firing | expected |
|---|---|---|
| 20% | 13 / 64 | ~13 |
| 40% | 26 / 64 | ~26 |
| 60% | 39 / 64 | ~38 |
| 80% | 44 / 64 | ~51 |
| 100% | 47 / 64 | ~64 |

At 80–100% a large minority of malicious RSUs never schedule a duplicate —
no traffic routes through them — so a latched signal cannot rescue them; they
stay 0 forever. A5/A7 labels at 80–100% will therefore under-count attackers.

**Two observations that likely settle this without a new decision:**

1. **This is item 2's declared-vs-acted distinction reappearing.** An RSU that
   is compromised but never had traffic routed through it has not *acted* — it
   never had the opportunity. The supervisor already ruled: report recall
   **both** ways. So `active_hf_malicious_nodes[]` is the *declared* set and
   observed sends (even latched) the *acted* set — **not one instead of the
   other, both**. `detector_windows.csv` **already emits both** for A5–A8
   (`truth` = acted, `truth_declared` = declared); only the LSTM pipeline's
   `y_indep` lacks a declared counterpart.

2. **The non-monotonicity has a concrete cause.** `hf_declare_malicious_rsus()`
   sorts `on_path_nodes` by traffic load descending, and that load comes from
   each run's own delta values. Different runs → different sort order → the
   top-N sets at different percentages are **not nested**. Expected given the
   implementation, but it means "attacker set" is not stable across a
   percentage sweep, and that should be stated wherever such sweeps are reported.

---

## 8. Environment warnings — read before running anything

Full detail in `HANDOFF_OTHER_MACHINE_2026-08-30.md` §1. The essentials:

- `local_path_swap.sh` knows **exactly two** machine conventions. On a third
  machine it will rewrite paths to a machine you are not on. Run
  `./scripts/local_path_swap.sh status` and check `$HOME`/`pwd` first.
- **Two path families the script does not handle**, both needed for LSTM work:
  `lstm_logger.h`'s `g13_project_repo` paths, and `preprocessor.py`'s `BASE` /
  `evaluator.py`'s `RESULTS` (`$HOME` + a cluster suffix, no leading/trailing
  slash, so the script's rule misses it). `BASE` must resolve to the directory
  containing `lstm_training/`.
- **Two failure modes with different timing.** The `.py` helpers are read
  **fresh every cycle** — wrong paths **degrade** a run silently rather than
  stopping it (observed: 28 min of CPU for 3.7 simulated seconds). The mobility
  path is **compiled into** `routing.cc` — wrong at build time aborts instantly.
  Order: fix paths → rebuild → verify → run.
- **Never swap paths while a run is in flight** — the ns-3 tree's
  `scratch/optimization*.py` are symlinks into the repo. Commit *before*
  launching, never during.
- Verify every run before trusting it:
  `grep -c "Solution not found\|Unexpected error in link lifetime" <log>` → must be **0**.
- `detector_windows.csv` is now **11 columns, not 9**. Do not glob old and new
  files together; the sweep tool refuses pre-change files, ad-hoc scripts will not.

---

## 9. What to run next, in priority order

### P1 — complete the handoff-fix comparison (blocks the item 7 recommendation)
The only missing cell in §4. Without it, "handoff beats persistence" rests on A1 alone.

```
--simTime=300 --sim_seed=1 --attack_number=2 --attack_percentage=60 \
  --attack_delay_ms=80 --attack_delay_pseudo_random=0 \
  --enable_detector_windows=1 --s1_suppress_handoff_fp=1
```

Then 4 more zero-attack seeds for a 5-seed FPR mean, matching the published
table's rigour:
```
--simTime=300 --sim_seed={2,3,4,5} --enable_detector_windows=1 --s1_suppress_handoff_fp=1
```

### P2 — the untested combination
Handoff fix **+** persistence, zero-attack + A1 + A2. Handoff alone is
0.03% / 95.55%; persistence M=3 is 0.06% / 79.11%. The combination at M=2 may
beat both, and because M sweeps offline from the count columns this is
**3 runs, not 3 × N**.

### P3 — item 9's confirming trace (optional now)
`[S5]` lines carry `t=` as of commit `b5f3857`, so the per-condition breakdown
is recoverable. The latch is already validated on data (§6), so this only
confirms conjunctions 3–4 behave as expected in the disagreeing cycles.

### Analysis for all of the above
```
python3 scripts/item7_persistence_sweep.py --results-dir <RESULTS_DIR> \
  --baseline detector_windows_Attack0_0_seed1_<tag>.csv \
  --attack   detector_windows_Attack1_60_d80ms_seed1_<tag>.csv \
  --attack   detector_windows_Attack2_60_d80ms_seed1_<tag>.csv
```
Self-check: **M=1 must reproduce the published k·σ numbers.** If it does not,
the run or the columns are wrong — stop and investigate rather than reporting.

---

## 10. Do NOT

- **Run the Q3–Q6 grid.** Supervisor's explicit instruction; finding (b)'s
  rescore decision and item 9's gate signal are both still open, so it would
  bake in known problems and need redoing.
- **Flip any default.** Every fix this session is behind a flag defaulting to
  the old behaviour, so all previously reported numbers stay reproducible.
  Adoption is the supervisor's call.
- **Report any MCC for A5/A6/A7** until finding (b)'s rescore is signed off —
  standing instruction, still binding.

---

## 11. Open decisions needing the supervisor

1. **Finding (b) + item 9 — now confirmed as one problem.** The cross-check
   landed on the 65% branch, so by their own rule these get fixed together.
   Needs: approval to rescore A5–A8 against `y_indep`, and to implement the
   latched gate. Both move every HF number.
2. **80–100% saturation (§7).** Our reading is that this is item 2's
   declared-vs-acted rule, already decided, needing only application rather
   than a new ruling — but worth confirming, since it changes what A5/A7 labels
   mean at high intensity.
3. **Item 7 — which lever.** Handoff fix wins on A1 and needs no per-variant
   tuning; persistence has no evasion-window exposure but has no single M that
   serves both A1 and A2. Pending P1/P2 above before a final recommendation.
