# Supervisor's four fixes — tracking, 2026-08-14

Supersedes `docs/SUPERVISOR_QUESTIONS_STATUS_2026-08-12.md` (deleted — every
item in it is now resolved; see `git log -- docs/SUPERVISOR_QUESTIONS_STATUS_2026-08-12.md`
for its content if needed). This doc tracks implementation of the supervisor's
2026-08-14 four-fix response to the previous round's findings.

## Status at a glance

| Fix | Status | Notes |
|---|---|---|
| 1. Q3 LSTM gating for A3 | **DISPUTED — see below** | Diagnosed mechanism does not match current code |
| 2. Two-tier LSTM / trust cascade break | **implemented, verified NULL RESULT** | Zero FP movement on Q6 — the gated path (trust) never drove those FP numbers; see below for the mechanically-correct extension, not yet applied |
| 3. Windowed-max δ_t + binary exceedance feature | **implemented, retrained, verified — DOES NOT FIX A1/A2** | Full 205-job grid collected, clean retrain done 2026-08-18 07:22. A1 DR=2.7%, A2 DR=4.6% — barely moved from the earlier confounded interim checkpoint (1.7%/2.3%). See below. |
| 4. SIM_TIME=300 in ablation runner | **implemented; Q1 complete (8/8), Q2-Q6 pending** | `run_q1q6_ablation.py` default now 300s. Q1 banked 2026-08-18 08:38 before a 09:00 machine handover; resume with `--configs Q2,Q3,Q4,Q5,Q6` |

---

## Fix 1 — supervisor's diagnosis does not match the current code

**Supervisor's claim**: `--g_disable_s3_s4` suppresses not just
`record_detection_event()` but also the computation of
`g_tcam_flag_s3_last`/`g_tcam_flag_s4_last`, so under Q3 (S3/S4 off) the LSTM
gate sees `flag_S3=false` always and runs unsuppressed on A3 traffic,
producing the negative MCC (−0.348).

**Code audit (2026-08-14)**: this is not what the code does.

- `scratch/tcam_detection.h:272,310`: `flag_s3`/`flag_s4` are computed
  unconditionally — `g_disable_s3_s4` is applied *only* at
  `tcam_detection.h:336,349`, to the `record_detection_event()` calls.
  This exact asymmetry is already documented at `tcam_detection.h:261-271`
  and independently in `docs/Q1Q6_ABLATION_RUNBOOK.md` §3 as *"intentional
  and supervisor-confirmed. Do not 'fix' it."* (dated 2026-08-03).
- `g_tcam_flag_s3_last[node_id]`/`g_tcam_flag_s4_last[node_id]` are published
  at `tcam_detection.h:325-326`, inside the same unconditional block.
- `lrad.h:321-337` reads those raw published flags directly
  (`tcam_covers_this_rsu = g_tcam_flag_s3_last[rsu] || g_tcam_flag_s4_last[rsu]`)
  and suppresses `flag_LSTM` when both that and `lstm_would_fire` are true.
- **Empirically confirmed live**: re-examined the Q3/A3 run log from this
  session's Blocker 4 sweep (90s/60%/seed1) — `[LSTM-GATE] ... total_suppressed=2860`
  by the end of the run. The gate fires thousands of times. It is not silently
  disabled.

**Conclusion**: implementing Fix 1 as literally described would be a no-op
(the described unconditional computation already exists) or, if
misapplied, could break the asymmetry the runbook explicitly protects.
**Not implementing as specified — flagging back to supervisor instead.**

**The real symptom is still real and needs a different explanation.** Q3/A3
confusion matrix (this session, 90s/60%/seed1): TP=2, FP=141, FN=30, TN=95.
Ground-truth positives (TP+FN) = 32, but raw LSTM-positive firings = 143 —
the detector is firing on nearly 3× as many RSU-windows as are genuinely
TCAM-attacked, and almost entirely on the *wrong* ones (2/32 true positives
recovered). The gate is suppressing correctly during confirmed S3/S4
conditions; the remaining false positives are firing during windows the
raw TCAM signal does *not* cover. Candidate causes not yet ruled out:
per-RSU θ miscalibration for this specific config, a ground-truth scoping
mismatch between the LSTM's own confusion-matrix bucket and the TCAM
gate's per-cycle raw condition, or genuine reconstruction-error inflation
from TCAM residual occupancy *between* saturation windows (the gate's own
documented rationale — "inflates reconstruction error... throughout the
simulation run" — read literally, this could mean the raw condition being
gated on is itself too narrow a window relative to the effect it's meant to
suppress). Not resolved yet; flagged rather than guessed at.

---

## Fix 2 — implemented; verified against Q6, zero effect on FP (as predicted)

**Before implementing, an exhaustive grep of every `trust_update_negative()`
call site in the tree** (`crypto_layer.h`, `lrad.h`, `routing.cc`) found none
keyed on `flag_LSTM`'s truth value — every call site is crypto/timing-keyed
(BTMM: `sig_valid && batch_passed && !flag_S2f`; S5's explicit call; witness
BFT quorum). `flag_LSTM` firing only ever does two things: (a) permanently
sets `is_detected_node[v][n] = true` via `record_detection_event()`
(`lrad.h:403-410`, `routing.cc:115389-115394` — never reset within a run),
and (b) makes `D_RSU` true, which opens the shared `btmm()` call
(`lrad.h:372-374`) whose reward/punish *outcome* is decided by crypto/S2f,
not by `flag_LSTM` itself — an LSTM-only false positive on a packet with
valid crypto and no S2f would, if anything, receive an *unearned*
`trust_update_positive()`. **There is no LSTM→`trust_update_negative()` edge
to gate as literally specified.**

**Implemented anyway**, as the closest faithful mapping: `lstm_detect()`
(`lstm_inference.h`) gained an out-param returning the effective per-RSU
theta it decided against; `lstm_logger.h` computes
`g_lstm_high_confidence[r] = score > 2×theta_used` alongside the existing
`g_lstm_last_dlstm[r]`; `lrad.h` reads it into a new `flag_LSTM_high_conf`
field and skips the shared `btmm()` call entirely when `flag_LSTM` is the
*only* thing that made `D_RSU` true and it isn't high-confidence — the
closest available proxy for "soft detections don't trigger
`trust_update_negative()`". `record_detection_event()` (confusion-matrix
recording) is untouched, exactly as instructed ("records detections at θ as
before").

**Verified against Q6, same 90s/60%/seed1 config as the Blocker 4 baseline
(100–221 FP range): confusion matrices are byte-for-byte identical across
all 8 variants, zero FP movement anywhere.** This was the predicted outcome,
not a surprise — the gate I added touches only the trust path, and the trust
path was never what produced those FP numbers. The sticky per-node latch
(`is_detected_node[][]`, set on the *first* `flag_LSTM` firing at θ,
regardless of confidence, and never cleared) is what's actually driving
Q6's FP counts, and Fix 2 as specified cannot reach it.

**Recommendation, not yet applied without sign-off**: extend the same
`score > 2×theta_used` gate to `record_detection_event()`'s `flag_LSTM`
call at `lrad.h:403-410` — i.e., only a high-confidence LSTM detection
reaches the sticky per-node latch; soft detections stay silent in the
confusion matrix too, not just in the trust path. This directly contradicts
the "confusion matrix records detections at θ as before" instruction, which
is why it's flagged rather than applied. Raising the multiplier to 3× (the
supervisor's own stated fallback) will not help either — the multiplier
value was never the problem; the gated code path is.

## Fix 3 — δ_t → windowed max + binary exceedance indicator

**Code implemented (C++ and Python), retraining NOT started — scale decision
needed before proceeding, see bottom.**

Implementation:

- `s1_detection.h`: new `s1_rsu_obs_max[]`/`s1_rsu_exceeded_dmax[]`
  accumulators, updated in `s1_detect_packet()` alongside the existing
  mean accumulators but **not consumed by `s1_update_baseline()`** — S1's
  own rule-based EWMA is untouched, only the LSTM's copy of this signal
  changes. `LSTM_DELTA_MAX_S = 0.050` (matches `S2_DELTA_MAX`, redefined
  locally since `s1_detection.h` is `#include`'d before `s2_detection.h`).
- `routing.cc`: drains the new accumulators alongside the existing mean
  drain, passes `obs_delay_max`/`obs_exceeded_dmax` to `lstm_log_rsu_cycle()`
  instead of the mean.
- `lstm_logger.h`: `raw_feat` now 11 elements (`delta_t_exceeded` appended
  last); CSV header bumped to 18 columns (`LSTM_CSV_HEADER`), old 17-column
  files migrate by appending `,0` (extended `lstm_migrate_stale_header()`'s
  existing chain, same pattern as the 16→17 `hf_send_gt` migration it
  already had — **old rows' `delta_t` value is still mean-based**, migration
  only adds the missing column, it can't retroactively fix what old rows
  measured).
- `lstm_inference.h`: `lstm_normalize_features()` now **aborts loudly**
  (`std::cerr` + `std::abort()`) on a raw/model feature-count mismatch
  instead of silently zero-padding — this fires on any run with
  `--enable_lstm_inference=1` until the model below is retrained, by design
  (better than the quiet corruption the old code would have produced).
- `lstm_pipeline/src/preprocessor.py`: `FEATURES` list gets `delta_t_exceeded`
  appended. The spike-labeling logic (`delta_t > benign p99`) is
  threshold-derived from the data itself, not hardcoded to mean semantics —
  needs no code change, will recalibrate automatically against the new
  max-based distribution once fresh data is collected.
- `lstm_model.py`: `N_FEATURES` 10→11. Every other pipeline script
  (`evaluator.py`, `local_trainer.py`, `fed_aggregator.py`, etc.) imports
  this constant rather than hardcoding it, so they pick up the change
  automatically — checked all nine call sites.
- `export_weights_cpp.py`/`gen_cpp_validation_case.py`: derive `n_features`
  from the checkpoint itself at export time, not hardcoded — docstrings
  updated for accuracy only, no logic change needed.

Rebuilt (`-O3` confirmed, 39/0 `.so` split) — compiles clean.

**Scale decision resolved 2026-08-17/18: full grid regenerated, not a
scoped subset.** Collected the complete 205-job grid (8 attacks × 5
percentages × 5 seeds + benign, 13,120 CSVs, 3,894,464 rows, all at
`simTime=300` with genuinely per-cycle-max `delta_t`) — took considerably
longer than the 1–3h estimate (~19h wall clock across two sessions,
including a mid-collection worker-count/thermal-throttling detour; see
git history / conversation log for the operational detail, not repeated
here). Old 8,064-CSV/49-combo dataset backed up and superseded, not mixed
into the new one — verified 0% zero-delta_t rate and 0 malformed rows
across the full new dataset before retraining.

**Retrained 2026-08-18 07:22 on the clean full grid.** Result:

| | TP | FN | M1 MCC | M2 DR | M3 FPR |
|---|---|---|---|---|---|
| A1 CP-SelectiveDelay | 30 | 1080 | 0.083 | **2.7%** | 0.51% |
| A2 DP-SelectiveDelay | 67 | 1382 | 0.129 | **4.6%** | 0.68% |
| A3 CP-TCAM (rule-based, unaffected by this fix) | — | — | 0.940 | 96.6% | 0.75% |
| A4 DP-TCAM (rule-based, unaffected by this fix) | — | — | 0.840 | 81.8% | 1.02% |
| A5 CP-ActiveHF | 7582 | 738 | 0.0\* | 91.1% | 0% |
| A6 DP-ActiveHF | 8320 | 0 | 0.0\* | 100% | 0% |
| A7 CP-PassiveHF | 7589 | 731 | 0.0\* | 91.2% | 0% |
| A8 DP-PassiveHF | 8057 | 90 | 0.437 | 98.9% | **56.1%** |
| Overall (LSTM: A1,2,5-8, pooled) | 31645 | 4021 | 0.822 | 88.7% | 1.27% |

\*A5-A7's `M1_MCC=0.0` is a TN=0 divide-by-zero artifact in the per-variant
formula (per the project's MCC reporting convention — report M1 pooled/
deduped, not per-variant, when TN=0 makes the per-variant formula
degenerate), not a real failure — their 88-100% DR is the honest
per-variant signal for those three.

**Conclusion: Fix 3 does not fix the A1/A2 detection collapse.** DR moved
from 1.7%/2.3% (earlier confounded checkpoint, missing A5-8 data) to
2.7%/4.6% now — a small, real improvement, but both remain far below any
usable threshold. The pooled "Overall" MCC=0.822 should **not** be read as
evidence the system works well across the board — it's dominated by
A5-A8's much larger sample counts (31,548 of 31,645 total TP) drowning out
A1/A2's near-total failure; the per-variant breakdown (not the pooled
number) is what matters here, and it says A1/A2 need real further
diagnosis, not declared fixed.

**New issue surfaced by this same retrain, not previously visible**: A8's
FPR is 56.1% — over half of benign windows misclassified as attacks for
that variant specifically, despite its DR being high (98.9%). Not
investigated yet; flagging alongside A1/A2 rather than separately, since
both need attention before Q6 can be called complete.

## Q1 results (2026-08-18, 300s, 60%, seed 1) — complete, 8/8

Q1 = rule signatures only (S1-S4 live, S5-S8 off, LSTM off, crypto forced
pass, witness off).

| variant | TP | FP | FN | TN | MCC |
|---|---|---|---|---|---|
| A1 | 25 | 94 | 0 | 149 | 0.3589 |
| A2 | 148 | 80 | 0 | 40 | 0.4652 |
| A3 | 32 | 0 | 0 | 236 | 1.0000 |
| A4 | 41 | 0 | 6 | 221 | 0.9216 |
| A5 | 0 | 0 | 40 | 228 | 0.0000 |
| A6 | 0 | 0 | 158 | 110 | 0.0000 |
| A7 | 0 | 0 | 39 | 229 | 0.0000 |
| A8 | 0 | 0 | 158 | 110 | 0.0000 |

A5-A8 at zero is the **correct** isolation result, not a failure: their
S5-S8 signatures are disabled in Q1 by design, so TP=0/FN=all is what the
config is supposed to produce. Confirms the Q1 flag isolation works.

**Load-bearing observation for the A1/A2 question (Fix 3):** the rule-based
S1/S2 path shows **FN=0 on both A1 and A2** — it catches every attack
window — while the LSTM on the same attacks gets DR=2.7%/4.6%. The
denominators differ (ablation detector-windows vs. the LSTM evaluator's own
windows), so this is not a strict like-for-like comparison, but the
qualitative gap is far too large to be accounted for by that. It argues the
timing signal is present and detectable, and the failure is in the LSTM's
labeling/feature/threshold path rather than in signal strength — which cuts
against the D3 premise that mean δ_t's 0.28σ separation makes A1/A2
inherently hard. Worth checking before spending effort on feature
engineering: whether the LSTM's per-window label for A1/A2 actually marks
the same windows S1/S2 fires on.

Q2-Q6 not yet run (machine handover at 09:00). Resume:
`python3 scripts/run_q1q6_ablation.py --configs Q2,Q3,Q4,Q5,Q6 --workers 8`
— `--configs` composes with the banked Q1 CSVs, so Q1 is not redone (~4h).

## Fix 4 — SIM_TIME 90→300 in `run_q1q6_ablation.py` — implemented

`--sim-time` default changed 30→300 in `scripts/run_q1q6_ablation.py`.
`MAX_CYCLE=310` was already set correctly in
`lstm_pipeline/src/preprocessor.py` (2026-08-02, anticipating 300s runs) —
nothing to change there. `WARMUP_CYCLES=30` unchanged (untouched by this
fix). `docs/Q1Q6_ABLATION_RUNBOOK.md`'s sizing section annotated with the
supersession note and a rough 300s wall-clock projection (65–135 min for
a single-lane `optimized` run, scaling the measured 90s figure by ~3.3x).

---

## Rerun sequence (per supervisor) — status

1. Fix 1 → verify A3/Q3 shows TP=0/FP=0/MCC=0.000.
   **Blocked — the diagnosed mechanism doesn't exist in the current code**
   (see Fix 1 section). Not applied, not verified. Flagging back rather than
   implementing a no-op or guessing at a different fix without sign-off.
2. Fix 2 → rerun Q6 alone, confirm FP drop from the 100–221 range.
   **Done. Confirmed FP is unchanged (byte-for-byte identical confusion
   matrices, all 8 variants) — predicted before running, then verified.**
   Root cause and a recommended (not-yet-applied) extension documented above.
3. Fix 3 → retrain on 11-feature input, then full Q1–Q6 at 300s.
   **Retrain done 2026-08-18 07:22 on the full clean 205-job grid — does
   not fix A1/A2 (DR 2.7%/4.6%, see Fix 3 section above). Q1-Q6 ablation
   (48 runs, 300s, 60% attack, seed 1, per supervisor's spec) launched
   2026-08-18, in progress, ETA ~2h.**
4. Send updated cumulative MCC table. **Partial — LSTM per-variant table
   above is final; Q6 rule/crypto/witness numbers pending the Q1-Q6 run
   in progress.**

Target: Q6 macro-MCC ≥ Q5 macro-MCC (0.856), Q6 > Q5 > Q1 on every variant,
Q6 macro-MCC ≥ 0.85 overall, before final experiments are authorized.

## Open decision for the user/supervisor

Three items need a call before this can close out:

1. **Fix 1**: the diagnosed mechanism (`g_disable_s3_s4` suppressing flag
   computation) isn't what the code does — it's already unconditional,
   confirmed via a live suppression counter (2860 firings in one run). A3's
   real Q3 negative MCC needs fresh diagnosis, not this fix.
2. **Fix 2**: implemented as specified, verified to have zero effect on the
   FP numbers it was meant to reduce, for a structural reason (no
   LSTM-keyed `trust_update_negative()` call exists to gate). A concrete,
   mechanically-correct extension is proposed (gate `record_detection_event()`
   itself) but not applied — it contradicts the "confusion matrix records at
   θ as before" instruction, so it needs explicit sign-off, not a unilateral
   change.
3. **Fix 3 retraining scale**: resolved — full grid regenerated (205 jobs,
   not the smaller 49-combo scope originally estimated at 1-3h; actually
   took ~19h wall clock). Retrain complete, verified NOT to fix A1/A2 (see
   above). **New open question this raises**: what should the actual
   diagnosis path be for A1/A2's near-total detection failure (DR 2.7%/
   4.6%), given the windowed-max feature only produced a marginal
   improvement over the mean-based one? Candidate directions not yet
   investigated: per-class training imbalance for these two attack types
   specifically, θ threshold miscalibration, or a labeling/ground-truth
   issue specific to Selective Time Delay's window construction. Also
   flagging A8's 56.1% FPR, newly visible in this same retrain, as a
   second open item needing attention before Q6 can be called complete.
