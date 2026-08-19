# Update on the four fixes (2026-08-14 response) — draft for review

Hi [Supervisor name],

Update on the four fixes from your 2026-08-14 response. Short version: two
are done and verified, one I'm flagging back to you rather than
implementing as literally specified, and the headline result — Fix 3 — is
a real negative: it does **not** fix the A1/A2 detection collapse.

## Fix 1 (Q3 LSTM gating for A3) — flagging back, not implemented

I audited the code path you described (`g_disable_s3_s4` suppressing the
computation of `flag_s3`/`flag_s4`, not just detection-event recording).
That's not what the code does — `flag_s3`/`flag_s4` and the published
`g_tcam_flag_s3_last`/`s4_last` signals the LSTM gate reads are computed
**unconditionally**; `g_disable_s3_s4` only gates
`record_detection_event()`. This asymmetry is intentional and already
documented in the runbook as supervisor-confirmed ("do not fix it").
Live-verified the gate is actually firing (2,860 suppressions in one run),
so it isn't silently disabled either.

A3/Q3's real confusion matrix (TP=2, FP=141, FN=30, TN=95) still needs
explaining — the detector is firing on ~3x as many RSU-windows as are
genuinely attacked, mostly on the wrong ones. I don't have a diagnosis yet
and didn't want to guess at a fix without your input — candidates are
per-RSU θ miscalibration, a ground-truth scoping mismatch, or the gate's
own documented "narrow window" caveat. Flagging rather than implementing
something that would either no-op or break the runbook's protected
asymmetry.

## Fix 2 (two-tier LSTM / trust cascade) — implemented, verified zero effect

Before implementing, grepped every `trust_update_negative()` call site —
none are keyed on `flag_LSTM`'s truth value. Implemented the closest
faithful mapping anyway (high-confidence gate on the trust path). Verified
against Q6 at the same config as the earlier FP baseline: confusion
matrices are byte-for-byte identical across all 8 variants, zero FP
movement. This was the predicted outcome, not a surprise — the sticky
per-node latch (`is_detected_node[][]`, set on first `flag_LSTM` firing at
θ, never cleared) is what actually drives the FP counts, and this fix
can't reach it.

**Proposed extension** (not applied without sign-off): gate
`record_detection_event()`'s `flag_LSTM` call the same way, so only
high-confidence detections reach the sticky latch. This contradicts your
"confusion matrix records detections at θ as before" instruction, which is
why I haven't just done it — need an explicit call here.

## Fix 3 (windowed-max δ_t + binary exceedance) — implemented, retrained, does not fix A1/A2

Implemented in both C++ (`s1_detection.h`, `routing.cc`, `lstm_logger.h`)
and the Python pipeline (11th feature, `N_FEATURES` bump, all
downstream scripts). Collected a full, clean 205-job training grid (8
attacks × 5 percentages × 5 seeds + benign, 3.89M rows) with genuinely
per-cycle-max `delta_t` — this took much longer than expected (~19h wall
clock vs. the original 1-3h estimate; happy to go into the operational
detail separately if useful, mostly thermal/scheduling issues on the
shared host, not a code problem). Verified 0% zero-`delta_t` rate and 0
malformed rows before retraining, so the input going into this result is
clean.

**Retrained 2026-08-18. Result:**

| | DR | FPR | MCC |
|---|---|---|---|
| A1 CP-SelectiveDelay | **2.7%** | 0.51% | 0.083 |
| A2 DP-SelectiveDelay | **4.6%** | 0.68% | 0.129 |
| A3 CP-TCAM (rule-based) | 96.6% | 0.75% | 0.940 |
| A4 DP-TCAM (rule-based) | 81.8% | 1.02% | 0.840 |
| A5 CP-ActiveHF | 91.1% | 0% | 0.0\* |
| A6 DP-ActiveHF | 100% | 0% | 0.0\* |
| A7 CP-PassiveHF | 91.2% | 0% | 0.0\* |
| A8 DP-PassiveHF | 98.9% | **56.1%** | 0.437 |

\*A5-A7's MCC=0 is the TN=0 divide-by-zero artifact in the per-variant
formula, not a real failure — DR is the honest number there.

**A1/A2 are still catastrophically under-detected.** DR moved from
1.7%/2.3% (an earlier, confounded interim checkpoint that was missing
A5-8 data) to 2.7%/4.6% now — a small, real improvement, but nowhere near
usable. The windowed-max feature helped marginally, not fundamentally.
I want to flag clearly: **the pooled "Overall" MCC (0.822) should not be
read as the system working well** — it's dominated by A5-A8's much larger
sample counts and drowns out A1/A2's near-total failure. Per-variant is
the number that matters here.

I don't have a next diagnosis direction yet and would rather ask than
guess — candidates I can think of: per-class training imbalance specific
to these two attack types, θ threshold miscalibration, or something in
how Selective Time Delay's windows get labeled that differs from the HF
attacks where detection works well. Open to direction here.

**New issue surfaced by this same retrain, not previously visible**: A8's
FPR is 56.1% — over half of benign windows misclassified as attacks for
that variant, despite DR being high. Flagging alongside A1/A2 as needing
attention before Q6 can be called complete.

## Fix 4 (SIM_TIME 30→300 in the ablation runner) — implemented, Q1-Q6 running now

Done, `run_q1q6_ablation.py` defaults to 300s. Launched the full 48-run
Q1-Q6 grid (your spec: 300s, 60% attack, seed 1, all 8 variants, 6
configs) — in progress as I write this, ETA a couple hours. Will send the
completed table as a follow-up once it's done rather than delay this
update further.

## Summary / what I need from you

- **Fix 1**: needs your input on a fresh diagnosis direction for A3/Q3 —
  the mechanism you described isn't in the code, so I can't apply the fix
  as specified.
- **Fix 2**: sign-off (yes/no) on extending the gate to
  `record_detection_event()` itself, which changes what "confusion matrix
  records at θ" means.
- **Fix 3**: does not resolve A1/A2. Need direction on where to dig next,
  and a decision on whether A8's new FPR issue should be treated as
  blocking before Q6 is considered done.
- **Q1-Q6 cumulative table**: coming as soon as the current run finishes.

Happy to walk through any of this live if that's faster than text.

[Your name]
