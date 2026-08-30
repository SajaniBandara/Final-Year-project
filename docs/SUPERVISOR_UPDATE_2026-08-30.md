# Supervisor update — 2026-08-30

Answers to your six decisions of 2026-08-29. Numbers first, explanation second.
Two of your premises need correcting and one item you were told was outstanding
turned out to be already done.

    STATUS AT A GLANCE
      1  Item 1 methodology sentence ... DONE
      5  Witness + R_anom ladder ....... BUILT AND MEASURED
      7  S1 percentile threshold ....... ANSWERED IN FULL. Regression fixed,
                                         but the RECALL COST makes the trade
                                         UNFAVOURABLE — recommend NOT adopting
      9  A5 residual FP ................ ANSWERED — residual is SYSTEMIC,
                                         not confined to the 3 known nodes
     11  Temporal curve clarification .. ANSWERED (previous report)
    (a)  A3/A4 leak-free label ......... ALREADY DONE — the "not started" was stale
    (b)  Degenerate MCC for A5-A7 ...... ROOT CAUSE FOUND. It is your branch 2
                                         (scoping bug), not saturation.


## 7. S1 PERCENTILE THRESHOLD — both halves you asked for

### 7a. The two delay populations do NOT share a shape

You asked for mean/median/p99 of both populations from one clean baseline
before trusting a threshold borrowed from one traffic class to gate another.
Zero-attack, 300 s, seed 1, both histograms fed from the same run:

    population        n         mean     median      p99      max
    high-priority   260,750    5.08 ms   3.00 ms   113 ms   278 ms
    best-effort     216,732    7.12 ms   3.00 ms   202 ms   305 ms

    ratio best-effort / high-priority:  mean 1.40x   median 1.00x   p99 1.79x

**Your preferential-queueing concern is correct, and it is a tail effect.**
The medians are identical to the bin resolution (3.00 ms); the divergence is
entirely in the tail — 1.79x at p99, which is precisely the statistic the
threshold reads.

CAVEAT, stated because it changes how to read the gap: the high-priority
histogram is fed only by samples that did not breach the current threshold
(the sigma admission gate in s1_detection.h), so it is RIGHT-CENSORED and its
113 ms p99 is a LOWER BOUND. Best-effort is fed unconditionally and is
uncensored. The true ratio is therefore smaller than 1.79x; we cannot measure
how much smaller without removing the gate, which would reintroduce the
self-masking the gate exists to prevent.

### 7b. FPR — the regression is fixed, the target is not met

Zero-attack: every S1 firing is a false positive by definition.

    arm                              S1 firings   threshold(mean)   OBU window FPR
    k*sigma (old bound)                   6,156        24.30 ms          18.86 %
    percentile, HP-calibrated             8,005         4.80 ms          44.66 %
    percentile, best-effort-calibrated    2,676       150.85 ms          17.11 %

The correction does what it was designed to do — it removes the truncation
spiral (44.66% -> 17.11%) and edges past k*sigma. **It does not approach the
<=1% target: 17.11% is ~17x outside it.** We are reporting item 7 as "the
regression is fixed", not as solved.

**One structural result you should see.** Firings fell 2.3x (6,156 -> 2,676)
but FPR fell only 1.1x (18.86% -> 17.11%). The firings removed were
concentrated in windows that ALREADY contained another firing. Window-level
FPR is therefore governed by how many DISTINCT windows contain at least one
firing, not by firing volume — so further reducing the firing count will not
move this metric much. Whatever closes the remaining FPR gap has to reduce the
BREADTH of firing across windows, not its depth.

Reproducibility: the FPR run reproduced the distribution run exactly (same
2,676 firings, bit-identical histograms; only --enable_detector_windows
differed).

**5 seeds per arm** (retires the "single seed, no dispersion" caveat in the
methodology chapter):

    arm                              seed1    seeds 2-5              mean     sd
    k*sigma                         18.86%   18.33 19.31 18.37 17.11  18.40%  0.82
    percentile, HP-calibrated       44.66%   48.22 49.09 42.06 46.29  46.06%  2.82
    percentile, best-effort-calib   17.11%   17.52 17.33 16.49 15.15  16.72%  0.96

The best-effort arm beats k*sigma by 1.68 points with sd ~0.9 on both — a real
but small separation, ~2 sd.

### 7c. RECALL — and this is what changes the recommendation

You asked for recall alongside FPR. We had not measured it; here it is.
A1/A2 @60%, 80 ms fixed delay, 300 s, seed 1, scored on the RSU column's
`score_primary` (the S1-attributed column item 1 added — A1's OBU truth vector
is identically zero, so OBU recall is undefined for A1 by construction):

    run                     TP     FN     FP     TN     RECALL      FPR
    A1  k*sigma            802      7    684   2219     99.13%   23.56%
    A1  best-effort        751     58    687   2216     92.83%   23.67%
    A2  k*sigma           1618      1    151   1942     99.94%    7.21%
    A2  best-effort       1315    304    121   1972     81.22%    5.78%

**The trade is bad.** On A1 the corrected threshold costs 6.3 points of recall
and buys nothing (FPR 23.56% -> 23.67%, i.e. very slightly worse). On A2 it
costs **18.7 points of recall** (99.94% -> 81.22%) to buy 1.4 points of FPR
(7.21% -> 5.78%).

The zero-attack view flattered it: calibrating on best-effort raises the
threshold roughly six-fold (mean at firing 24.30 ms -> 150.85 ms), which
suppresses a few false positives and a great many true detections.

**RECOMMENDATION: do not adopt the best-effort-calibrated percentile as the
default.** It fixes the truncation-spiral regression and is the right
diagnosis of why the first percentile attempt failed, but on live attack
traffic it is worse overall than the k*sigma bound it was meant to replace.
We suggest keeping it behind its flag as a documented negative result, exactly
as the HP-calibrated arm is kept, and treating S1's FPR as still open.


## (b) WHY A5/A6/A7 HAVE NO NEGATIVE CLASS — answered, with the line of code

Your question: *"Why don't you get any negative classes for A5, A6, and A7?"*

**It is your branch 2 — a scoping bug in window-truth computation. It is not
saturation, and it needed no HPC data.** Two things in our previous report
were wrong and are corrected here:

  - `lstm_training/` DOES hold A5/A6/A7 data locally (1,600 files each). The
    "zero rows" we reported was the PREPROCESSED CACHE, not the source data.
  - The local reruns were never contradicting the pooled-split result. They
    were showing the same thing from the other side.

**Mechanism.** `evaluator.py:predict_test()` loads `test_y.npy` — the
spike-based label `y_bin`, not the leak-free `y_indep`. In
`preprocessor.py:355`, `is_spike` for A5-A8 includes

    ddiv_spike = df["attack_v"].isin(HF_VARIANTS) & (df["d_div"] > 1)

`d_div > 1` holds in ~92-96% of ALL rows in an HF run, dormant cycles
included. Window truth is `max()` over a 10-cycle window, so a signal present
in ~92% of rows makes essentially EVERY window positive. The negative class is
annihilated before scoring, which is what zeroes the MCC denominator.

Measured on the actual test split (seed 5), and it predicts your table
variant-for-variant:

    variant   rows d_div>1   windows positive by that leg ALONE   observed TN
    A5           91.7 %                100.0 %                        0
    A6           96.4 %                100.0 %                        0
    A7           91.9 %                100.0 %                        0
    A8           54.1 %                 92.6 %                      173

**A8 is the control.** Its lower d_div rate leaves 7.4% of windows able to be
negative — which is exactly why it alone has a nonzero TN. Nothing else in the
pipeline distinguishes A8 from A5/A6/A7 in a way that would explain that.

This was not an oversight anyone hid: the comment at `preprocessor.py:294`
documents the trade deliberately. `d_div` was added on 2026-08-09 because
99.2-99.5% of what the evaluator was counting as A5-A8 false positives were
windows with d_div genuinely elevated — real detections being scored wrong.
Fixing that scoring error destroyed the negative class as a side effect.

**Fix candidate — NOT APPLIED, awaiting your call**, because it moves every
A5-A8 number: score A5-A8 against `y_indep`, the leak-free injection-based
label the pipeline already computes and saves as `test_y_indep.npy`.
Relabelled that way the SAME test split carries healthy negatives:

    A5  13,062 negative windows of 18,240   (71.6 %)
    A6  10,476 of 18,240                    (57.4 %)
    A7  13,115 of 18,240                    (71.9 %)

Your instruction stands and we have followed it: **no MCC for A5/A6/A7 is
reported anywhere in this document.**


## (a) A3/A4 LEAK-FREE LABEL — already done; our previous status was stale

We reported this as "built, needs a collection sweep". Verified against the
data on 2026-08-29: **the collection was already done** by commit `e34f353`
on 2026-08-28.

    variant   column           header    populated
    A1/A2     std_send_gt      19 col    24.0 % / 32.2 % of rows at pct100
    A3/A4     tcam_send_gt     20 col    32.7 % / 30.6 % of rows
    A5-A8     hf_send_gt       18 col     6.5 % - 24.0 %

All three injection counters feed `y_indep` via
`_inj = max(hfgt, stdgt, tcamgt)`. The mixed 18/19/20-column schema is handled
deliberately — `preprocessor.py:119` backfills zeros for files predating a
column and prints a warning. No sweep is needed.


## 1. M1 SCORES OBU ROWS — methodology sentence added

Added after eq:mcc_variant in the methodology chapter: S1 is EVALUATED at the
OBU (where the per-packet delay is observable) but SCORED against the covering
RSU — the same RSU `s1_detect_packet()` already records its detection event
against — and therefore contributes to the RSU column. The reason given is
that ground truth for the Selective Time Delay variants is RSU-indexed by
construction: the adversary is the controller plus the compromised RSU obeying
the poisoned FlowMod, so no vehicle is ever marked malicious and an
OBU-indexed truth vector for A1 is identically zero. Scoring S1 in the OBU
column would register every firing as a false positive irrespective of
detector quality.


## 5. WITNESS + R_anom LADDER — built as you specified

You said to build the real config rather than keep Q4 as a stand-in. Done.

The blocker was that R_anom had no independent switch: the R_anom>0
zero-tolerance rule rode the S7/S8 path and was gated by `g_disable_s7_s8`, so
silencing S7/S8 to isolate the witness silenced R_anom with it, and the only
config carrying R_anom (Q2) also carried the whole crypto layer.

Added `g_disable_ranom` as a TRI-STATE flag:

    -1 (default) = follow g_disable_s7_s8  <- the pre-existing coupling exactly
     0           = force R_anom ON  with S7/S8 silenced  <- the new rung
     1           = force R_anom OFF with S7/S8 live

Every existing Q1-Q6 run is therefore bit-identical unless the flag is passed
explicitly. New config `Q4R` = witness + R_anom and nothing else.

One trap avoided: `g_ranom_rule_fired_this_pkt` has never been gated by
`g_disable_s7_s8` and it drives Q3's LSTM suppression, so we deliberately left
it on the ungated value. Routing it through the new flag would have silently
changed Q3's LSTM results.

**Results — A7/A8 @60%, 300 s, seed 1, Q4R (witness + R_anom, everything else
off, crypto forced pass):**

    metric              A7 Q4R      A8 Q4R
    TP / FP / TN / FN   39/0/229/0  44/2/108/114
    MCC                   0.963       0.330
    DR                   96.13 %     26.14 %
    FPR                   0.00 %      1.25 %
    witness TP_W/FP_W/FN_W  38/9/1      48/1/2
    WAP precision        80.85 %     97.96 %
    WAP recall           97.44 %     96.00 %

A7 on the real rung is strong: MCC 0.963, DR 96.1% at zero false positives.

A8's generic matrix (DR 26.1%) and its witness-native counters (recall 96.0%,
precision 98.0%) disagree by ~70 points. This is the known Q4 measurement
caveat, not a detector failure: in a witness-only config the witness never
calls record_detection_event() directly — it reaches the generic matrix only
via trust_update_negative() -> quarantine — so the generic TP/FP measure
"did trust collapse far enough to quarantine", not "did the witness detect".
**For A8 on this rung the witness-native numbers are the correct ones.**

Both variants have healthy TN (229 and 108), so unlike the LSTM pipeline's
A5-A7 the MCC here is not degenerate.



## 9. THE THREE A5 NODES — the residual is SYSTEMIC, not confined to them

You asked us to fix the gate and then "rerun A5 in full to confirm no similar
residuals surface elsewhere." They do, extensively.

The gate repoint itself is correct and is in. But the residual FP mechanism
survives it, and it is not a property of nodes 220/225/233.

A5 @60%, 300 s, seed 1, per-cycle, comparing the gate (hf_send_gt > 0) against
S5's own firing (bc_detection_log, signal_idx==5):

    node   cycles   S5 fired   gate>0   FIRED&!GATE   agree
     220     298       135        28        119       56.0 %
     225     298       156        31        143       46.0 %
     233     298       158        27        141       49.3 %

**Answering the granularity question directly: no, they do not match.** The
gate is nonzero in ~10% of cycles (27-31 of 298) while S5 fires in ~45-53%
(135-158). hf_send_gt increments only when an RSU SCHEDULES a hidden
duplicate; S5's firing condition is true far more often than that.

**The sweep over every node with S5 activity:**

    39 nodes show FIRED&!GATE cycles. 36 of them are NOT 220/225/233.

Several are worse than the three you were shown — e.g. node 236 (166 residual
cycles, 81.8%), 227 (157, 66.2%), 219 (154, 79.8%) — all exceeding node 220's
119. The three nodes in the original report were not special; they were simply
the ones inspected.

**Implication.** The A5-A8 window-level FP figures are not three outliers to
be cleaned up. The window activity gate systematically under-reports attack
activity, so correct S5 detections are scored as false positives across most
attacking nodes. Note this is the same CLASS of defect as finding (b) — window
truth derived from a signal whose granularity does not match the detector's —
in the opposite direction: finding (b) labels nearly everything positive,
this labels too much negative. We have not changed the gate further, since the
fix needs your decision on what the correct send-side truth signal is.
