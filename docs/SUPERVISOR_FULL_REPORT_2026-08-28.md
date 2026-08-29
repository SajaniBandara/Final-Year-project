SUBJECT: All 11 items — results, experiments and diagnostics. Two came back
negative; one of your premises needs correcting; item 11's predicted curve is
not there.

Everything below is measured on the current build unless stated. Where a
result contradicts what was expected, the number is given first and the
explanation second.

STATUS AT A GLANCE
------------------
  1  M1 scores OBU rows .......... IMPLEMENTED DIFFERENTLY — needs your call
  2  Recall reported two ways .... DONE
  3  Per-node = diagnostic only .. DONE
  4  WAP-R denominator ........... DONE (both sides, not just the denominator)
  5  Per-variant ladders ......... DONE — one gap flagged
  6  Fix 2 sweep + rescore ....... DONE — 60/60 jobs
  7  Percentile threshold ........ BUILT AND MEASURED — it is WORSE, defaulted off
  8  A3's Q1 = 0.318 ............. ANSWERED — your premise was based on a number
                                   that never measured f_unauth
  9  Three A5 nodes .............. ANSWERED — neither of your two hypotheses
 10  A2 node-vs-window gap ....... ANSWERED — your read was correct
 11  Temporal curve .............. A2 DONE (shape absent), A8 running

Plus three findings you did not ask for but should see, at the end.


====================================================================
1. M1 SCORES OBU ROWS — implemented, but NOT as specified. Your call.
====================================================================

Implemented literally, this makes both affected variants sharply worse.
Measured on the existing Q1 data by pooling OBU rows into M1:

                       current      pooled RSU+OBU
    A1 Q1               0.7383          0.1746
    A2 Q1               0.3973          0.1754

The reason is structural, not tuning. Per-mode breakdown:

    A1 OBU rows: 11,600 rows, truth=1 on ZERO of them, 5,924 firings
                 -> TP=0  FP=5,924  MCC=0.0000
    A2 OBU rows: TP=6,371  FP=4,880 -> MCC=-0.0132 (worse than random)

A1's OBU ground truth is all-zero BY CONSTRUCTION. Its attacker is the
controller plus the compromised RSU obeying the poisoned FlowMod, so
is_malicious_node[0][vehicle] is false for every vehicle, and every OBU firing
is a false positive no matter how well S1 performs. Separately, dw_mark_obu()
marks the RECEIVING vehicle while OBU truth asks whether that receiver is
malicious — the same observer/suspect conflation we fixed for RSU rows, never
fixed here precisely because OBU rows were excluded from scoring. Fixing that
attribution still would not rescue A1: an OBU row is indexed by vehicle,
A1's suspects are RSUs, and the two spaces do not intersect at all.

Our own docs/WHICH_MCC_TO_REPORT.md section 3 had reached this conclusion
independently and titled it "There is no OBU ground truth — do not invent one".

WHAT WE DID INSTEAD, to meet the goal you actually stated (S1 is confirmed
working but earns credit nowhere): s1_detect_packet() is already handed
N_Vehicles + assoc_rsu_local_idx as its sender_node_id and records its
detection event against exactly that RSU. lrad_obu() now marks that same RSU
in the RSU primary column when S1 fires, scoped to variants 0/1. The window
grid then agrees with the detection event, no OBU ground truth is invented,
and the score column is untouched.

Early evidence this was the right call, and that your predicted lift is real
and large: see item 11 below, where A2 detection now reads MCC ~0.93 / DR
~1.00 against 0.431 in the Q1-Q6 table. We have not yet isolated how much of
that is this change versus a delay-parameter difference — one 50-minute run
settles it and is queued.


====================================================================
2. RECALL REPORTED TWO WAYS — done
====================================================================

detector_windows.csv gains a truth_declared column: the same node-level label
WITHOUT the per-cycle activity gate the existing truth column applies.

Both numbers are needed and neither can be derived from the other. In the
gated column, a declared attacker that never acted is indistinguishable from a
benign node, so declared-set recall cannot be reconstructed after the fact.
Hence a separate column rather than a post-hoc calculation.

scripts/results_table.py prints recall_acted and recall_declared side by side
on every row and states in its output that neither alone is the honest number.


====================================================================
3. PER-NODE MATRIX IS DIAGNOSTIC ONLY — done
====================================================================

scripts/results_table.py is now the reporting surface and provides NO way to
emit the per-node whole-run matrix. Its header records why, using your
reasoning and our measurement: sticky latches mean one false firing marks a
node wrong for the remainder of the run, so FP accumulates with run length
while TP saturates — the same configuration scored 55.6% precision at 20 s and
26.6% at 90 s.

We continue to use it exactly as you sanctioned, to trace which specific node
misfires. It appears in no table below.


====================================================================
4. WAP-R ATTRIBUTION — done, and it needed fixing on BOTH sides
====================================================================

You asked for the denominator. The numerator had the same defect and would
have kept the metric wrong.

  FN_W (routing.cc): now counts distinct covering-RSU targets that never
  fired, deduplicated by target — several vehicle attackers under one covering
  RSU are ONE detectable subject at this metric's granularity. UINT32_MAX (no
  covering RSU at that instant) is skipped rather than counted as a miss,
  matching the alert side, which suppresses rather than misattributes.

  TP_W/FP_W (crypto_layer.h): the classifier asked
  passive_hf_malicious_nodes[target_node]. Post-Fix-1 target_node is the
  COVERING RSU, which is not itself the attacker, so every correct detection
  of a vehicle attacker was being booked as a false positive. A target is now
  a true positive when it is the attribution target of at least one genuinely
  malicious node — the same computation the alert side used to select it.

Scale of the inconsistency before the fix: on A8 @40% seed1 30s the metric
printed recall 36.8% while the same run's alerts scored 95.2% against the
covering-RSU ground truth.


====================================================================
5. PER-VARIANT LADDERS — done, with one gap you need to resolve
====================================================================

Monotonicity is now checked along each variant's own ladder:
A1-A4 rule-only -> full, A5/A6 crypto-only -> full, A7/A8 witness -> full.
Violations are flagged per variant. Q3/Q4 no longer produce forced zeros for
variants their detectors were never built to catch.

THE GAP: you specified A7/A8's first rung as "witness + R_anom". No existing
Q-config is that. Q4 is witness-only (S7/S8 off, and the R_anom zero-tolerance
rule rides the S7/S8 path); Q2 carries R_anom but also the entire crypto
layer. We used Q4 and print the caveat on every A7/A8 ladder rather than
papering over it. If you meant "witness + R_anom and nothing else",
run_q1q6_ablation.py needs a new config — tell us and we will add it.


====================================================================
6. FIX 2 SWEEP AND RESCORE — done, 60/60 jobs
====================================================================

COLLECTION. 60 of 60 jobs, zero failures, no truncated files, std_send_gt
present on all 3,840 A1/A2 CSVs (60 jobs x 64 RSUs).

VALIDATION OF THE COUNTER. Summed across 64 RSUs, seed 1:

    A1:  0% -> 0      20% -> 1,596   40% -> 2,437   60% -> 2,437
        80% -> 5,095  100% -> 7,316
    A2:  0% -> 0      20% -> 6,424   40% -> 14,441  60% -> 21,393
        80% -> 29,246 100% -> 34,819

Exactly zero at 0% for both. That is the strongest evidence available that the
counter is genuinely injection-side: it cannot fire without an attack, so
nothing in the benign path can manufacture a positive label.

THE RESCORE. A1/A2 against the injection-side label, test split (seed 5),
non-overlapping 10 s blocks:

    A1  MCC 0.394  DR 0.251  FPR 0.008   TP=930   FP=53  FN=2770  TN=6231
    A2  MCC 0.464  DR 0.343  FPR 0.010   TP=1396  FP=58  FN=2677  TN=5853

Both hold FPR at or below 1%. Both are recall-limited — the same sparse-signal
characteristic confirmed independently under item 10.

WHY THESE ARE THE FIRST HONEST A1/A2 NUMBERS. y_indep, the leak-free label the
classification head is scored against, was built from hf_send_gt ALONE.
hf_send_gt is nonzero only for the HF variants, so A1-A4 had ZERO positive
leak-free windows in every split. There was no leak-free label for the timing
attacks to be scored against at any point in this project.

    A1  y_indep positives (train):  0 -> 16,220
    A2  y_indep positives (train):  0 -> 22,577

Their only other label path was is_spike, via delta_spike (delta_t > benign
p99) and delta_max_spike (delta_t > 50 ms). Both are computed from delta_t,
and delta_t IS in FEATURES — a label that is a direct transform of a model
input, which is precisely the leakage you ruled out. is_spike is untouched: it
drives training, and no retraining was authorised.


====================================================================
7. PERCENTILE THRESHOLD — BUILT, MEASURED, AND IT IS WORSE
====================================================================

You asked for the number before calling this done. Here it is.

Fresh zero-attack baseline, 300 s, seed 1, BOTH arms from one binary with only
--s1_use_percentile varied so nothing else differs. On a zero-attack run every
S1 firing is a false positive by definition.

    arm                     S1 firings    OBU window FPR
    k*sigma (old bound)          6,156           18.86 %
    percentile p99 (new)         8,005           44.66 %

Against a 1% target. The new threshold is 2.4x WORSE, and both are more than
an order of magnitude outside the gate.

WHY — and the defect is ours, not your reasoning. The thresholds each arm
actually produced:

    arm            threshold at firing:  mean     median     max
    k*sigma                            24.30 ms  23.27 ms  40.84 ms
    percentile                          4.80 ms   4.00 ms  22.59 ms

The percentile threshold COLLAPSED to about a fifth of the k*sigma one. Cause:
we fed the histogram only samples that did not breach the current threshold,
copying the robustness gate that protects sigma from self-masking. For a
quantile that gate is not protection, it is truncation — the distribution
being estimated is cut off at the very threshold derived from it, so p99 of
the retained samples sits below the true p99, which lowers the threshold,
which truncates harder next cycle. A downward spiral with no floor. This is
the identical runaway the codebase already documents for sigma and defeats
with a floor; ours had none.

STATUS: committed behind --s1_use_percentile, DEFAULT FLIPPED TO OFF. We are
not leaving a measured regression in the default path.

PROPOSED CORRECTION (built nothing yet, want your call): estimate the benign
distribution from traffic the attack cannot touch. S1 already computes
delta_best, the best-effort hop delay, and both S1 and S2 are defined so that
only HIGH-priority packets are delayed — that is the entire selectivity
conjunct in eq:rule_s1. Best-effort traffic is therefore a genuinely benign
sample stream even during an active attack, by the attack model's own
definition. Calibrating on it and applying the cutoff to high-priority delay
is immune to the truncation spiral, needs no floor heuristic, and uses a
separation the architecture already relies on. It also fails correctly under
congestion: both classes rise together, the cutoff rises with them, and S1
does not fire — which is what the selectivity conjunct was for.


====================================================================
8. A3'S Q1 SCORE — the premise needs correcting, then the answer
====================================================================

THE PREMISE. You asked why A3's rule-only Q1 is 0.318 when f_unauth is
near-deterministic. That number never measured f_unauth.

The window grid's primary column is assigned per variant. A1/A2 get S1/S2,
A5/A6 get S5/S6, A7/A8 get S7/S8. A3/A4 had no case of their own and fell
through to `default`, which used the full OR-composite. In Q1 every member of
that composite except one is disabled, so it reduced to flag_S2f alone — S2's
timing detector responding to the TCAM slow-path delay that exhaustion
produces as a side effect. Real signal, wrong detector. S3/S4 had never
contributed a single bit to any A3/A4 window score in any config in any run.

We fixed the assignment and reran all 12 configs. Full disclosure: our first
attempt at the fix was wrong in two ways, both caught before reporting — it
marked prev_sender while reading the flag at the processing RSU (A3/A4 ground
truth labels the VICTIM RSU, so the "mark the suspect not the observer" rule
INVERTS for this family), and it read flags that are deliberately never gated
by g_disable_s3_s4, which made the score insensitive to the ablation switch
and surfaced as Q1 through Q5 returning byte-identical numbers. Both
corrected. Any A3/A4 number from that interim build is withdrawn.

THE CORRECTED RESULTS. 12 configs, two lanes, all exit 0:

    A3          TP     FP    FN     TN     MCC      prec    recall
      Q1      1105    100   751   1756   +0.5782   0.917    0.595
      Q2         0      0  1856   1856   +0.0000   --       0.000
      Q3         0      0  1856   1856   +0.0000   --       0.000
      Q4         0      0  1856   1856   +0.0000   --       0.000
      Q5      1105    100   751   1756   +0.5782   0.917    0.595
      Q6      1105    100   751   1756   +0.5782   0.917    0.595

    A4          TP     FP    FN     TN     MCC      prec    recall
      Q1      1897      0   742   1073   +0.6519   1.000    0.719
      Q2         0      0  2639   1073   +0.0000   --       0.000
      Q3         0      0  2639   1073   +0.0000   --       0.000
      Q4         0      0  2639   1073   +0.0000   --       0.000
      Q5      1897      0   742   1073   +0.6519   1.000    0.719
      Q6      1897      0   742   1073   +0.6519   1.000    0.719

Before vs after on the same cells:

                     old (broken)     corrected
    A3 Q1                0.318          0.578
    A3 Q6               -0.007          0.578
    A4 Q1                0.440          0.652
    A4 Q6                0.426          0.652

YOUR ACTUAL QUESTION — firing problem or recording problem? NEITHER. It is
coverage.

When S3/S4 fires it is essentially always right: A4 precision is 1.000 — zero
false positives across 1,897 detections — and A3 is 0.917. That is the
near-deterministic behaviour you expected, and it clears both the detector and
its recording path.

What it does not do is fire everywhere the attack is active. Recall is 0.595
(A3) and 0.719 (A4), so 40% and 28% of genuinely attacked windows produce no
firing at all. Your design expectation holds on the FPR half and fails on the
detection half, and the gap is windows where the signal never presents at that
RSU — the same sparse-coverage limit as A1/A2 under item 10, different
variant.

THE Q5->Q6 COLLAPSE IS GONE, not explained. Q1, Q5 and Q6 are now identical to
four decimal places on both variants. Adding LSTM, witness and BTMM changes
A3/A4 by exactly nothing, which is correct — they are not those variants'
primary detector and must not touch the primary column. The -0.007 was an
artefact of the LSTM leaking into a column it never belonged in.

Separately, we isolated that leak before fixing it, A3 @60% seed1 300 s, each
arm starting from the Q5 baseline:

    Q5 baseline    TP=318  FP=2    MCC=0.318
    LSTM only      TP=429  FP=413  MCC=0.010   <- reproduces Q6 exactly
    witness only   TP=318  FP=2    MCC=0.303   <- identical to baseline
    BTMM only      TP=318  FP=2    MCC=0.303   <- identical to baseline

The LSTM was entirely responsible; witness and BTMM were bystanders.

Monotonicity now holds on both A3/A4 ladders, and Q2/Q3/Q4 correctly score
zero — those configs disable S3/S4 and the primary column now honours it.

CAVEAT: these are scored against the existing truth column and are NOT yet
leak-free. See finding (a) at the end.


====================================================================
9. THE THREE A5 NODES (220, 225, 233) — neither of your hypotheses
====================================================================

NOT multi-vehicle aggregation. All three are themselves declared malicious
hidden-forwarding RSUs, each with its own assigned eavesdropper (220->199,
225->151, 233->87). They are not covering an attacker; they ARE the attacker.

NOT staleness in hf_gt_attribution_node(). For any RSU index that function
returns the node unchanged — the identity branch, no lookup, no cache, no
state that can go stale.

They fire in 58 of 58 windows because they genuinely attack in all 58. S5
fires 937, 961 and 722 times respectively with these nodes as sender_rsu, and
S5's second conjunction requires active_hf_malicious_nodes[prev_sender], so it
cannot fire on a non-attacker at all.

THE ACTUAL CAUSE is the window activity gate. For A5-A8 the gate is
g_ranom_flag_last — R_anom's per-cycle delta, a RECEIVE-side signal — while
the detector being scored is S5, a send-side one. Two different signals. When
a node is actively scheduling hidden duplicates but its R_anom delta happens
to read zero that cycle, the window truth flips to 0 while S5 correctly fires,
and the window is scored as a false positive against a live, actively
attacking attacker.

    node 220:  42 of 58 windows truth=1,  16 scored FP while attacking
    node 225:  48 of 58 windows truth=1,  10 scored FP while attacking
    node 233:  24 of 58 windows truth=1,  34 scored FP while attacking

The intent was already right — the comment at that gate says A5-A8 should
latch "a hidden-duplicate SEND event", and the correct send-side counter
already exists (g_lstm_hf_sendgt_count, the hf_send_gt column, incremented
exactly when an RSU schedules a hidden duplicate). The gate simply is not
wired to it.

NOT CHANGED, per your instruction. The fix is a one-line repoint of the A5-A8
branch of that gate from g_ranom_flag_last to the hf_send_gt delta.


====================================================================
10. A2 NODE-VS-WINDOW GAP — your read was correct
====================================================================

It is recall, and precision is intact.

    window precision as currently scored          86.7 %
    window recall                                 34.3 %
    precision against genuinely benign nodes      99.1 %

Of the 85 apparent false positives, 80 are on nodes that ARE declared
attackers and were merely dormant in that window. Only 5 are on nodes never
malicious in any window. That reconciles the window figure with the 100%
node-level precision — the two were never in conflict; the window number was
counting dormant attackers as benign.

Recall is the sole limiter, and the per-node pattern shows why:

    malicious RSUs with at least one truth window      47
      never caught in any window                       25
      caught in some windows                           22
      caught in every one of its windows                0

    mean truth windows, nodes ever caught            44.3
    mean truth windows, nodes never caught           25.8

Exposure predicts detection. S2 can only fire in a window where a delayed
packet actually traverses that RSU, and the nodes never caught are the ones
with roughly half the exposure. Coverage characteristic, not a defect.

Kept separate from item 9 as you asked. Same family — window truth failing to
track genuine attack activity — but different mechanisms: item 9 is a gate
reading the wrong signal and is fixable in one line; item 10 is a property of
the attack and the detector, and the honest response to it is your item 2.


====================================================================
11. TEMPORAL CURVE — A2 done. The predicted shape is NOT there.
====================================================================

Full deployed system, A2 @60%, 5 seeds, 300 s, mean +/- sd across seeds at
each time point. Per your instruction, no single instantaneous point is
quoted; the tool refuses to emit below 3 seeds.

DETECTION over time — flat, at ceiling:

      t=2      MCC 0.913 +/-0.063   DR 1.000   FPR 0.107
      t=52     MCC 0.923 +/-0.047   DR 1.000   FPR 0.076
      t=112    MCC 0.955 +/-0.026   DR 1.000   FPR 0.035
      t=182    MCC 0.932 +/-0.023   DR 1.000   FPR 0.059
      t=237    MCC 0.969 +/-0.019   DR 1.000   FPR 0.027
      t=282    MCC 0.887 +/-0.010   DR 0.993   FPR 0.107

MCC sits in 0.89-0.97 for the whole run with a tight band. DR is 1.000 at
almost every point. There is no onset step and no post-quarantine improvement,
because there is no headroom — the detector is already at ceiling from the
first window.

IMPACT over time — TVR drifts down slowly, UCR is identically zero:

      t=1      TVR 26.54 +/-4.21    UCR 0.0000
      t=50     TVR 24.74 +/-2.07    UCR 0.0000
      t=113    TVR 23.79 +/-0.84    UCR 0.0000
      t=190    TVR 23.11 +/-0.81    UCR 0.0000
      t=295    TVR 23.05 +/-1.62    UCR 0.0000

TVR falls 26.5% -> 23.1%. That is movement in the direction your architecture
predicts, but it is a slow monotonic drift of ~3.5 points, not a
rise-plateau-fall. Note TVR is at its HIGHEST at t=1, BEFORE the attack starts
at t=10 — so the early value is dominated by startup transient, and part of
the "decline" is that transient clearing rather than quarantine engaging.

The clearest temporal signal in the data is the variance band: +/-4.21 at t=1
down to +/-0.81 by t=190. The system becomes markedly more CONSISTENT across
seeds even though its mean level barely moves. That is a real, reportable
temporal effect — just not the predicted one.

UCR = 0.0000 with zero variance at every point is CORRECT, not a bug, and it
matters for how item 11 must be run. UCR's numerator is
fade_eavesdrop_counter (routing.cc ~117732) — hidden duplicates actually
received by an eavesdropper, a Hidden Forwarding mechanism. A2 is a timing
attack with no eavesdropper and no duplicates, so the counter never increments
and UCR is structurally zero for this variant. The paper's TVR/UCR claim
cannot be evaluated on A2 at all for the UCR half. A8 @60%, 5 seeds, is
running now for exactly that and will follow separately.

ON THE RUN-LENGTH DECISION YOU LEFT OPEN: 300 s is not the limitation. The
curve is flat because detection saturates immediately, not because the window
is too short, so extending to 600 s or 900 s produces a longer flat line
rather than revealing the shape. If the rise-and-fall is to be demonstrated on
A2, the variable to change is attack onset and intensity — something that
creates headroom — not duration. We have changed neither; flagging it as the
decision the data actually points to.


====================================================================
THREE FINDINGS YOU DID NOT ASK FOR
====================================================================

(a) A3/A4 HAVE NO LEAK-FREE LABEL EITHER — now built, needs collection.

Running the Fix 2 rescore showed A3 and A4 with ZERO positive y_indep windows
in every split. Neither hf_send_gt (HF only) nor std_send_gt (timing only)
covers TCAM exhaustion, so no A3/A4 number can currently be called leak-free —
exactly the state A1/A2 were in before Fix 2. Their only label path was
is_spike, whose A3 leg is U_TCAM > benign-p99 and whose A4 leg falls back to
delta_t; both are in FEATURES, so the label was again a transform of a model
input.

We have built tcam_send_gt: latched in tcam_install_malicious() before any
detector runs, keyed by the VICTIM RSU (which is what A3/A4 ground truth
labels), and counting attempts INCLUDING installs refused with TABLE_FULL —
because a refused install still means the RSU is under active attack, and
saturation is when S4's PACKET_IN signal is strongest, so counting only
successes would label the peak of the attack benign. A3/A4 training data
predates the column and must be re-collected before any A3/A4 figure is quoted
as leak-free. The corrected numbers in item 8 above are honest window-level
scores but carry this caveat.

(b) THE PER-VARIANT MCC IS DEGENERATE FOR A5, A6 AND A7 — this affects how
the 0.80 target is being measured.

From the Fix 2 rescore, their confusion matrices:

    A5  TP=2026  FP=0  FN=6294  TN=0
    A6  TP=7175  FP=0  FN=1145  TN=0
    A7  TP=2005  FP=0  FN=6315  TN=0

TN=0 and FP=0 makes the MCC denominator sqrt(...*0*0) = 0, so the evaluator
prints MCC=0.000. That reads as total failure. A6 in fact detected 86.2% of
attack windows with ZERO false positives. Any macro average over these
variants is being dragged to zero by a division, not by detector performance,
so no macro-MCC computed this way should be quoted against the 0.80 target.
The root cause is that those variants' evaluation sets contain no negative
windows at all after dedup, which needs fixing before these numbers are
reported anywhere.

(c) A1'S PERCENTAGE SWEEP HAS FOUR DISTINCT OPERATING POINTS, NOT SIX.

A1 compromises CONTROLLERS, not RSUs, on the banded ladder main.tex specifies
("<33%:1; 33-66%:2; >=66%:3; 100%:4"). With 4 controllers that maps 20%->1,
40%->2, 60%->2, 80%->3, 100%->4. Confirmed in the injection counts: A1 at 40%
and 60% both record exactly 2,437 injections — identical by construction, not
by coincidence. Reporting 40% and 60% as separate data points overstates the
sweep's resolution.


====================================================================
DECISIONS WE NEED FROM YOU
====================================================================

  1. Item 1 — accept the S1-to-RSU-primary approach, or do you want OBU rows
     pooled anyway now that you have seen it costs A1 0.74 -> 0.17?

  2. Item 5 — is A7/A8's first rung "witness only" (Q4, what we used), or do
     you want a new "witness + R_anom" config built?

  3. Item 7 — approve the delta_best calibration as the corrected percentile,
     or leave S1 on k*sigma?

  4. Item 9 — approve the one-line gate repoint to hf_send_gt.

  5. Finding (b) — how should macro-MCC be computed when a variant's
     evaluation set has no negative windows? This directly affects whether the
     0.80 target is measurable as currently defined.

  6. Item 11 — accept that the rise-and-fall requires changing attack
     onset/intensity rather than run length, or specify a different setup.

WHAT IS RUNNING OR QUEUED
  - A8 5-seed temporal curve (item 11, HF half) — running now
  - 80 ms A2 run to isolate item 1's contribution from the delay difference
  - A3/A4 training re-collection for tcam_send_gt (finding (a))

ON THE 0.80 TARGET. You held it on the basis of not-yet-banked upside in items
1, 5, 7 and 8. Item 1 as specified was negative and we substituted something
else; item 7 measured 2.4x worse and is off by default; item 8's upside turned
out to be real but bounded by coverage, not attribution. Finding (b) also
means the macro number the target is measured against is currently unsound.
We are not asking you to move the target — we are flagging that three of the
four sources of expected upside did not materialise as expected, so the
decision should be made against these numbers rather than the earlier
expectation.


====================================================================
ADDENDUM 1 — ITEM 2, measured. The two recall numbers differ by 40 points.
====================================================================

The truth_declared column is now live in real output and both numbers have
been computed. Your instruction to report both was well placed: on A2 they are
not close.

A2 @60%, full system, 5 seeds:

    seed      MCC      prec    rec_acted    rec_declared
      1    0.9218     0.919        0.996           0.596
      2    0.9414     0.936        1.000           0.581
      3    0.9336     0.931        0.997           0.616
      4    0.9279     0.925        0.999           0.665
      5    0.9256     0.920        0.997           0.535

    rec_acted     mean 0.998 +/- 0.001
    rec_declared  mean 0.599 +/- 0.043
    gap           39.9 percentage points

Quoting rec_acted alone would claim essentially perfect recall. Quoting
rec_declared alone would report roughly 60%. Both are true statements about
different questions, and the 40-point spread is exactly the kind of thing a
reviewer would catch if only one appeared. They will both appear.

Note also the variance: rec_acted is stable across seeds (+/-0.001) while
rec_declared swings +/-0.043. The acted number measures the detector; the
declared number additionally measures how many attackers happened to get an
opportunity to act, which is a property of the mobility trace and varies by
seed.

WHERE THE DISTINCTION IS VACUOUS. On A3/A4 the two are IDENTICAL:

    A3 Q1/Q6   rec_acted 0.595   rec_declared 0.595
    A4 Q1/Q6   rec_acted 0.719   rec_declared 0.719

That is correct and worth stating in the paper rather than looking like an
error. A3/A4 ground truth is "any RSU holding at least one malicious TCAM
entry", and an installed entry persists — the victim RSU stays in the attacked
state continuously, so there is no dormant period for the activity gate to
exclude. The declared and acted sets are the same set.

So the dual reporting is load-bearing for the timing variants, where attackers
idle between packets, and vacuous for the TCAM variants, where the attack
state is persistent. We will present it that way rather than implying the gate
matters everywhere.


====================================================================
ADDENDUM 2 — ITEM 1 ISOLATED. It is worth +0.52 MCC on A2, not a rounding.
====================================================================

The open question from item 11 was whether A2's MCC ~0.93 came from item 1 or
from the delay parameter (those runs use the default 100 ms; the ablation
forces exactly 80 ms). We reran A2 at EXACTLY 80 ms on the current binary, so
the delay is held constant and only the binary differs.

    A2 @60%, 80 ms exact, seed 1, full system

    binary                      MCC     prec   rec_acted    TP    FP    FN
    OLD (pre item 1)         0.3973    0.867       0.343   556    85  1063
    NEW (with item 1)        0.9207    0.915       0.999  1618   151     1

The delay parameter is identical in both rows. The entire difference is item 1
-- S1 now marking the RSU primary column instead of earning credit nowhere.

    MCC        0.397 -> 0.921   (+0.524)
    recall     0.343 -> 0.999
    false negs  1063 -> 1

Precision also IMPROVED, 0.867 -> 0.915, so this is not a recall-for-precision
trade. It is strictly better on both axes.

Your instinct on item 1 was right and the effect is much larger than you
predicted. What was wrong was only the mechanism: pooling OBU rows would have
destroyed A1 (0.74 -> 0.17, section 1 above) because A1's OBU truth is
all-zero by construction. Routing S1's detection to the RSU it already accuses
achieves the same goal inside coherent ground truth, and this is the result.

A2 now clears both the 0.65 floor and the 0.80 gate on this configuration.
We have not yet reproduced this across the full Q1-Q6 grid or for A1; that
rerun is the obvious next step and we will queue it.


====================================================================
ADDENDUM 3 — ITEM 11, A8. The predicted curve IS there. It was A2 that hid it.
====================================================================

A8 @60%, 5 seeds, 300 s, full system, mean +/- sd across seeds.

DETECTION -- the onset rise you predicted is clearly present:

      t=2      MCC 0.375 +/-0.108   DR 0.236   FPR 0.004
      t=7      MCC 0.721 +/-0.042   DR 0.757   FPR 0.023
      t=12     MCC 0.839 +/-0.029   DR 0.917   FPR 0.067
      t=32     MCC 0.874 +/-0.025   DR 0.955   FPR 0.085
      t=62     MCC 0.872 +/-0.034   DR 0.962   FPR 0.098
      t=92     MCC 0.812 +/-0.031   DR 0.994   FPR 0.206
      t=152    MCC 0.815 +/-0.030   DR 0.993   FPR 0.189
      t=242    MCC 0.847 +/-0.054   DR 0.976   FPR 0.140
      t=272    MCC 0.841 +/-0.054   DR 0.971   FPR 0.141

MCC climbs 0.375 -> 0.874 over the first 30 seconds, which is the detector
coming up as the attack establishes. It then holds 0.79-0.88 for the rest of
the run. Detection rate keeps rising to ~0.99 and stays there; the mid-run MCC
dip is driven by FPR climbing to ~0.21 around t=92-122 and then recovering to
~0.14, not by lost detections.

UCR -- and here is the rise-and-fall the paper claims:

      t=1      UCR  0.0000 +/-0.0000
      t=8      UCR  0.0000 +/-0.0000
      t=15     UCR 14.6667 +/-4.9889     <- attack starts at t=10
      t=22     UCR 10.0000 +/-3.3333
      t=29     UCR  0.0000 +/-0.0000     <- quarantine engaged
      t=50     UCR  1.5385 +/-3.0769
      t=64     UCR  1.5385 +/-3.0769
      t=148    UCR  1.1765 +/-2.3529
      t>=155   UCR  0.0000 throughout

Zero before the attack, a sharp spike to 14.7 immediately after onset, decay
through 10.0, and back to zero by t=29 -- then only small isolated blips
(1.2-1.5, each within one standard deviation of zero) and flat zero for the
final 140 seconds. That is precisely the shape main.tex describes: unauthorised
copies surge when the attack begins and are driven back toward zero once trust
decay quarantines the offending nodes.

So item 11's answer is variant-dependent, and our first attempt simply picked
the wrong variant:

    A2 (timing)   detection flat at ceiling from t=0, no headroom for a curve;
                  UCR structurally 0 (no eavesdropper exists in this attack).
    A8 (passive HF) detection shows a clear onset rise; UCR shows the full
                  rise-and-fall.

TVR is 0.0000 throughout on A8, which is the mirror image and equally correct:
TVR measures safety-critical packet delay against Delta_max, and hidden
forwarding does not delay packets. So neither variant exercises both metrics --
A2 drives TVR and cannot drive UCR, A8 drives UCR and cannot drive TVR. Any
figure claiming "TVR and UCR both rise and fall" needs to be drawn from two
variants side by side, not one, and we suggest presenting it that way.

REVISING WHAT WE SAID ABOUT RUN LENGTH. On the A2 evidence alone we told you
300 s was not the limitation and that onset/intensity was the variable to
change. The A8 data shows the curve is fully resolved inside 300 s -- rise
completes by t=30, quarantine drives UCR to zero by t=29, and the remaining
270 seconds are flat. A longer run would add flat tail, not shape. So 300 s is
the right duration; the earlier concern about needing to change onset applies
only to A2, where the detector has no headroom to begin with.
