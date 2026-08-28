SUBJECT: Items 9 and 10 — findings, no code touched on either. Plus one
correction to what we sent you about A3.

Items 9 and 10 are answered below. As instructed, no code was changed on
either — both were resolved from the existing run data and the source.

Item 8 needs a correction rather than an answer, because the number you asked
us to explain turns out not to measure what its column header claims. That is
first, since it changes what you asked for.


====================================================================
CORRECTION TO ITEM 8 — the 0.318 never measured f_unauth
====================================================================

You asked why A3's rule-only Q1 score is 0.318 when f_unauth is near-
deterministic and was designed for close to 100% detection at 0% FPR.

The premise does not hold: S3/S4 have never contributed a single bit to any
A3 or A4 window score, in any Q-config, in any run we have.

The window grid's primary column is assigned per variant in lrad.h. A1/A2 get
S1/S2, A5/A6 get S5/S6, A7/A8 get S7/S8. A3/A4 had no case of their own and
fell through to `default`, which used flags.D_RSU -- the full OR-composite.
In Q1 every member of that composite except one is disabled (crypto forced
pass, S5-S8 off, LSTM off, witness off), so D_RSU reduces to flag_S2f alone.

A3's entire Q1 column was S2's timing detector, firing on the TCAM slow-path
delay that exhaustion produces as a side effect. It is a real signal, but it
is not f_unauth and it is not S3. So 0.318 is not a statement about the
rule-based TCAM detector's performance -- that detector was never in the
measurement.

The Q5 -> Q6 collapse to -0.007 has the same origin and is now root-caused.
Once the LSTM is enabled it joins that same OR-composite, ungated. We
isolated it with a three-way ablation, A3 @60% seed1 300s, each config
starting from the Q5 baseline:

    Q5 baseline    TP=318  FP=2    MCC=0.318
    LSTM only      TP=429  FP=413  MCC=0.010   <- reproduces Q6 exactly
    witness only   TP=318  FP=2    MCC=0.303   <- identical to baseline
    BTMM only      TP=318  FP=2    MCC=0.303   <- identical to baseline

The LSTM is entirely responsible; witness and BTMM are bystanders on this
variant. The mechanism is the LSTM-suppression gate: it only silences
flag_LSTM at an RSU whose OWN S3/S4 fired last cycle, and that file's own
comment states the reconstruction error is elevated by residual TCAM
occupancy "independently of any co-firing signature". A bystander RSU with no
local exhaustion therefore fires ungated, and D_RSU carried it into the
score -- the same pollution pattern as S2f in A5 before the 2026-08-21
primary-detector work, simply never applied to A3/A4.

So your item 8 splits cleanly: the Q5->Q6 half is answered and fixed; the
"why is rule-only only 0.318" half is void, because no rule-only TCAM number
exists yet. Once the corrected sweep runs we will have a genuine S3/S4 figure
and can say whether f_unauth meets its near-deterministic expectation.

Full disclosure on the fix itself: our first attempt at it was wrong in two
ways, both caught before reporting. It marked prev_sender while reading the
flag at the processing RSU (A3/A4 ground truth labels the VICTIM RSU, so the
"mark the suspect not the observer" rule inverts for this family), and it
read flags that are deliberately never gated by g_disable_s3_s4, making the
score insensitive to the ablation switch -- which surfaced as Q1 through Q5
returning byte-identical numbers for both variants. Both corrected; the
marking now mirrors the fold-in already proven on the score column. Any
A3/A4 number we quoted from the interim build is withdrawn.


====================================================================
ITEM 9 — the three A5 residual nodes (220, 225, 233)
====================================================================

Neither hypothesis you offered is the cause. It is a third mechanism.

NOT multi-vehicle aggregation. All three are themselves declared malicious
hidden-forwarding RSUs, each with its own assigned eavesdropper (220->199,
225->151, 233->87). They are not covering an attacker; they ARE the attacker.

NOT staleness in hf_gt_attribution_node(). For any RSU index that function
returns the node unchanged -- the identity branch, no lookup, no cache, no
state that can go stale.

They fire in 58 of 58 windows because they genuinely attack in all 58. S5
fires 937, 961 and 722 times respectively with these nodes as sender_rsu, and
S5's second conjunction requires active_hf_malicious_nodes[prev_sender], so
it cannot fire on a non-attacker at all.

The cause is the window activity gate. For A5-A8 the gate is
g_ranom_flag_last -- R_anom's per-cycle delta -- while the detector being
scored is S5. Two different signals. When a node is actively scheduling
hidden duplicates but its R_anom delta happens to read zero for that cycle,
the window truth flips to 0 while S5 correctly fires, and the window is
scored as a false positive against a live, actively-attacking attacker.

    node 220:  42 of 58 windows truth=1,  16 scored FP while attacking
    node 225:  48 of 58 windows truth=1,  10 scored FP while attacking
    node 233:  24 of 58 windows truth=1,  34 scored FP while attacking

The intent was already right. The comment at the gate says A5-A8 should latch
"a hidden-duplicate SEND event", and the correct send-side counter exists --
g_lstm_hf_sendgt_count, the hf_send_gt column, which increments exactly when
an RSU schedules a hidden duplicate. The gate is simply not wired to it, and
reads the receive-side counter instead.

We have not changed this, per your instruction. The fix would be a one-line
repoint of the A5-A8 branch of that gate from g_ranom_flag_last to the
hf_send_gt delta.


====================================================================
ITEM 10 — the A2 node-vs-window gap
====================================================================

Your read is confirmed. It is recall, and precision is intact.

    window precision as currently scored          86.7 %
    window recall                                 34.3 %
    precision against genuinely benign nodes      99.1 %

Of the 85 apparent false positives, 80 are on nodes that ARE declared
attackers and were merely dormant in that window. Only 5 are on nodes never
malicious in any window. That reconciles the window figure with the 100 %
node-level precision -- they were never in conflict, the window number was
counting dormant attackers as benign.

Recall is the sole limiter, and the per-node pattern shows why:

    malicious RSUs with at least one truth window      47
      never caught in any window                       25
      caught in some windows                           22
      caught in every one of its windows                0

    mean truth windows, nodes ever caught            44.3
    mean truth windows, nodes never caught           25.8

Exposure predicts detection. S2 can only fire in a window where a delayed
packet actually traverses that RSU, and the nodes that are never caught are
the ones with roughly half the exposure. This is the same sparse-signal
characteristic already confirmed for A1, not a defect.

Separately from item 9, as you asked. The two are the same family -- window
truth failing to track genuine attack activity -- but different mechanisms:
item 9 is a gate reading the wrong signal, item 10 is genuine sparse
coverage. Item 9's is fixable in one line; item 10's is a property of the
attack and the detector, and the honest reporting of it is your item 2
(recall stated against both the declared and the acted attacker sets).


====================================================================
STATUS OF THE REST
====================================================================

Not started, awaiting your go-ahead on sequencing:
  item 1  M1 scores OBU rows
  item 4  WAP-R denominator to covering-RSU attribution
  item 5  per-variant monotonicity ladders
  item 7  percentile threshold for S1, plus the fresh-baseline FPR number
  item 11 temporal performance curve, 5 seeds

Item 6 (Fix 2 data collection) is approved and ready to launch; it is the
longest-running item, so we plan to queue it first unless you say otherwise.
Item 3 (per-node matrix demoted to diagnostic only) is a reporting rule and
is already in force in this document.

The corrected A3+A4 Q1-Q6 sweep also needs to run before those two columns
can be reported at all.


====================================================================
ITEM 7 — THE NUMBER YOU ASKED FOR. The percentile threshold made it WORSE.
====================================================================

Built as specified, ran the fresh zero-attack baseline (300 s, seed 1, both
arms from ONE binary with only --s1_use_percentile varied, so nothing else
differs). Every S1 firing on a zero-attack run is a false positive by
definition.

    arm                     S1 firings    OBU window FPR
    k*sigma (old bound)          6,156           18.86 %
    percentile p99 (new)         8,005           44.66 %

Against a 1 % target. The new threshold is worse by a factor of 2.4, and both
are more than an order of magnitude outside the gate.

(RSU-mode window FPR is 0.000 % in both arms, but that is not a result: S1's
new RSU-column marking is scoped to variants 0/1 and a zero-attack run is
variant -1, so nothing marks there by construction. The OBU column is the one
carrying S1 on this run.)

WHY — and it is a defect in our implementation, not in your reasoning.

The thresholds the two arms actually produced:

    arm            threshold at firing:  mean     median     max
    k*sigma                            24.30 ms  23.27 ms  40.84 ms
    percentile                          4.80 ms   4.00 ms  22.59 ms

The percentile threshold COLLAPSED to roughly a fifth of the k*sigma one,
which is why it fires more. The cause is the histogram's admission rule. We
fed it only samples that did NOT breach the current threshold -- deliberately,
copying the robustness gate that protects sigma from the self-masking failure
fixed in 033210a. But for a quantile that gate is not a safeguard, it is a
truncation: the distribution being estimated is cut off at the very threshold
being derived from it, so p99 of the retained samples sits below p99 of the
real distribution, which lowers the threshold, which truncates harder next
cycle. A downward spiral with no floor.

This is precisely the failure the codebase already documented for the sigma
path -- "a self-reinforcing feedback loop where a shrinking sigma excludes
more packets, shrinking sigma further with no floor". Sigma was rescued with a
floor. We reintroduced the same loop for the percentile and gave it none.

So item 7 is NOT closed, and the honest status is that the fix as built is
worse than what it replaced. The code is committed behind
--s1_use_percentile, DEFAULT ON in the commit, which we will flip to default
OFF unless you say otherwise -- we do not want an untested regression sitting
in the default path while the corrected version is built.

PROPOSED CORRECTION (not implemented, flagging for your call).

Estimate the benign distribution from traffic the attack cannot touch. S1
already computes delta_best, the best-effort hop delay, and both S1 and S2 are
defined so that only HIGH-priority packets are delayed -- that is the whole
selectivity conjunct in eq:rule_s1 ("only high-priority packets are delayed,
while best-effort traffic from the same RSU remains within baseline"). Best-
effort traffic is therefore a genuinely benign sample stream even during an
active attack, by the attack model's own definition.

Calibrating the percentile on best-effort delay and applying it to
high-priority delay is immune to the truncation spiral (the estimator never
sees the samples it is judging), needs no floor heuristic, and uses a
separation the architecture already relies on rather than inventing one.

It also predicts the right failure mode: under genuine congestion both classes
rise together, the cutoff rises with them, and S1 correctly does not fire --
which is what the selectivity conjunct was there to achieve in the first
place.

We have not built this. Say the word and it is a small change.


====================================================================
ITEM 6 — Fix 2 collection COMPLETE (60/60) and A1/A2 rescored
====================================================================

Collection finished clean: 60 of 60 jobs, zero failures, no truncated files,
std_send_gt present on all 3,840 A1/A2 CSVs (60 jobs x 64 RSUs).

VALIDATION OF THE COUNTER ITSELF. Summed across 64 RSUs, seed 1:

    A1:  0% -> 0     20% -> 1,596   40% -> 2,437   60% -> 2,437
        80% -> 5,095  100% -> 7,316
    A2:  0% -> 0     20% -> 6,424   40% -> 14,441  60% -> 21,393
        80% -> 29,246 100% -> 34,819

Exactly zero at 0% for both, which is the strongest evidence available that
the counter is genuinely injection-side: it cannot fire without an attack, so
nothing in the benign path can produce a positive label.

A1's 40% and 60% being IDENTICAL is not an error and is worth recording for
the paper. A1 compromises CONTROLLERS, not RSUs, on the banded ladder
main.tex specifies ("<33%:1; 33-66%:2; >=66%:3; 100%:4"). With 4 controllers
that maps 20%->1, 40%->2, 60%->2, 80%->3, 100%->4. A1's attack_percentage
sweep therefore has FOUR distinct operating points, not six, and reporting
40% and 60% as separate data points overstates the sweep's resolution.

THE RESCORE. A1/A2 scored against the injection-side label, test split
(seed 5), non-overlapping 10 s blocks:

    A1  MCC 0.394   DR 0.251   FPR 0.008   TP=930  FP=53  FN=2770  TN=6231
    A2  MCC 0.464   DR 0.343   FPR 0.010   TP=1396 FP=58  FN=2677  TN=5853

Both hold FPR at or below 1%. Both are recall-limited, which is the same
sparse-signal characteristic already confirmed for A2 under item 10 -- the
detector is precise when it fires and simply does not get the chance often.

WHY THIS IS THE FIRST HONEST A1/A2 NUMBER. y_indep, the leak-free label the
classification head is scored against, was built from hf_send_gt ALONE.
hf_send_gt is nonzero only for the HF variants, so A1-A4 had ZERO positive
leak-free windows -- there was no leak-free label for the timing attacks to be
scored against at any point. Measured before and after this change, train
split:

    A1  y_indep positives:  0 -> 16,220
    A2  y_indep positives:  0 -> 22,577

Their only other label path was is_spike, via delta_spike (delta_t > benign
p99) and delta_max_spike (delta_t > 50 ms). Both are computed from delta_t,
and delta_t IS in FEATURES -- a label that is a direct transform of a model
input, i.e. precisely the leakage you ruled out. is_spike is untouched; it
drives training and no retraining was authorised.

TWO THINGS THIS SURFACED THAT YOU SHOULD SEE.

1. A3/A4 STILL HAVE NO LEAK-FREE LABEL. Their y_indep positive count is 0 in
   every split, because neither hf_send_gt (HF only) nor std_send_gt (timing
   only) covers TCAM exhaustion. This is the same gap Fix 2 just closed for
   A1/A2, still open for A3/A4, and it means no A3/A4 number can currently be
   called leak-free. The equivalent counter would latch at TCAM rule-install
   time in the attack injector.

2. THE PER-VARIANT MCC IS DEGENERATE FOR A5, A6 AND A7. Their confusion
   matrices from this run:

       A5  TP=2026  FP=0  FN=6294  TN=0
       A6  TP=7175  FP=0  FN=1145  TN=0
       A7  TP=2005  FP=0  FN=6315  TN=0

   TN=0 and FP=0 makes the MCC denominator sqrt(...*0*0) = 0, so the
   evaluator prints MCC=0.000. That reads as total failure. A6 in fact
   detected 86.2% of attack windows with ZERO false positives. Any macro
   average over these variants is being dragged to zero by a division, not by
   detector performance, and no macro-MCC computed this way should be quoted
   -- including against the 0.80 target. The underlying cause is that those
   variants' evaluation sets contain no negative windows at all after dedup,
   which is itself worth fixing before these numbers are reported anywhere.


====================================================================
ITEM 8 — ANSWERED. Corrected A3/A4 Q1-Q6, and what f_unauth actually does.
====================================================================

The corrected sweep ran clean: 12 configs, two lanes, all exit 0. These are
the first A3/A4 numbers ever produced by S3/S4 rather than by an unrelated
detector leaking through the OR-composite.

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

YOUR QUESTION: is f_unauth firing on every unauthorized FlowMod, and if any
are missed, is it a firing problem or a recording problem?

Neither. It is a COVERAGE problem, and the distinction matters.

When S3/S4 fires it is essentially always right: A4 precision is 1.000 --
zero false positives across 1,897 detections -- and A3 is 0.917. That is the
near-deterministic behaviour you expected, and it confirms the detector and
its recording path are both sound.

What it does not do is fire everywhere the attack is active. Recall is 0.595
(A3) and 0.719 (A4), so 40% and 28% of genuinely attacked windows produce no
firing at all. The design expectation of "close to 100% detection at 0% FPR"
holds on the FPR half and fails on the detection half, and the gap is not
mis-attribution or a lost record -- it is windows where the signal never
presents at that RSU. Same family as A1/A2's sparse-signal limit under item
10, different variant.

THE Q5->Q6 COLLAPSE IS GONE. Q1, Q5 and Q6 are now identical to four decimal
places on both variants. Adding LSTM, witness and BTMM changes A3/A4's score
by exactly nothing, which is the correct behaviour: they are not those
variants' primary detector and must not touch the primary column. A3's
-0.007 is not "explained", it no longer exists -- it was an artefact of the
LSTM leaking into a column it never belonged in.

Monotonicity now holds on the A3/A4 ladders (rule-only -> full, flat rather
than decreasing).

Q2/Q3/Q4 correctly score zero. Those configs set g_disable_s3_s4=1 to isolate
the crypto/LSTM/witness layers, and the primary column now honours that. The
byte-identical-across-configs defect reported earlier is fixed.

FOR COMPARISON, what the same cells reported before this correction:

                 old (broken)     corrected
    A3 Q1            0.318          0.578
    A3 Q6           -0.007          0.578
    A4 Q1            0.440          0.652
    A4 Q6            0.426          0.652

The old A3/A4 column was flag_S2f -- S2's timing detector responding to the
TCAM slow-path delay -- plus, from Q6, ungated LSTM noise. Neither number was
about TCAM detection.

REMAINING CAVEAT ON A3/A4. These are window-level scores against the existing
truth column. They are not yet LEAK-FREE: A3/A4 had no injection-side ground
truth at all, the same gap Fix 2 closed for A1/A2. tcam_send_gt is now built
(latched in tcam_install_malicious(), keyed by victim RSU, counting attempts
including TABLE_FULL refusals) but the A3/A4 training data predates the
column, so a re-collection is required before any A3/A4 figure can be called
leak-free.


====================================================================
ITEM 11 — temporal curve, A2, 5 seeds. The predicted shape is NOT there.
====================================================================

Full deployed system (everything live), A2 @60%, 5 seeds, 300 s, mean +/- sd
across seeds at each time point. A single instantaneous point is never quoted;
the script refuses to emit below 3 seeds.

DETECTION over time -- flat, near ceiling, no rise and no fall:

      t=2      MCC 0.913 +/-0.063   DR 1.000   FPR 0.107
      t=52     MCC 0.923 +/-0.047   DR 1.000   FPR 0.076
      t=112    MCC 0.955 +/-0.026   DR 1.000   FPR 0.035
      t=182    MCC 0.932 +/-0.023   DR 1.000   FPR 0.059
      t=237    MCC 0.969 +/-0.019   DR 1.000   FPR 0.027
      t=282    MCC 0.887 +/-0.010   DR 0.993   FPR 0.107

MCC sits in 0.89-0.97 for the whole run with a tight variance band. Detection
rate is 1.000 at almost every point. There is no visible onset step and no
post-quarantine improvement, because there is no headroom: the detector is
already at ceiling from the first window.

IMPACT over time -- TVR drifts DOWN slowly, UCR is identically zero:

      t=1      TVR 26.54 +/-4.21    UCR 0.0000
      t=50     TVR 24.74 +/-2.07    UCR 0.0000
      t=113    TVR 23.79 +/-0.84    UCR 0.0000
      t=190    TVR 23.11 +/-0.81    UCR 0.0000
      t=295    TVR 23.05 +/-1.62    UCR 0.0000

TVR falls 26.5% -> 23.1% across the run. That is movement in the direction
your architecture predicts, but it is a slow monotonic drift of ~3.5 points,
not a rise-plateau-fall. Note also that TVR is at its HIGHEST at t=1, before
the attack starts at t=10 -- so the early value is dominated by startup
transient, not by the attack, and the "decline" is partly that transient
clearing rather than quarantine engaging.

The variance band tightens sharply over the run (+/-4.21 at t=1 down to
+/-0.81 by t=190), which is itself the clearest temporal signal in the data:
the system becomes more CONSISTENT across seeds even though its mean level
barely moves.

UCR = 0.0000 with zero variance at every point is CORRECT here, not a bug, and
the reason matters for how item 11 should be run. UCR's numerator is
fade_eavesdrop_counter (routing.cc ~117732) -- hidden duplicates actually
received by an eavesdropper. That is a Hidden Forwarding mechanism. A2 is a
timing attack with no eavesdropper and no duplicates, so the counter never
increments and UCR is structurally zero for this variant.

So the paper's claim that "TVR/UCR rise during an attack and return toward
zero after quarantine" cannot be evaluated on A2 at all for the UCR half. A
passive-HF variant is required. A8 @60%, 5 seeds, is running now for exactly
that, and we will send the HF curve separately.

WHAT THIS MEANS FOR THE RUN-LENGTH QUESTION YOU LEFT OPEN.

300 s is not the limitation. The curve is flat because detection saturates
immediately, not because the window is too short to show a trend, so extending
to 600 s or 900 s would produce a longer flat line rather than revealing the
shape. If the rise-and-fall is to be demonstrated on A2, the variable to
change is attack onset and intensity -- something that creates headroom for
performance to move -- not run duration. We have not changed either; flagging
it as the decision the data actually points to.

ONE NUMBER THAT NEEDS YOUR ATTENTION. A2 detection here reads MCC ~0.93 and
DR ~1.00, against 0.431 in the Q1-Q6 table and 0.464 in the Fix 2 rescore.
Two differences could account for it and we have not yet separated them:
these runs use the default 100 ms injected delay (the ablation forces exactly
80 ms), and they include your item 1 -- S1 now marks the RSU primary column,
which it never did before. If item 1 is the dominant cause, that is the "lift
A1/A2 meaningfully" effect you predicted, and it is much larger than expected.
An 80 ms A2 run on the current binary isolates the two; it is one 50-minute
job and we will queue it.
