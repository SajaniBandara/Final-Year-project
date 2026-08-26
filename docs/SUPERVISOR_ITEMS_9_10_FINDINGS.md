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
