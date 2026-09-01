# Per-class feature analysis and the root cause of the LSTM's high FPR (2026-09-01)

Measured directly on `results_routing/lstm_training/`, 32 of 64 RSUs (even ids),
attack_v 0–8, pct ∈ {0,20,60,100}, seeds 1–5, cycles 1–310 — **1,372,800 rows**.
Reproduction script: `/tmp/.../scratchpad/{featload,an1..an6}.py` (analysis-only,
nothing written back into the pipeline).

## TL;DR

The LSTM's high FPR is **not** a threshold problem, a training problem, or benign
noise. Two of the eleven features — **`d_div` and `a_tp` — are simulation-wide
global scalars, identical for all 64 RSUs in every cycle**. They are also the
largest-magnitude features in the model's input under hidden forwarding. So in
any A5–A8 run the model receives a network-wide "attack is happening" signal at
every RSU, while ground truth labels only the attacker/covering RSU. Every other
RSU is a structurally guaranteed false positive. That is the 73–82% A5–A8 FPR in
[FPR_REDUCTION_ANALYSIS](FPR_REDUCTION_ANALYSIS_2026-08-31.md).

A1–A4 do not have this problem — their features are clean and their FPR is at
baseline (0.84–0.98%). Their failure mode is the opposite one: weak signal, DR
25–34%.

---

## 1. Benign baseline — five of eleven features are degenerate

Pure-benign runs (`attack_v==0`), cycles 1–310:

| feature | mean | std | p99 | frac ≠ 0 |
|---|---|---|---|---|
| delta_t | 0.0190 | 0.0603 | 0.294 | 1.000 |
| lambda_PI | 4.886 | 17.045 | 86.0 | 0.349 |
| U_TCAM | 0.0302 | 0.0665 | 0.327 | 0.879 |
| **zkp_delay_fail** | 0 | **0** | 0 | 0.000 |
| **zkp_hop_fail** | 0 | **0** | 0 | 0.000 |
| rho | 9.926 | 13.438 | 56.0 | 0.638 |
| v_bar | 7.669 | 5.554 | 14.56 | 0.901 |
| **d_div** | 1.0 | **0** | 1.0 | 1.000 |
| **a_tp** | 1.0 | **0** | 1.0 | 1.000 |
| **r_anom** | 0 | **0** | 0 | 0.000 |
| delta_t_exceeded | 0.061 | 0.239 | 1.0 | 0.061 |

Five features have **exactly zero benign variance**. `preprocessor.py:fit_scaler`
substitutes `std = 1.0` for these, so they are never actually normalised — they
enter the network at raw (post-`log1p`) scale while the five real-valued features
are compressed to unit variance. The `log1p` on `d_div`/`a_tp`/`r_anom`
(2026-08-20) reduced but did not remove this asymmetry: see §4.

## 2. Per-class feature signature

Mean z-score vs. the benign baseline, attack runs, pct > 0:

|  | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 |
|---|---|---|---|---|---|---|---|---|
| delta_t | 0.14 | 0.38 | 0.04 | 0.09 | 0.00 | 0.00 | 0.00 | −0.09 |
| lambda_PI | 0.00 | 0.00 | 0.38 | **1.85** | 0.00 | 0.00 | 0.00 | −0.01 |
| U_TCAM | 0.00 | 0.00 | **5.16** | **4.78** | 0.00 | 0.00 | 0.00 | −0.03 |
| zkp_delay_fail | 0.00 | 0.13 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| zkp_hop_fail | 0.00 | 0.00 | 0.00 | 0.00 | 0.18 | 0.33 | 0.18 | 0.23 |
| **d_div** | 0.00 | 0.00 | 0.00 | 0.00 | **11.45** | **61.93** | **11.38** | **19.91** |
| a_tp | 0.00 | 0.00 | 0.00 | 0.00 | −0.78 | −0.95 | −0.78 | −0.95 |
| r_anom | 0.00 | 0.00 | 0.00 | 0.00 | 1.63 | **18.44** | 1.61 | 6.36 |
| delta_t_exceeded | 0.33 | **0.83** | 0.18 | 0.43 | 0.00 | 0.00 | 0.00 | −0.08 |

Three disjoint feature blocks, one per attack family — the design intent holds:

- **A1/A2 (Selective Time Delay)** → `delta_t`, `delta_t_exceeded`, and for A2
  `zkp_delay_fail`. Effect sizes are **small**: 0.14–0.83 σ. This is the DR
  problem, not the FPR problem.
- **A3/A4 (TCAM)** → `U_TCAM` (+4.8 to +5.2 σ), `lambda_PI`. Strongest and
  cleanest per-class signal in the dataset — matching A3/A4's offline MCC of
  0.78 / 0.69 at FPR 0.000.
- **A5–A8 (Hidden Forwarding)** → `d_div` (+11 to +62 σ), `r_anom`, `a_tp`,
  `zkp_hop_fail`. Enormous magnitudes — and this is exactly where the FPR is.

## 3. Root cause — `d_div` and `a_tp` are broadcast, not per-RSU

### 3.1 The measurement

Fraction of cycles in which **all 32 sampled RSUs report the identical value**:

| variant/pct | d_div | a_tp | r_anom |
|---|---|---|---|
| A5 @20 | **1.000** | **1.000** | 0.027 |
| A5 @60 | **1.000** | **1.000** | 0.027 |
| A6 @20 | **1.000** | **1.000** | 0.027 |
| A6 @60 | **1.000** | **1.000** | 0.027 |
| A7 @20/60 | **1.000** | **1.000** | 0.040 / 0.027 |
| A8 @20/60 | **1.000** | **1.000** | 0.027 / 0.030 |

`r_anom` is genuinely per-RSU (RSUs agree only 3–4% of the time, i.e. when all
are quiet). `d_div` and `a_tp` are the *same number everywhere*, every cycle.

### 3.2 The code

`crypto_layer.h:868-869` declares the accumulators as plain globals, not
per-RSU vectors:

```cpp
std::set<uint32_t> g_lstm_flow0_dest_set;
uint32_t           g_lstm_flow0_total_delivery_count = 0;
uint32_t           g_lstm_flow0_legit_count = 0;
```

They are inserted into at the `MacRx` sites in [routing.cc:122191, :122266,
:122303](../scratch/routing.cc) with **no RSU attribution**, then snapshotted
once per cycle in [lstm_logger.h:963-975](../scratch/lstm_logger.h) and handed to
every RSU row identically. The comment there already says it out loud —
*"global, not per-RSU, accumulators"* — but the consequence for the label was
never followed through.

This contradicts `main.tex`'s specification, which the header itself quotes:
*"D_div is computed from per-source per-destination byte counts logged at each
RSU"* and *"A_tp is computed from per-flow directional byte rate logs"*. The
2026-07-28 correction fixed the *derivation* (no longer a transform of `r_anom`)
but not the *scope*.

### 3.3 The label is node-local, the feature is global

`lstm_rsu_ground_truth_label()` ([lstm_logger.h:723](../scratch/lstm_logger.h))
labels an RSU 1 only if it is the attacker, the covering RSU of an attacking
vehicle, or (A3/A4) a victim RSU holding malicious TCAM entries. Downstream RSUs
carrying hidden-forwarded traffic are labelled **0**.

So on RSUs the ground truth calls benign, inside A5–A8 runs:

| variant | rows | frac `d_div > 1` | mean `d_div` | frac `a_tp < 1` | `r_anom > 0` | `zkp_hop_fail` |
|---|---|---|---|---|---|---|
| A5 | 56,880 | **0.850** | 6.48 | 0.857 | **0.000** | **0.000** |
| A6 | 36,976 | **0.887** | 35.79 | 0.887 | **0.000** | **0.000** |
| A7 | 58,750 | **0.862** | 6.45 | 0.864 | **0.000** | **0.000** |
| A8 | 37,240 | **0.718** | 22.11 | 0.889 | **0.000** | **0.000** |
| **A0–A4 (all)** | — | **0.000** | 1.000 | **0.000** | 0.000 | 0.000 |

85–89% of *negative-labelled* HF rows carry a feature that is exactly constant in
every benign run. A benign-trained autoencoder has no choice but to fire on them.

### 3.4 It is not mobility drift or RSU-selection bias

Paired comparison, **same RSU, same seed, same cycle**, attack-run `label==0` row
minus the benign-run row (in benign σ), pct=60:

| | A1 | A2 | … | A7 | A8 |
|---|---|---|---|---|---|
| delta_t | 0.004 | 0.034 | | 0.000 | −0.001 |
| **rho** | **0.000** | **0.000** | | **0.000** | **0.000** |
| **v_bar** | **0.000** | **0.000** | | **0.000** | **0.000** |
| **d_div** | 0.000 | 0.001 | | **+11.07** | **+27.70** |
| **a_tp** | 0.000 | 0.000 | | **−0.83** | **−0.91** |

Mobility is seed-determined and **byte-identical** across benign and attack runs —
the apparent `v_bar`/`rho` shift in unpaired statistics was purely RSU-selection
bias. The *only* collateral contamination in the whole feature set is `d_div`
and `a_tp`, and only in A5–A8.

Fraction of matched `label==0` rows > 3σ on any feature of each block:

| | mobility (rho,v_bar) | traffic (delta_t,λ,U_TCAM) | **structural (d_div,a_tp)** |
|---|---|---|---|
| A1 / A3 | 0.020 / 0.019 | 0.073 / 0.070 | **0.000** |
| A2 / A4 | 0.002 / 0.001 | 0.002 / 0.001 | **0.000** |
| A5 / A6 | 0.001 / 0.000 | 0.006 / 0.001 | **0.896 / 0.908** |
| A7 / A8 | 0.001 / 0.000 | 0.006 / 0.001 | **0.900 / 0.470** |
| *benign control* | *0.024* | *0.081* | *0.000* |

A1/A3's 7% traffic-tail is **at or below the pure-benign control rate (8.1%)** —
`delta_t` is simply heavy-tailed. Not attack-induced.

### 3.5 Zero per-node information, confirmed

Per-feature AUC computed **within each (pct, seed, cycle) stratum** and averaged,
attacker-RSU vs. benign-RSU rows — this strips run-level and temporal
confounding and leaves only per-node discriminative power:

| feature | A5 | A6 | A7 | A8 |
|---|---|---|---|---|
| **d_div** | **0.500** | **0.500** | **0.500** | **0.500** |
| **a_tp** | **0.500** | **0.500** | **0.500** | **0.500** |
| r_anom | 0.690 | 0.740 | 0.688 | 0.708 |
| zkp_hop_fail | 0.690 | 0.740 | 0.688 | 0.708 |
| U_TCAM | 0.860 | 0.900 | 0.864 | 0.894 |
| rho | 0.886 | 0.932 | 0.885 | 0.932 |
| delta_t | 0.380 | 0.379 | 0.380 | 0.376 |

**Exactly 0.500 — the theoretical value for a constant.** Marginally (ignoring
strata) `d_div` scores AUC 0.76–0.83, which is why it has never looked broken:
that number is entirely run-configuration confounding (higher pct ⇒ both more
positive labels and higher global `d_div`), not detection ability.

### 3.6 The precision ceiling this imposes

A detector keying on a broadcast feature fires on **all** RSUs simultaneously,
so its FPR among negative-labelled RSUs is **1.000 by construction**, and its
precision is capped at the label prevalence:

| | A5 | A6 | A7 | A8 |
|---|---|---|---|---|
| ceiling precision @20% | 0.202 | 0.575 | 0.201 | 0.576 |
| ceiling precision @60% | 0.612 | 0.702 | 0.613 | 0.699 |

Compare the observed in-sim A5–A8 FPR of 73–82%. **Raising θ cannot help**: the
attacker and every bystander receive the *same input value*, so any threshold
that removes a false positive removes the corresponding true positive too.

## 4. Why `d_div` dominates the reconstruction error

Mean |z| per feature over A5–A8 runs, applying the deployed transform chain
(`log1p` on d_div/a_tp/r_anom, then the train-benign scaler with its std=1.0
fallback):

| feature | label=0 (**FP source**) | label=1 (TP) | margin |
|---|---|---|---|
| **d_div** | **1.498** | **2.208** | 1.47× |
| v_bar | 1.059 | 0.843 | — |
| rho | 0.739 | 0.817 | 1.11× |
| a_tp | 0.477 | 0.635 | 1.33× |
| U_TCAM | 0.479 | 0.661 | 1.38× |
| **r_anom** | **0.000** | **0.876** | **∞** |
| **zkp_hop_fail** | **0.000** | **0.345** | **∞** |
| delta_t | 0.321 | 0.512 | 1.60× |

`d_div` is the **single largest contributor to reconstruction error on false
positives** — larger than any feature's contribution on true positives except its
own. The two features that perfectly localise the attack (`r_anom`,
`zkp_hop_fail`, both exactly 0 on every negative row, ∞ margin) contribute 0.876
and 0.345 — together less than `d_div` alone contributes to the noise. The model
is being told, loudly, the wrong thing.

## 5. Per-class summary

| class | signal features | effect size | per-node? | FPR verdict |
|---|---|---|---|---|
| A1 CP-Delay | delta_t, delta_t_exceeded | 0.14 / 0.33 σ | yes | **fine** (0.84%); DR-limited (0.25) |
| A2 DP-Delay | delta_t, delta_t_exceeded, zkp_delay_fail | 0.38 / 0.83 σ | yes | **fine** (0.98%); DR-limited (0.34) |
| A3 CP-TCAM | U_TCAM, lambda_PI | 5.16 / 0.38 σ | yes | LSTM clean (FPR 0.000). A3's in-sim FPR is the **S3 rule**, not the LSTM — see [FPR_REDUCTION_ANALYSIS §Fix 5](FPR_REDUCTION_ANALYSIS_2026-08-31.md) |
| A4 DP-TCAM | U_TCAM, lambda_PI | 4.78 / 1.85 σ | yes | LSTM clean (FPR 0.000) |
| A5–A8 HF | **d_div**, a_tp, r_anom, zkp_hop_fail | 11–62 σ | **d_div/a_tp: NO** | **broken by construction** — §3 |

Note the offline `evaluation_results.json` reports FPR 0.000 with **TN = 0** for
A5–A7: under the `y_indep`/latched HF label, essentially every window in an HF
run is positive, so there are no negatives to be false about. The 73–82% figure
is the in-sim per-RSU-window number against the node-local truth. Same model,
different denominator — the offline FPR is not evidence the feature set is sound.

## 6. Second, independent FPR mechanism: window-OR amplification

`detector_windows.h` marks a 10 s window positive if the detector fired in **any**
of its 10 cycles (M = 1). For an i.i.d. per-cycle rate `p` the window rate is
`1 − (1−p)^10`:

| per-cycle p | window FPR |
|---|---|
| 0.005 | 0.049 |
| 0.010 | 0.096 |
| **0.023** | **0.208** |
| 0.025 | 0.224 |
| 0.050 | 0.401 |

The benign per-cycle anomaly rate measured here is 2.3–2.5% (and the offline
Benign-class FPR is 0.0228). That maps to a **20.8–22.4% window FPR** — matching
A3's reported 20.0–22.0% almost exactly. So for the non-HF variants the residual
FPR is a **~10× amplification of an acceptable per-cycle rate**, which is exactly
what `FPR_REDUCTION_ANALYSIS` Fix 2 (persistence M) targets. `d_lstm` is 0 in
every row of this dataset (in-sim inference is off under `--training=1`), so this
mechanism is arithmetic consistent with the doc's numbers, **not** a direct
measurement here.

## 7. What to do

Ordered by value. These are **complementary to**, not a replacement for, the four
fixes ranked in [FPR_REDUCTION_ANALYSIS](FPR_REDUCTION_ANALYSIS_2026-08-31.md).

> **Correction (2026-09-01, arm A).** An earlier revision of this section said
> those four fixes "all gate or threshold a signal that is corrupted at source."
> That is wrong for **Fix 2 (persistence M)**, which operates on `score_primary`
> — a path with no `d_div` in it at all — and delivers a real, independent gain
> there (A5 FPR 36.8% → 6.9%). §8 below analyses that second, independent
> mechanism. Fixes 1, 3 and 4 do act on the LSTM term and are the ones §3
> qualifies.

1. **Make `d_div`/`a_tp` per-RSU** — `std::set<uint32_t>` → `std::vector<std::set<uint32_t>>`
   indexed by RSU, attributed at the `MacRx` sites in `routing.cc:122191/122266/122303`
   the way `g_lstm_ranom_count[r]` already is. This is what `main.tex` specifies,
   and `r_anom` proves the attribution machinery already exists. Requires a
   dataset re-collection.
2. **Interim, no re-run: drop `d_div` and `a_tp` from `FEATURES`.** They carry
   AUC 0.500 per node (§3.5) — the model loses no per-node information and sheds
   its largest FP driver. `ab3_feature_ablation.py` can measure this offline on
   the existing `preprocessed/` arrays today. Do this before spending any HPC
   time on (1).
3. **Do not use `d_div` in `is_spike`.** `preprocessor.py`'s 2026-08-09 change
   added `d_div > 1` to the ground-truth OR, reasoning that it has zero benign
   variance. True — but it is also global, so it labels *every* RSU in an HF
   cycle as attack-active. That change did not fix the labels; it papered over
   the same defect on the label side, and it is why the A5–A8 numbers looked
   better afterwards.
4. **Flag `rho` as a confound.** It is the strongest per-node HF discriminator
   (AUC 0.886–0.932) — but it is vehicle density. A detector keying on it is
   partly detecting *busy RSUs*, not attackers. Worth a stratified check before
   any of it is claimed as detection performance.
5. **A1/A2 remain a DR problem, not an FPR problem** — 0.14–0.83 σ effect sizes
   at FPR < 1%. Nothing in this analysis changes that diagnosis.

---

# 8. The second, independent FPR mechanism: the primary path (added 2026-09-01)

Measured on **arm A** (`results_routing/armA_autoencoder_2026-09-01/`,
`detector_windows_Attack{1..8}_60_seed1_Q6.csv`), RSU rows, 30 s warm-up
dropped, de-duplicated to non-overlapping 10 s blocks per `m1_local.py`.
13,312 windows. Reproduces the arm-A A5 figure exactly: `score_primary`
FPR = **0.368** at M=1, **0.069** at M=5.

`d_div` cannot explain this — `score_primary` excludes `flag_LSTM` for every
variant, and `d_div` reaches the window score only through `flag_LSTM`. There is
a genuinely separate cause, and it is not a detector error at all.

## 8.1 Every primary false positive is a *dormant declared attacker*

The `truth_declared` column (supervisor item 2, 2026-08-27) is the node-level
label **without** the per-cycle activity gate. Decomposing the primary FPs:

| variant | FPR_primary | FP | **dormant declared attacker** | true non-attacker |
|---|---|---|---|---|
| A5 | 0.368 | 420 | **420 (100.0%)** | 0 (0.0%) |
| A6 | 0.342 | 312 | **312 (100.0%)** | 0 (0.0%) |
| A7 | 0.363 | 412 | **392 (95.1%)** | 20 (4.9%) |
| A8 | 0.305 | 298 | **298 (100.0%)** | 0 (0.0%) |

**S5–S8 essentially never accuse an innocent RSU.** That is structural, not
luck: `s5_detect()` conjunction 2 early-returns unless
`active_hf_malicious_nodes[prev_sender] == true`, and `dw_mark_rsu_primary()`
marks that same `prev_sender`. A non-attacker cannot reach the primary column.

So the residual 30–37% is **not a false accusation. It is a truth-definition
mismatch.**

## 8.2 The mismatch: latched detector vs. event-gated truth

Two definitions in the same pipeline disagree about what "attack in this window"
means:

**Truth** ([detector_windows.h:170](../scratch/detector_windows.h),
[routing.cc:118521-118528](../scratch/routing.cc)) is *event-gated*:

```cpp
rt[r] = (node_lvl && g_dw_activity_last[r]) ? 1 : 0;
// A5-A8: act = g_hf_send_flag_last[r]  -- the per-cycle DELTA of
//        g_lstm_hf_sendgt_count, i.e. "did this RSU schedule a hidden
//        duplicate in THIS cycle"
```

**S5–S8** fire on *persistent compromise state*. `s5_detection.h`'s own comment
(supervisor item 9, 2026-08-30) says so in as many words:

> *"Reaching this line already PROVES conjunctions 1 and 2 held … Both are
> PERSISTENT state: the malicious flag is assigned once in
> `hf_declare_malicious_rsus()` and never cleared, and the unendorsed FlowMod
> stays installed. So every [S5] line is evidence of an ongoing compromised
> state, not of a discrete send event — which is exactly why S5 fires far more
> often than `hf_send_gt`."*

`hf_send_gt` is precisely what the activity gate is built from. The detector and
the ground truth were **deliberately given opposite temporal semantics**, and
`score_primary` is scored across that gap. A compromised RSU sitting on an
unendorsed FlowMod but not currently duplicating is counted as a false positive
for correctly reporting that it is compromised.

Decision 4 (2026-08-21) introduced the activity gate for a good reason — 40.7% of
node-level positive windows contained no attack activity, capping DR at ~59.3%.
The gate fixed the DR side and created this FPR side. Both halves are the same
unresolved question: *is a persistently compromised, momentarily quiet RSU a
positive?* The pipeline currently answers "no" for truth and "yes" for S5–S8.

## 8.3 Why persistence M works so well — it is a density proxy for the gate

`score_primary_cycles` (cycles out of 10 in which the primary detector fired):

| | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | median |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **A5** dormant FP | 106 | 91 | 79 | 65 | 31 | 22 | 11 | 13 | 1 | 1 | **3** |
| **A5** true pos | 8 | 29 | 40 | 57 | 67 | 72 | 69 | 77 | 61 | 44 | **6** |
| **A6** dormant FP | 128 | 76 | 45 | 34 | 16 | 7 | 5 | 1 | 0 | 0 | **2** |
| **A6** true pos | 31 | 57 | 81 | 89 | 113 | 97 | 94 | 75 | 52 | 40 | **5** |
| **A7** dormant FP | 84 | 85 | 66 | 55 | 48 | 24 | 13 | 11 | 5 | 1 | **3** |
| **A7** true pos | 10 | 31 | 50 | 65 | 56 | 71 | 57 | 74 | 79 | 32 | **6** |
| **A8** dormant FP | 148 | 80 | 42 | 15 | 8 | 4 | 1 | 0 | 0 | 0 | **2** |
| **A8** true pos | 63 | 102 | 111 | 110 | 98 | 73 | 59 | 41 | 12 | 1 | **4** |

The two distributions are the **same shape, shifted** — not a signal/noise split.
A dormant attacker still relays ordinary traffic, so S5–S8 fire at *low density*
on its persistent state; an active attacker floods duplicates and fires at *high
density*. Persistence M does not remove noise. It **reconstructs the activity
gate from firing density**, which is why it lands on the primary path with no
`d_div` anywhere near it. This is a real and well-founded fix, and §7 was wrong
to lump it in.

It is also the reason M is so effective here specifically: HF is the one family
where the detector is latched and the truth is event-gated. Expect a smaller
return on A1/A2, whose gate (`obs_exceeded_dmax`) is itself an event.

## 8.4 But M=5 is past the optimum — M=2–3 is the right operating point

Full sweep on `score_primary`, A5–A8, arm A:

| M | A5 FPR/DR | A6 FPR/DR | A7 FPR/DR | A8 FPR/DR | **mean MCC** |
|---|---|---|---|---|---|
| 1 | 0.368/1.000 | 0.342/0.971 | 0.363/0.996 | 0.305/0.974 | 0.625 |
| **2** | 0.275/0.985 | 0.202/0.929 | 0.275/0.977 | 0.154/0.882 | **0.690** |
| **3** | 0.196/0.929 | 0.118/0.854 | 0.198/0.919 | 0.072/0.734 | **0.697** |
| 4 | 0.126/0.853 | 0.069/0.746 | 0.138/0.824 | 0.029/0.573 | 0.671 |
| 5 | **0.069**/0.744 | 0.032/0.627 | 0.090/0.701 | 0.013/0.413 | 0.622 |
| 6 | 0.042/0.616 | 0.014/0.477 | 0.048/0.595 | 0.005/0.270 | 0.554 |

Per-variant MCC: A5 0.592→0.705 (peak M=4), A6 0.647→0.735 (M=3),
A7 0.595→0.678 (M=3), A8 0.667→0.721 (M=2).

The 36.8% → 6.9% headline is M=1 → M=5, and it is real — but at M=5 the mean MCC
(0.622) is **below M=1's** (0.625): A8's DR collapses to 0.413 and A6's to 0.627.
Quote the FPR drop with its DR cost attached, and set **M=3** (mean MCC 0.697,
+0.072 over M=1) or **M=2** if DR is the binding constraint. If M is tuned per
variant, A8 wants 2 and A5 wants 4 — consistent with A8's much steeper
dormant-FP decay in §8.3.

## 8.5 A confound in attributing the composite gap

`score` and `score_primary` differ in **two** ways, not one:

```cpp
if (flags.D_RSU) dw_mark_rsu(rsu);            // lrad.h:465 — marks the OBSERVER
dw_mark_rsu_primary(prev_sender, _prim);      // lrad.h:550 — marks the SUSPECT
```

The 2026-08-22 attribution fix ("mark the suspect, not the observer") was applied
**only to the primary column**. So the `score` → `score_primary` delta mixes a
detector-set change with a node-attribution change. Decomposing `score`'s FPs:

| variant | FPR `score` | FP | on dormant declared attackers | **on non-attacker RSUs (observers)** |
|---|---|---|---|---|
| A5 | 0.836 | 953 | 487 (51.1%) | **466 (48.9%)** |
| A6 | 0.849 | 775 | 435 (56.1%) | **340 (43.9%)** |
| A7 | 0.766 | 869 | 472 (54.3%) | **397 (45.7%)** |
| A8 | 0.782 | 763 | 463 (60.7%) | **300 (39.3%)** |

The 39–49% landing on non-attacker RSUs is where §3's `d_div` lives — but it is
**also** where the un-fixed observer attribution lives, and these two columns
cannot separate them. Both mechanisms produce the same signature (a benign RSU
scoring 1 against truth 0) and both are confined to the composite path.

So: "`d_div` accounts for the LSTM's contribution" is supportable; "`d_div`
accounts for 53–61% of all FPs" is **not yet** — some unknown share of the
non-attacker FPs is `dw_mark_rsu(rsu)` marking the observer, exactly as
lrad.h:538-549 already documents for the pre-fix primary column ("a benign RSU
that correctly detects a malicious neighbour gets score=1 against its own
truth=0, i.e. penalised for detecting").

**To separate them**, one run is enough: with `require_lstm_high_conf` on (Fix 1)
or `flag_LSTM` forced false, re-measure `score`'s FP split by `truth_declared`.
Whatever non-attacker FP remains is attribution, not the LSTM.

## 8.6 Revised summary of FPR mechanisms

| # | mechanism | path | variants | evidence |
|---|---|---|---|---|
| 1 | `d_div`/`a_tp` are global scalars fed as per-RSU features | LSTM → `score` only | A5–A8 | §3, AUC 0.500 within-stratum |
| 2 | **Latched detector vs. event-gated truth** | **`score_primary` and `score`** | **A5–A8** | **§8.1–8.3, 95–100% of primary FPs** |
| 3 | `dw_mark_rsu()` marks the observer, not the suspect | `score` only | all | §8.5, lrad.h:538-549 |
| 4 | 10-cycle window OR amplifies per-cycle FPR ~10× | both | non-HF | §6 |

Mechanisms 1 and 3 are **defects** — fix them. Mechanism 2 is a **specification
question** the project has not settled, and persistence M is a good empirical
answer to it; settling it explicitly (does a dormant compromised RSU count as a
positive?) would let truth and detector agree by construction instead of by
tuning.
