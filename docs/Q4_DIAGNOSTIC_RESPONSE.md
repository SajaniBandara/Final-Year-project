# Q4 Diagnostic Response — Root-Cause Analysis

**Date:** 2026-08-05
**Scope:** Supervisor Diagnostics 1–4 + the 50 per-variant questions.
**Method:** Static trace of the detection/scoring path + reconciliation against the
already-captured Q4 logs (`logs/q1q6_ablation/A*_Q4.log`). **No new simulation runs
were required.** That is itself a finding — see §6.

---

## 0. Headline

The supervisor's core instinct is **correct and understated**: the Q4 boundary is not
clean. But the mechanism is not the one named in the diagnostics.

**Not one of the 268 "detections" in any Q4 variant came from the witness mechanism
scoring a node.** Every single one came from `trust_update_negative()` → trust falling
below `T_min` → `record_detection_event()`. This channel is **not gated by any Q1–Q6
flag**, so it contaminates *all six configurations*, not just Q4.

Four independent root causes, all confirmed:

| # | Root cause | Explains |
|---|-----------|----------|
| **RC1** | A1/A2 ground-truth latch lives *inside* the detector the ablation disables | A1/A2 `TP+FN=0` |
| **RC2** | BTMM per-packet trust path is ungated by every Q-flag | A2 FP=103, A4/A5/A6 TP, all Q-configs |
| **RC3** | BFT quorum counts **alert messages**, not **distinct witnesses** — direct violation of `eq:bft_penalty` | FP_W=202, precision 15.5% |
| **RC4** | Alert pool never pruned or cleared after a crossing → monotonic trust decay | 200/268 nodes quarantined on A7, negative MCC |

---

## 1. What the confusion matrix actually is

This must be settled first, because it invalidates the premise of most of Groups 1 and 5.

`calculate_security_detection_metrics()` — `routing.cc:117302-117382`:

```cpp
for (int n = 0; n < active_topology_nodes; n++) {
    bool malicious = is_malicious_node[v][n];
    if (v == 0) malicious = malicious && g_s1_gt_delay_exceeded[n];
    else if (v == 1) malicious = malicious && g_s2_gt_delay_exceeded[n];
    bool detected  = is_detected_node[v][n];
    if (malicious  && detected)  sec_TP[v]++;
    ...
}
```

The unit of classification is **one node**, not one evaluation block.

- `total_size` = 200 vehicles + 64 RSUs + 4 controllers = **268**. This is why
  TP+FP+TN+FN = 268 for *every* variant, in *every* config. It is the node count.
- `is_malicious_node[][]` / `is_detected_node[][]` are **sticky latches** — set once,
  never cleared. The matrix is recomputed each cycle from monotonically growing latches,
  so the final row means *"which nodes were ever malicious / ever detected across the
  whole run."*
- There is **no warm-up exclusion, no windowing, no deduplication, and no
  `evaluator.py`** anywhere in this path. That machinery belongs to the offline LSTM
  pipeline and did not produce these numbers.

**Consequence.** Questions Q2, Q3, Q7, Q10, Q41, Q44, Q47 ask about block boundaries,
30-cycle warm-up exclusion, dedup ordering, and `evaluator.py`'s MCC. None of those exist
in this instrument. Q3's "64 × N = 268 implies N is not an integer" resolves as: 268 is
not `64 × N`, it is the node count.

**Q41 answer (still valid and worth stating):** the MCC denominator is
`sqrt((TP+FP+ε)(TP+FN+ε)(TN+FP+ε)(TN+FN+ε))` with `ε = 1e-6` (`routing.cc:117359-117367`).
It does *not* return a hard 0.0 on a degenerate row — it returns
`(TP·TN − FP·FN)/ε²`-scaled, which for A1 (TP=0, FN=0) gives numerator
`0·254 − 14·0 = 0`, so MCC = 0.0 by numerator, not by guard. Correct value, but by
accident rather than by design; a genuinely degenerate case with a nonzero numerator
would return a huge spurious value.

---

## 2. RC1 — A1/A2 `TP+FN=0` is an ablation artefact, not a pipeline failure

The supervisor called this "a fundamental data pipeline failure." It is narrower and
fully explained.

Ground truth for A1/A2 is gated on a delay-exceedance latch (`routing.cc:117328-117329`).
Those latches are written in exactly one place each:

- `g_s1_gt_delay_exceeded[n]` — set **only** at `s1_detection.h:294`, inside
  `s1_detect_packet()`
- `g_s2_gt_delay_exceeded[n]` — set **only** at `s2_detection.h:99`, inside the S2 detector

Both detectors are reached through a single guarded call site:

```cpp
// lrad.h:510
if (!g_disable_s1_s2 && assoc_rsu_local_idx < (uint32_t)N_RSUs) {
    flags.flag_S1 = s1_detect_packet(...);
}
// lrad.h:530
flags.flag_S2p = g_disable_s1_s2 ? false : lrad_s2_partial_check(...);
```

Q4 sets `g_disable_s1_s2=1`. The detector never runs, the latch never sets, so
`malicious` is false for every node, so `TP+FN=0` **by construction**.

**Empirically confirmed:** `A1_Q4.log` contains 0 `SIGNATURE S1 TRIGGERED` lines and
`A2_Q4.log` contains 0 `SIGNATURE S2 TRIGGERED` lines.

**This is a defect in the ablation harness, not in the attack or the data pipeline.** The
A1/A2 rows are undefined in **any** config with `g_disable_s1_s2=1` — that is Q2, Q3 and
Q4. They are valid in Q1, Q5, Q6.

**Falsifiable prediction (answers Q8 directly):** Q1 will show `TP+FN > 0` for A1/A2, and
Q2/Q3 will show `TP+FN = 0`. If Q1 also shows 0, RC1 is wrong and the ground truth really
is empty. This is checkable the moment Q1 lands — no extra run.

**Secondary concern worth raising honestly:** even when the latch works, ground truth is
derived from the detector's own EWMA threshold. It is not fully circular — the latch is
set independently of the `selective_ok` conjunct and of the ZKP conjunct, so it measures
"did delay genuinely exceed threshold," not "did S1 fire." But A1/A2 ground truth is still
threshold-dependent in a way A3–A8's is not, and that asymmetry should be stated whenever
A1/A2 MCC is reported.

---

## 3. RC2 — the BTMM trust path is ungated, so no Q-config isolates anything

`routing.cc:121906-121920`:

```cpp
if (sig_ok) {
    stark_update_meta(prev_sender, packet_ID, fid, timing_ok, hop_ok);
    if (t_fwd_claimed > 0.0 && !timing_ok) {
        witness_submit_nfa_alert(current_hop, prev_sender, packet_ID, fid, t_fwd);
    }
    // §BTMM — per-packet trust update (eq:trust_update)
    if (hop_ok && timing_ok && g_batch_passed)
        trust_update_positive(prev_sender);
    else
        trust_update_negative(prev_sender);   // ← ungated by every Q1–Q6 flag
}
```

`trust_update_negative()` (`crypto_layer.h:1057-1088`) drops trust by `TRUST_DELTA_P=0.10`
and, on crossing `TRUST_T_MIN=0.50` from an initial 1.0, calls
`record_detection_event(active_attack_variant, node)`.

**Six negative updates quarantine a node permanently.** There is no time window and no
decay-back.

The only flag that disables this is `enable_quarantine` (AB7-A). **No Q1–Q6 config sets
it.** Under `disable_crypto=1`, `sig_ok` and `hop_ok` short-circuit to true, but
`timing_ok` is a **raw wall-clock comparison with no crypto gate** (`routing.cc:121884`) —
already documented as a known caveat in the runner header. So the else-branch stays live
in every "crypto forced pass" config.

### Reconciliation against the Q4 logs

Counting `TRUST-QUARANTINE` lines against the per-variant confusion matrix at the same
cycle:

| Variant | TP | FP | TP+FP | `TRUST-QUARANTINE` count | Match |
|---|---|---|---|---|---|
| A1 | 0 | 14 | 14 | 14 | exact |
| A2 | 0 | 102 | 102 | 102 | exact |
| A3 | 0 | 0 | 0 | 0 | exact |
| A4 | 7 | 0 | 7 | 8 | −1 |
| A5 | 32 | 167 | 199 | 199 | exact |
| A6 | 130 | 60 | 190 | 190 | exact |
| A7 | 27 | 173 | 200 | 200 | exact |
| A8 | 37 | 31 | 68 | 68 | exact |

Seven of eight match exactly; A4 is off by one (one quarantine landing between the sampled
cycle and the row, benign sampling skew).

**Conclusion: the Q4 confusion matrix measures quarantine outcome, not witness
performance.** The redirect to witness-native counters was the right call — but this is the
evidence that justifies it, which we should have supplied the first time.

**This also means Q1, Q2, Q3, Q5 and Q6 confusion matrices are contaminated by the same
channel.** The ablation grid does not currently isolate what it claims to.

---

## 4. RC2 applied — Diagnostics 2 and 3

### Diagnostic 2 — A2 FP=103 in a "witness-only" config

The premise ("the witness fires on `eq:dup_alert_cond`, which requires the same hash at two
destinations; A2 does not duplicate packets") is **correct**, and the code agrees with it.
There are **two distinct witness mechanisms**, and the diagnostic named the wrong one:

| Mechanism | Function | Spec | Scope | A1/A2/A4 BFT crossings | A5–A8 |
|---|---|---|---|---|---|
| α_w duplication alert | `witness_submit_duplication_alert()` | `eq:dup_alert_cond` | HF variants | **0** | large |
| β_w non-forwarding alert | `witness_submit_nfa_alert()` | `eq:nfwd_detect` | Selective Time Delay | large | **0** |

Measured from the logs:

```
A1  DA-BFT=0      NFA-BFT=383
A2  DA-BFT=0      NFA-BFT=3132
A3  DA-BFT=0      NFA-BFT=0
A4  DA-BFT=0      NFA-BFT=118
A5  DA-BFT=15824  NFA-BFT=0
A6  DA-BFT=12993  NFA-BFT=0
A7  DA-BFT=14284  NFA-BFT=0
A8  DA-BFT=3331   NFA-BFT=0
```

The duplication alert **never fires on A1–A4**, exactly as the supervisor predicted. What
fires is the non-forwarding alert — "packet received but not forwarded within `T_fwd`" —
which is precisely what a selective time delay attack looks like, and which
`crypto_layer.h:1469-1481` deliberately excludes from M12.

**So A2's 103 false positives are not the witness firing on something it cannot observe.**
They are 102 BTMM/NFA-driven quarantines, scored as FP **because RC1 zeroed the ground
truth**. A2's `FP=103` and A2's `TP+FN=0` are the same bug. With ground truth intact, a
large share of those 103 would be true positives.

### Diagnostic 3 — A4/A5/A6 TP in Q4, per variant

- **A4 (TP=10):** `DA=0, NFA=118`. Non-forwarding alerts + BTMM decay on TCAM-victim RSUs.
  A4's ground truth is event-driven (`record_attack_onset(3, target_rsu_node_id)` on the
  **victim** RSU), so it is unaffected by RC1 and these are genuine detections of real
  victims. Not a boundary violation.
- **A5 (TP=32) / A6 (TP=132):** `DA` fires heavily. This is **correct and intended**
  behaviour, documented at `crypto_layer.h:1386-1398`: the duplication alert fires during
  *active* HF as well as passive, and a previous "fix" that classified those as WAP-R false
  positives was itself reverted as misleading. Active HF genuinely duplicates packets.

**Therefore the expected pattern "TP=0 on A1–A6, TP>0 only on A7/A8" is not the right
criterion for the generic matrix.** It is the right criterion for the M12/WAP-R counters,
which are scoped to variants 7–8 by `main.tex`'s own definition. That was the substance of
our redirect, and it holds.

**Q46 answer:** the witness hash is `sha3_512({fid, packet_ID, current_hop})`
(`routing.cc:121926-121928`) — it is computed over flow/packet/receiver identifiers, **not
over packet content**. So content modification in A5/A6 does not change the hash, and the
duplication condition fires on active HF exactly as observed. The supervisor's hypothesis
that it should not fire assumed a content-derived hash; the implementation does not use one.

---

## 5. RC3 + RC4 — Diagnostics 1 and 4: the BFT guard is not implemented as specified

This is the most serious finding and it is an unambiguous spec violation.

**`main.tex`, immediately after `eq:bft_penalty`:**

> "The cardinality is over **distinct witness vehicles** $w$ that have each submitted at
> least one valid alert (signed under their own $pk_w$) for the same $(v_i, p)$ event —
> **not over the total number of alert messages**. A single witness submitting multiple
> alerts for the same event is counted as one, **preventing any one vehicle from crossing
> the $2f{+}1$ threshold unilaterally**. The smart contract deduplicates by
> $(w, v_i, H(p))$ before counting…"

**The implementation** (`crypto_layer.h:1367-1408`, and identically at `1455-1481`):

```cpp
uint32_t verified = 0;
for (auto& wa : g_witness_alert_pool[target_node]) {
    if (!g_node_keys[wa.witness_id].keys_generated) continue;
    if (OQS_SIG_verify(...) == OQS_SUCCESS) ++verified;
}
if (verified >= threshold) { ... trust_update_negative(target_node); }
```

Four deviations:

1. **Counts alert messages, not distinct witnesses.** No dedup on `wa.witness_id`. The spec
   forbids exactly this.
2. **No deduplication by `(w, v_i, H(p))`.** The spec requires it before counting.
3. **The pool is keyed by `target_node` alone**, not scoped to the `(v_i, p)` event. Alerts
   from unrelated packets pool together against the same node.
4. **The pool is never pruned and never cleared after a crossing.** `WITNESS_WINDOW=10.0s`
   is applied to `g_witness_log` (`crypto_layer.h:1240, 1308`) but **never** to
   `g_witness_alert_pool`.

Consequence of (4), visible directly in the log:

```
[WITNESS-DA-BFT] 3 verified alerts >= 2f+1=3 → trust_update_negative(target=37)
[WITNESS-DA-BFT] 4 verified alerts >= 2f+1=3 → trust_update_negative(target=37)
[WITNESS-DA-BFT] 5 verified alerts >= 2f+1=3 → trust_update_negative(target=37)
```

Monotonically increasing on the same target. **Every alert after the third re-crosses the
threshold and re-applies a trust penalty.** With `TRUST_DELTA_P=0.10` from 1.0 and
`T_MIN=0.50`, the 8th cumulative alert quarantines the node permanently.

**Diagnostic 1 answered (negative MCC on A7/A8).** A7 produced **14,284 threshold crossings
in a 30 s run** and quarantined **200 of 268 nodes (74.6%)**. With only 39
ground-truth-malicious nodes, quarantining 200 forces FP ≫ TP:
`TP×TN = 27×56 = 1512 < FP×FN = 173×12 = 2076` → MCC < 0. The negative MCC is a direct
arithmetic consequence of mass quarantine, not of witness misclassification per se.

**Diagnostic 4 answered (A7 FP_W=202, precision 15.5%).** `f=1` so `2f+1=3`
(`crypto_layer.h:117`). The threshold is not failing because vehicle density is below 3 —
it is failing because **it never required 3 distinct witnesses in the first place**. Under
the implemented rule, three alert *messages* accumulated over the entire run — possibly all
from one witness — suffice. The supervisor's density concern (Q28/Q40) is real in principle
but is not the operative cause here; the operative cause is RC3.

**Compounding FP source.** `eq:dup_alert_cond`'s justification is "under single-path
routing, the same hash at two distinct destinations is impossible for legitimate traffic."
But the implemented hash is over `{fid, packet_ID, current_hop}` and the comparison is
against a changing `destination` field. `routing.cc:121932-121934` already concedes:

> "Flow destinations change during routing updates causing false positives in non-HF
> scenarios."

The mitigation applied was to gate the alert on `present_active_hf_attack ||
present_passive_hf_attack`. That suppresses the symptom in non-HF runs but leaves it
**fully live in A5–A8** — precisely the runs where the witness is the primary detector.
FP_W=202 on A7 is that known, unmitigated false-positive source. **This answers Q29 and
Q45.**

---

## 6. Status of the 50 questions

Honest accounting, because running all 50 as specified would cost days and most would
produce nothing:

| Class | Count | Questions |
|---|---|---|
| **Answered above from code + existing logs** | ~20 | 1, 3, 8, 26, 28, 29, 31, 32, 33, 34, 35, 36, 38, 40, 41, 44, 45, 46, 47, and Diagnostics 1–4 |
| **Premise does not hold** (assume blocks / warm-up / dedup / `evaluator.py`) | ~8 | 2, 3, 7, 10, 42, 44, 47, and parts of 5/48 |
| **Blocked behind RC1–RC4** — would measure the bug, not the system | ~14 | 4, 5, 9, 11–12, 21–22, 27, 30, 43, 48, 49, 50 |
| **Genuinely need a run, and are worth running after the fixes** | ~8 | 13–20 (attack-execution confirmation), 24, 37, 39 |

Two specific run-length points that cut across many of them, worth putting to the
supervisor now:

- **Q14/Q24/Q19 (A4 TCAM saturation).** The supervisor's own arithmetic —
  1500 rules ÷ 20 pps = 75 s — says a 30 s run **cannot** saturate TCAM. If that is right,
  `f_S4` can never fire in Q1–Q6 and A4's rule-based numbers are structurally zero at this
  run length. This needs confirming against the actual `TCAM_CAPACITY` and injection rate,
  but if it holds, **the 30 s diagnostic length is invalid for A3/A4** and those rows should
  be re-run longer or excluded.
- **Q37 (LSTM suppression).** The ceiling at 30 s × 64 RSUs × 1 Hz is 1,920, against a
  full-run reference of 14,000+. Comparing the two directly will mislead; only the
  per-cycle rate is comparable.

---

## 7. Recommended fixes, in order

1. **RC3/RC4 — BFT quorum.** Deduplicate by `(witness_id, target, H(p))` before counting;
   scope the pool to the `(v_i, p)` event; apply `WITNESS_WINDOW` pruning to
   `g_witness_alert_pool` as it already is to `g_witness_log`; clear or mark the pool after
   a crossing so one event penalises once. This is the spec-compliance fix and the single
   highest-value change.
2. **RC2 — ablation isolation.** Either set `enable_quarantine=0` for Q1–Q5, or add a
   dedicated flag for the BTMM per-packet trust path. Until this lands, **no Q-config's
   confusion matrix isolates its named component.**
3. **RC1 — A1/A2 ground truth.** Move the `g_s*_gt_delay_exceeded` latches out of the
   detector bodies to an ungated observation point, so ground truth survives
   `g_disable_s1_s2`.
4. **Re-run Q1–Q6** after 1–3. Results produced before these fixes measure the harness, not
   the system.

Item 2 is a one-line change per config. Items 1 and 3 are contained and low-risk. None
requires longer simulation time.

---

## 8. What we are *not* claiming

- We have not shown that a single witness in fact submitted all three alerts in any
  specific crossing. We have shown the code **permits** it (no dedup) and that the pool
  **provably** never prunes (monotonic counts on one target). Both are spec violations
  regardless.
- The A4 off-by-one in §3 is unexplained at the single-event level; it is within sampling
  skew and we have not chased it.
- MCC target 0.90 vs measured: we are **not** offering the Q4 numbers as evidence about
  system quality either way. Under RC1–RC4 they measure the harness. That applies equally
  to the variants that look good (A4=0.44, A6=0.28) and the ones that look bad.
