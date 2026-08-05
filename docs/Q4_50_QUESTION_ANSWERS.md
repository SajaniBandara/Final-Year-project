# Answers to the 50 Per-Variant Diagnostic Questions

**Date:** 2026-08-05 · **Config:** Q4 (witness-only), 30 s, 60 %, seed 1, all 8 variants
**Companion:** [`Q4_DIAGNOSTIC_RESPONSE.md`](Q4_DIAGNOSTIC_RESPONSE.md) — root causes RC1–RC4
**Sources:** `scratch/*.h`, `scratch/routing.cc`, `logs/q1q6_ablation/A*_Q4.log`

Every answer is tagged:

| Tag | Meaning |
|---|---|
| **[A]** | Answered from code or captured logs |
| **[P]** | Premise does not hold — the described machinery is not in this path |
| **[B]** | Blocked by RC1–RC4 — a measurement here would score the harness, not the system |
| **[R]** | Legitimately needs a new run or new instrumentation |

---

## Reference constants (used throughout)

| Constant | Value | Source |
|---|---|---|
| `total_size` | 268 (200 veh + 64 RSU + 4 ctrl) | `routing.cc:114657` |
| `attack_start_time` | **10.0 s** → 20 s of attack in a 30 s run | `routing.cc:114828` |
| `attack_rate_pps` | 20.0 | `routing.cc:114827` |
| `TCAM_CAPACITY` | 1500 | `routing.cc:117642` |
| `tcam_util_thresh` (S4) | **0.213** (benign p99) — *not* 0.80 | `routing.cc:117782` |
| `lambda_fm_thresh` / `lambda_pi_thresh` | 10.0 / 15.0 | `routing.cc:117780-117781` |
| `S2_DELTA_MAX` | 0.050 s | `s2_detection.h:42` |
| `s1_beta` | 0.8 | `s1_detection.h:79` |
| `WITNESS_F` → `2f+1` | 1 → **3** | `crypto_layer.h:117` |
| `WITNESS_WINDOW` | 10.0 s (applied to `g_witness_log` only) | `crypto_layer.h:116` |
| `TRUST_DELTA_P` / `T_MIN` / init | 0.10 / 0.50 / 1.0 → **6 penalties to quarantine** | `crypto_layer.h:107-108, 1024` |
| `CRYPTO_DEBUG_LOG` | **false** — per-alert witness/target IDs not logged | `crypto_layer.h:60` |

### Q4 measured matrix, ground truth, and event counts

| Var | TP | FP | TN | FN | MCC | GT pos (TP+FN) | GT pos % | DA-BFT | NFA-BFT | Quarantines |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | 0 | 14 | 254 | 0 | 0.000 | **0** | 0.0 % | 0 | 383 | 14 |
| A2 | 0 | 103 | 165 | 0 | 0.000 | **0** | 0.0 % | 0 | 3132 | 102 |
| A3 | 0 | 0 | 236 | 32 | 0.000 | 32 | 11.9 % | 0 | 0 | 0 |
| A4 | 10 | 0 | 224 | 34 | 0.444 | 44 | 16.4 % | 0 | 118 | 8 |
| A5 | 32 | 167 | 61 | 8 | 0.055 | 40 | 14.9 % | 15824 | 0 | 199 |
| A6 | 132 | 64 | 46 | 26 | 0.282 | 158 | 59.0 % | 12993 | 0 | 190 |
| A7 | 27 | 173 | 56 | 12 | −0.051 | 39 | 14.6 % | 14284 | 0 | 200 |
| A8 | 37 | 31 | 79 | 121 | −0.054 | 158 | 59.0 % | 3331 | 0 | 68 |

---

# GROUP 1 — Ground truth presence and evaluation window

**Q1. [A] A1/A2 positive ground-truth count and first-flip cycle.**
**Zero, for both, in Q4 — structurally.** `g_s1_gt_delay_exceeded[]` is written only at
`s1_detection.h:294` (inside `s1_detect_packet()`); `g_s2_gt_delay_exceeded[]` only at
`s2_detection.h:99`. Both are reached solely through the `g_disable_s1_s2`-guarded call site
(`lrad.h:510` and `:530`), which Q4 sets to 1. The latch never flips, so there is no "first
flip cycle." Confirmed: **0** `SIGNATURE S1 TRIGGERED` lines in `A1_Q4.log`, **0**
`SIGNATURE S2 TRIGGERED` in `A2_Q4.log`. This is **RC1**, an ablation-harness defect. It does
*not* mean the attack fails to exceed Δ_max — it means nothing was measuring whether it did.

**Q2. [P] Evaluation blocks per RSU after 30-cycle warm-up exclusion.**
There are none. This instrument has no blocks, no windows, and no warm-up exclusion. See Q3
and Q44. Warm-up is handled instead by `attack_start_time = 10.0` plus the event-gated latch
at `routing.cc:117328-117329`, which scores pre-exceedance nodes as TN rather than FN.

**Q3. [A] Derivation of 268.**
268 is not `64 × N`. It is `total_size` = `N_Vehicles(200) + N_RSUs(64) + N_Controllers(4)`,
the loop bound at `routing.cc:117311-117316`. The confusion matrix classifies **one node**,
not one block. It is 268 in every variant and every config because the node count is
constant. No RSU is dropping blocks; there are no blocks.

**Q4. [A] A3: 32 positives, zero detections — is `f_unauth` firing?**
`f_unauth` fires strongly. `A3_Q4.log` contains **608 `[S3]` and 64 `[S4]` firings**, first at
`t=10.998 s` (one cycle after onset). The signal is generated and reaches `flag_s3`/`flag_s4`.
It does not reach the confusion matrix because Q4 sets `g_disable_s3_s4=1`, which by design
gates only `record_detection_event()` (`tcam_detection.h:336, 349`) and not the flag itself.
**So TP=0 for A3 in Q4 is correct, intended ablation behaviour, not a broken evaluation path.**

**Q5. [A] A8: temporal distribution of the 37 TPs.**
**Not clustered at the end.** Quarantine timestamps in `A8_Q4.log` spread near-uniformly
across the whole attack window: 7 at t=10 s, 8 at 11, 1 at 12, 7 at 13, 4 at 14, 8 at 15, 5 at
16, 3 at 18, 5 at 19, 3 at 20, 2 at 21, 3 at 24, 3 at 25, 3 at 26, 2 at 27, 4 at 28 (68 total).
Detection begins in the first second after onset. **Witness accumulation delay is therefore
not the cause of A8's 76.6 % miss rate**, and lengthening the run will not fix it. The misses
are a scoring problem (RC2/RC4), not a latency problem.

**Q6. [A] `attack_start_time`.**
**10.0 s** (`routing.cc:114828`), giving a 20 s attack window in a 30 s run. It is *not* at or
after cycle 20, so the premise that exceedance events fall inside a warm-up window does not
apply. A1/A2's zero comes from RC1, not from onset timing.

**Q7. [P] Warm-up exclusion before or after dedup in `evaluator.py`.**
Neither. `evaluator.py` belongs to the offline LSTM pipeline and is not in the path that
produced these numbers. The matrix comes from `calculate_security_detection_metrics()`
(`routing.cc:117302`), computed in-simulation from sticky per-node latches.

**Q8. [A/R] Is TP+FN = 0 also true in Q1?**
**Prediction: no — Q1 will show TP+FN > 0 for A1 and A2**, because Q1 sets
`g_disable_s1_s2=0`, so the detectors run and the latches set. Q2 and Q3 will show 0, like Q4.
This is the direct falsification test for RC1 and costs nothing extra — it reads off the Q1
run already queued. **If Q1 also shows 0, RC1 is wrong and the ground truth really is empty.**

**Q9. [R] Distinct RSU zones affected by A1 attackers per cycle.**
Not currently instrumented; the per-cycle attacker→RSU-zone map is not logged. Note the
related result already established: `hf_gt_attribution_node()` mapped 91/91 vehicles with 0
unmapped in the A6 check, so zone attribution itself works. Worth adding a counter, but it is
downstream of RC1 — with the latch fixed, A1's zone coverage becomes directly readable from
the ground-truth count.

**Q10. [A] Positive-block ratio per variant.**
Per-node positive ratios are in the reference table: A1 0 %, A2 0 %, A3 11.9 %, A4 16.4 %,
A5 14.9 %, A6 59.0 %, A7 14.6 %, A8 59.0 %. **The supervisor's expectation that "the majority
of blocks should be positive at 60 % penetration" holds only for A6 and A8.** For A5 and A7 the
attacker allocation is control-plane-scoped (39–40 malicious nodes, not 158), so a 15 % positive
rate is correct, not sparse labelling. The class imbalance is real and does suppress MCC — see
Q47.

---

# GROUP 2 — Per-variant attack execution confirmation

**Q11–Q12. [B] A1/A2 measured per-hop delay vs Δ_max = 50 ms.**
Cannot be answered from Q4: the only code that measures hop delay against Δ_max for A1/A2 is
inside the disabled detectors (RC1). The *raw* wall-clock check `timing_ok`
(`routing.cc:121884`) does run ungated and evaluates false often enough to produce **3132 NFA
BFT crossings on A2** — strong indirect evidence that the injected delay does exceed 50 ms.
Direct confirmation requires Q1/Q5/Q6, where S1/S2 are live.

**Q13. [A] A3 FlowMod rate and `f_unauth`.**
Firing correctly. `A3_Q4.log`: λ_FM = **20.000 rules/s** against `lambda_fm_thresh = 10.0`,
with `malicious=20` unauthorised entries at t = 10.998 s, rising to `malicious=320` by
t = 25.998 s. 11,512 `[BC-FLOWMOD]` events and 32 `[BC-S3]` blockchain records. The malicious
controller is issuing FlowMods and they are failing the endorsement check as intended.

**Q14. [A] A4 `U_TCAM` and time-to-saturation — premise incorrect.**
The 75 s figure assumes `U_thresh = 0.80`. The actual S4 gate is **`tcam_util_thresh = 0.213`**
(`routing.cc:117782`), calibrated as the benign 99th percentile; 0.80 is `BC_S4_UTIL_THRESH`, a
separate blockchain-write gate. A4 crosses it at **t = 11.998 s** — under 2 s after onset —
with `util = 0.241`, `λ_PI = 180.0`. **384 S4 firings** in the run. Aggregate injection is
~180 pps per targeted RSU, not 20, because 158 attackers act in parallel. **30 s is adequate
for A4.**

**Q15–Q18. [R] A5–A8 copy delivery to d′ / unauthorised listener.**
Not directly instrumented per cycle. Indirect evidence is strong: the duplication alert fires
**15,824 times on A5, 12,993 on A6, 14,284 on A7, 3,331 on A8**, and `witness_check_duplication()`
only returns true when the same hash is logged at two distinct destinations — so copies *are*
reaching a second destination and being observed. What is unverified is whether that second
destination is the *intended* d′ or a routing-churn artefact (see Q29/Q46). That distinction is
the open question, and it needs a targeted counter, not a longer run.

**Q19. [A] A3/A4 attack onset and immediate TCAM installation.**
Both begin at `attack_start_time = 10.0 s` and install immediately: A3's first S3 firing is at
t = 10.998 s, A4's first S4 firing at t = 11.998 s. No warm-up-to-saturation delay problem.

**Q20. [R] Active attacker count per cycle vs initial allocation.**
Not logged per cycle. Attacker identity is fixed at declaration (`declare_attackers()`) and not
re-drawn on mobility-induced disconnection, so the *declared* count is constant while the
*effective* count varies with connectivity. This is a genuine and unmeasured confound; it is
also the exact concern behind Gate 3's on-path restriction for variants 5–8. Worth a counter.

---

# GROUP 3 — Detection signal measurement per variant

**Q21–Q22. [B] A1 δ_t vs adaptive threshold, and δ_best selectivity.**
Both quantities are computed inside `s1_detect_packet()`, disabled in Q4 (RC1). Q1 is the right
config. Flagging a related open item: the EWMA that produces σ_r(t) uses `s1_beta = 0.8`, whose
calibration is itself unresolved — see §5 of the handoff doc; the 1 %-tolerance convergence
criterion may never latch on noisy input, so the threshold this question asks about may be
mis-tuned independently of everything here.

**Q23. [A] A3 per-cycle `f_unauth` toggling.**
Toggles as expected — it is not stuck at 0. 608 S3 firings across the run from 1,792 `[S3-DBG]`
evaluation records, with `malicious_count` climbing 20 → 320. See Q13.

**Q24. [A] A4 per-cycle `U_TCAM`, maximum reached.**
Observed range at firing: **0.213 – 0.245**; threshold 0.213. `max_tcam_util` is tracked at
`tcam_detection.h` and exceeded the gate from t = 11.998 s onward. `f_S4` therefore fires
freely; A4's Q4 TP=10 is limited by `g_disable_s3_s4`, not by utilisation.

**Q25. [R] A5/A6 `CopyVerify_d′` / `BC.QueryReceipt` returning 1.**
Not resolvable in Q4 — S5/S6 are computation-disabled (**0 `[S5]` and 0 `[S6]` lines**, which
independently confirms the flag works). This is a Q2/Q5 question. It is a real risk worth
keeping open: if `BC.QueryReceipt` never returns 1, S5/S6 cannot produce TP in *any* config.

**Q26. [A] A7/A8 witness cache size / sufficiency of 2f+1.**
The cache is far from empty and the threshold is not the binding constraint. A7 crossed
2f+1 = 3 **14,284 times** in 30 s. The problem is the opposite of insufficiency — see Q28/Q40.

**Q27. [B] LSTM anomaly-score distribution on A5/A7 in Q3.**
Q3 has not been run. Independently, this number carries the standing caveat already accepted:
A2's LSTM feature had zero gradient across the entire training history, so pre-retrain Q3/Q6
scores understate real contribution.

**Q28. [A] Exact 2f+1 and witness density.**
`WITNESS_F = 1` (`crypto_layer.h:117`), so **2f+1 = 3**. But the density question is moot:
**the implementation never requires 3 distinct witnesses.** `crypto_layer.h:1368-1375` counts
alert *messages* in `g_witness_alert_pool[target_node]` with no deduplication by `witness_id`
and no scoping to a `(v_i, p)` event. Three messages — possibly all from one witness, possibly
spread across the whole run — cross the threshold. So low vehicle density cannot prevent
crossings, which is exactly why 14,284 occurred. **This is RC3, a direct violation of the text
under `eq:bft_penalty`.**

**Q29. [A] A2 packet-hash collision rate in the witness cache.**
**Zero. The duplication alert never fires on A2** — `DA-BFT = 0` in `A2_Q4.log`. The
supervisor's architectural reasoning is correct: A2 does not duplicate packets, and the cache
sees no cross-destination collision. A2's 103 FPs come from the **non-forwarding alert**
(`witness_submit_nfa_alert`, `eq:nfwd_detect`, 3,132 crossings) plus the ungated BTMM trust
path — a different mechanism, deliberately excluded from M12 (`crypto_layer.h:1469-1481`).
The broadcast-overhearing hypothesis is not needed and is not what happened.

**Q30. [R] Min/mean/max positive ground-truth cycles per RSU across the 64 RSUs.**
Not logged per RSU. The aggregate spread is visible though: on A7, the 200 quarantined nodes
break down as **170 vehicles + 30 RSUs**, i.e. 30 of 64 RSUs (47 %) were penalised. So the
effect is broad, not spatially concentrated — which argues against class-imbalance-from-
concentration as the driver, and for RC3/RC4.

---

# GROUP 4 — Component wiring verification per variant

**Q31. [A] Does `ComputeTcamDetection()` run for A3 in Q1, and is the gate recording-only?**
Confirmed on both counts, in Q4 (a stronger test — the flag is *on* there). S3/S4 computed
608 + 64 times with `g_disable_s3_s4=1`, and `record_detection_event()` was correctly
suppressed (A3 TP=FP=0). The gate is applied at `tcam_detection.h:336` and `:349` only, never
to `flag_s3`/`flag_s4`. Confusion-matrix recording reads `is_detected_node[][]`, written by
that call — there is no second path.

**Q32. [A] Are `g_tcam_flag_s3_last`/`s4_last` still set to 1 under `g_disable_s3_s4`?**
**Yes — the asymmetry is intact and this is exactly why it was built that way.** They are
assigned unconditionally at `tcam_detection.h:~272-273`, above the gated recording, with the
rationale documented in-line: `eq:lstm_gate`'s suppression is *structural* (TCAM residual
occupancy), so it must track the raw condition regardless of a diagnostic flag. A3's 608/64
firings prove the raw condition is live. The LSTM gate will therefore behave correctly in Q3.

**Q33. [B] Is `b_batch` ever 0? Per-cycle trace for A5/A6 in Q2.**
Q2 has not been run. In Q4 `disable_crypto=1` forces `b_batch = 1` by short-circuit, so the
question is unanswerable there by construction. Flagged in the runner header as a known
caveat. This is a legitimate Q2 question and should be answered when Q2 lands.

**Q34. [B] Do `f_unauth ∧ ¬b_batch` ever co-occur for A5 in Q5?**
Q5 not yet run. Genuinely important — if they never co-occur, S5 cannot produce a TP in any
config. Should be instrumented as a paired counter before Q5 is interpreted.

**Q35. [A] Trust trajectory for a quarantined node in A4/A5/A6.**
The mechanism is fully determined. Trust starts at 1.0; `TRUST_DELTA_P = 0.10`;
`TRUST_T_MIN = 0.50` — so **six negative updates quarantine a node permanently**, with no time
window and no decay-back. Two callers of `trust_update_negative()` are live in Q4:

1. the witness BFT path (`crypto_layer.h:1380`, `:1468`), and
2. **the BTMM per-packet update at `routing.cc:121919`, which no Q1–Q6 flag disables.**

The second is **RC2** and is the answer the question is really after: **trust penalties are
accumulating from a mechanism other than witness-driven `SC.PenalizeTrust`.** Confirmation —
TP+FP equals the `TRUST-QUARANTINE` count exactly on 7 of 8 variants (A1 14/14, A2 102/102,
A3 0/0, A5 199/199, A6 190/190, A7 200/200, A8 68/68; A4 off by one). **The witness boundary
is not clean, and neither is any other Q-config's.**

**Q36. [A] Do `--g_disable_s5_s6` / `--g_disable_s7_s8` suppress computation, not just logging?**
**Computation, confirmed.** In Q4: **0 `[S5]`, 0 `[S6]`, 0 `[S7]`, 0 `[S8]` lines across all
of A5–A8**, despite those being the runs where they would otherwise fire hardest. The gates sit
at the `lrad_rsu()` call site on the `s*_detect()` calls themselves, so flags, `D_RSU`, the BTMM
penalty and `BC.Write` all go silent together. The Q5 half (non-zero where enabled) awaits Q5.

**Q37. [P/R] LSTM suppression count for A3/A4 in Q3.**
The comparison as posed is invalid: 14,000+ is a **full-run (300 s)** figure and the 30 s
ceiling is 64 × 30 = 1,920. Only the **per-cycle suppression rate** is comparable across the
two. Q3 has not been run; `lstm_suppression_count()` in the runner already parses
`total_suppressed=` from the lane logs, so the number will be available — it just must be
normalised before being compared to the paper.

**Q38. [R] Q6 per-TP detection-source breakdown.**
Not currently attributable — `record_detection_event()` records *that* a node was detected, not
*which* component fired. Adding a source tag is a small, worthwhile change, and under RC2 it is
close to essential: without it there is no way to separate genuine signature detections from
quarantine side-effects. **Recommended before Q6 is interpreted.**

**Q39. [R] `BC.QueryReceipt` call timing and endorsement-set correctness for A3.**
Not verified. Circumstantially it is working — A3 produced 32 `[BC-S3]` records, 29
`[BC-REJECT]`, 28 `[BC-COMMIT]`, and `f_unauth` fires correctly with a rising malicious count
(Q13), which is inconsistent with a stale or wrong endorsement set always returning 0. A
stale-cache bug would show `f_unauth ≡ 0`. Not proof of correct call ordering; worth a check.

**Q40. [A] Per-cycle distinct witnesses at the target RSU; is 2f+1 = 3 achievable?**
Achievable and vastly exceeded — 14,284 crossings on A7. But the density calculation in the
question does not apply, because the threshold does not count distinct witnesses (Q28/RC3).
**Limitation stated honestly:** `CRYPTO_DEBUG_LOG = false` in these runs, so per-alert
`witness=`/`target=` lines were not emitted and we **cannot** show from this log that a single
witness in fact crossed the threshold alone. What the log *does* prove is RC4 — the pool is
never pruned:

```
[WITNESS-DA-BFT] 3 verified alerts >= 2f+1=3 → trust_update_negative(target=37)
[WITNESS-DA-BFT] 4 verified alerts >= 2f+1=3 → trust_update_negative(target=37)
[WITNESS-DA-BFT] 5 verified alerts >= 2f+1=3 → trust_update_negative(target=37)
```

Monotonically rising on one target. `WITNESS_WINDOW` is applied to `g_witness_log`
(`crypto_layer.h:1240, 1308`) but **never** to `g_witness_alert_pool`, and the pool is not
cleared after a crossing. Every alert past the third re-penalises trust; the eighth quarantines.

---

# GROUP 5 — Confusion matrix computation and MCC validity

**Q41. [A] MCC formula and degenerate-denominator handling.**
`routing.cc:117359-117367`:
`MCC = (TP·TN − FP·FN) / sqrt((TP+FP+ε)(TP+FN+ε)(TN+FP+ε)(TN+FN+ε))`, `ε = 1e-6`.
It does **not** return a guarded 0.0. For A1/A2 it returns 0.0 only because the *numerator*
is 0 (`0·254 − 14·0`). **A degenerate row with a non-zero numerator would return a huge
spurious value** — real latent bug, not triggered by the current data. The offline analyser
(`scripts/run_q1q6_ablation.py`) uses the conventional guarded form returning exactly 0.0, so
the two disagree at the edge; the analyser's is correct.

**Q42. [A] Exact code path for the A1/A2 ground-truth label.**
`routing.cc:117327-117329`:
`malicious = is_malicious_node[v][n] && g_s{1,2}_gt_delay_exceeded[n]`, evaluated per node
(not per cycle boundary) inside `calculate_security_detection_metrics()`. The latch operand is
written only inside the disabled detectors. **This is RC1 in one line.** The event-gated latch
fix *was* applied — it works, but it was placed inside the detector body, which the ablation
switches off.

**Q43. [A] A4: `U_TCAM` during the 34 false-negative blocks.**
Not a threshold-calibration issue. `U_TCAM` exceeds `tcam_util_thresh = 0.213` from
t = 11.998 s and S4 fires 384 times. The 34 FNs exist because Q4 sets `g_disable_s3_s4=1`, so
none of those firings reach `record_detection_event()`. A4's 10 TPs come from the NFA/BTMM
quarantine path (118 NFA crossings), not from S3/S4 at all. **Expected ablation behaviour.**

**Q44. [P] Is the matrix per-block post-dedup or per-raw-window pre-dedup?**
Neither. It is **per-node**, over `total_size = 268`, from sticky latches. 268 is not "between
320 and 192" by coincidence — it is the node count (Q3). No dedup step exists in this path.

**Q45. [A] A7 false-positive breakdown per RSU.**
The arithmetic in the question is right: `TP·TN = 27×56 = 1512 < FP·FN = 173×12 = 2076`, so
MCC < 0 purely because FP dominates. The distribution: of 200 quarantined nodes,
**170 are vehicles (0–199) and 30 are RSUs (200–263)** — 47 % of all RSUs and 85 % of the
quarantine set are vehicles. **Not concentrated at specific RSUs; broadly distributed.** Cause
is RC3+RC4 (unbounded re-penalisation), compounded by a known false-positive source in the
duplication condition: the hash is `sha3_512({fid, packet_ID, current_hop})`
(`routing.cc:121926-121928`), compared against a *changing* `destination` field.
`routing.cc:121932-121934` already concedes "flow destinations change during routing updates
causing false positives"; the mitigation gates the alert on HF-attack-present, which suppresses
it in non-HF runs but leaves it **fully live in A5–A8** — precisely where the witness is the
primary detector.

**Q46. [A] Is the witness hash taken before or after content modification?**
**Neither — the hash is not over packet content at all.** It is
`sha3_512({fid, packet_ID, current_hop})`. Content modification in A5/A6 therefore cannot change
it, and the duplication condition fires on active HF exactly as observed (15,824 / 12,993
crossings). The expectation that A5/A6 should yield zero witness TPs assumed a content-derived
hash; the implementation does not use one. Per `crypto_layer.h:1386-1398`, firing on active HF
is **intended** — an earlier change that scored those as WAP-R false positives was reverted as
misleading, since they are correct detections of real attackers.

**Q47. [A] Class balance per variant.**
Positive fraction: A1 0 %, A2 0 %, A3 11.9 %, A4 16.4 %, A5 14.9 %, A6 59.0 %, A7 14.6 %,
A8 59.0 %. The observation is correct — A1's 254/268 = 94.8 % negative class does suppress MCC.
But note this cuts **both ways**: A6 and A8 at 59 % positive are close to balanced, and A8 still
returns −0.054. So imbalance is not a sufficient explanation for the negative values; RC3/RC4
is.

**Q48. [A] A8: at what cycle do the first TPs appear?**
**t = 10 s — the first second after onset.** Full distribution in Q5. The run length is *not*
structurally inadequate for A8; detection starts immediately and continues throughout. The
76.6 % miss rate is a scoring artefact, not an accumulation-time artefact.

**Q49. [R] Q1/Q3/Q4/Q5/Q6 MCC per variant in one table.**
Only Q4 exists. **Strong recommendation: do not build this table from the current code.** Under
RC2 every config shares the ungated BTMM→quarantine channel, so the monotonicity test
("Q6 > Q5 > Q3/Q4 > Q1") would compare six measurements of the same contaminating mechanism and
could show non-monotonicity for reasons having nothing to do with component contribution. The
table becomes meaningful after RC1–RC3 are fixed.

**Q50. [R] Macro-averaged MCC per config; is Q6 ≥ 0.70?**
Same blocker as Q49, and the stakes are higher because this is the stated go/no-go figure. The
Q4 macro-average is 0.085 — but that number measures the harness, not the system. **This
applies symmetrically: the variants that look good (A4 = 0.444, A6 = 0.282) are exactly as
untrustworthy as the ones that look bad.** We are not offering Q4 as evidence of system quality
in either direction.

---

## Summary of tags

| Tag | Count | Questions |
|---|---|---|
| **[A] Answered** | 27 | 1, 3, 4, 5, 6, 8*, 10, 13, 14, 19, 23, 24, 26, 28, 29, 31, 32, 35, 36, 40, 41, 42, 43, 45, 46, 47, 48 — plus Diagnostics 1–4 |
| **[P] Premise invalid** | 4 | 2, 7, 37*, 44 |
| **[B] Blocked by RC1–RC4** | 7 | 11, 12, 21, 22, 27, 33, 34 |
| **[R] Needs run/instrumentation** | 12 | 9, 15, 16, 17, 18, 20, 25, 30, 38, 39, 49, 50 |

Total 50.

\* Q8 is answered as a falsifiable prediction; Q37 is part-premise-invalid, part-needs-run.

**Nothing in Groups 1–5 required a new simulation to reach these answers.** The four items most
worth adding before the next round are: a detection-**source** tag on
`record_detection_event()` (Q38), a paired `f_unauth ∧ ¬b_batch` counter (Q34), a
`CopyVerify_d′` counter (Q25), and per-cycle attacker/zone counts (Q9, Q20, Q30).
