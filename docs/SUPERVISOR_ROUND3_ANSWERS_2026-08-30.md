# Round-3 answers — 2026-08-30

Responses to the supervisor's 2026-08-30 instructions. Three of the four asks
are answered from code/existing data; the fourth (item 7 persistence) is built
and has an early result, with the full sweep pending runs.

**Machine split discovered while doing this, and it shapes who can do what:**
this laptop holds `lstm_training/` data for **Attack 0-4 only** — searched
exhaustively, zero A5-A8 CSVs anywhere under `/home/nipuni`, and
`test_meta.npy` contains only `attack_v` 0-4. A5-A8 data lives on HPC. So the
two empirical A5 checks below must run there; everything A1/A2 runs here.

---

## Item 5 — what A7's 0.963 is scored against: ANSWERED, trustworthy as-is

**It is not the pipeline finding (b) broke.** `scripts/run_q1q6_ablation.py`'s
`analyse()` reads TP/FP/TN/FN via `read_confusion()` from the
`MOBIGUARD_*.csv` results file (columns 13-16). Those counters are written by
`routing.cc`'s own security-metrics path from `is_malicious_node[]` /
`is_detected_node[]` — the simulator's ground truth.

Verified: `run_q1q6_ablation.py` contains **zero** references to `is_spike`,
`y_bin`, or `test_y.npy`. It never touches the LSTM preprocessing pipeline.

The witness-native figures (TP_W/FP_W/FN_W, WAP precision/recall) are more
direct still — read from the witness's own counters in the same CSV.

**Conclusion: Q4R's A7 = MCC 0.963 / DR 96.1% / 0 FP needs no re-scrutiny when
finding (b) is fixed.** The two live in different pipelines.

---

## Finding (b) — how the cleaner label is built, and at what granularity

`y_indep`, built in `lstm_pipeline/src/preprocessor.py:235-238`:

```python
_inj = max(hfgt[i:i+window].max(),      # hf_send_gt   (A5-A8)
           stdgt[i:i+window].max(),     # std_send_gt  (A1/A2)
           tcamgt[i:i+window].max())    # tcam_send_gt (A3/A4)
yi_list.append(1 if (av > 0 and _inj > 0) else 0)
```

**Granularity: a per-cycle EVENT counter, OR-ed (`max`) across the 10-cycle
window.** Not a persistent state flag. A window is positive iff the injector
fired in *at least one* of its ten cycles.

### The connection to item 9 — structurally, YES, same signal

This matters and does not need the empirical run to establish: for the HF
variants `y_indep`'s source is `hf_send_gt` — **the exact signal item 9 just
proved is too coarse**. `y_indep` is literally the window-level OR of item 9's
per-cycle gate.

So the two problems share one root: *window truth derived from a
send-instant event counter, while the detector it is scored against responds
to a persisting state.* They are the same defect seen at two granularities,
which argues for solving them together, as the supervisor suspected.

### The cross-check that still needs HPC

Required: A5's `y_indep` per-window positive rate vs S5's 45-53% per-cycle
firing rate. **Cannot run here** — no A5 `lstm_training` CSVs on this machine.

Prediction to test, from item 9's measured ~10% per-cycle `hf_send_gt` rate: if
cycles were independent, a 10-cycle OR gives `1-(1-0.10)^10 ~= 65%` per window,
against S5's per-window rate of essentially 100%. A *narrowed* gap but not a
closed one. If the measured value lands near 65% the two problems are the same
defect at two scales; if it lands near 100% the window-level OR already
launders the coarseness away and only item 9 needs fixing.

---

## Item 9 — which S5 condition is true: ANSWERED FROM CODE

**The supervisor's working guess is correct, and it is provable from the
firing rule rather than inferred from a trace.**

`s5_detect()` (`scratch/s5_detection.h:101-190`) conjuncts:

| # | condition | nature |
|---|---|---|
| 1 | `!bc_query_flowmod(base_flow_id)` — FlowMod never endorsed | **persistent** property of the installed rule |
| 2 | `active_hf_malicious_nodes[prev_sender]` | **persistent** — set once in `hf_declare_malicious_rsus()`, never cleared |
| 3 | `mldsa87_verify_copy_content(...)` fails | per-packet, deterministic given 1-2 |
| 4 | `!stark_verify_hop(...)` | per-packet, deterministic given 1-2 |

Verified: `active_hf_malicious_nodes[mal_node] = true` is assigned once
(`hf_attack_helper.h:642`); the injector runs **once** at `attack_start_time`
(`routing.cc:144266` — "injects the attack only once"); the array is never
reset anywhere.

So **S5 fires on an ongoing compromised state** — an unendorsed rule installed
at a node flagged compromised — every time a packet traverses it. `hf_send_gt`
increments only at the instant a duplicate is *scheduled*. S5 firing more often
than `hf_send_gt` is therefore **correct detection of a persisting bad state,
not a bug in S5**.

**Implication, matching the supervisor's own conclusion:** the replacement must
reflect *state persisting over time*, not a narrower event. The natural
candidate already in the code is a **latched** `hf_send_gt` — "this RSU has
scheduled at least one hidden duplicate at any point up to this cycle" —
which turns the send-instant event into the persisting-compromise signal S5
actually responds to. That is a one-line change from a per-cycle delta to a
cumulative test, and unlike a guessed new signal it is derived from the same
counter already trusted for ground truth.

Empirical per-condition trace still worth running on HPC to confirm 3 and 4
behave as expected in the disagreeing cycles, but it cannot change conclusion
1-2, which are structural.

---

## Item 7 — persistence build: BUILT, early result strong, sweep pending

Implemented as additive CSV columns rather than a behaviour change, so **no
existing number moves and the threshold M can be swept offline from one run
per configuration instead of one run per M**:

- `detector_windows.csv` gains `score_cycles` and `score_primary_cycles` —
  how many DISTINCT CYCLES inside the window the detector fired in.
- `score` / `score_primary` keep their exact OR semantics.
- A window is positive under persistence-M iff the count column `>= M`
  (M=1 reproduces today's behaviour exactly).

### Early result, zero-attack 300 s seed 1 (existing log, OBU rows)

Benign false positives are overwhelmingly **single-cycle**:

| distinct cycles fired | share of fired windows |
|---|---|
| 1 | 88.8% |
| 2 | 10.1% |
| >=3 | 1.1% |

| M | FP windows | window FPR |
|---|---|---|
| 1 (today) | 1985 | 17.11% |
| 2 | 215 | **1.85%** |
| 3 | 22 | **0.19%** |
| 4 | 3 | 0.03% |

Attack windows persist longer than benign ones — 10.8% of A1 fired cells reach
>=3 cycles vs 1.1% benign, a **10x separation at M=3**.

**Caveat, stated because it decides the recommendation:** those attack-side
figures are keyed by the log's receiving node, and mix true positives with the
attack run's own false positives. They are *not* recall. Real recall needs the
RSU-attributed `score_primary_cycles` column from a fresh run. An earlier
version of this analysis that counted *firings* rather than *distinct cycles*
showed only ~1.3x separation and would have been misleading — the persistence
gain is specifically about spread over time, not firing volume.

### Runs still required for the side-by-side the supervisor asked for
Zero-attack + A1@60% + A2@60%, default threshold, with the new count columns;
then sweep M offline. Queued behind the currently-running validation.

---

## Also on item 7: a separate root cause found before this round

Recorded in `SESSION_README_2026-08-29.md` and commit `1448111`. 94.8% of
zero-attack false positives fall in the 50-300 ms handoff-jitter band that
`s1_detect_packet()` injects itself, and that band strictly contains the 80 ms
A1/A2 inject — which is why no threshold could separate them and why the
best-effort arm (threshold ~151 ms, above the 85 ms signal) lost recall.
Suppressing accusations on packets already known to carry handoff jitter
measured 18.86% -> 0.03% window FPR at 95.55% A1 recall on seed 1
(`--s1_suppress_handoff_fp`, default OFF). 5-seed + A2 validation running.

**These two are complementary, not competing:** the handoff fix removes the
dominant *source* of false positives; persistence-M filters whatever isolated
ones remain. They can be measured independently and combined.

**Limitation to weigh on the handoff fix:** suppressing during handoff cycles
creates an evasion window for an attacker timing delays to coincide with
handoffs. Handoffs are controller-mediated so cannot be manufactured at will,
but the exposure is real and is the source of its 3.6-point recall cost.
Persistence-M has no equivalent exposure, which may make it the safer of the
two if it holds up on recall.
