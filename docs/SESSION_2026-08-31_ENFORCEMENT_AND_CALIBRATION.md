# Session record — 2026-08-30/31
## Quarantine enforcement, HF label definition, threshold calibration

Machine: the one holding the A5–A8 LSTM dataset (`/home/sinhala_llm/G_13/`).
All numbers below are measured on this machine, seed 1 unless stated.

---

## 0. Headline outcomes

| # | Outcome | Status |
|---|---|---|
| 1 | **Quarantine had no enforcement.** `g_quarantined[]` was write-only; ~90% of quarantined RSUs kept attacking for 286+ s. | **Fixed and validated — 0 post-quarantine firing, all 4 variants** |
| 2 | Finding (b) + item 9 are **one problem**; the latched signal fixes both | Answered, code ready (default OFF) |
| 3 | Item 7 persistence swept; **handoff fix alone (M=1) wins** | Done, 5-seed |
| 4 | A6's 78% FPR is **calibration, not labelling** | Root-caused |
| 5 | **M4 was measuring the wrong thing** in three separate ways | Fixed (default OFF) |
| 6 | The **autoencoder is the accuracy bottleneck**, not features or federation | Diagnosed |

---

## 1. Environment problems found first (both silent)

**The NS-3 tree held copies, not symlinks.** [CLAUDE.md](../CLAUDE.md) documents
`scratch/` as symlinked into the build tree. It was not: six files were 17 h
stale and the compiled binary predated all three commits the work depended on.
Building as instructed would have produced 9-column `detector_windows.csv` with
no handoff fix — looking like "the fix does nothing" rather than a build error.

Synced, then **restored the symlinks** and proved propagation by editing the
repo file and confirming waf recompiled. (`touch` proves nothing — waf uses
content hashes, not mtimes.)

**Build profile verified at every level**, not just `_cache.py`:
`BUILD_PROFILE=optimized`, `CXXFLAGS` carries `-O3`, `routing.cc`'s own TU
compiles at `-O3`, and live processes map 39 optimized / 0 debug libraries.

**Speed on this machine:** 5.6 wall-s/sim-s solo, ~17 averaged across 10
concurrent, degrading to ~44 late in a 300 s run as flow/TCAM state accumulates.
A 300 s run is *not* 15× a 20 s run — budget accordingly.

---

## 2. Priority one — quarantine enforcement

### Scoping

- **RSU side (`eq:quarantine`) was completely unenforced, for every attack type.**
  `g_quarantined[]` is written at `crypto_layer.h:1342` and read *only* by its
  own double-set guard. No enforcement point existed anywhere.
- **Vehicle side (`eq:local_quarantine`) is wired but only defers.**
  `fwd_hold_remaining()` *is* consulted at `routing.cc:121672`, but it adds a
  delay of at most `T_HOLD` = 0.1 s and the packet still goes. It also defaults
  OFF. **This matches the paper** — `eq:local_quarantine` is defined as a hold
  pending RSU confirmation, never as isolation. Not a defect.
- `t_quarantine[]` **is** read — only to compute M4.

### The measurement that made it concrete

Control arm (enforcement off), full 300 s runs:

| variant | quarantined RSUs | kept attacking | post-q cycles | **max lag** |
|---|---|---|---|---|
| A5 | 43 | 39 | 1,329 | **286.9 s** |
| A6 | 48 | 44 | 5,210 | **286.8 s** |
| A7 | 44 | 38 | 1,348 | **286.5 s** |
| A8 | 46 | 41 | 3,618 | **286.7 s** |

Attacks continued for the *entire remaining run*. This is total
non-enforcement, not a slow drain — the "already in flight" allowance is not
needed.

### The fix

Behind `--enable_quarantine_enforcement` (default 0, so all prior results
reproduce):

1. `quarantine_blocks()` helper — `crypto_layer.h:489`
2. Guards at both hidden-duplicate sites — `routing.cc:121541`, `:121636`
3. Guard in `tcam_install_malicious`, above the ground-truth counter
4. **Origin-based drop** implementing `eq:quarantine` as written — "all RSUs
   drop flows originating from *v*" — at the relay path, emitting
   `[QUARANTINE-DROP]`

**Both mechanisms are needed and are not alternatives.** `eq:quarantine` drops a
quarantined node's *own* traffic, but an HF attacker duplicates *other* nodes'
flows — so origin-dropping alone would not have stopped the attack at all. The
send-side guards stop the attack; the origin drop implements the equation.

**One bug found and fixed during validation:** the first guard tested
`current_hop` only. For DP variants (A6/A8) `current_hop` is a *vehicle relay*,
which never crosses the trust threshold, so duplicates still went out while
`hf_send_gt` attributed them to the quarantined covering RSU. A5/A7 went to 0;
A6/A8 leaked 50 and 137 cycles. Fixed by also testing
`hf_gt_attribution_node(current_hop)`.

### Validation — ask #3 satisfied

| variant | enforcement ON | control OFF |
|---|---|---|
| A5 | **0 of 46 RSUs, 0 cycles** | 39 of 43, 1,329 |
| A6 | **0 of 45, 0** | 44 of 48, 5,210 |
| A7 | **0 of 44, 0** | 38 of 44, 1,348 |
| A8 | **0 of 42, 0** | 41 of 46, 3,618 |

8 runs, all `t=299.901`, all exit 0, zero helper-path errors.

### Cost — small, and partly negative

| variant | PDR ON/OFF | latency ON/OFF | UCR ON/OFF |
|---|---|---|---|
| A5 | 64.00 / 64.41 | 23.69 / 23.27 | 0.71 / 0.72 |
| A6 | 59.55 / 63.33 | **22.75 / 25.57** | 0.85 / 0.86 |
| A7 | 62.63 / 63.88 | 23.65 / 23.61 | 0.72 / 0.72 |
| A8 | 26.76 / 30.48 | **21.38 / 24.61** | 0.86 / 0.87 |

PDR costs 0.4–3.8 points; latency *improves* on the DP variants. No partition.

---

## 3. M4 / `eq:l_mit` — three defects

1. **Not a mean of L_mit.** `routing.cc` accumulated a per-cycle mean over a
   growing node set. A5 control: true mean 2,697 ms reported as **6,937 ms**.
2. **`t_onset` was the wrong timestamp** — `attack_start_time` for every
   *declared* node, not when that node first acted. Correcting it alone cuts
   L_mit by **1.5–2.5×**.
3. **Nodes quarantined without ever acting were averaged in as slow
   mitigations.** Under enforcement that is 13–34 RSUs per variant (vs 3–6
   without) — and it is *the mitigation benefit*, inverted into a penalty.

Reported vs corrected (ms):

| variant | arm | reported | **corrected** | blocked before acting |
|---|---|---|---|---|
| A5 | ON | 9,605 | **1,684** | **34** |
| A5 | OFF | 6,937 | **1,121** | 4 |
| A6 | ON | 5,174 | **2,110** | **23** |
| A6 | OFF | 4,975 | **5,214** | 3 |
| A7 | ON | 10,689 | **3,036** | **30** |
| A7 | OFF | 9,466 | **2,373** | 6 |
| A8 | ON | 14,067 | **5,014** | **13** |
| A8 | OFF | 14,099 | **10,653** | 3 |

**L_mit must be reported beside the blocked count or it inverts the story.**
A5/A7 look *worse* under enforcement only because the easy cases left the
denominator — 34 of 46 A5 attackers never acted at all.

Fixed in-sim behind `--enable_corrected_lmit` (default 0). Verified:
corrected mode yields `avg_mit_ms == cur_mit_ms`, i.e. accumulation gone.

---

## 4. Finding (b) and item 9 — one problem

`y_indep` is a **per-cycle event counter OR-ed across the 10-cycle window**
(`preprocessor.py:235-238`), not a state flag. (`hf_send_gt` is a *count* 0–5,
booleanised by `_inj > 0`.)

Cross-check, A5, five seeds:

| granularity | label | S5 | gap |
|---|---|---|---|
| per cycle | 7.05% | 45–53% | ~7× |
| per window | 31.99% | **56.33%** (measured) | ~1.8× |

**Gap present → connected → fix together.** Item 9 is the supervisor's branch 1:
across 51,466 traced firings, conjunctions 1–2 held every time and 3–4 were true
on 100%; only conjunction 0 ever filters (0.47%). S5's conditions are genuinely
true — correct detection of ongoing compromised state.

Latched signal, A5@60% seed 1:

| | attacker RSUs | benign RSUs |
|---|---|---|
| S5 (measured) | 92.44% | 0.00% |
| label, latched | 94.74% | 0.00% |
| label, per-event | 52.03% | 0.00% |

Per-window agreement with S5: **75.46% → 94.07%**; disagreements 904 → 75.

Implemented in `preprocessor.py` as `HF_LATCHED_LABEL` (default OFF,
`MOBIGUARD_HF_LATCHED=1`). **Derived offline from `hf_send_gt` — no simulator
change, no re-run of the 14,400-file dataset.** Verified: OFF reproduces the
stored labels byte-for-byte (3,648 windows, 0 mismatches).

---

## 5. Item 7 — persistence swept, fix alone wins

M=1 reproduces the published k·σ figures exactly (FPR 18.86%, A1
TP=802/FP=684/FN=7/TN=2219), validating the tool.

| approach | zero-attack FPR | A1 recall | MCC |
|---|---|---|---|
| baseline k·σ | 18.86% | 99.13% | 0.637 |
| persistence M=3 | 0.06% | 79.11% | 0.721 |
| **handoff fix (M=1)** | **0.03%** | **95.55%** | **0.8395** |
| fix + M=2 | 0.00% | 84.80% | 0.8392 |

5-seed zero-attack FPR with the fix: **0.022% ± 0.014%**. A2 recall 97.53%.
Persistence does not beat the fix alone — MCC is a dead heat and M=2 costs 10.8
points of recall.

---

## 6. Calibration — A6, and the ceiling

**A6's 78% FPR is calibration.** A5–A8 shared one pooled `theta_hf` = 0.7895,
but A6's median window scores **1.452** — above the threshold, so 85.5% of
windows are flagged against 42.6% real positives.

**Why:** A6's "quiet" windows are not quiet. Against the true benign floor:

| pool | median score | vs benign |
|---|---|---|
| A0 benign | 0.006 | — |
| A5 quiet | 0.279 | 47× |
| A8 quiet | 0.436 | 73× |
| **A6 quiet** | **0.984** | **164×** |

A6 is data-plane HF: it perturbs traffic network-wide, so windows correctly
labelled negative for a given RSU still look anomalous.

**The supervisor's `theta_HF^(k) = max` construction was implemented**
(`calibrate_hf_theta_pervariant.py`). Binding variant: A6 at 34/64 RSUs, A5 11,
A8 8, A7 5, 6 fallback — **not always A6**. But it costs A5/A7 heavily
(DR 61.8% → 10.5%), because they inherit A6's inflated floor. There is a genuine
conflict: one θ per RSU cannot serve A5/A7 and A6 together.

**Caveat:** μ + 3.5σ lands *above the 99th percentile* of A6's own calibration
pool (2.279 vs p99 1.576). μ + 2σ was the best rule tested.

---

## 7. The real accuracy ceiling

| approach | AUC | honest MCC |
|---|---|---|
| Autoencoder (currently reported) | 0.82 | 0.45–0.53 |
| **Classifier head (already in repo)** | **0.966–0.983** | 0.55–0.81 |
| Supervised GBM (diagnostic) | 0.943–0.953 | 0.749 untuned |
| **S5 rule detector** | — | **0.897** |

- **Federation is not the bottleneck**: global 0.8221 vs local 0.8209 AUC.
  BRFA-v2 costs nothing.
- **Features are not the bottleneck**: a GBM on identical windows reaches 0.95.
- **The autoencoder is.** `train_cls_leakfree.py` and
  `global_clshead_leakfree.pt` already exist and reach AUC 0.966–0.983.
- **The rule detector beats every LSTM variant.** A7's published 0.963 is a
  *system-level* number, not the LSTM's.

**0.95 does not live in the LSTM.** It lives in the system-level confusion
matrix, where A7 already demonstrates it.

---

## 8. Traps identified — do not do these

- **Do not chase MCC via label redefinition.** Compromised-state ground truth
  reaches A6 MCC 0.975, but AUC is *flat* (0.853 → 0.837): the gain is class
  rebalancing, not detection. For S5 it is outright circular — S5 gates on
  `active_hf_malicious_nodes`, so FP=0 is structural.
- **Do not "fix" the injector** so perimeter RSUs fire. The 17 silent RSUs are
  grid-perimeter nodes with 157–200× less traffic in *every* config including
  benign; 97.7% of their cycles have zero vehicles in range. `hf_send_gt = 0` is
  correct and S5 agrees by staying silent.
- **Do not report the per-variant θ table as deployed performance.** It implies
  the detector knows which attack it faces.
- **Do not rebuild while simulations run** — overwriting a running executable.

---

## 9. Artifacts produced

| path | purpose |
|---|---|
| `scripts/quarantine_enforcement_report.py` | validation table, M4 ON/OFF, cost |
| `scripts/corrected_mitigation_latency.py` | offline corrected L_mit |
| `lstm_pipeline/src/calibrate_hf_theta_pervariant.py` | per-variant/per-RSU θ, max rule |
| `lstm_pipeline/src/masked_eval.py` | traffic-masked both-ways evaluation |
| `docs/supervisor_message_2026-08-30_round4/5*.txt` | supervisor correspondence |

New flags, **all default OFF**: `--enable_quarantine_enforcement`,
`--enable_corrected_lmit`, `MOBIGUARD_HF_LATCHED=1`.

---

## 10. Next steps

**Blocked on supervisor**
1. Adopt the latched label → then rescore A5–A8 (code ready, default OFF)
2. Whether per-variant θ is a diagnostic table or the deployed number
3. Whether legitimate forwarding by a quarantined RSU should also be blocked
   (would change PDR/latency for every variant — not done, deliberately)

**Ready to run, unblocked**
4. Decision 3's **density sweep** (0/20/40/60%) — untouched
5. The **handoff-fix mechanical writeup** — is it a new component or a corrected
   implementation of `eq:mobility_baseline`? Determines paper treatment
6. **Item 11 A8 rise-and-fall recheck** — the decline cannot have come from
   mitigation, since mitigation did nothing
7. Switch reported LSTM from autoencoder to the **existing classifier head**
   (+0.15 AUC, no new method), then retrain it on latched labels

**Known remaining gap**
8. `tcam_install_malicious` guards only `node_id`; **A4's attacker is a vehicle**,
   so the same class of leak the DP fix closed for A6/A8 may remain for A4.
   Untested — A3/A4 were not in this validation set.

**Do not run**
9. The Q3–Q6 grid, until the label decision and A6 are settled. Q3/Q6 are the
   only configs with LSTM on, so they are the *most* exposed to a rescore.
