# Every remaining lever on MCC — ranked by evidence (2026-09-01)

Baseline: M1 = **0.3836** (Q6, arm A, `score`/D_RSU, M=1, 300 s, 60%, seed 1).
All figures from `scripts/m1_local.py`; arm-to-arm valid, absolute not comparable
to the historical 0.2721.

Grouped by how well established each is. **Nothing below is speculative about
whether the defect exists** — the open items are open on *magnitude* or on a
*decision*, not on whether there is something to fix.

---

## Tier 1 — measured, fix written, cost ~0

### 1a. Persistence M — **free, biggest confirmed single gain**
`detector_windows.h` already emits `score_cycles`; nothing needs rebuilding.

| construction | M=1 | best | at M |
|---|---|---|---|
| `score` (D_RSU) pooled | 0.3836 | **0.4831** | 3 |
| `score_primary` pooled | 0.6187 | **0.6870** | 3 |
| mean A5–A8 (`score_primary`) | 0.6252 | **0.6971** | 3 |

**Use M=3.** Do *not* use the pooled-optimal M=8: it maximises pooled MCC by
collapsing A1–A4 (0.5818 → 0.3988) and leaves some variant at 10% DR. Pooled MCC
hides that because it aggregates one confusion matrix rather than per-variant
performance — MCC is not decomposable across strata.

**Better still: per-variant M in calibration, variant-blind in application** (the
θ pattern). The families want opposite things — A1–A4 peak at M=1, A5–A8 at M≈8 —
so any single global M is a compromise by construction.

### 1b. Observer→suspect attribution — `--dw_mark_suspect`
Written, awaiting rebuild. `dw_mark_rsu()` marks the *observer*, so an RSU that
correctly detects a malicious neighbour scores 1 against its own truth 0. The
2026-08-22 fix corrected this for `score_primary` only.

| column | non-attacker share of A5–A8 FPs |
|---|---|
| `score` (observer) | **44.7%** (39.3–48.9%) |
| `score_primary` (suspect) | 0–4.9% |

Measurement-only: `dw_mark_rsu()` writes only `g_dw_rsu_fired[]`; `D_RSU` is
untouched so BC.Write/BTMM/quarantine are unaffected.

### 1c. LSTM high-confidence gate — `--require_lstm_high_conf`
Written; **arm C is measuring it now**. The codebase already refuses soft
LSTM-only hits for the BTMM trust gate (`lrad.h:571`) and the per-node confusion
matrix (`lrad.h:628`) but still admits them to the score M1 reports.

---

## Tier 2 — defect confirmed, magnitude not yet measured

### 2a. `d_div` / `a_tp` are broadcast globals
`std::set`/`uint32_t` with **no RSU key** (`crypto_layer.h:869/889/890`), vs
`std::map<uint32_t,uint32_t> g_lstm_ranom_count`. Independently reproduced:
**100.0%** of cycles have every RSU reporting an identical `d_div`/`a_tp`
(`r_anom` control: 3.0%). AUC 0.500 within a (pct, seed, cycle) stratum ⇒ zero
per-node information, and a precision ceiling of label prevalence by construction.

- **cheap:** drop both from `FEATURES`, re-run `preprocessor.py` (27 s) + AB3
- **real:** per-RSU accumulators, as `g_lstm_ranom_count[r]` already does —
  needs a dataset re-run
- **watch:** 11 → 9 features breaks `export_weights_cpp.py`'s hardcoded
  assertion and `lstm_inference.h`'s feature-count abort. Both fail loudly.

### 2b. `is_spike` label contamination
`preprocessor.py` added `d_div > 1` to the `is_spike` OR on 2026-08-09. Being
broadcast, it labels **every** RSU in an HF cycle attack-active. The code's own
comment flags the risk and sets the revisit condition — which is now met.

Scope: `is_spike` → **`y_binary`** → `local_trainer.py`'s hyperparameter
selection ⇒ **`hparams.json` is contaminated**. **`y_indep` is clean** (built from
`hf_send_gt`/`std_send_gt`/`tcam_send_gt`), so the classifier-head and §6b
per-variant-θ results are not invalidated by this.

### 2c. `cls_theta` does not transfer offline → in-sim  ← *new, and large*
Calibrated offline for **FPR ≤ 1%**; in-simulator the same thresholds fire on
**21.8%** of windows — identical to the autoencoder's 21.8%. This is why arm B
moved M1 by −0.003 despite a real offline gain (A1 DR 2.7% → 11.3%).

**Fix: recalibrate the per-RSU thresholds on in-simulator scores**, not on the
preprocessed split. This is probably the single largest untapped LSTM-side lever,
and it is cheap — one instrumented run to collect in-sim P(attack) per RSU, then
re-derive `cls_theta.json`.

### 2d. A3/A4 recall
DR 57.7% / 70.8%, FPR 6.0% / **0.0%**, flat across every M. Worth **+0.1108**
pooled if recall is recovered at unchanged FPR. Three hypotheses tested and
**rejected**: predicate mismatch (predicates coincide), endorsement failure
(`endorsement_rate=1.0` was a vacuous empty-pool default), detection never
computed (`ComputeTcamDetection` runs per-cycle from `routing.cc:118055`).
Remaining: S4's utilisation threshold not crossed as the attack matures, or
one-cycle staleness in `g_tcam_flag_s3_last`.

**Blocker to diagnosing it: A1–A4 produce zero `tcam_*` diagnostic files** (A5–A8
produce two each) because the snapshot dumper is scheduled only on `first_ever`
from `tcam_install`/the passive path, never from `tcam_install_malicious`. Fix
that first — it is why this has been hard to see.

---

## Tier 3 — needs a decision, not a patch

### 3a. Latched detector vs event-gated truth (HF)
Truth is `node_lvl && g_dw_activity_last[r]`, and for A5–A8 that gate is the
per-cycle delta of `hf_send_gt`. S5–S8 fire on *persistent compromise state* —
`s5_detection.h` says so: "every [S5] line is evidence of an ongoing compromised
state, not of a discrete send event." Opposite temporal semantics, scored across
the gap. **55.3% of A5–A8 `score` FPs are dormant declared attackers** (100% of
the `score_primary` FPs).

**The question: does a persistently compromised but momentarily quiet RSU count
as a positive?** Persistence M is an empirical proxy; deciding it explicitly
makes truth and detector agree by construction rather than by tuning. This is the
same question the supervisor's latch thread is circling — settle it once for both.

### 3b. S5–S8 oracle gate — *raises* FPR, do not use to lower it
All four gate on `active_/passive_hf_malicious_nodes[prev_sender]`, written by
the attack injector. `eq:sig_s5`'s five conjunctions do **not** include it.
Removing it exposes the first real HF FPR — a truth-telling change that will make
numbers worse, and must not be conflated with an FPR reduction. Until resolved,
**do not report S5–S8 precision as a detector property**, and do not present
`score_primary` as an achievable ceiling — it is attacker-identity-aware.

---

## Untried, plausible

- **`train_cls_head.py --unfreeze`** — end-to-end. §6a's diagnosis was that the
  frozen autoencoder latent, not the head, is the binding constraint; this is the
  direct test and it is minutes of GPU.
- **A8 PDR 30.5%** vs ~64% for every other variant. Unexplained.
- **M7 units** — `o_crypto_bytes_pkt` = 209,427 is not per-packet (ML-DSA-87
  sigs are ~4.6 kB). Do not report M7 until confirmed.

## Dead ends — measured, do not revisit

| lever | result |
|---|---|
| per-RSU M (FPR-target) | 0.3344 — worse than global |
| per-RSU M (MCC-optimal **ceiling**, same-data fit) | 0.4224 — still below global M=8's 0.5539 |
| longer warm-up | FPR is flat across the run (61%→53%), no startup transient |
| classifier head as shipped | −0.003 (see 2c — the head is fine, its calibration is not) |
