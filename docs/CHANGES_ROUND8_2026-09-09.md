# Round 8 code changes — what changed, why, and what it measured

Covers everything committed for supervisor round 8. Paths in this commit are the
**HPC forms** (`/home/sdvn_hidden_attacks/ns3_g13/...`); see "Path handling" at
the end.

---

## 1. Q5 — the S5–S8 oracle gate, REMOVED

**Files:** `s5_detection.h`, `s6_detection.h`, `s7_detection.h`,
`s8_detection.h`, `crypto_layer.h`

**What was wrong.** Each of the four HF signatures early-returned unless
`active_/passive_hf_malicious_nodes[prev_sender]` — *the attack injector's own
assignment array* — confirmed the sender was a true attacker. The signature was
therefore structurally incapable of accusing an innocent node, so every
precision figure it produced was guaranteed by construction rather than
measured. `eq:sig_s5`'s conjuncts reference no such oracle. Same class of defect
as training on a label derived from an input feature; it survived this long only
because it lived in C++ control flow rather than a training script.

**What replaced it.** Each signature now evaluates the conjunct the gate stood
in for — `b_hop(u) = 0` via `stark_verify_hop()`, which compares the receiving
hop against the `signed_next_hop` embedded at sign time and consults no ground
truth. A benign packet on its intended path passes and the signature stays
silent; a duplicate diverted to an eavesdropper fails and evaluation continues.
The signatures **can now fire on an innocent node**, which is what makes their
precision a measurement.

`--hf_oracle_gate=1` restores the legacy gate for A/B only. It must never
produce a reported number.

**Measured** (60%, seed 1, 90 s — diagnostic length, error gate 0 on all 8):

| variant | gate ON | gate OFF | false positives |
|---|---|---|---|
| A5 | P 1.0000 · R 0.9327 · F1 0.9652 | P 0.7335 · R 0.9615 · F1 0.8322 | **0 → 218** |
| A6 | P 1.0000 · R 0.8798 · F1 0.9360 | P 0.8127 · R 0.9249 · F1 0.8652 | **0 → 156** |
| A7 | P 0.9529 · R 0.9071 · F1 0.9294 | P 0.7383 · R 0.9631 · F1 0.8359 | 28 → 213 |
| A8 | P 1.0000 · R 0.8115 · F1 0.8959 | P 0.8471 · R 0.8702 · F1 0.8585 | **0 → 115** |

Three of four had **exactly zero** false positives with the gate on. Recall
*improves* in all four once it is out: the gate never bought detection
capability, it only suppressed precision's denominator.

---

## 2. Item 3 — the richer per-RSU D_div

**Files:** `crypto_layer.h`, `lstm_logger.h`

The approved definition counts, per RSU, **how many distinct source vehicles
have a destination set exceeding their authorized set** — not how many
destinations that RSU saw. The simple per-RSU form collapses to
`1 + 1[r_anom > 0]`; the richer one distinguishes one loud attacker from several
quiet ones, which `R_anom` conflates.

Most of the machinery already existed from the smoke test: `ddiv_smoke_record()`
was wired at the three MacRx sites through `hf_gt_attribution_node()`, and
`ddiv_smoke_count()` already computed the quantity. Both were gated behind
`--ddiv_smoke_test` and only *logged*, never feeding the feature.

**Change:** `lstm_ddiv_atp_per_rsu` was hoisted above the helpers so they can
gate on it; recording and counting now run for the production feature; and
per-RSU `D_div` reads `N_div(r)` instead of `|dest_set(r)|`.

**Status:** compiles and is committed, but **not yet validated end-to-end** —
see "Outstanding" below.

**A_tp (Q4, option two) needed no work** — per-RSU A_tp was already implemented
(`g_lstm_flow0_legit_by_rsu` / `_total_delivery_by_rsu`) behind the same flag.
The earlier note that `fade_*_count` was "still flow-keyed" pointed at the wrong
target: `crypto_layer.h:973` states those counters are explicitly unusable here.

---

## 3. The confidence multiplier — RETIRED and recalibrated

**Files:** `lstm_logger.h`, `lrad.h`, new `lstm_pipeline/src/calibrate_hc_theta.py`,
new `lstm_pipeline/hc_theta.json`

**What was wrong.** The high-confidence tier was `score > LSTM_HC_MULT *
theta_used` with `LSTM_HC_MULT = 2.0`, tying its strictness to each RSU's own
theta. Per-RSU theta spans **0.0064 … 8.30** (64 RSUs, median 0.134), so the bar
ranged 0.013 … 16.6 — a ~1000× spread tracking nothing but theta's scale.

Note the score is an **unbounded reconstruction error** (measured range
0.0002 … 16.64), not a bounded probability. Measured on 40,023 benign
validation windows:

| gate | benign fire rate |
|---|---|
| detection (`score > theta`) | 9.52% |
| **old HC tier** (`score > 2·theta`) | **4.20%** |
| **new HC tier** (`score > theta_HC`) | **0.10%** |

A 4.20% benign rate on the tier permitted to reach BTMM trust evaluation is a
live contributor to indiscriminate quarantine.

**Fix.** Not an offset — that would still be theta-scale-coupled. The tier gets
its own absolute threshold, calibrated like the main one but stricter: a **true
empirical 99.9th-percentile cut** on the benign validation split, giving
`theta_HC = 12.628`. A true percentile rather than the Gaussian `mu + z·sigma`
used for theta/theta_HF, because `val_X.npy` is on disk and the tail can be
measured directly — which matters at the 99.9th percentile of a heavy-tailed
distribution.

**`calibrate_hc_theta.py` must be re-run after every retrain** — theta_HC is a
property of the trained model, not a constant.

---

## 4. A false comment corrected

**File:** `crypto_layer.h:839–844`

The covering-RSU proxy was justified with *"because vehicles never cross the
trust threshold."* Measured, counting distinct `[TRUST-QUARANTINE]` node ids:

| | A5 | A6 | A7 | A8 |
|---|---|---|---|---|
| vehicles quarantined | 199/200 | 199/200 | 173/200 | 167/200 |

128 and 125 even with the legacy gate still in. Vehicles cross it routinely. The
proxy may still be right for other reasons — it is what truth's latch is indexed
on — but any reasoning resting on that premise needs re-deriving.

---

## 5. Analyses committed as docs (no code)

- `ITEM4_LATCH_RERAISE_2026-09-07.md` — the approval was given without the
  −0.326 measurement; re-raised.
- `ITEM4_REMEASURE_AND_OPTION_B_2026-09-07.md` — the re-measurement and our
  recommendation: **adopt option (b) scoped to A5/A7 only**. Truth collapses to
  0.4% post-quarantine there while the detector keeps firing ~30%; for A6/A8
  truth stays flat at **43.6% for the whole run**, so a uniform guard would
  silence genuine detections. Also records that the −0.326 does not reproduce
  structurally: the latch writes `truth` and never touches `truth_declared`,
  which `score_primary` is scored against.
- `A1A2_RECALL_DECAY_2026-09-07.md` — per-bucket ground truth vs caught. No
  decay on `score`; A2 `score_primary` is real degradation (0.7290 → 0.5833
  against steady ground truth).
- `Q8_UCR_WINDOW_NOTE_2026-09-07.md` — duplicates are scheduled at a fixed
  `Seconds(0.001)` on both paths, 1 ms against a 30 s window, so no candidate
  `W` changes the outcome.

---

## Two findings that outrank the items they came from

**Enforcement is not containing vehicle attackers.** For A6/A8, truth-positive
rate stays at 43.6% *after* enforcement quarantines the network. That sits badly
beside item 1's "post-quarantine leak 0 of 44,171"; one of the two is measuring
something other than its name.

**The honest detectors trigger near-total quarantine.** With the gate out, 122
nodes are quarantined by t=10 s and **249 of 268 by t=20 s**. The false
positives feed the trust system and containment becomes indiscriminate. This
also means option (c) — excluding quarantined nodes from scoring — would compute
the metric on ~7% of the network.

---

## Outstanding

1. **D_div end-to-end validation.** The feature compiles but has never been
   confirmed to reach the model input. Needs `--training=1
   --lstm_ddiv_atp_per_rsu=1`, attack + benign arms, checked against the three
   criteria (non-constant across RSUs, exactly zero benign, corr with `R_anom`
   below 1). **Gates the regeneration** — a bad feature wastes ~8 h.
2. **The 300 s regeneration + retrain**, bundling item 3 and Q5. Every prior
   round's numbers are provisional until it lands. Re-run
   `calibrate_hc_theta.py` afterwards.
3. **Awaiting the supervisor:** option (b) itself, and item 4's close.
4. **Paper edits** (Q1, Q2, Q9, Q11, item 2, Q7's retirement of 0.2721) — not
   started, deliberately.

---

## Path handling

This commit carries the **HPC paths** (`/home/sdvn_hidden_attacks/ns3_g13/...`),
matching the rest of the repo, which is shared with the cluster. Three distinct
families were normalised: the tree root, `.../mobility/*.tcl`, and the
`$HOME`-relative forms in `routing.cc` / `crypto_event_log.h`.

The local working tree keeps the `nipuni` paths so builds and runs work here.
That leaves ~518 lines permanently dirty against HEAD — expected, and it is why
`routing.cc` shows no diff in this commit despite being edited locally: its only
real change was path-related.
