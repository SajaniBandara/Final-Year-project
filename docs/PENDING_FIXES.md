# Pending Fixes & Deferred Work

**Created:** 2026-07-10
**Status:** Living document — remove items as they are completed.
**Context:** LSTM training data (90s, 240 runs) collected 2026-07-08/09; federated LSTM
pipeline currently training on it with A3/A4 excluded (see Fix 1 for why).

---

## AI-part completion summary (all 8 attacks via LSTM)

| Issue | Attacks | Fixable | Fix | Effort |
|---|---|---|---|---|
| **A — A3/A4 label bug** | A3, A4 | Yes | Label victim RSUs holding a malicious TCAM entry (`lstm_logger.h`). U_TCAM saturates to 1.0, so detection should be strong once labeled. | code ~15 min + rebuild + re-run 60 sims + retrain |
| **B — dead ZKP hop feature** | A5–A8 | Yes | Wire `g_lstm_stark_counts` hop-fail to fire on unauthorized copies so `1[π_hop=⊥]` populates (see Fix 2b). Also makes AB3 ablation real. | code ~30–60 min + rebuild + re-run 120 sims + retrain |
| C — thin benign windows | all | Optional | Pool RSUs / more benign runs. Works as-is. | low priority, skip for deadline |

**Already fixed (working):** cycle-level labeling (AUC 0.54→0.93 for A1/A2), benign-only
autoencoder training, seeded reproducibility, `torch.load` weights_only, `_global.pt`
glob. A1/A2 detect genuinely; M8 passes (BRFA-v2 robust, FedAvg collapses).

**Batched wall-clock for A+B:** ~1–1.5 h code + one rebuild + ~20–22 h re-run (180 sims,
25 workers, mostly unattended) + ~15 min retrain ≈ **~1 day, ~2 h hands-on.**

**Code status (2026-07-10) — all sim-side fixes applied, pending rebuild + re-run:**
- Fix 1 (A3/A4 label, `lstm_logger.h`) — ✅ code applied
- Fix 2b (`zkp_hop_fail` wiring, `routing.cc` at both HF eavesdrop points 121255/121309) — ✅ code applied
- Fix 3 (TCAM threshold 0.80→0.054688, `routing.cc:117522`) — ✅ code applied
- Pending: commit → `./waf build` → short verification run → delete old A3–A8 CSVs →
  re-run A3,A4,A5–A8 (180 sims) → remove `EXCLUDE_ATTACKS` (Fix 2) → retrain.

---

## Fix 1 — A3/A4 ground-truth labels are wrong (HIGH, blocks 2 of 8 attacks)

### Problem

The labels for A3 and A4 in the collected data are wrong, and the LSTM can't be
trained or evaluated on those two attacks without fixing them.

**How the label works now** (`scratch/lstm_logger.h:156`): each CSV row is one RSU's
features for one cycle, and the label is `is_malicious_node[variant][this_RSU]` —
i.e. *"is this RSU itself an attacker?"*

**Why that fails for A3/A4 specifically:**

- **A4 (DP-TCAM):** the attackers are **vehicles** (nodes 0..N) flooding junk flow
  rules into RSU TCAMs. No RSU is ever an attacker → every A4 row in the whole
  dataset is labeled 0. The data confirms it: **0 malicious rows across all 30 A4
  files** (every percentage, every seed).
- **A3 (CP-TCAM):** the attacker is a **compromised controller** flooding RSUs. The
  code marks a single "representative" RSU (`is_malicious_node[2][N_Vehicles]`,
  routing.cc:114968) purely as a bookkeeping marker → exactly 88 rows (1 RSU × 88
  cycles) labeled regardless of attack percentage, while in reality up to all 64
  RSUs are being flooded.

**Proof the attacks themselves ran correctly** (the labels are the only problem):

| Dataset (pct100, seed1) | U_TCAM mean | median | max |
|---|---|---|---|
| A0 benign | 0.008 | 0.004 | 0.039 |
| A3 | 0.344 | 0.016 | 1.000 |
| A4 | 0.573 | **1.000** | 1.000 |

### Consequences if unfixed

1. **A4 detection rate is structurally 0** — the evaluator has no positive labels to
   count TP/FN against. A3 DR is capped by the single labeled RSU.
2. **Benign training set is poisoned** — the autoencoder trains on label-0 windows;
   A3/A4's TCAM-saturated windows (U_TCAM = 1.0) count as "benign", teaching the
   model that attack behaviour is normal and degrading detection of *all* attacks.

### Fix (verified compile-safe; include order already correct)

In `scratch/lstm_logger.h`, after the existing `is_malicious_node` check
(line ~156), label the **victim** RSUs — any RSU holding ≥1 malicious TCAM entry.
`tcam_detection.h` (which declares `g_tcam_table`) is included immediately before
`lstm_logger.h` in routing.cc, so the symbol is visible:

```cpp
label = is_malicious_node[active_attack_variant][rsu_sim_idx] ? 1 : 0;
// A3/A4 (TCAM attacks): the attacker is a controller (A3) or vehicles (A4),
// never the RSU itself, so is_malicious_node stays false for RSU rows. Label
// the *victim* RSUs instead: any RSU holding >=1 malicious TCAM entry is
// attack-affected (entries persist — slow-flow exhaustion).
if (!label && (active_attack_variant == 2 || active_attack_variant == 3))
{
    for (const auto& entry : g_tcam_table)
    {
        if (entry.node_id == rsu_sim_idx && entry.is_malicious)
        {
            label = 1;
            break;
        }
    }
}
```

Both attacks install entries with `is_malicious = true` and the victim RSU's node id
(`tcam_install_malicious()`, tcam_attack_helper.h:372-400), so this is exact ground
truth, not a heuristic.

### Procedure when resumed

1. Apply the fix above to `scratch/lstm_logger.h`.
2. **COMMIT IT IMMEDIATELY.** This fix was already applied once (2026-07-08) but was
   never committed and a later git operation silently reverted it — the entire 90s
   A3/A4 dataset was collected with the old labels as a result.
3. Rebuild: `cd ~/ns3_g13/ns-allinone-3.35/ns-3.35 && ./waf build`
   (NS-3 scratch files are **symlinks** into this repo's `scratch/` — edit here only.)
4. **Delete old A3/A4 CSVs first** — the logger opens with `std::ios::app`, so
   re-runs would append onto stale data:
   `find ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training -name "A[34]_*.csv" -delete`
5. Re-run only A3+A4 (60 runs ≈ 7 h at 25 workers):
   `python3 scripts/run_training_attacks.py --attack 3 4 --workers 25`
6. Sanity-check labels: A3 labeled rows should scale with attack percentage;
   A4 should be ≫ 0 (was exactly 0).
7. Remove `EXCLUDE_ATTACKS = {3, 4}` from `lstm_pipeline/src/preprocessor.py`
   (see Fix 2) and re-run the pipeline.

---

## Fix 2 — Preprocessor temporarily excludes A3/A4 (tied to Fix 1)

`lstm_pipeline/src/preprocessor.py` currently has `EXCLUDE_ATTACKS = {3, 4}` to keep
the mislabeled TCAM windows out of the benign training set (see Fix 1, consequence 2).
**Remove this after Fix 1 is complete** so A3/A4 are trained/evaluated like the rest.

---

## Fix 2b — `zkp_hop_fail` LSTM feature is dead → A5–A8 undetectable (HIGH, breaks a core thesis contribution)

### Why this is important

main.tex makes the LSTM detection of **hidden forwarding (A5–A8)** a stated novelty
(line 729: *"No work applies federated LSTM specifically to detecting selective time
delay patterns **or hidden forwarding signatures**"*). The LSTM input vector
(eq:lstm_input) includes two "novel mobility-cryptographic" binary features precisely
for this:

    x_t = [ delta_t, lambda_PI, U_TCAM, 1[pi_delay=⊥], 1[pi_hop=⊥], rho, v_bar ]

`1[pi_hop=⊥]` (hop-legitimacy failure) is the feature meant to catch hidden forwarding,
and ablation **AB3** (5-feature vs 7-feature) is built to prove it adds value.

**Current reality: both ZKP features (`zkp_delay_fail`, `zkp_hop_fail`) are 0 in every
collected row, including A5–A8 malicious rows.** So the LSTM cannot detect A5–A8, and
AB3 would show no difference between the 5- and 7-feature models — silently nullifying
a claimed contribution. This is a bug, NOT a design boundary. Do **not** describe A5–A8
as "handled by another layer, by design" — that contradicts the thesis.

(Note: eFADE = the state-of-the-art baseline compared against; UCR = an evaluation
metric; S5–S8 = MOBIGUARD's rule-based signatures. None of these is a reason the LSTM
"shouldn't" see A5–A8 — the thesis says it should.)

### Root cause

`zkp_hop_fail` is fed by `g_lstm_stark_counts`, incremented only inside
`stark_update_meta()`. That call is gated on `sig_ok` at **routing.cc:121385**:

```cpp
if (sig_ok) {
    stark_update_meta(prev_sender, packet_ID, timing_ok, hop_ok);
```

A hidden-forward copy goes to an eavesdropper that is NOT the signed next-hop, so
`mldsa87_verify` returns `sig_ok = false` (correctly — unauthorized recipient), the
`stark_update_meta` call is skipped, and the hop failure never reaches the LSTM
feature. The event IS caught on a separate path (`fade_eavesdrop_counter`, which powers
the UCR metric), but that signal is never wired into `g_lstm_stark_counts`.

### Fix

At the unauthorized-copy / eavesdrop detection point, increment the offending
(malicious) RSU's LSTM hop-fail counter, e.g.
`g_lstm_stark_counts[malicious_rsu].second++`, so `1[pi_hop=⊥]` fires for that RSU's
cycle. Methodologically sound: a hidden-forward *is* a hop-proof violation, so the
feature *should* be 1. (Same pattern would populate `zkp_delay_fail` for the relevant
timing cases.)

### Procedure when resumed

1. Wire the counter at the eavesdrop-detection site (find via `fade_eavesdrop_counter`
   increment in routing.cc; attribute to the malicious RSU's LSTM cycle counter).
2. COMMIT + rebuild (`./waf build`) — batch with Fix 1 and Fix 3 into one rebuild.
3. Delete old A5–A8 CSVs (logger appends) and re-run: 4 attacks × 6 pct × 5 seeds =
   **120 sims (~14 h at 90 s, 25 workers)**.
4. Verify `zkp_hop_fail` is now > 0 on A5–A8 malicious rows.
5. Re-run the pipeline; A5–A8 should now be LSTM-detectable via the hop feature, and
   AB3 becomes a real ablation.

**Until fixed:** present only A1/A2 as working LSTM detection. Report A5–A8 LSTM
detection as *intended design, currently blocked by this instrumentation gap* — not as
working, and not as out-of-scope.

---

## Fix 3 — Apply calibrated S3/S4 TCAM threshold in routing.cc (before evaluation runs)

`rule_calibrator.py` Step 5 (2026-07-10) calibrated the TCAM utilisation threshold
from benign data:

| Threshold | Hardcoded now | Calibrated | Basis |
|---|---|---|---|
| `tcam_util_thresh` | **0.80** | **0.054688** | benign p99, 0.95% benign exceedance (FPR ≤ 1% budget) |
| `lambda_pi_thresh` | 15.0 | 15.0 retained | benign λ_PI all zero — nothing to calibrate; documented as initial estimate |
| `lambda_fm_thresh` | 10.0 | 10.0 retained | FlowMod rate not logged in LSTM CSVs; documented as initial estimate |

The hardcoded 0.80 is ~15× above the entire benign distribution (benign max 0.094) —
dead space. Update the `ComputeTcamDetection()` call site at **routing.cc:117518-117524**
(third arg = λ_FM, fourth = λ_PI, fifth = util threshold): change `0.80` → `0.054688`.
Requires the same rebuild as Fix 1 — do them together.

**Thesis caveat to note:** U_TCAM grows monotonically over a run (rule accumulation,
never plateaus), so this threshold is calibrated for the current run durations
(90–150 s). Longer evaluation runs need recalibration on matching-duration benign data.

---

## Fix 4 — Evaluation-phase items (for the M2–M12 simulation runs)

1. **M9 / M11 first build+run verification** — code-complete per
   `docs/METRICS_VERIFICATION_REPORT.md` but never compiled/run. The Fix 1/3 rebuild
   covers the compile check; the first evaluation run covers the run check.
   (M8's verification is the currently-running `pipeline.py` — poison_sweep step.)
2. **MOBIGUARD result CSV filenames have no seed** —
   `MOBIGUARD_Attack{N}_{pct}{delay}.csv` opens with `ios::app`, so parallel seeds
   with the same attack+pct interleave rows into one file. For evaluation runs either
   run one seed at a time per (attack, pct) or add `_s{seed}` to the filename in
   `write_security_metrics_csv()` (routing.cc:117234).
3. **Detection flags (scheme changed 2026-07-09, commit 790e0fe)** — the individual
   per-signature `s1..s8_detection_active` flags were removed. MOBIGUARD's own rule
   detectors (S1–S8) are now gated at mode level by `enable_lrad_obu` /
   `enable_lrad_rsu` (lrad.h); the FADE baseline keeps its own `fade_detection_active`
   (default false). Evaluation runs must set the mode flags for whichever detectors
   they exercise. **Does NOT affect the LSTM pipeline** — `lstm_logger.h` feature
   logging references no detection flag; all 7 features are raw observables computed
   regardless of detector state, so training-data collection is unchanged.

---

## Optional / nice-to-have

- **λ_FM benign logging:** add FlowMod-rate to the per-cycle logger so
  `lambda_fm_thresh` can be percentile-calibrated like U_TCAM (currently a documented
  initial estimate). Needs one benign re-run after the logging addition.
- **Mobility-stratified MCC** (`MCC[ρ_b, v̄_b]` bins) — flagged "HIGH (still open)" in
  METRICS_VERIFICATION_REPORT.md; post-processing of logs, no new simulation needed.
