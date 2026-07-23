# LSTM Hidden-Forwarding (A5-A8) DR Improvement Plan

Context: LSTM-only DR for A5-A8 is 37-47% (`evaluator.py`, held-out test
split) vs. the rule engine's own 75-88% cumulative node-level DR for the
same attacks (`MOBIGUARD_Attack{5,6,7,8}_60_seed*.csv`, `cur_DR` column).
These are different metrics measuring different things (see prior
conversation), but three concrete, code-level actions were identified
before concluding a model/architecture redesign is needed. None of these
change `eq:lstm_input` or the LSTM architecture itself.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## 1. Fix window-labeling ground truth for A5-A8 `[~]` implemented, pipeline rerun in progress
**File**: `lstm_pipeline/src/preprocessor.py`

**Bug**: `is_spike` (~L155), the flag that makes a window "attack-positive"
for ground truth, is computed **only** from `delta_t` exceeding its benign
p99 (`SPIKE_QUANTILE`). HF attacks (A5-A8) don't perturb `delta_t` — so
almost no HF windows are correctly labeled positive today. The reported
DR for A5-A8 is measured against ground truth that's largely blind to when
the attack is actually active.

**Fix**: extend the spike criterion for A5-A8 to also trigger on
`zkp_hop_fail`/`zkp_delay_fail` (the two ZKP failure indicators main.tex
explicitly designed to carry cryptographic evidence of HF attacks into the
LSTM input — see AB3, `main.tex:4648-4676`). Keep the existing
`delta_t`-only criterion for A1-A4 (still correct there).

**Predicted time**: ~30-45 min to implement + rerun `preprocessor.py`
(fast, no NS-3 re-simulation needed — reuses existing collected CSVs) +
rerun `local_trainer.py` → `fed_aggregator.py` → `evaluator.py` to get
corrected numbers. `fed_aggregator.py` has crashed intermittently this
session (unresolved, see prior crash investigation) — budget up to
2-3 attempts before landing a clean run. **Total: ~1-2 hours.**

## 2. Wire `flag_LSTM` into `D_RSU`
**Files**: `scratch/lrad.h`, `scratch/lstm_logger.h`, `scratch/routing.cc`

Already tracked as item #10 in `DEV_MERGE_SPEC_CHANGES.md`. Doesn't raise
the LSTM's own DR — unions the live in-sim `D_LSTM` (already computed,
logging-only per Fix 17) into the system's composite RSU detection
decision, alongside the rule engine's already-strong 75-88% HF DR. Highest
system-level leverage without touching model internals.

**Predicted time**: ~1-2 hours implementation (per-RSU `D_LSTM` flag
already exists in `g_lstm_last_dlstm[r]`, per `lstm_logger.h:449` — mainly
needs threading into `lrad_rsu()`'s `D_RSU` computation and
`record_detection_event()` call, matching the plane-attribution routing
already sketched in `DEV_MERGE_SPEC_CHANGES.md` #11) + rebuild
(`./waf build`, ~13s) + a verification run to confirm it fires under real
HF violations (mirroring the Fix-16 empirical-confirmation methodology).
**Total: ~2-3 hours.**

## 3. Run AB3 ablation (5-feature vs 7-feature)
**Files**: new `--feature_config` mode in `preprocessor.py`, or a
standalone variant script; reuses existing `local_trainer.py`/
`fed_aggregator.py`/`evaluator.py` unmodified.

Tests whether the autoencoder is actually using `zkp_hop_fail`/
`zkp_delay_fail` at all, per main.tex's own AB3 spec (`main.tex:4648-4676`,
5-feature `[δ_t,λ_PI,U_TCAM,ρ,v̄]` baseline vs. 7-feature proposed,
compared via per-variant M1/MCC "particularly for Variants 5-8"). Should
be run **after** #1, since AB3's comparison is only meaningful against
correctly-labeled ground truth.

**Predicted time**: ~30 min to add the 5-feature config path +
full pipeline rerun (preprocess → train → aggregate → evaluate) for the
AB3-A variant, reusing already-collected CSVs (no new NS-3 runs needed).
Same `fed_aggregator.py` crash-risk buffer as #1. **Total: ~1-2 hours.**

---

## Overall predicted time
Sequential (², recommended — #1 must land before #3 is meaningful; #2 is
independent and can run in parallel with #1/#3 if needed):
**~4-7 hours** of active work, dominated by pipeline rerun time and
`fed_aggregator.py`'s unresolved intermittent-crash risk (each crash costs
a full re-run, ~10-20 min lost per occurrence, not a hard blocker but an
unpredictable multiplier). No new NS-3 simulation sweeps are needed for
any of the three items — all reuse already-collected training data.
