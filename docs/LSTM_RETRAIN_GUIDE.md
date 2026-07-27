# Guide: Retrain the Federated LSTM on the new 10-feature CSVs

Context: `docs/PENDING_FIXES.md` Fix 23 — `lstm_weights_cpp.bin` and
`validation_case*.bin` are still the old 7-feature model; the "N8" commit
extended `eq:lstm_input` to 10 features (`D_div`/`A_tp`/`R_anom`) but nothing
was retrained against it. This guide is the exact remaining sequence, once
you have the new 10-feature training CSVs from your friend.

While writing this guide, one real blocker bug was found and already fixed:
`export_weights_cpp.py` had a hardcoded assertion checking the scaler's
feature list against the OLD 7-feature list — it would have thrown
`AssertionError` on step 4 below against a real 10-feature `scaler_params.json`.
Fixed in this session (added `d_div`/`a_tp`/`r_anom` to the asserted list).
Everything else in the pipeline (`preprocessor.py`, `lstm_model.py`,
`fed_aggregator.py`, `gen_cpp_validation_case.py`) already reads `N_FEATURES`
dynamically (=10) — no other blockers found by inspection.

## 0. Get the CSVs into the expected location

`preprocessor.py` looks for CSVs at:
```
$HOME/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/RSU_*/A{v}_pct{p}_seed{s}.csv
```
(`lstm_pipeline/src/preprocessor.py:44-45`). On Windows there's no `HOME` env
var by default, so either:
- set one before running anything: `export HOME=/c/Users/user/Desktop/FYP/lstm_data` (bash) —
  then place the CSVs at `$HOME/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/RSU_*/...`, or
- just recreate that exact relative folder structure wherever your friend's
  CSVs land and point `HOME` at its root.

Each file must be named `A{variant}_pct{pct}_seed{seed}.csv` (e.g.
`A5_pct60_seed3.csv`) inside a `RSU_{k}/` subfolder, and must already contain
the 10-feature header (`cycle,rsu_id,delta_t,lambda_PI,U_TCAM,zkp_delay_fail,
zkp_hop_fail,rho,v_bar,d_div,a_tp,r_anom,escalated,label,lstm_anomaly_score,
d_lstm` — the 16-column format `lstm_logger.h`'s `LSTM_CSV_HEADER` writes).
If your friend's CSVs are still the legacy 10/13/14-column format, they'll
need the same migration `lstm_logger.h`'s `lstm_migrate_stale_header()` does
at simulation runtime — check the header row of a couple of files first
(`head -1` on a couple of the files) before trusting the count below.

**Sanity check before running anything**: confirm you actually have all
`6 attack-percentages × 8 variants × 5 seeds = 240` run-instances expected by
`main.tex:5775`, and that a spot-checked file's header has 16 columns with
`d_div,a_tp,r_anom` present. If it's short, `preprocessor.py` will still run
but the split sizes / per-variant coverage may be thinner than the thesis
numbers assume.

## 1. Environment setup (once)

No local conda env or venv on this machine has `torch` (checked in the
previous session — `base`/`faceid_env`/`tf_env`, and two on-disk venvs, none
qualify). Create a fresh one:

```bash
# from anywhere
python -m venv /c/Users/user/Desktop/FYP/simulations/lstm_pipeline/.venv
source /c/Users/user/Desktop/FYP/simulations/lstm_pipeline/.venv/Scripts/activate
pip install torch numpy pandas scikit-learn scipy matplotlib
```

CPU-only `torch` is enough to run the pipeline (it'll just be slower than
the "RTX 5090 / CUDA" case `pipeline.py`'s docstring mentions — if the HPC
machine has a CUDA GPU, run there instead and torch will pick it up
automatically, no code change needed).

## 2. Run the pipeline

From `lstm_pipeline/src/`, with the venv active and `HOME` set (step 0):

```bash
python pipeline.py
```

This runs, in order (`lstm_pipeline/src/pipeline.py:38-44`):
1. **`preprocessor.py`** — loads all CSVs, Z-score normalizes (benign-only
   fit), builds windowed sequences, 70/15/15 split by seed. Outputs
   `lstm_pipeline/preprocessed/{split}_X.npy` etc. and
   `lstm_pipeline/scaler_params.json`.
2. **`local_trainer.py`** — per-RSU hyperparameter grid search.
3. **`fed_aggregator.py --gamma_factor 2.0`** — federated training (BRFA-v2:
   trust gate + hash verify + Krum), R rounds. Outputs
   `lstm_pipeline/models/global.pt`, `lstm_pipeline/models/rsu_{k}.pt`, and
   `lstm_pipeline/fed_summary.json` (per-RSU calibrated θ).
4. **`evaluator.py`** — M1-M3 (MCC/DR/FPR) etc. on the held-out test split.
   Writes `lstm_pipeline/evaluation_results.json`.

If something fails partway, resume from the failed step instead of
restarting: `python pipeline.py --from-step 3`.

(Step 5, `poison_sweep.py`, is the M8 poisoning-resistance sweep — optional,
run explicitly with `--from-step 5` after steps 1-3 have produced a clean
`rsu_*.pt`; not required just to refresh the live-inference weights.)

## 3. Export the C++ weight file

```bash
python export_weights_cpp.py
```
Reads `lstm_pipeline/models/global.pt` + `lstm_pipeline/fed_summary.json` +
`lstm_pipeline/scaler_params.json`, writes
`lstm_pipeline/lstm_weights_cpp.bin`. Watch the printed `n_features=` line —
**it must say 10**, not 7.

## 4. Regenerate the validation case

```bash
python gen_cpp_validation_case.py
```
Writes `lstm_pipeline/validation_case.bin` against the freshly-trained
`global.pt`. (`validation_case2.bin` isn't produced by any script in this
repo as-is — if you need it too, just copy `validation_case.bin` over it,
or re-run `gen_cpp_validation_case.py` with a different `RandomState` seed
first and save under that name if you want a second independent case.)

## 5. Verify locally — no HPC needed for this step

Back in a normal shell (the C++ test needs no venv, no torch):
```bash
cd scratch
g++ -O2 -std=c++17 lstm_inference_test.cpp -o /tmp/lstm_test.exe
/tmp/lstm_test.exe ../lstm_pipeline/lstm_weights_cpp.bin ../lstm_pipeline/validation_case.bin
```
Expect:
```
Loaded weights: n_features=10 hidden1=64 hidden2=32 n_rsus_theta=64 global_theta=<value>
...
PASS (tolerance=1e-003)
```
If `n_features` still says 7, step 3 didn't pick up the new model — check
you're pointing `--ckpt`/`FED_SUMMARY`/`SCALER_PATH` at the freshly-generated
files, not stale ones from a previous run.

If this fails (`FAIL`, or a large `abs_diff`), do **not** proceed to a live
sim — that means either the export or the hand-rolled forward pass has a
real numerical mismatch, and results collected against it wouldn't be
trustworthy.

## 6. Only after step 5 PASSes

- Commit the new `lstm_weights_cpp.bin` / `validation_case.bin` (git-lfs or
  as-is, matching however the existing 360KB file was committed).
- Live simulations with `--enable_lstm_inference=1` will now load the
  10-feature model automatically — no other code changes needed (the
  `D_LSTM` → `D_RSU` wiring, blockchain signal 9, etc. from the earlier
  session already work against whatever `n_features` the loaded file has).
- Consider re-running `evaluator.py`'s M1-M3 table and the HF-specific plot
  script (`plot_hf_detection_results.py`) to see whether the new features
  actually move A5-A8 MCC off its ~0.2 baseline — that was the whole point
  of collecting these CSVs.

## Not covered by this guide

- Fix 21 (pure-benign FPR mismatch, needs more standalone-benign CSVs) — a
  separate, larger data-collection gap, not fixed by this retrain alone.
- `preprocessor.py` still doesn't consume the `escalated` column as a
  feature or split criterion (Fix 17's still-open bullet) — out of scope
  here unless you want it added while you're already in this code.
