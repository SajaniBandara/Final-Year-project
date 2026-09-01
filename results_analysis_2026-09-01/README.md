# Analysis data + restore point — 2026-09-01

Everything needed to (a) roll back to tonight's model state and (b) plot the
figures, without re-running any simulation.

## Restore point

`lstm_pipeline/restore_point_2026-09-01_pre_ddiv/` (410 MB) — the complete
pipeline state **before** any `d_div`/`a_tp` feature change:

| item | what it is |
|---|---|
| `preprocessed/` | 11-feature arrays, **HF-latched** `y_indep` (rebuilt 2026-08-31 23:0x) |
| `models/` | 134 checkpoints incl. `global.pt`, `global_clshead_indep.pt` |
| `scaler_params.json` | 11-feature mu/std, benign TRAIN_SEEDS-only fit |
| `hparams.json` | per-RSU grid-search hyperparameters (64 RSUs) |
| `fed_summary.json` | per-RSU theta from federated aggregation |
| `cls_theta.json` | per-RSU classifier thresholds (FPR<=1% offline calibration) |
| `hf_theta.json` | pooled HF theta (**known-defective** — fit on `y_binary`, scored on `y_indep`) |
| `hf_theta_pervariant.json` | §6b per-variant/per-RSU thetas |
| `lstm_weights_cpp.bin` | C++ export **including `fc_cls`** |
| `validation_case.bin` | §5 verify case (PASSES, abs_diff 1.2e-07) |
| `src_snapshot/` | the 6 pipeline scripts as they stood tonight |

### To roll back

```bash
cd lstm_pipeline
R=restore_point_2026-09-01_pre_ddiv
rm -rf preprocessed models
cp -r $R/preprocessed $R/models .
cp $R/*.json $R/*.bin .
```

Then re-verify before trusting it:

```bash
cd scratch && g++ -O2 -std=c++17 lstm_inference_test.cpp -o /tmp/t.exe
/tmp/t.exe ../lstm_pipeline/lstm_weights_cpp.bin ../lstm_pipeline/validation_case.bin
# expect: n_features=11 ... PASS
```

**Note on a 9-feature retrain.** Dropping `d_div`/`a_tp` changes `n_features`
11 -> 9, which breaks three things by design (all fail loudly, none silently):
`export_weights_cpp.py`'s hardcoded 11-name assertion, `lstm_inference.h`'s
feature-count abort, and any `.bin` exported under the other count. Budget for
updating the assertion and re-exporting.

## Plot-ready data

All from the Q6 A/B runs (300 s, 60%, seed 1, binary 2026-08-31 23:10:39,
identical across both arms). M1 convention: RSU rows only, 30 s warm-up
excluded, non-overlapping 10 s blocks.

| file | rows | contents |
|---|---|---|
| `persistence_sweep.csv` | 396 | arm x score_col x M(1-11) x variant -> TP/FP/FN/TN, MCC, DR, FPR. **The main figure source.** |
| `fpr_decomposition.csv` | 16 | per variant: FP from OR vs primary vs LSTM-only, and the LSTM's share |
| `fpr_vs_time.csv` | 18 | FPR in 30 s bins across the run (shows it is flat — no warm-up effect) |
| `per_rsu_confusion.csv` | 128 | per-RSU TP/FP/FN/TN and precision (shows the 20.7% vs 91.1% split) |
| `t_hold_sweep.csv` | 18 | T_hold vs confirm/timeout releases (**floor = 1 ms**) |
| `hf_theta_pervariant.csv` | 64 | per-RSU theta_HF and which variant binds it |
| `hf_theta_deployed_vs_diagnostic.csv` | 8 | §6b deployed (max) vs per-variant diagnostic |

`arm` is `armA` (autoencoder, `--enable_lstm_cls=0`) or `armB` (classifier head,
`=1`). `score_col` is `score` (D_RSU OR-composite, **includes** `flag_LSTM`) or
`score_primary` (the variant's primary detector, **excludes** the LSTM — note it
is variant-aware, so it is a diagnostic ceiling, not a deployable configuration).

### Suggested figures

1. **M vs MCC**, one line per `score_col` — the persistence result
   (`score` peaks 0.5539 @ M=8; `score_primary` peaks 0.6870 @ M=3)
2. **Stacked FP bars per variant** — LSTM-only vs primary, from
   `fpr_decomposition.csv` (A4 is 100% LSTM)
3. **T_hold vs timeout%** — log x-axis, the floor at 1 ms is the story
4. **Per-RSU precision histogram** — the bimodal 20.7% / 91.1% split
5. **FPR vs time** — flat line; use it to show warm-up is *not* the issue

### Caveats to carry onto any figure

- M1 here is `scripts/m1_local.py`, a **re-implementation** — the canonical
  `metrics/` package does not exist on this host. Arm-to-arm deltas are valid;
  absolute values are **not** comparable to the historical M1 = 0.2721.
- `score_primary` is variant-aware. Never present it as deployed performance.
- M4 (mitigation latency) is deliberately absent: quarantine enforcement is OFF,
  so it measures an inert flag.
