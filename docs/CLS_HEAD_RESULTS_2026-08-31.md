# §6a results — classifier head vs autoencoder (2026-08-31, HPC)

Test split (seed 5), frozen encoder, per-RSU threshold calibrated at FPR≤1%,
latched `y_indep`. `train_cls_head.py --labels indep --timing-labels indep`
→ `models/global_clshead_indep.pt`. Runtime **11 s** (latents cached once).

## Deployed — leak-free labels

| variant | MCC | DR | FPR |
|---|---|---|---|
| A1 | 0.2597 | 11.3% | 0.6% |
| A2 | 0.5009 | 37.1% | 1.1% |
| A5 | 0.2551 | 15.8% | 1.5% |
| A6 | 0.3973 | 58.2% | 15.9% |
| A7 | 0.2524 | 15.7% | 1.6% |
| A8 | 0.2197 | 18.6% | 3.2% |
| **macro** | **0.3142** | | |

## A1/A2: the collapse is substantially improved

§6a named the A1/A2 detection collapse (DR **2.7% / 4.6%** under the
autoencoder) as the worst pair of numbers in the thesis. The classifier head on
leak-free labels:

| | autoencoder | classifier head | change |
|---|---|---|---|
| A1 DR | 2.7% | **11.3%** | ×4.2 |
| A2 DR | 4.6% | **37.1%** | ×8.1 |

Both still short of the GBM's 0.95, so the head is an improvement over the
autoencoder without closing the gap — consistent with §6a's diagnosis that the
autoencoder latent, not the head, is the binding constraint. `--unfreeze`
(end-to-end) is the untried lever if more is needed.

## A label leak found and fixed in `train_cls_head.py`

`build_labels()` built A1/A2's target as
`(X[:, :, DT_EXC_IDX] > 0).any(axis=1)` — `DT_EXC_IDX = 10` is
`delta_t_exceeded`, **a `FEATURES` column the head reads as input**. The head
could satisfy that label by echoing one input, the identical defect the file
already documents for `--labels supervisor` on `r_anom`.

The docstring justified it as "no independent alternative exists in the
collected data". True on 2026-08-20; **false since 2026-08-27**, when
`std_send_gt` (A1/A2's send-side injection counter, excluded from `FEATURES`)
began being collected. `preprocessor.py`'s `make_windows` already folds it into
`y_indep` via `_inj = max(_hf, stdgt, tcamgt)`. Verified 2026-08-31:
`std_send_gt` present on all 3840 A1/A2 files.

Fixed: A1/A2 now take `y_indep`. The legacy form stays available as
`--timing-labels dt_exceeded` so the inflation stays measurable.

### What the leak was worth

| | leaky (`dt_exceeded`) | leak-free (`indep`) | inflation |
|---|---|---|---|
| A1 MCC | 0.5083 | 0.2597 | **+0.249 (×1.96)** |
| A2 MCC | 0.6573 | 0.5009 | **+0.156** |
| A1 DR | 35.3% | 11.3% | ×3.1 |
| A2 DR | 56.1% | 37.1% | ×1.5 |
| macro-MCC | 0.4177 | 0.3142 | **+0.104** |

**Do not report the leaky numbers.** An A1 MCC of 0.51 was available for free by
echoing an input column; the defensible figure is 0.26.

## Caveat on `enable_lstm_cls`

These are Python-side numbers. For in-simulator evaluation the run must pass
`--enable_lstm_cls=1` (it **is** CLI-settable — see the §5b correction in the
runbook) and the exported `lstm_weights_cpp.bin` must contain `fc_cls`. If it
does not, the C++ side falls back to the reconstruction path **with only a
warning** and you will silently be measuring the autoencoder. Check that warning
line before trusting any in-sim classifier result.

## Reproduce

```bash
cd lstm_pipeline/src
MOBIGUARD_HF_LATCHED=1 python3 preprocessor.py
python3 train_cls_head.py --labels indep --timing-labels indep     # deployed
python3 train_cls_head.py --labels indep --timing-labels dt_exceeded  # leak, diagnostic
```
