# §6b results — per-variant HF theta + latched label (2026-08-31, HPC)

Test split (seed 5), autoencoder `global.pt`, `Z_ALPHA` from `fed_aggregator`.
Produced by `calibrate_hf_theta_pervariant.py --latched 1`
→ `lstm_pipeline/hf_theta_pervariant.json`.

## Which variant binds theta_HF^(k)

The supervisor's instruction not to assume A6 was correct — it binds at barely
half the RSUs:

| binder | RSUs |
|---|---|
| A6 | 34 / 64 |
| A5 | 11 / 64 |
| A8 | 8 / 64 |
| A7 | 5 / 64 |
| fallback (no fittable cell) | 6 / 64 |

188 / 256 (variant, RSU) cells fitted; 68 too thin (<10 quiet windows).

## DEPLOYED — single combined threshold, variant-blind

Latched label, `theta_HF^(k) = max_v theta_v,k`:

| variant | DR | FPR | MCC |
|---|---|---|---|
| A5 | 10.5% | 0.3% | 0.227 |
| A6 | 55.8% | 4.1% | 0.495 |
| A7 | 10.4% | 0.2% | 0.227 |
| A8 | 18.0% | 0.5% | 0.261 |
| **mean** | | | **0.303** |

## DIAGNOSTIC ONLY — each variant under its own threshold

**Not deployed performance.** The LSTM's per-attack-type ceiling.

| variant | DR | FPR | MCC |
|---|---|---|---|
| A5 | 17.3% | 1.0% | 0.285 |
| A6 | 58.1% | 4.2% | 0.513 |
| A7 | 19.3% | 0.6% | 0.314 |
| A8 | 20.7% | 1.1% | 0.275 |

## The finding the runbook did not anticipate

§6b predicted "A6 FPR 76.3% → 8.3%, MCC 0.304 → 0.707". Measured:

- **A6 FPR 75.3% → 4.1%** — better than predicted
- **A6 MCC 0.308 → 0.495** — well short of the predicted 0.707

And the prediction covered only A6. Across all four variants, the 2×2 (label
form × threshold construction), mean MCC over A5-A8:

| | pooled `theta_hf` | per-variant max |
|---|---|---|
| **un-latched** `y_indep` | **0.478** | 0.359 |
| **latched** | 0.363 | **0.303** |

Per-variant, going from pooled to per-variant max under the latched label:

| variant | MCC pooled → per-variant | DR pooled → per-variant |
|---|---|---|
| A5 | 0.418 → **0.227** | 37.6% → 10.5% |
| A6 | 0.301 → **0.495** | 92.3% → 55.8% |
| A7 | 0.416 → **0.227** | 37.2% → 10.4% |
| A8 | 0.317 → **0.261** | 52.2% → 18.0% |

Taken at face value this says the max-across-variants construction helps A6 and
hurts the other three. **It does not. That comparison is invalid**, and the
reason matters enough to write down.

### Why the pooled baseline above is not a baseline

`calibrate_hf_theta.py:56` fits on `val_y.npy` — that is **`y_binary`**, not
`y_indep`. Under the HF spike criterion (`zkp_delay_fail|zkp_hop_fail`) almost
every A5/A6 window is flagged positive, so those variants contribute **no quiet
windows at all**: the stored pool is 87 windows, A5 **0**, A6 **0**, A7 52,
A8 35. So `theta_hf = 0.7895` was calibrated against one label and is being
scored against a different one. It is not a conservative baseline — it is an
*accidentally permissive* one, which is what buys A5/A7 their flattering DR and
what simultaneously produces A6's 75% FPR.

Refit the pooled threshold on the **same latched label**, so the two
constructions differ only in pooled-vs-per-variant:

- refit quiet pool: **32,497** windows — A5 9484, A6 6437, A7 9528, A8 7048
  (versus 87 with two variants empty)
- **`theta_hf` 0.7895 → 2.1114** — nearly 3× higher, as a correctly-calibrated
  pool must be

### Like-for-like: per-variant max wins on all four variants

All under the latched label, test split:

| variant | pooled-refit (2.1114) | **per-variant max** |
|---|---|---|
| A5 | 0.135 | **0.227** |
| A6 | 0.376 | **0.495** |
| A7 | 0.133 | **0.227** |
| A8 | 0.196 | **0.261** |
| **mean MCC** | 0.210 | **0.303** |

**The supervisor's construction is vindicated.** It beats a fairly-calibrated
pooled threshold on every variant, not just A6. The earlier "regression" was an
artifact of the miscalibrated baseline, not a property of the construction.

### Summary against every candidate baseline

| baseline | A5-A8 mean MCC | per-variant max vs it |
|---|---|---|
| per-RSU `fed_summary` theta (**today's shipped default**, `enable_hf_theta=0`) | **-0.232** (FPR 78-99%) | wins on all four, decisively |
| pooled refit on latched label (fair comparison) | 0.210 | **wins on all four** |
| pooled `hf_theta.json` as stored (fit on `y_binary`, A5/A6 empty) | 0.363 | not a valid comparison — see above |

Report the first two. The third should be retired: `hf_theta.json` should either
be refit on the label it is scored against, or superseded outright by
`hf_theta_pervariant.json`.

## Latch effect, isolated

Latched HF positives on the test split: 33.9% → 57.7% of HF windows. Under
either threshold construction the latch *lowers* mean MCC (0.478 → 0.363 pooled;
0.359 → 0.303 per-variant). §1 rules the latch settled and says not to report the
intermediate — recorded here as diagnosis only.

Cross-check: the preprocessor's latch (`MOBIGUARD_HF_LATCHED=1`) and
`calibrate_hf_theta_pervariant.py`'s own CSV re-derivation produce **identical**
labels. Two independent implementations agree.

## Conclusion

**Ship the per-variant max as specified (§1's settled answer).** It is the best
of the three constructions against a like-for-like baseline, and no open
question remains for the supervisor on this point.

One follow-up worth doing, not blocking: `calibrate_hf_theta.py` fits on
`y_binary` while everything downstream scores `y_indep`. That mismatch is a live
bug in its own right, independent of tonight's work — any future use of
`hf_theta.json` inherits it. Either refit it on `y_indep` or delete it in favour
of `hf_theta_pervariant.json`.

## Reproduce

```bash
cd lstm_pipeline/src
MOBIGUARD_HF_LATCHED=1 python3 preprocessor.py          # ~27s
python3 calibrate_hf_theta_pervariant.py --latched 1 \
        --json ../hf_theta_pervariant.json              # ~5s
```

Note `calibrate_hf_theta_pervariant.py` re-derives the latch from the CSVs
itself, so it does not depend on the `MOBIGUARD_HF_LATCHED` rebuild. The two
implementations were cross-checked and produce identical labels.
