# HPC runbook — 12-hour window, 2026-08-31 night

**Read this whole file before running anything.** It is written for a Claude
session on the HPC machine that has none of the context from the machine where
these decisions were made. Every "do not" below is something that already went
wrong once today.

**Goal for the window:** retrain the LSTM on 11 features, switch the reported
model to the classifier head, apply per-variant threshold calibration together
with the latched label in one pass, and produce the A5-A8 numbers the supervisor
asked for.

---

## 0. The one thing that can destroy this window

Re-collecting the LSTM training set takes about **7 hours**. If you discover at
hour 6 that the data is unusable, the window is gone.

So: **verify the data in the first 15 minutes, before any training.** Section 2
is not optional and not reorderable.

If verification fails, **do not start a re-collection.** Pivot to section 8.

---

## 1. What is already settled — do not re-litigate these

Today's session on the other machine resolved several things. Re-opening them
will waste hours.

| Question | Settled answer |
|---|---|
| 10 or 11 LSTM features? | **11.** `N_FEATURES = 11`, `delta_t_exceeded` included |
| Is `delta_t_exceeded` a label leak? | **No, not any more.** The leak was against the OLD label (`delay > 50ms`, MCC 1.0000). `y_indep` replaced it on 2026-08-20 and is built ONLY from `std_send_gt`/`hf_send_gt`/`tcam_send_gt`, all excluded from `FEATURES`. `crypto_layer.h`'s "banned" comment refers to its use as ground truth, not as an input |
| Latch reset boundary: end-of-run or quarantine time? | **End-of-run, unchanged.** The training data predates the enforcement flag, so in that data the compromised state genuinely never ends. Moving the boundary would clip the label where nothing changes in the data. Revisit only for data collected WITH enforcement on |
| Latch + per-variant recalibration: separately or together? | **Together, one pass.** Supervisor approved. Do not report the intermediate |
| Per-variant theta: diagnostic or deployed? | Deployed number = `theta_HF = max` across the four per-variant thetas. Per-variant values are a **labelled diagnostic table only** — never presented as deployed performance |

---

## 2. First 15 minutes — verify the data (GO / NO-GO)

Run in `results_routing/lstm_training/`:

```bash
# coverage: which variants, percentages, seeds exist
ls RSU_0 | sed -E 's/_seed[0-9]+\.csv//' | sort | uniq -c
ls RSU_0 | grep -oE 'seed[0-9]+' | sort | uniq -c
find . -name 'Attack[5-8]_*' | wc -l

# header width across the whole set -- must be uniform
find . -name '*.csv' -exec head -1 {} \; | awk -F',' '{print NF}' | sort | uniq -c

# the leak-free label columns must exist AND be non-zero
python3 -c "
import csv,glob
f=sorted(glob.glob('RSU_10/Attack5_*seed1.csv'))[0]
r=list(csv.reader(open(f))); h=[x.strip() for x in r[0]]
print('ncols:', len(h)); print(h)
for c in ('hf_send_gt','std_send_gt','tcam_send_gt','delta_t_exceeded'):
    if c in h:
        i=h.index(c); v=[x[i] for x in r[1:] if len(x)>i]
        print(f'{c}: nonzero {sum(1 for x in v if x.strip() not in (\"0\",\"0.0\",\"\"))}/{len(v)}')
    else: print(c, 'MISSING')
"

# collection date -- context only, does not gate anything
find . -name 'Attack[5-8]_*' -printf '%TY-%Tm-%Td\n' | sort -u
```

**GO requires all four:**

1. A5, A6, A7, A8 all present, 5 seeds each
2. `delta_t_exceeded` present in **every** file's header
3. Each attack family carries **its own** injection-side ground-truth column:
   `hf_send_gt` on A5-A8, `std_send_gt` on A1/A2, `tcam_send_gt` on A3/A4
4. That column is **non-zero** in each family's files

**Corrected 2026-08-31 (HPC).** An earlier draft of this section demanded a
*uniform header width* across the whole set and *all three* GT columns in every
file. That is stricter than the pipeline and produces a **false NO-GO** on this
machine's data. Measured here: 18 cols (A0, A5-A8), 19 (A1/A2), 20 (A3/A4) —
three widths, because the GT columns were appended over time and are only
written by the runs that can produce them.

That is fine, and `preprocessor.py` already knows it
([`load_all_csvs`](../lstm_pipeline/src/preprocessor.py), lines 124-169): it
backfills a missing GT column with 0 but only *counts it as harmful* for the
family it can harm — `std_send_gt` for A1/A2, `tcam_send_gt` for A3/A4. Its own
comment: "every other run legitimately has nothing to record, so a backfilled
zero there is the true value, not a gap. Counting all files would fire this
warning on ~10k benign/HF files and train people to ignore it." An A5 run has no
STD and no TCAM attack, so `std_send_gt = 0` there is a *measurement*, not a gap.

**The real failure mode** is narrower than "a missing column": it is a family's
**own** GT column being absent or all-zero, because `y_indep` is built from it
(`make_windows`, lines 265-270) and a backfilled zero silently yields an
all-negative label. That is what item 4 catches — and it is the only thing that
should stop you.

**Measured on this machine 2026-08-31 — all four PASS:**

| check | result |
|---|---|
| A5-A8 coverage | 5 variants × 5 pct × 5 seeds, 6400 files |
| `hf_send_gt` on A5-A8 | present, nonzero 15-115 / 298 rows (A5/6/7/8 @60% seed1) |
| `std_send_gt` on A1/A2 | present (19-col), nonzero 62/298 |
| `tcam_send_gt` on A3/A4 | present (20-col) |

**Still a genuine NO-GO:** a 16-col header (predates `hf_send_gt` entirely — the
preprocessor warns and HF labels fall back to `zkp_delay_fail|zkp_hop_fail`), or
a family's own GT column reading all-zero. The other machine's A0-A4-only copy
with a `delta_exceed` column at position 13 matches no documented format and
remains NO-GO.

---

## 3. Minutes 15-45 — dry-run step 1 only

Do **not** launch the full pipeline yet.

```bash
cd lstm_pipeline/src
python pipeline.py            # let step 1 finish, then interrupt
```

Then check what step 1 produced:

```bash
python3 -c "
import numpy as np, json
X=np.load('../preprocessed/train_X.npy'); y=np.load('../preprocessed/train_y_indep.npy')
print('X shape:', X.shape, '<- last dim MUST be 11')
print('label balance: %.1f%% positive' % (100*y.mean()))
print('scaler features:', json.load(open('../scaler_params.json')).get('features'))
"
```

**Filename corrected 2026-08-31:** the label file is `train_y_indep.npy`, not
`train_yi.npy` ([`preprocessor.py:459`](../lstm_pipeline/src/preprocessor.py)).
The old name throws `FileNotFoundError`, which mid-window reads as a pipeline
failure when the pipeline is fine.

Note the train split holds **all** variants for seeds 1-3 — only the *scaler* is
benign-only (`fit_scaler`, line 181). So a positive balance well above 0% is
expected here; a 0% reading means the split, not the scaler, is wrong.

**Pass criteria:**

- `X.shape[-1] == 11`
- Label balance roughly **30-45% positive**. If it reads ~99%, you are on
  `y_binary` not `y_indep` — that is the known `TN=0` problem and the numbers
  will be meaningless
- `scaler_params.json` lists 11 feature names ending in `delta_t_exceeded`

This 30 minutes is what protects the remaining 11 hours. Every failure mode hit
today — stale headers, missing columns, a flag that was never CLI-exposed —
would have surfaced right here.

---

## 4. Hours 0:45-3:30 — train, skipping the grid search

**Skip step 2** — but not for the reason originally given here.

**Corrected 2026-08-31 (HPC).** This section claimed `hparams.json` has
`grid_mcc` ~0.98 for all 64 RSUs. **It does not.** Measured across all 64 keys:
**mean 0.4664, min -0.2287** — several RSUs sit at *negative* MCC, i.e. worse
than chance. The ~0.98 figure is RSU 0's value (0.9834), which is what you get
if you eyeball the first entry. Do not repeat "grid_mcc ~0.98" to the
supervisor; it is a per-RSU spread with a long bad tail, and that tail is
itself a finding worth reporting.

The **real** reason step 2 is skippable tonight is stronger. Re-running step 1
with the latch changes **only `y_indep`** — verified byte-for-byte on this
machine: `{train,val,test}_{X,y,y_multi,meta}.npy` are all identical to the
pre-latch build; only `*_y_indep.npy` differs. And `local_trainer.py` selects on
`_y.npy` (`y_binary`), not `y_indep` (line 45). So:

- the **autoencoder** path (`local_trainer` → `fed_aggregator` → `global.pt`)
  is **unaffected by the latch**. Existing `rsu_*.pt` / `global.pt` stay valid;
  steps 2 **and 3** are both unnecessary for §6b
- only the **classifier head** (§6a) trains on `y_indep` and genuinely needs a
  retrain

This means **§6b can run immediately against the existing `global.pt`** rather
than waiting on the 2h45m in this section. Do §6b first — it is the
highest-confidence win and it is not blocked by anything.

```bash
python pipeline.py --from-step 3      # fed_aggregator -> evaluator
```

Run the above only if you want the autoencoder numbers refreshed end-to-end;
it is **not** a prerequisite for §6b.

```bash
python pipeline.py --from-step 3      # fed_aggregator -> evaluator
```

Step 3 is `fed_aggregator.py --gamma_factor 2.0` (BRFA-v2: trust gate + hash
verify + Krum). Step 4 is `evaluator.py`.

If a step fails, resume from that step rather than restarting:
`python pipeline.py --from-step N`.

---

## 5. Hours 3:30-4:15 — export and verify the weights

```bash
python export_weights_cpp.py
python gen_cpp_validation_case.py
```

Then run **section 5 of `docs/LSTM_RETRAIN_GUIDE.md`** (the local verify). Do not
skip it: that guide already caught one hardcoded assertion in
`export_weights_cpp.py` that asserted the OLD 7-feature list. Assume there is a
second bug of that kind and let the verify find it.

`lstm_inference.h`'s `lstm_normalize_features()` aborts loudly on a feature-count
mismatch rather than zero-padding, so a wrong `n_features` in the exported file
will fail fast at simulation time — but only if you actually run a sim.

---

## 5b. CRITICAL — two flags you must set (they ARE CLI-settable here)

Added 2026-08-31 evening. **Corrected on the HPC machine the same night: both
flags are already registered with `cmd.AddValue` at
[`crypto_layer.h:2127-2131`](../scratch/crypto_layer.h), so
`--enable_lstm_cls=1 --enable_hf_theta=1` works from the command line. No
`crypto_layer.h` edit and no rebuild are required for them.**

They do both still default to `false`, so they must be passed explicitly — that
part of the warning stands. The original text said they had no `AddValue`
registration and needed a source edit; that was true of the tree the runbook was
written on, not this one. Per §11, treat every C++-side claim in this document
the same way: **check the source before acting on it.**

| flag | gates | why it matters tonight |
|---|---|---|
| `enable_lstm_cls` | the **classifier head** — needs a `lstm_weights_cpp.bin` exported from a checkpoint containing `fc_cls`; per-RSU threshold from `cls_theta.json`, else falls back to the reconstruction path **with only a warning** | this IS section 6a. Left off, you evaluate the autoencoder you were trying to replace |
| `enable_hf_theta` | per-variant HF thresholds from `hf_theta.json`, applied when `active_attack_variant` is 4-7 | this IS section 6b. Left off, A6 stays at FPR ~76% |

The silent-fallback behaviour on `enable_lstm_cls` is the trap: if the export
lacks `fc_cls` you get a warning and autoencoder numbers, not an error. **Check
the warning line before trusting any classifier result.**

This only affects **in-simulator** evaluation. The Python training and
calibration in sections 2-4 do not read these flags.

---

## 6. Hours 4:15-7:30 — the results work (highest value)

Two things, in **one pass**, because they share a retrain:

### 6a. Classifier head (this is the biggest available win)

The accuracy ceiling was diagnosed on 2026-08-31: **the autoencoder is the
bottleneck**, not the features and not federation. Same features under GBM score
**0.95**; the autoencoder delivers ~0.82. `train_cls_head.py` and a calibrated
`cls_theta.json` already exist.

This is also the best shot at the **A1/A2 detection collapse (DR 2.7% / 4.6%)**,
which is the worst pair of numbers in the thesis. Fix 3 tried to solve it with a
feature change against the autoencoder and moved DR by 1-2 points. A
discriminative head on features whose best single-feature rule already scores
MCC 0.794 against the leak-free label should do substantially better.

### 6b. Per-variant theta + latch, combined

- Compute mu and sigma **separately per variant per RSU**. Never pool A5/A6/A7/A8
  quiet windows before fitting
- Deployed threshold: `theta_HF^(k) = max` across the four per-variant thetas.
  Variant-aware in construction, variant-blind in application — no attack label
  reaches the detector at inference
- Enable the latch at the same time: `MOBIGUARD_HF_LATCHED=1`
- Report **which variant binds** the max at each RSU (do not assume it is always
  A6)
- Report FPR / DR / MCC for all four variants **under the single combined
  threshold**
- Keep per-variant thresholds as a separate, clearly labelled diagnostic table

Expected from the earlier diagnosis: A6 FPR 76.3% -> 8.3%, MCC 0.304 -> 0.707.

---

## 7. Hours 7:30-12:00 — evaluate, then stop

Produce and save:

- DR / FPR / MCC for A5-A8 under the single max-theta
- Which variant binds at each RSU
- The per-variant diagnostic table, labelled as such
- Classifier-head vs autoencoder comparison on the same test split

**Reserve the last 2 hours as buffer.** Something will go wrong.

---

## 8. If verification fails — the pivot

Do **not** start a re-collection. Instead:

1. Apply **per-variant theta calibration only** — it needs no retrain, it works
   on existing scores, and it alone delivers the A6 improvement (MCC 0.304 ->
   0.707)
2. Report the existing autoencoder numbers with that calibration
3. Defer the classifier head and the 11-feature retrain, and say clearly in the
   report that they are deferred and why

That still gives the supervisor most of what he asked for.

---

## 9. Traps — every one of these bit someone today

- **Do not rebuild while a simulation is running.** `./waf build` overwrites the
  binary. Wait for the run to finish. (This happened today and straddled two
  measurements across a code change.)
- **Do not use `&` inside a backgrounded command.** It orphans the job and
  reports false completion. Use a proper wait loop on a sentinel file.
- **Do not read a CSV while its run is still writing.** Check the process is gone
  first. Mid-write reads today produced `total_malicious = 0` and looked like a
  real result.
- **Do not trust a doc's numbers without re-measuring.** Three items from the
  2026-07-29 priority list (S5/S7 FPR 37%, witness causal-order violations,
  batch-verification failures) all measure **zero** now. Two more were already
  fixed. Measure before fixing.
- **Do not compare against pre-2026-08-31 A4 numbers.** The A4 quarantine leak
  was fixed today; both arms of that A/B moved. Old A4 figures are not
  comparable.
- **Check `git log` before assuming a binary is current.** A stale binary
  silently voided an entire A/B comparison earlier today. Confirm the binary is
  newer than the commits it depends on.

---

## 10. What to send back

1. The verification output from section 2 (so the other machine knows the data
   state)
2. Combined A5-A8 numbers under the new threshold construction **and** the latch
3. Which variant binds the max threshold at each RSU
4. Classifier head vs autoencoder on the same split
5. Anything that failed, with the actual error text rather than a summary

---

## 11. Context: what changed on the other machine today

**You do NOT need a `git pull` to do the work in this runbook.**

Sections 2-7 (verify -> preprocess -> train -> export -> classifier head ->
per-variant theta) are **pure Python operating on CSVs that already exist on this
machine**. `pipeline.py` only shells out to other Python scripts -- it never
touches `waf`, `routing.cc`, or the ns-3 build. Step 5's verify is a standalone
`g++` compile of `lstm_inference_test.cpp`, which needs no ns-3 build either.

So if you cannot pull, **proceed anyway**. Nothing below blocks you.

The commits are listed only so you know what changed elsewhere and why any
C++-side numbers quoted to you may not match what this machine would produce.

Branch `n11`, four commits:

| commit | what |
|---|---|
| `4db2532` | LRAD HMAC keyed by (node, flow, packet); `eq:hmac_light` nonce implemented |
| `cd6d626` | UCR: `H(p)` SHA3-512 packet identity + `\|P_total\|` fix (the A8 "rise and fall" was a saturation artefact, not quarantine) |
| `c121cde` | `eq:delay_evidence` implemented — controller trust now reacts to S1 timing evidence |
| `78244a0` | Docs: bug inventory, HMAC modelling note |

Uncommitted on that machine at time of writing: the A4 vehicle-attacker
quarantine fix (`tcam_detection.h`), M4 population-count CSV columns, and
`--trust_t_min` / `--trust_delta_p` / `--trust_delta_r` CLI flags.

Full detail: `docs/BUGS_MISMATCHES_AND_OPEN_DOUBTS_2026-08-31.md`.
