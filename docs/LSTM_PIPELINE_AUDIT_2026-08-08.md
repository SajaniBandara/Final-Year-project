# LSTM / Federated Pipeline — Audit and Fixes

**Written:** 2026-08-08
**Scope:** does the federated LSTM tier currently work end-to-end?
**Verdict:** the model code and C++ inference are correct. The **data and the artifact chain
around them are not**, and `evaluation_results.json` does not describe the model that is
actually deployed in `lstm_weights_cpp.bin`.
**Companions:** [`LSTM_FULL_PICTURE.md`](LSTM_FULL_PICTURE.md),
[`LSTM_RETRAIN_GUIDE.md`](LSTM_RETRAIN_GUIDE.md), [`PENDING_FIXES.md`](PENDING_FIXES.md)

---

## 0. Summary table

| # | Finding | Severity | Fix in this doc |
|---|---|---|---|
| 1 | C++ ↔ PyTorch forward pass is numerically exact | ✅ working | — |
| 2 | The parity **gate** always fails for a bogus reason; `validation_case.bin` is 7-feature | **blocker** | §3 |
| 3 | Deployed weights and local eval artifacts are from two different runs | **blocker** | §5 |
| 4 | Deployed per-RSU thresholds are pathological (25 of 64 at θ ≥ 800) | **blocker** | §5 |
| 5 | Training seeds contain no A1–A4 at all | **high** | §6 |
| 6 | Seeds 6/7/8 — the only full percentage sweep — silently discarded | **high** | §4 |
| 7 | `preprocessor.py` cannot load the current data at all | **high** | §4 |
| 8 | Run lengths mixed (4 … 88 cycles) across the collection | **high** | §6 |
| 9 | Five of ten features dead in the deployed scaler | medium | §6 |
| 10 | `tab:lstm_detection` reports the **validation** split under a "Held-Out Test Split" caption | **blocker** | §9 |
| 11 | Live inference is off by default; no launcher passes `--enable_lstm_inference=1` | **high** | §8.1 |
| 12 | Training CSVs are written to a directory `preprocessor.py` does not read | **high** | §8.3 |
| 13 | `MOBIGUARD_*.csv` has no LSTM-specific column — D_LSTM is unseparable there | medium | §8.2 |

---

## 1. What is verified working

The hand-rolled C++ forward pass in `scratch/lstm_inference.h` matches PyTorch exactly.
Regenerating a 10-feature validation case from the current `models/global.pt` and running the
standalone harness against the committed `lstm_weights_cpp.bin`:

```
Loaded weights: n_features=10 hidden1=64 hidden2=32 n_rsus_theta=64
anomaly_score: PyTorch=1.38531280  C++=1.38531280  abs_diff=0
max |x_hat_ref - x_hat_cpp| over all (t,f) = 1.7881393e-07
PASS (tolerance=1e-03)
```

Also sound, and worth not disturbing:

- The autoencoder trains **benign-only** (`meta[:,1] == 0` in `local_trainer.py`) — correct
  discipline for a reconstruction-error detector.
- The seed-partitioned split *concept* (no window leaks across train/val/test).
- `evaluation_results.json` (test, seed 5) is kept separate from `evaluation_results_val.json`
  (val, seed 4). The val file is optimistically biased — hparams **and** θ are both selected on
  it — and must never be the reported number. Compare A1: val MCC 0.939 vs test MCC 0.655.

---

## 2. The two artifact sets are not the same run

This is the finding that invalidates every currently quoted LSTM number.

| Artifact | mtime | Provenance |
|---|---|---|
| `models/*.pt`, `lstm_weights_cpp.bin`, `calibrated_params.json` | Aug 8 | commits `124b665` / `3a14fb7`, retrained on another machine |
| `preprocessed/`, `scaler_params.json`, `fed_summary.json`, `hparams.json`, `evaluation_results.json` | Jul 31 | this machine — **all gitignored**, so they never sync |

They disagree concretely:

| Quantity | In `lstm_weights_cpp.bin` | In local JSON |
|---|---|---|
| `lambda_PI` scaler | μ = 4.5719, σ = 14.3205 | μ = 0.0, σ = 1.0 (`scaler_params.json`) |
| `d_div` scaler | μ = 1.0, σ = 1.0 (dead) | μ = 1.0122, σ = 0.3382 |
| `a_tp` scaler | μ = 1.0, σ = 1.0 (dead) | μ = 0.9988, σ = 0.0321 |
| per-RSU θ | median **368.94**, max **952.87** | 0.38 – 0.67 (`fed_summary.json`) |
| global θ | **445.92** | **0.83** |

**Consequence:** `evaluation_results.json` (overall MCC 0.802 / DR 0.890) is the *Jul-31* model's
report card. Nothing on disk evaluates the weights the simulation actually loads.

Reproduce:

```bash
cd lstm_pipeline
python3 - <<'EOF'
import struct, json, numpy as np
b = open('lstm_weights_cpp.bin','rb').read(); off = 4
n, h1, h2, nf = struct.unpack('<IIII', b[off:off+16]); off += 16
for s in [(4*h1,nf),(4*h1,h1),(4*h1,),(4*h1,),(4*h2,h1),(4*h2,h2),(4*h2,),(4*h2,),
          (4*h1,h2),(4*h1,h1),(4*h1,),(4*h1,),(4*h1,h1),(4*h1,h1),(4*h1,),(4*h1,),
          (nf,h1),(nf,)]:
    off += int(np.prod(s))*4
theta = np.frombuffer(b[off:off+n*4], dtype='<f4'); off += n*4
gt = struct.unpack('<f', b[off:off+4])[0]; off += 4
mu = np.frombuffer(b[off:off+nf*4], dtype='<f4'); off += nf*4
sd = np.frombuffer(b[off:off+nf*4], dtype='<f4')
print('theta quantiles', np.round(np.quantile(theta,[0,.25,.5,.75,1]),3), 'global', gt)
print('bin mu ', mu); print('bin std', sd)
sc = json.load(open('scaler_params.json'))
print('json mu ', [sc['mu'][f]  for f in sc['features']])
print('json std', [sc['std'][f] for f in sc['features']])
print('fed_summary global_theta', json.load(open('fed_summary.json'))['global_theta'])
EOF
```

### 2.1 The deployed thresholds are pathological

θ distribution in the committed `.bin`: 17 below 10, 8 between 10 and 100, **39 at or above 100,
25 at or above 800** — against benign reconstruction errors of ≈ 0.7 under the `.bin`'s own
scaler. Those 25 RSUs can never fire.

Scoring the committed `global.pt` with the committed θ (after undoing the Jul-31 normalisation
and re-applying the `.bin`'s scaler, so the comparison is apples-to-apples):

```
val : benign err mean 0.726  DR 0.229  FPR 0.0175  MCC 0.351
test: benign err mean 0.683  DR 0.241  FPR 0.0159  MCC 0.369
```

versus the reported DR 0.890 / MCC 0.802.

⚠️ **Caveat on that number.** It was measured against the *Jul-31* windows, which are not the
Aug-8 training distribution, so treat 0.24/0.37 as indicative rather than as the replacement
figure. What it is *not* sensitive to: a θ of 900 against errors of ≈ 0.7 cannot be correct on
any dataset. The θ blowup implies σ_A ≈ 260 for those RSUs, i.e. extreme outliers in the
calibration population — most plausibly the mixed run lengths of §6.3.

---

## 3. Fix 1 — repair the C++/Python parity gate

**Do this first.** It is cheap, self-contained, and it is the only thing standing between a bad
export and the live simulation. It also *detects* the §2 scaler mismatch automatically once
fixed.

### 3.1 Why it fails today

```
$ ./lstm_test lstm_pipeline/lstm_weights_cpp.bin lstm_pipeline/validation_case.bin
FAIL: normalization mismatch
normalize_features max diff vs Python reference = 4.0781536
```

Two independent staleness bugs:

1. `scratch/lstm_inference_test.cpp` hardcodes a **7-feature** raw vector and its expected
   normalised form, from the scaler in force before the 2026-07-26 7→10 feature expansion. It
   fails unconditionally and returns *before* the forward pass ever runs — so the check that
   matters is never reached.
2. `lstm_pipeline/validation_case.bin` is itself 7-feature (`W,F = (10, 7)`; 576 bytes =
   16 + 2·10·7·4). It cannot validate a 10-feature model.

Confirm both:

```bash
python3 -c "import struct; b=open('lstm_pipeline/validation_case.bin','rb').read(); \
print(b[:4], struct.unpack('<II', b[4:12]))"
# -> b'MGV1' (10, 7)      <-- must be (10, 10)
```

### 3.2 Fix step A — regenerate the validation case

`gen_cpp_validation_case.py` already imports `N_FEATURES` from `lstm_model.py` (= 10), so no
code change is needed for the dimension. It just has not been re-run since July. Its docstring
still says `n_features : uint32 (= 7)` — correct that while you are in there.

```bash
cd lstm_pipeline/src && python3 gen_cpp_validation_case.py
python3 -c "import struct; b=open('../validation_case.bin','rb').read(); \
print(struct.unpack('<II', b[4:12]))"   # must now print (10, 10)
```

### 3.3 Fix step B — make the normalisation check data-driven

The hardcoded vector is the actual defect: it will go stale again on the next feature or scaler
change. Make the validation case carry the normalisation reference too, so Python and C++ are
never able to drift apart silently.

Bump the format to `MGV2` and append two more blocks after `anomaly_ref`:

```
  ... existing MGV1 layout ...
  anomaly_ref  : 1 float32
  -- new in MGV2 --
  raw[n_features]       : float32   a fixed RAW (unnormalised) feature vector
  norm_ref[n_features]  : float32   Python's (raw - mu)/std using scaler_params.json
```

In `gen_cpp_validation_case.py`, read `scaler_params.json` and emit those two blocks:

```python
SCALER_PATH = REPO / "lstm_pipeline" / "scaler_params.json"
...
sc  = json.load(open(SCALER_PATH))
mu  = np.array([sc["mu"][f]  for f in sc["features"]], dtype=np.float64)
std = np.array([sc["std"][f] for f in sc["features"]], dtype=np.float64)
assert len(sc["features"]) == N_FEATURES, \
    f"scaler has {len(sc['features'])} features, model has {N_FEATURES}"

# Fixed raw probe vector — same RNG discipline as x_np: reproducible, not
# random per-run. Values are in raw feature units, NOT normalised.
raw      = rng.uniform(0.0, 2.0, size=N_FEATURES).astype("float32")
norm_ref = ((raw.astype(np.float64) - mu) / std).astype("<f4")

with open(out_path, "wb") as f:
    f.write(b"MGV2")                                   # was b"MGV1"
    f.write(struct.pack("<II", WINDOW, N_FEATURES))
    f.write(x_np.astype("<f4").tobytes())
    f.write(x_hat_np.tobytes())
    f.write(struct.pack("<f", anomaly_val))
    f.write(raw.astype("<f4").tobytes())               # new
    f.write(norm_ref.tobytes())                        # new
```

In `scratch/lstm_inference_test.cpp`, accept either magic and replace the hardcoded block
(currently the `std::vector<float> raw = {0.0025f, ...}` / `expected = {...}` pair) with a read
of those blocks. Keep the check **skippable** for an MGV1 case so old artifacts still exercise
the forward pass rather than aborting:

```cpp
    char magic[4];
    vf.read(magic, 4);
    const bool has_norm_block = (std::memcmp(magic, "MGV2", 4) == 0);
    if (std::memcmp(magic, "MGV1", 4) != 0 && !has_norm_block)
    {
        std::fprintf(stderr, "FAIL: bad magic in validation case\n");
        return 1;
    }
    ...
    // (after reading x, x_hat_ref, anomaly_ref)
    if (has_norm_block)
    {
        std::vector<float> raw(n_features), norm_ref(n_features);
        vf.read(reinterpret_cast<char*>(raw.data()),      n_features * sizeof(float));
        vf.read(reinterpret_cast<char*>(norm_ref.data()), n_features * sizeof(float));
        auto norm = lstm_normalize_features(model, raw);
        float max_norm_diff = 0.0f;
        for (size_t i = 0; i < norm_ref.size(); ++i)
            max_norm_diff = std::max(max_norm_diff, std::fabs(norm[i] - norm_ref[i]));
        std::printf("normalize_features max diff vs Python reference = %.8g\n", max_norm_diff);
        if (max_norm_diff > 1e-4f)
        {
            std::fprintf(stderr,
                "FAIL: scaler in weights.bin disagrees with scaler_params.json — "
                "the .bin was exported from a different preprocessing run\n");
            return 1;
        }
    }
    else
    {
        std::printf("NOTE: MGV1 case, no normalisation block — skipping scaler check\n");
    }
```

That failure message is the §2 bug. With this in place, exporting a `.bin` whose embedded scaler
does not match the `scaler_params.json` the model was trained under becomes a hard, loud failure
instead of a silent 3× degradation in the live path.

### 3.4 Verify

```bash
g++ -O2 -std=c++17 -I scratch scratch/lstm_inference_test.cpp -o /tmp/lstm_test
/tmp/lstm_test lstm_pipeline/lstm_weights_cpp.bin lstm_pipeline/validation_case.bin
echo "exit=$?"    # 0 = PASS
```

Against the currently committed `.bin` this is **expected to fail** on the new scaler check —
that is the correct outcome, and it is §5's problem, not a bug in the gate.

---

## 4. Fix 2 — make `preprocessor.py` able to load the data

Three independent problems. Today the pipeline cannot be re-run end-to-end at all.

### 4.1 Filename mismatch — 0 files found

`load_all_csvs()` globs `RSU_*/Attack*_seed*.csv` and `FNAME_RE` expects
`Attack{v}_{pct}[_d{X}ms]_seed{s}`. Every one of the 4,160 files on disk is named
`A{N}_pct{P}_seed{S}.csv`:

```bash
B=~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training
find $B -name '*.csv' | wc -l                       # 4160
find $B -name '*.csv' -exec basename {} \; | sort -u | head -3
# A0_pct0_seed1.csv
# A0_pct0_seed2.csv
# A0_pct0_seed3.csv
python3 -c "import sys; sys.path.insert(0,'lstm_pipeline/src'); import preprocessor as p, glob; \
print(len(glob.glob(str(p.BASE/'lstm_training'/'RSU_*'/'Attack*_seed*.csv'))))"   # 0
```

Note the direction: `scratch/lstm_logger.h:846-854` **does** currently write `Attack{N}_...`, so
a fresh collection would parse. It is the existing dataset that is out of sync — it predates
commits `162b52e` / `d080aaf`. The preprocessor must read both, or the 4,160 files already
collected are unusable.

Replace the single regex with a tolerant pair:

```python
# Both namings are in the wild: the current logger writes Attack{N}_{pct}[_d{X}ms]_seed{S}
# (lstm_logger.h:846-854, post-162b52e), while everything collected before that commit is
# A{N}_pct{P}_seed{S}. Accept both rather than silently globbing zero files.
FNAME_RES = [
    re.compile(r"^Attack(?P<attack_v>\d+)_(?P<pct>\d+)(?:_d\d+ms)?_seed(?P<seed>\d+)$"),
    re.compile(r"^A(?P<attack_v>\d+)_pct(?P<pct>\d+)(?:_d\d+ms)?_seed(?P<seed>\d+)$"),
]


def parse_run_name(stem: str):
    for rx in FNAME_RES:
        m = rx.match(stem)
        if m:
            return int(m.group("attack_v")), int(m.group("pct")), int(m.group("seed"))
    raise ValueError(f"Unrecognized lstm_training filename shape: {stem}")
```

and in `load_all_csvs()`:

```python
    pattern = str(lstm_dir / "RSU_*" / "A*_seed*.csv")   # covers Attack* and A*_pct*
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No CSVs found at {pattern}")
    for path in files:
        p = Path(path)
        attack_v, pct, seed = parse_run_name(p.stem)
```

### 4.2 Missing `hf_send_gt` column

Every header on disk is the 16-column vintage:

```bash
head -1 $B/RSU_0/A2_pct60_seed6.csv
# cycle,rsu_id,delta_t,lambda_PI,U_TCAM,zkp_delay_fail,zkp_hop_fail,rho,v_bar,
# d_div,a_tp,r_anom,escalated,label,lstm_anomaly_score,d_lstm
```

`preprocessor.py:207` reads `df["hf_send_gt"]` for the A5–A8 spike criterion → `KeyError` even
once §4.1 is fixed. Note `lstm_migrate_stale_header()` only upgrades files at *write* time, so it
never touches an already-closed collection.

Default it, but say so loudly — an absent `hf_send_gt` means HF ground truth falls back to the
`zkp_*` half of the OR only, which is exactly the signal §4/defect A of `LSTM_FULL_PICTURE.md`
had to fix:

```python
    if "hf_send_gt" not in df.columns:
        n_missing += 1
        df["hf_send_gt"] = 0
...
    if n_missing:
        print(f"  WARNING: {n_missing}/{len(files)} files predate the hf_send_gt column "
              f"(16-col header). HF (A5-A8) window labels fall back to zkp_delay_fail|"
              f"zkp_hop_fail only — see LSTM_FULL_PICTURE.md §4 defect C.")
```

### 4.3 Seeds assigned to no split are silently discarded

`TRAIN_SEEDS = {1,2,3}`, `VAL_SEEDS = {4}`, `TEST_SEEDS = {5}`. The split loop uses
`np.isin(meta[:,3], list(seed_set))`, so **any seed outside 1–5 is dropped with no message**.

Seeds 6, 7 and 8 are on disk and hold the only full percentage sweep in the entire collection —
`A2` at 0/20/40/60/80/100. All of it is currently thrown away. (`split_indices()` at line 159 is
dead code and can go.)

```python
ALL_SPLIT_SEEDS = TRAIN_SEEDS | VAL_SEEDS | TEST_SEEDS
...
    orphan = sorted(set(df["seed"].unique().tolist()) - ALL_SPLIT_SEEDS)
    if orphan:
        raise SystemExit(
            f"Seeds {orphan} are present in {lstm_dir} but belong to no split "
            f"(TRAIN={sorted(TRAIN_SEEDS)} VAL={sorted(VAL_SEEDS)} TEST={sorted(TEST_SEEDS)}). "
            f"They would be silently discarded. Assign them to a split or pass "
            f"--allow-orphan-seeds to drop them deliberately.")
```

with `--allow-orphan-seeds` downgrading it to a printed warning. Failing loudly is the point: the
current behaviour is why nobody noticed that the newest collection never reached the model.

**Where seeds 6–8 should go is a judgement call, not a mechanical one.** They are A2-only, so
adding them to `TRAIN_SEEDS` gives the autoencoder more benign data (their `A0` runs) without
touching the class balance, since training is benign-only. That is probably right, but it
changes what θ is calibrated against and should be decided together with §6.

### 4.4 Verify

```bash
cd lstm_pipeline/src && python3 preprocessor.py
# expect: non-zero "Loaded N rows", a per-split line for train/val/test, and either
# a clean run or the explicit orphan-seed SystemExit above — never a silent 0.
```

---

## 5. What must happen before any LSTM number is quotable again

Neither artifact set from §2 can be trusted on its own, so pick one and make it whole.

1. **Decide which model is canonical.** Either (a) re-run `evaluator.py` against the committed
   `models/global.pt` using the `.bin`'s scaler and a matching preprocessing run, or (b) discard
   the Aug-8 weights and re-export from the Jul-31 model. Do not mix.
2. **Un-gitignore the provenance.** `fed_summary.json`, `scaler_params.json`, `hparams.json` and
   `evaluation_results.json` are all in `lstm_pipeline/.gitignore`, which is precisely how the
   weights and their evaluation came to disagree without anyone noticing. At minimum
   `fed_summary.json` and `scaler_params.json` must travel with `lstm_weights_cpp.bin` — they are
   *inputs* to the export, not per-run scratch. Alternatively, record a hash of both inside the
   `.bin` and check it at load time.
3. **Investigate the θ blowup** (§2.1) before collecting anything further. σ_A ≈ 260 on 25 RSUs
   is a data defect, not a threshold-formula question, and re-collecting without understanding it
   will reproduce it.

---

## 6. Data-quality findings (feed these into the next collection)

These do not block §3 or §4, but they cap how good the model can get.

### 6.1 No A1–A4 in the training seeds at all

```
train  3136 windows  variants {0: 2880, 5: 64, 6: 64, 7: 64, 8: 64}   147 positives
val    8640 windows  all 9 variants                                  2987 positives
test   8640 windows  all 9 variants                                  2844 positives
```

Seeds 1–3 hold only benign `A0` plus HF (`A5`–`A8`) at 100 %. Because training is benign-only,
the autoencoder itself is not directly harmed — but **hyperparameter selection and θ calibration
never see a delay or TCAM attack**, and both run on the val split.

It shows up exactly where you would predict, in `evaluation_results.json` (test, seed 5):

| Variant | MCC | DR | FPR |
|---|---|---|---|
| A1 CP-SelectiveDelay | 0.655 | 0.486 | 0.001 |
| A2 DP-SelectiveDelay | 0.644 | 0.544 | 0.016 |
| **A3 CP-TCAM** | **0.173** | 0.435 | **0.172** |
| **A4 DP-TCAM** | **0.182** | 0.568 | **0.270** |
| A5–A8 (HF) | 0.968 – 1.000 | 0.975 – 1.000 | 0.000 |

The HF variants — the only attack family present in the training seeds — are near-perfect. A3/A4
are barely better than chance at a 17–27 % false-positive rate. Note that A3/A4 are additionally
excluded from the θ calibration population by design (`local_trainer.py:180-181`,
`fed_aggregator.py`), so they are doubly unrepresented.

### 6.2 Percentage coverage is thin and lopsided

Only `{0, 40, 80, 100}` appear in val/test; the thesis sweep is `{0, 20, 40, 60, 80, 100}`. The
training seeds contain attacks at 100 % only. Against the §3 plan of
8 variants × 6 percentages × 5 seeds = 240 runs, the collection on disk is a partial subset with
A2 over-represented.

### 6.3 Run lengths are mixed — 4 to 88 cycles

```
   4 cycles  A5_pct60_seed4
   9 cycles  A5_pct60_seed1
  13 cycles  A5_pct60_seed5
  18 cycles  A5/A6/A7/A8_pct100_seed1     <-- the entire HF training signal
  35 cycles  A2_pct80_seed7, A2_pct100_seed7
  38 cycles  most A1-A4 runs (simTime=40)
  88 cycles  A0 benign, A5-A8 seed4/5 (simTime=90)
```

`LSTM_FULL_PICTURE.md` §3 warns explicitly: *"Pick one and record it — mixing lengths across the
set will bias per-cycle features."* It was not followed. With `WINDOW=10, STRIDE=5` and the
cycle-0 window dropped, an 18-cycle file yields **one window per RSU** — which is the whole of
the HF attack presence in training (64 windows per variant). This is also the most likely source
of the §2.1 θ blowup.

### 6.4 Five of ten features are dead in the deployed scaler

A σ clamped to 1.0 by `fit_scaler()` means the feature was constant across the benign training
population:

| Feature | Jul-31 scaler | Aug-8 scaler (deployed) |
|---|---|---|
| `lambda_PI` | **dead** (μ 0, σ 1) | live (μ 4.57, σ 14.32) |
| `d_div` | live (σ 0.338) | **dead** (μ 1, σ 1) |
| `a_tp` | live (σ 0.032) | **dead** (μ 1, σ 1) |
| `zkp_delay_fail` | dead | dead |
| `zkp_hop_fail` | dead | dead |
| `r_anom` | dead | dead |

The `lambda_PI`-fixed retrain (`124b665`) **traded two working features for one**. Five of ten
inputs now carry no benign variance.

Caveat on reading this table: `zkp_delay_fail`, `zkp_hop_fail` and `r_anom` are legitimately zero
in *benign* traffic — a σ of 1.0 there reflects the calibration population, not necessarily a
dead feature at inference. `d_div` and `a_tp` are different: they were live on Jul 31 and are
constant now, which is a regression in the data, not a property of benign traffic.

**AB3 (`ab3_feature_ablation.py`) remains invalid** for the same reason `LSTM_FULL_PICTURE.md` §7
gives — it ablates features that carried no signal during training. It must follow a clean
retrain, not precede one.

---

## 7. Ordered plan

| # | Action | Depends on | Doc |
|---|---|---|---|
| 1 | Repair the parity gate (regen case + data-driven scaler check) | nothing | §3 |
| 2 | Fix `preprocessor.py` load path, `hf_send_gt`, orphan seeds | nothing | §4 |
| 3 | Decide the canonical model; stop gitignoring export inputs | 1 | §5 |
| 4 | Root-cause the θ blowup | 2, 3 | §2.1 |
| 5 | Re-collect with a single run length, A1–A4 in the training seeds, full pct sweep | 4 | §6 |
| 6 | Retrain → re-export → parity gate → re-run AB3 | 5 | `LSTM_RETRAIN_GUIDE.md` |

Steps 1 and 2 are self-contained and do not depend on any collection decision.

---

## 8. Live in-sim path — what actually reaches the CSVs

Added 2026-08-08 in response to "will we get live results, and does anything get written?"

### 8.1 The live path is genuinely wired, but off by default

`enable_lstm_inference` defaults to **`false`** (`crypto_layer.h:300`). It must be passed
explicitly:

```bash
./waf --run "scratch/routing/routing ... --enable_lstm_inference=1"
```

None of the launcher invocations in `README.md` or `CLAUDE.md` pass it. A standard run produces
**no LSTM signal at all** — `flag_LSTM` stays `false` and `D_RSU` degrades to the rule-based
signatures only, silently.

When it is on, the chain is complete and matches the paper:

| main.tex | Implementation |
|---|---|
| `sec:fed_lstm` 10 s window, 1 Hz slide | `lstm_logger.h:800-830`, `g_lstm_rsu_window`, `LSTM_WINDOW` |
| `eq:lstm_threshold` per-RSU θ | `mglstm::lstm_detect()`, θ from the `.bin` |
| `eq:theta_adapt` warm-up adaptation | `lstm_theta_adapt_reset()` / `LSTM_WARMUP_S = 30.0` |
| `eq:lstm_gate` S3/S4 suppression | `lrad.h:319-339` |
| `alg:lrad_rsu` D_LSTM into D_RSU | `lrad.h:342` |
| `eq:bc_model_verify` model-hash commit | `lstm_logger_init()`, `bc_commit_model_hash()` |

Weights load from `$HOME/ns3_g13/g13_project_repo/Final-Year-project/lstm_pipeline/lstm_weights_cpp.bin`
(`lstm_weights_bin_path()`). On this machine that file exists and is md5-identical to the repo
copy, so loading succeeds. If it were missing the run does **not** abort — it prints
`[LSTM_INFERENCE] WARNING` and continues with inference silently disabled.

### 8.2 Where live LSTM output lands

Four sinks, only one of which separates the LSTM from the rule-based signatures:

| Sink | Gated on | LSTM separable? |
|---|---|---|
| `MOBIGUARD_Attack<N>_<pct>[_d<X>ms]_seed<S>.csv` | always | ❌ **no** |
| `bc_detection_log_Attack*.csv` | blockchain logging | ✅ yes — `signal_idx = 9` |
| `lstm_training/RSU_*/Attack*_seed*.csv` | `--training=1` | ✅ yes — `lstm_anomaly_score`, `d_lstm` |
| `detector_windows_Attack*.csv` | `--enable_detector_windows=1` | ❌ no (D_RSU-level) |

**The MOBIGUARD CSV has no LSTM column.** `flag_LSTM` reaches it only through
`record_detection_event(active_attack_variant, prev_sender, DSRC_LSTM)` (`lrad.h:409`), which
sets `is_detected_node[][]` and therefore folds into the shared `TP/FP/TN/FN`,
`cur_MCC`/`avg_MCC`, `cur_DR`, `cur_FPR` and `d_rsu_count` columns. Of that file's ~55 columns,
none isolates the LSTM's contribution from `flag_S2f ∨ S5 ∨ S6 ∨ S7 ∨ S8`. If per-signature
attribution is wanted there, a `d_lstm_count` (and ideally `lstm_gate_suppressed_count`, already
tracked as `g_lstm_gate_suppressed_count`) would have to be added to the header at
`routing.cc:117808-117823`.

### 8.3 The training CSV writes to a directory the pipeline does not read

```
lstm_logger.h:421  lstm_make_base_dir() -> /home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/
preprocessor.py:57 BASE                 -> $HOME/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing
```

A fresh `--training=1` run writes to the first path. The 4,160 existing CSVs, and everything
`preprocessor.py` reads, are under the second. **New collection will not be seen by the
pipeline.** This is also why `calibration_report.txt` names a `lstm_training/` directory that
does not exist on this machine.

Per `CLAUDE.md` the HPC path convention is deliberate and must not be committed as "fixed" —
but the two must at least agree with each other. Reconcile before collecting.

---

## 9. `tab:lstm_detection` reports the validation split, not the test split

**This is the most consequential finding in this document.** Every value in
`main.tex:6330-6355` — captioned *"Held-Out Test Split"* — is the **validation** split.

| Variant | main.tex table | `evaluation_results_val.json` | `evaluation_results.json` (**test**) |
|---|---|---|---|
| A1 CP-Selective Delay | 0.939 / 95.70 / 1.90 | **0.939 / 0.957 / 0.0194** | 0.655 / 0.486 / 0.0013 |
| A2 DP-Selective Delay | 0.971 / 98.50 / 1.40 | **0.971 / 0.985 / 0.0144** | 0.644 / 0.544 / 0.0155 |
| A5 CP-ActiveHF | 0.782 / 81.10 / 0.50 | **0.782 / 0.811 / 0.0051** | 0.974 / 0.980 / 0.0000 |
| A6 DP-ActiveHF | 0.900 / 92.60 / 1.00 | **0.900 / 0.926 / 0.0102** | 0.985 / 0.988 / 0.0000 |
| A7 CP-PassiveHF | 0.834 / 86.50 / 0.50 | **0.834 / 0.865 / 0.0052** | 0.968 / 0.975 / 0.0000 |
| A8 DP-PassiveHF | 0.849 / 84.70 / 0.80 | **0.849 / 0.847 / 0.0078** | 1.000 / 1.000 / 0.0000 |
| **Mean (A1–A8)** | 0.831 / 90.80 / 7.80 | **0.831 / 0.908 / 0.0778** | 0.802 / 0.890 / 0.0831 |

Six rows and the mean, matching to three decimals. This is not coincidence.

Why it matters: the val split (seed 4) is where **both** the hyperparameters
(`local_trainer.py`, MCC-selected under an FPR ≤ 1 % constraint) **and** the per-RSU θ
(`fed_aggregator.py`) were selected. Quoting it as held-out is a selection-bias error, and the
gap is not small — A1 MCC falls 0.939 → 0.655 and DR 95.7 % → 48.6 % on the genuinely held-out
seed.

Two further problems with the same table:

1. **A3 and A4 are omitted from the rows but included in the mean.** The row list is A1, A2, A5,
   A6, A7, A8. The "Mean (A1–A8)" label and the 7.80 % mean FPR both come from the overall block,
   which includes A3 (26.3 % FPR) and A4 (14.6 % FPR). That is why the mean FPR is roughly 4×
   larger than any FPR shown in the table — the two variants responsible are invisible.
2. **The dataset scale does not match.** `main.tex:5858` describes the dedup as
   21,504 → 12,288 windows. The current `preprocessed/test_X.npy` holds 8,640 raw windows. The
   table was produced from a different collection vintage than anything now on disk.

`eq:eval_dedup` itself **is** implemented correctly — `evaluator.py:158-181`
(`deduplicate_windows()`) does the 10 s non-overlapping block max-pool the paper specifies, and
`q30_holdout_eval.py:93-104` does the same. That part is fine; it is the split label that is
wrong.

**Action:** either re-caption the table as validation-split (and add A3/A4 rows), or replace it
with the test-split column — but the test column cannot be quoted until §5 resolves which model
the numbers describe. Note `WHICH_MCC_TO_REPORT.md` exists in `docs/` and should be reconciled
with this finding.

---

## 10. Path note

`preprocessor.py:57` resolves `BASE` to `$HOME/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing`
(the canonical cluster convention — correct, and the data is genuinely there on this desktop
too). `calibration_report.txt` however records its data source as
`/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/lstm_training`, a path that **does not
exist on this machine**. That report and `calibrated_params.json` therefore cannot be reproduced
locally as-is. Per `CLAUDE.md`, do not commit a path fix — the repo intentionally keeps the HPC
convention.
