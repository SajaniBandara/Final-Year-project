# Threshold Calibration — Handoff

**Written:** 2026-08-06
**Purpose:** hand threshold calibration over to whoever runs it on the cluster
**Companions:** [`HANDOFF_STATE_2026-08-04.md`](HANDOFF_STATE_2026-08-04.md),
[`LSTM_FULL_PICTURE.md`](LSTM_FULL_PICTURE.md)

---

## 0. TL;DR

**One 5-run benign baseline unblocks three separate calibrations.** That run is not blocked
on anyone — the supervisor explicitly asked for it before making the β decision:

> "Run the baseline first and show us the actual σ_r²(t) convergence curves per β, one plot
> or table per seed. We will make the criterion decision after seeing what the real traces
> show."

Three gating thresholds are currently **uncalibrated** and one was selected by a criterion
that provably does not work. Everything needed to fix that is in this document.

---

## 1. Calibration status of every threshold

The established methodology in this project is **benign 99th percentile, subject to an
FPR ≤ 1 % budget per signal** — that is how `s1_k` and `tcam_util_thresh` were set. Anything
below that bar is listed as uncalibrated.

| Parameter | Value | Location | Gates | Status |
|---|---|---|---|---|
| `s1_delta0` / `s1_alpha_rho` / `s1_alpha_v` | OLS-fitted | `s1_detection.h:81-83` | S1 baseline δ̄_r(t) | ✅ OLS on benign traces, 2026-07-25 |
| `s1_k` | 3.0 | `s1_detection.h:84` | S1 threshold | ✅ smallest k with FPR ≤ 1 % |
| `tcam_util_thresh` | 0.213 | `routing.cc:117873` | **S4** | ✅ benign p99, 2026-07-20 |
| **`s1_beta`** | **0.8** | `s1_detection.h:85` | **S1 variance σ²** | ❌ **selected by a broken criterion — §2** |
| **`VOL_RATE_THRESH`** | **5.0** | `crypto_layer.h:118` | **S7** | ❌ **never calibrated — §3** |
| **`TRUST_DELTA_P` / `_R` / `T_MIN`** | 0.10 / 0.05 / 0.50 | `crypto_layer.h:106-108` | **quarantine** | ❌ **paper calls Δ_p/Δ_r swept; never swept — §4** |
| `WITNESS_F` | 1 (→ 2f+1 = 3) | `crypto_layer.h:117` | witness BFT quorum | ❌ not fitted to vehicle density |
| `WITNESS_WINDOW` | 10.0 s | `crypto_layer.h:116` | witness observation W | ❌ |
| `T_HOLD` | 0.1 s | `crypto_layer.h` | `eq:local_quarantine` | ❌ placeholder; no value in main.tex |
| θ^(k) (LSTM anomaly) | — | offline | LSTM | ⏸ needs the retrain first |
| `lambda_fm_thresh` / `lambda_pi_thresh` | 10.0 / 15.0 | `routing.cc:117871-2` | *nothing* | ⚠️ marked "initial estimate" but **no longer gate S3/S4** — reported only, low priority |
| `S2_DELTA_MAX` | 0.050 s | `s2_detection.h:42` | S2 | ✅ spec value (50 ms), not a calibration target |

**The three that matter are β, `VOL_RATE_THRESH` and the trust triple.** All three gate live
signature or mitigation behaviour, and all three consume the same benign baseline.

---

## 2. β — the important one

### What happened

A β sweep *was* run on 2026-07-25 and moved β from 0.7 to 0.8. **That result is not
trustworthy.**

The selection criterion is: σ_r²(t) must sit within **1 % of its final value for N
consecutive cycles**. On realistic noisy input this essentially never latches — on synthetic
stationary white noise, **no β in {0.7, 0.8, 0.9, 0.95} converges at 1 %; only 0.99 does.**

The old code hid this. On failure it returned `len(series)`, so a β that never converged
scored as if it had converged on the final cycle. Every failing β therefore **tied**, and
`min()` picked one arbitrarily. That is how 0.8 was chosen.

A second, separate bug compounded it: `STABILITY_WINDOW` and the acceptance bound were
**one parameter** (`RSU_ZONE_WINDOW`), used simultaneously as the number of stable cycles
required *and* the search start offset, with the result reported as `i - window`. Raising it
9 → 22 therefore did not "look for convergence within 22 s" — it made the stability test
three times stricter and pushed every β's measured convergence *later*.

### What is already fixed in code

`lstm_pipeline/src/rule_calibrator.py`:

- `STABILITY_WINDOW = 9` and `CONVERGENCE_CEILING = 22` are now **separate** constants
- `ewma_convergence_time()` returns an **absolute cycle index**, and `inf` on failure
- `sweep_beta()` **rejects** any β that fails to converge inside the ceiling, and raises
  `SystemExit` if none qualify — it will no longer silently rank failures
- `CONVERGENCE_TOL = 0.01` is now an explicit named constant with the problem documented at
  its declaration

**So the tooling is honest now. The criterion itself is still unresolved.**

### What you need to do

1. Run the benign baseline (§5)
2. Run the calibrator (§6) — expect it to **reject every β** and exit
3. **That rejection is the result to report.** Produce the σ_r²(t) curves per β per seed and
   send them to the supervisor, who will then choose the criterion

If a criterion decision is needed, the principled alternative is the **EWMA effective
window**, `N_eff = 1/(1−β)`: deterministic, no convergence test required, and β = 0.9 → 10 s,
β = 0.95 → 20 s land naturally inside the 9–22 s band the thesis already uses. **Do not adopt
this unilaterally** — it is a spec decision.

⚠️ Note `s1_detection.h:85`'s inline comment still says *"β sweep: fastest σ²(t) convergence
in 9s window"*. That references the superseded criterion and must be updated once β is
re-selected.

---

## 3. `VOL_RATE_THRESH` — gates S7, never calibrated

```cpp
double VOL_RATE_THRESH = 5.0;   // crypto_layer.h:118
```

Used by `volume_check_anomaly()`:

```cpp
return (curr - prev) / T_SYNC_INTERVAL > VOL_RATE_THRESH;
```

This is the `dVol/dt > ε_vol` conjunct of **S7** (passive hidden forwarding, control plane).
Every other gating threshold in the project was fitted to a benign FPR budget. This one has
no calibration note anywhere in the tree.

**Method (mirror `tcam_util_thresh`):** from the benign baseline, collect the per-destination
delivery-rate deltas `(curr − prev)/T_SYNC_INTERVAL` across all cycles and all seeds, take
the **99th percentile**, and set `VOL_RATE_THRESH` to it. Report the resulting benign FPR and
confirm ≤ 1 %.

This is not currently emitted to CSV. You will need to add a per-cycle dump of the volume
deltas, or instrument `volume_check_anomaly()` to log its left-hand side under a debug flag.

---

## 4. Trust triple — gates quarantine, never swept

```cpp
double TRUST_DELTA_R = 0.05;   // reward
double TRUST_DELTA_P = 0.10;   // penalty
double TRUST_T_MIN   = 0.50;   // quarantine threshold
```

`main.tex:1333` defines Δ_r/Δ_p as *"trust reward increment and trust penalty decrement"*, and
`main.tex:1345` says the controller equivalents are **"swept independently"** — i.e. the
thesis treats these as swept parameters. They have never been swept.

**Why it matters:** trust starts at 1.0, so with Δ_p = 0.10 and T_min = 0.50 a node needs
**6 penalties** to quarantine. Measured 2026-08-06: this is the binding constraint on recall
for the NFA-driven variants (A1/A2/A4), which show **100 % precision but low recall** — the
detector is sound and simply never accumulates enough penalties inside a 20 s attack window.

**⚠️ Methodology warning.** Sweeping these against *attack* MCC is fitting to the test set.
They must be swept on the **benign baseline against an FPR budget**, exactly like `s1_k` and
`tcam_util_thresh`. Raise this with the supervisor before sweeping — it is the difference
between a calibration and a result you cannot defend.

---

## 5. The benign baseline run

**Spec:** 0 % attack, 300 s, 5 seeds. This is the input for §2, §3 and §4.

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
for S in 1 2 3 4 5; do
  ./waf --run-no-build "scratch/routing/routing \
    --routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
    --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --architecture=3 \
    --simTime=300 --attack_percentage=0 --sim_seed=$S --sim_run=$S \
    --training=1" > benign_seed${S}.log 2>&1 &
done
wait
```

Notes:

- **`--attack_percentage=0`** — benign. No `--attack_number`, so the run is baseline.
- **`--training=1`** is required: the calibrator reads the LSTM training CSVs
  (`results_routing/lstm_training/RSU_*/A0_pct0_seed{S}.csv`), which is where `delta_t`,
  `rho` and `v_bar` come from.
- ⚠️ **The logger APPENDS** (`lstm_logger.h`, `std::ios::app`). Move
  `results_routing/lstm_training/` aside first, or old rows mix into the new baseline and
  nothing downstream will flag it.
- **Estimated runtime: ~5–6 hours** for 5 parallel lanes. Extrapolated from a measured
  8 × 30 s sweep at 2,872 s wall; benign runs are somewhat cheaper (no attack machinery).

### Integrity check after the run

```bash
BASE=~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training
for f in $BASE/RSU_*/A0_pct0_seed*.csv; do
  d=$(awk -F, 'NR>1{print $1}' "$f" | sort -n | uniq -d | wc -l)
  [ "$d" -gt 0 ] && echo "DUPLICATE CYCLES: $f"
done
```

Silence = clean. Any output means that file holds more than one run.

---

## 6. Running the calibrator

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35/final\ yr\ project\ updated/Final-Year-project
python3 lstm_pipeline/src/rule_calibrator.py \
    --data-dir ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training \
    --val-fraction 0.3
```

Outputs:

- `lstm_pipeline/calibrated_params.json`
- `lstm_pipeline/calibration_report.txt`

Sweep spaces (`rule_calibrator.py:44-46`):

```python
BETA_CANDIDATES = [0.7, 0.8, 0.9, 0.95]
K_CANDIDATES    = [1.0, 2.0, 3.0]
PERTURBATIONS   = [0.10, 0.20, 0.30]   # robustness check
```

**Expect the β stage to fail with `SystemExit`.** That is correct behaviour, not a bug — it
means no candidate converged inside `CONVERGENCE_CEILING` at 1 % tolerance. Capture the
message and the per-β curves; that is exactly the evidence the supervisor asked for.

If you need the run to complete past the β stage to get the OLS and k-sweep outputs,
temporarily raise `CONVERGENCE_TOL` — but **record the value you used** and do not commit it
as the new default.

---

## 7. What to report back

1. **σ_r²(t) convergence curves per β, per seed** — the supervisor's explicit request
2. **Whether any β converges at 1 %**, and at what tolerance the first one does
3. **`VOL_RATE_THRESH` benign p99** and the resulting FPR
4. **Trust-triple sweep on benign FPR** (only after the supervisor confirms the methodology
   in §4)
5. The `calibration_report.txt` verbatim

---

## 8. Decisions needed from the supervisor

| # | Question | Blocks |
|---|---|---|
| 1 | β criterion — keep 1 % tolerance, loosen it, or switch to `N_eff = 1/(1−β)`? | β; the `s1_detection.h:85` comment |
| 2 | Is a benign-FPR sweep of Δ_p/Δ_r/T_min acceptable, and what is the budget? | §4 |
| 3 | `T_hold` has no value in main.tex — what should it be? | `eq:local_quarantine` |
| 4 | Should `WITNESS_F`/`WITNESS_WINDOW` be fitted to vehicle density, or left as spec constants? | witness BFT |

**Item 1 is the only one that blocks the baseline *result*; the baseline *run* itself is not
blocked by anything. Start it.**

---

## 9. Do not do these

- **Do not tune any threshold against attack MCC.** Every calibration in this project is
  fitted to a benign FPR budget. Tuning on attack data is fitting to the test set and will
  not survive examination.
- **Do not commit a changed `CONVERGENCE_TOL`** as the new default without the supervisor's
  decision on item 1.
- **Do not re-run calibration on the old training CSVs.** They carry the defects documented
  in `LSTM_FULL_PICTURE.md` §4 — collect fresh benign data per §5.
- **Do not skip the append check** in §5. It is silent when it fails.
