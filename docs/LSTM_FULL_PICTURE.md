# The LSTM Tier — Full Picture

**Written:** 2026-08-06
**Audience:** whoever runs the data collection and retrain (likely on HPC)
**Companions:** [`LSTM_RETRAIN_GUIDE.md`](LSTM_RETRAIN_GUIDE.md) (step-by-step retrain),
[`PENDING_FIXES.md`](PENDING_FIXES.md) (fix history), [`Q4_DIAGNOSTIC_RESPONSE.md`](Q4_DIAGNOSTIC_RESPONSE.md)

---

## 0. Read this first

**Every LSTM number currently in the report is a lower bound produced by a model trained on
partly-broken data.** Three separate defects corrupted the last training set. All three are
fixed in code — and, as of 2026-08-06, all three are **verified working in real data**.

**UPDATE 2026-08-06: the pre-flight in §5 has been RUN and ALL CHECKS PASSED.** All three
defects are now verified fixed in real data. Collection is cleared to start. §5 also records
an append hazard found in the process — read it before collecting.

**Good news that unblocks you:** LSTM data collection does **not** depend on any of the
open detection-layer decisions (the `eq:dup_alert_cond` redesign, the witness scope
question, the Q1–Q6 re-run). Verified 2026-08-06: witness-driven quarantine is inert —
`g_quarantined[]` is written but never read outside its own latch, and nothing in the
forwarding path checks trust. So the witness defect cannot perturb the network the LSTM
learns from. **Collection can start immediately and in parallel with everything else.**

---

## 1. Where it lives

| Piece | Path |
|---|---|
| Feature logger (C++, writes training CSVs) | `scratch/lstm_logger.h` |
| Live inference in-sim | `scratch/routing.cc` + `lrad.h` (`flag_LSTM`) |
| Compiled weights consumed by C++ | `lstm_pipeline/lstm_weights_cpp.bin` |
| Training pipeline (Python) | `lstm_pipeline/src/` |
| Per-RSU + global models | `lstm_pipeline/models/rsu_*.pt`, `rsu_*_global.pt` |

Key pipeline modules: `preprocessor.py`, `local_trainer.py`, `fed_aggregator.py` (BRFA-v2),
`evaluator.py`, `export_weights_cpp.py`, `ab3_feature_ablation.py`, `ab2_centralized_baseline.py`,
`poison_sweep.py` (M8), `brfa_param_sweep.py`, `rule_calibrator.py`.

---

## 2. The feature vector

`eq:lstm_input` — **10 features**, per RSU per 1 Hz cycle:

| # | Column | Meaning |
|---|---|---|
| 1 | `delta_t` | observed forwarding delay |
| 2 | `lambda_PI` | PACKET_IN rate |
| 3 | `U_TCAM` | TCAM utilisation |
| 4 | `zkp_delay_fail` | 1[π_delay = ⊥] |
| 5 | `zkp_hop_fail` | 1[π_hop = ⊥] |
| 6 | `rho` | vehicle density |
| 7 | `v_bar` | mean vehicle speed |
| 8 | `d_div` | delivery divergence |
| 9 | `a_tp` | throughput anomaly |
| 10 | `r_anom` | reception anomaly |

The CSV carries **17 columns** (`LSTM_CSV_HEADER`, `lstm_logger.h:190`):

```
cycle,rsu_id,delta_t,lambda_PI,U_TCAM,zkp_delay_fail,zkp_hop_fail,rho,v_bar,
d_div,a_tp,r_anom,escalated,label,lstm_anomaly_score,d_lstm,hf_send_gt
```

⚠️ **`LSTM_RETRAIN_GUIDE.md` §0 says 16 columns** — it predates `hf_send_gt`. The current
writer emits 17. Check `head -1` on a sample file and reconcile before trusting the
preprocessor's column expectations.

`lstm_logger.h` has `lstm_migrate_stale_header()` which upgrades older 10/13/14/16-column
files at runtime, so mixed-vintage directories are survivable — but verify rather than assume.

---

## 3. Collecting the data

**Flag:** `--training=1` (`routing.cc:142053`). Off by default.

**Output path** (`lstm_logger.h:801-812`, base from `lstm_make_base_dir()`):

```
$HOME/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/RSU_{r}/Attack{v}_{pct}[_d{X}ms]_seed{s}.csv
```

Note `A{v}` is the **proposal attack number**, not the internal variant index —
`attack_v = active_attack_variant + 1`, with benign = `A0`.

**Full example command:**

```bash
./waf --run-no-build "scratch/routing/routing \
  --routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --architecture=3 \
  --simTime=90 --attack_percentage=60 --sim_seed=1 --sim_run=1 \
  --attack_number=2 --attack_delay_ms=80 --attack_delay_pseudo_random=0 \
  --training=1"
```

⚠️ **For A1/A2 you MUST pass `--attack_delay_pseudo_random=0`.** Without it the banded
random draw gives 72–88 ms per packet instead of exactly 80 ms, and the delay feature
becomes noise. This is the same trap `run_q1q6_ablation.py` guards against.

**Scale:** 8 variants × 6 percentages {0,20,40,60,80,100} × 5 seeds = **240 runs**
(`main.tex:5775`).

**Run length — decide before starting.** The previous collection used **90 s**
(`PENDING_FIXES.md`). The thesis default for production runs is **300 s** (`main.tex:5860`).
90 s is cheaper and is what the existing pipeline was tuned against; 300 s matches the rest
of the evaluation. **Pick one and record it** — mixing lengths across the set will bias
per-cycle features.

**Compute estimate** (measured 2026-08-06 on a 16-core desktop: 8 runs × 30 s = 47 min wall
at 8 workers):

| Setup | 240 runs @ 90 s |
|---|---|
| 16-core desktop, 8 workers | **~3 days** |
| HPC, 25 workers | **~1 day** |

**Run it on HPC.** It is long, fully unattended, and blocked on nothing.

---

## 4. The three defects, and their real status

| # | Defect | Effect on last dataset | Code fix | **Verified in a run?** |
|---|---|---|---|---|
| A | `zkp_delay_fail` identically 0 for A2 | zero gradient across all 1,792 rows — the feature was dead | `7307662` (attribution via `hf_gt_attribution_node`) | ✅ **YES — 295 rows, 2026-08-06 (§5)** |
| B | A3/A4 labelled the attacker, not the TCAM victim | A3 had 1 labelled RSU instead of ~26 | `lstm_logger.h` victim-RSU labelling | ✅ **YES — 608 A3 labels (§5)** |
| C | A6/A8 labels missing via covering-RSU fallback | HF labels absent | `7307662` label fallback | ✅ **YES — 889 labels each (§5)**; was previously correct-but-inert |

**Defect C is worth understanding.** The fallback had been shown to map 91/91 vehicles with 0
unmapped — yet produced **zero additional labels**, because in that run every attacker was
already on-path so no covering RSU was clean. It was correct code that had never
demonstrably changed a label. The §5 pre-flight is what finally exercised it: 889 positive
labels on each of A6 and A8. This is why "the fix is committed" and "the fix works" are
different claims, and why §5 must be re-run after any change to labelling or attribution.

---

## 5. Pre-flight — RUN 2026-08-06, ALL CHECKS PASSED ✅

**Result: collection is cleared to start.** Executed on the 16-core desktop, 4 runs
(A2/A3/A6/A8) at 30 s, 60 %, seed 1, 4 workers, ~35 min wall.

| Check | Result | Verdict |
|---|---|---|
| Files written | 256 = 4 variants × 64 RSUs | ✅ |
| CSV header | **17 columns** (incl. `hf_send_gt`) | ✅ (see §2 — the retrain guide's "16" is stale) |
| **A2 `zkp_delay_fail` non-zero** | **295 rows** | ✅ **the dead feature is alive** |
| A6 `zkp_hop_fail` non-zero | 613 rows | ✅ |
| A8 `zkp_hop_fail` non-zero | 440 rows | ✅ |
| A2 positive labels | 2,409 | ✅ |
| A3 positive labels | 608 | ✅ victim-RSU labelling works |
| A6 positive labels | 889 | ✅ |
| A8 positive labels | 889 | ✅ fallback firing for the first time |

**Check 2 is the one that mattered.** `zkp_delay_fail` was identically zero across all 1,792
rows of the previous training set — the dead feature that invalidated it. Commit `7307662`
fixed it, and this is the first run to prove it in data.

**Defect C (§4) is now resolved too.** The A6/A8 covering-RSU fallback had been proven
*correct* but *inert* — it had never actually produced a label. It now yields 889 positives
on each.

### ⚠️ Operational hazard found while doing this: THE LOGGER APPENDS

`lstm_logger.h:816` opens with `std::ios::app`. Re-running any configuration **appends to the
existing file** rather than replacing it, silently mixing run vintages. Confirmed on this
machine: `A2_pct60_seed1.csv` contained duplicate `cycle` values from an earlier run before
the pre-flight even started.

Nothing downstream flags this. `preprocessor.py` will happily train on a file containing two
different runs.

**Before starting the 240-run collection:**

```bash
mv $HOME/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/lstm_training \
   $HOME/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/lstm_training_OLD_$(date +%F)
```

**After collection, verify no file contains duplicate cycles:**

```bash
BASE=$HOME/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/lstm_training
for f in $BASE/RSU_*/A*.csv; do
  d=$(awk -F, 'NR>1{print $1}' "$f" | sort -n | uniq -d | wc -l)
  [ "$d" -gt 0 ] && echo "DUPLICATE CYCLES: $f ($d)"
done
```

Silence means clean. Any output means that file holds more than one run and must be
regenerated.

### The pre-flight procedure (for re-running it elsewhere, e.g. on HPC)

Four short runs (30 s, 60 %, seed 1), chosen by known risk:

```bash
for A in 2 3 6 8; do
  EXTRA=""; [ "$A" = "2" ] && EXTRA="--attack_delay_ms=80 --attack_delay_pseudo_random=0"
  ./waf --run-no-build "scratch/routing/routing \
    --routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
    --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --architecture=3 \
    --simTime=30 --attack_percentage=60 --sim_seed=1 --sim_run=1 \
    --attack_number=$A $EXTRA --training=1" > preflight_A${A}.log 2>&1 &
done; wait
```

**Then check all four of these. Any failure blocks collection:**

```bash
BASE=$HOME/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/lstm_training

# 1. Files exist at all
find $BASE -name 'Attack*_60_seed1.csv' | wc -l          # expect > 0, ideally 64 per variant

# 2. A2's zkp_delay_fail is NOT all zero  <-- the failure that killed the last dataset
awk -F, 'NR>1 && $6!=0 {n++} END{print "A2 zkp_delay_fail nonzero rows:", n+0}' \
    $BASE/RSU_*/Attack2_60_seed1.csv

# 3. A6/A8 zkp_hop_fail is NOT all zero
awk -F, 'NR>1 && $7!=0 {n++} END{print "zkp_hop_fail nonzero rows:", n+0}' \
    $BASE/RSU_*/Attack6_60_seed1.csv $BASE/RSU_*/Attack8_60_seed1.csv

# 4. Labels are present for A3/A6/A8
for V in 3 6 8; do
  awk -F, -v v=$V 'NR>1 && $14==1 {n++} END{print "A"v" positive labels:", n+0}' \
      $BASE/RSU_*/A${V}_pct60_seed1.csv
done
```

Column indices assume the 17-column header (`$6`=`zkp_delay_fail`, `$7`=`zkp_hop_fail`,
`$14`=`label`). **Confirm with `head -1` first** — if the header is a legacy format the
offsets shift.

**If check 2 returns 0, stop.** That is exactly the state that invalidated the previous
collection, and it means fix A did not take effect.

---

## 6. Retrain sequence

From `LSTM_RETRAIN_GUIDE.md` — steps in order, do not skip step 5:

0. Place CSVs at the `$HOME/...` path in §3 (set `HOME` explicitly on Windows)
1. Create a venv with `torch numpy pandas scikit-learn scipy matplotlib`
2. Run the pipeline (`preprocessor.py` → `local_trainer.py` → `fed_aggregator.py`)
3. Export C++ weights (`export_weights_cpp.py` → `lstm_weights_cpp.bin`)
4. Regenerate the validation case (`gen_cpp_validation_case.py`)
5. **Verify locally — C++ inference must match Python on the validation case.** No HPC needed
6. Only after step 5 PASSes, treat the new weights as live

A blocker already fixed while writing that guide: `export_weights_cpp.py` had a hardcoded
7-feature assertion that would have thrown on a real 10-feature `scaler_params.json`.

---

## 7. What unblocks downstream

```
collect (§3)  →  retrain (§6)  →  AB3 re-run  →  Q3/Q6 numbers quotable
```

- **AB3** (`ab3_feature_ablation.py`) — ZKP failure indicators as LSTM features. **Currently
  invalid**; it ablates features that were dead in training, so it measures nothing. Must
  follow the retrain.
- **AB2** (`ab2_centralized_baseline.py`) — federated vs centralised. Has a runner.
- **AB5** — Byzantine-robust aggregation (BRFA-v2 vs FedAvg). M8 already passes via
  `poison_sweep.py` → `brfa_param_sweep_results.json`; this is one of the few metrics that
  runs on real data today.
- **Q3 / Q6** in the supervisor's ablation grid depend on live inference and inherit every
  caveat in §8.

---

## 8. Caveats that must accompany any LSTM figure

State these explicitly — the supervisor has already accepted them and expects them carried
forward on **every** number, not as a generic disclaimer:

1. **Pre-retrain model.** Weights are trained on the corrupted set until §6 completes.
2. **A2 specifically had zero gradient**, not merely a weak feature. Q3/Q6 A2 numbers
   understate real contribution *even after the fix*, because the model never saw a working
   feature there. Carry this on A2 rows specifically.
3. **Q3 runs 9 effective features, not 10** — `zkp_hop_fail` zeroes out under
   `disable_crypto=1` (`stark_verify_hop` short-circuits), while `zkp_delay_fail` does **not**
   (it is a raw wall-clock comparison at `routing.cc:121884` with no crypto gate).
4. **Suppression counts don't scale linearly.** The paper's 14,000+ figure is a 300 s
   full-run number; a 30 s run's ceiling is 64 RSUs × 30 cycles = 1,920. Compare per-cycle
   rates, never totals.

---

## 9. The LSTM gate — do not "fix" this

`eq:lstm_gate` (`main.tex:3317-3326`): LSTM output is suppressed when `flag_S3 ∨ flag_S4`.

This creates a **deliberate asymmetry** that looks like a bug and is not:

- `g_disable_s3_s4` gates **only** the confusion-matrix `record_detection_event()` calls in
  `tcam_detection.h` — **never** `flag_s3`/`flag_s4` themselves.
- Those flags keep publishing `g_tcam_flag_s3_last` / `g_tcam_flag_s4_last`, which
  `lrad_rsu()` reads as the suppression gate.
- Rationale is **structural**: TCAM residual occupancy inflates reconstruction error at
  non-attacking RSUs throughout the run, independent of any co-firing signature. A diagnostic
  flag does not change that physical condition.

Gating the flags themselves would silently un-suppress the LSTM during TCAM saturation and
inflate FPR in exactly the runs meant to isolate the LSTM. **This was attempted once and
reverted.** Verified working 2026-08-06: an A3/Q4 run showed 608 S3 and 64 S4 firings with
recording correctly suppressed.

---

## 10. Open items

| Item | Status |
|---|---|
| Pre-flight (§5) | **Do this first** |
| Collection run length: 90 s vs 300 s | **Undecided** — pick and record |
| CSV header 16 vs 17 columns | Guide is stale; verify against `head -1` |
| Supervisor authorisation for retrain | Required before step 6 |
| β calibration (`s1_beta`) | Independent of LSTM, but affects `delta_t`'s threshold. The 1 % convergence criterion may never latch on noisy data — see `HANDOFF_STATE_2026-08-04.md` §5 |
| `metrics/` package M1–M6, M12 | Cannot run — sim doesn't emit `detector_windows.csv` etc. LSTM evaluation currently uses `evaluator.py`, not the `metrics/` package |

---

## 11. One-paragraph summary

The federated LSTM is fully implemented and integrated — logger, pipeline, BRFA-v2
aggregation, C++ inference, weight export. What it lacks is **trustworthy training data**.
Three defects corrupted the last set; **all three are now fixed AND verified in real data
(§5, 2026-08-06)**. The remaining sequence is: clear `lstm_training/` (the logger appends —
§5), collect 240 runs on HPC (~1 day), retrain (§6), re-run AB3. Collection is blocked on
nothing and should start now.
