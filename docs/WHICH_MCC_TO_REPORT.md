# Which MCC To Report — READ BEFORE QUOTING ANY DETECTION NUMBER

**Written:** 2026-08-07
**Status:** binding convention for this project
**Why it exists:** we spent a full session reporting an MCC the thesis does not
define, and drew wrong conclusions from it. Do not repeat that.

---

## 0. The rule

> **Report `M1` computed per `eq:eval_dedup`: per-RSU, non-overlapping 10 s blocks.
> Never quote the per-node MCC printed by the simulator as M1.**

The simulator prints an MCC every cycle. **That number is not M1.** It is a
per-node diagnostic that exists because it was easy to compute inline. The thesis
does not define it, ask for it, or evaluate against it.

---

## 1. The two numbers, and why they are different

| | **PAPER M1 (report this)** | **per-node (diagnostic only)** |
|---|---|---|
| Unit of classification | one **RSU × 10 s block** | one **node**, whole run |
| Population | 64 RSUs × blocks × variants | 268 nodes (200 veh + 64 RSU + 4 ctrl) |
| Where from | `metrics/m01_detection_quality.py` on `detector_windows.csv` | `calculate_security_detection_metrics()`, `routing.cc` |
| Defined by | `eq:mcc`, `eq:mcc_variant`, `eq:eval_dedup` | nothing — implementation artefact |
| Sticky? | no — each block scored independently | **yes**, `is_detected_node[][]` latches for the whole run |
| Deduplicated? | yes — non-overlapping blocks, max-pooled | no |

They are not two views of one quantity. They answer different questions:

- **Paper M1:** *"in this 10 s block at this RSU, was an attack present, and did the detector say so?"*
- **Per-node:** *"across the entire run, was this node ever malicious, and was it ever flagged?"*

## 2. What the paper actually specifies

`eq:eval_dedup` (main.tex:5838-5863) is explicit:

```
ŷ_b^(k) = max_{t ∈ B_b} D_LSTM^(k)(t)      (prediction)
y_b^(k) = max_{t ∈ B_b} GT^(k)(t)          (truth)
```

- `B_b` = the b-th **non-overlapping** evaluation block, width `Δ_eval = 10 s`
- `(k)` indexes the **RSU** — every quantity in the paper's evaluation is per-RSU
- max-pooling within the block is the deduplication step

The paper is emphatic that the dedup matters: *"collapses approximately 42% of raw
overlapping windows (21,504 → 12,288 in the evaluated run), **materially affecting
all figures**… all reported DR, FPR, and MCC values are computed over deduplicated
blocks."*

Stratification comes from `eq:mcc_variant` (`MCC_{s,m}`) and `eq:mcc_mobility`.
The FPR gate (≤ 1 %, hard constraint) is evaluated on the same blocks.

**There is no per-node evaluation anywhere in main.tex.** The only occurrence of
"per-node" (line 1252) is about trust scores, not detection scoring.

## 3. There is no OBU ground truth — do not invent one

`eq:eval_dedup` indexes everything by `(k)`, the RSU. The paper evaluates
**per-RSU only**.

This is not an oversight. `lrad_obu()` runs at the *receiving* vehicle and fires
when a packet **it received** was delayed — by someone else. The OBU is a
pre-filter that ESCALATES; its suspicion is attributed to the RSU, which is why
S1 records against `N_Vehicles + assoc_rsu_local_idx` and not against the vehicle.

So there is nothing coherent to score at the vehicle: the node that fires is the
victim, not the suspect. An earlier version of `detector_windows.h` emitted OBU
rows labelled `is_malicious_node[variant][vehicle]`; the resulting column was
uninformative for **all eight** variants (degenerate for the control-plane ones,
and merely meaningless for the rest, since the firing vehicle is a different node
from the labelled one). **OBU rows are excluded from M1.**

## 4. How to compute M1

```bash
# 1. Run with the window emitter on, and LONG ENOUGH.
#    >= 90 s: a 30 s run produces too few blocks after the warm-up window.
./waf --run-no-build "scratch/routing/routing ... --simTime=90 \
    --enable_detector_windows=1"

# 2. Stitch the per-variant files into the single file metrics/ expects.
python3 scripts/m1_from_detector_windows.py \
    --results-dir ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing \
    --tag pct60_seed1 --out-dir /tmp/m1_run

# 3. Compute M1 (from the ns-3 tree root, where metrics/ is a package).
python3 -m metrics.run_metrics /tmp/m1_run
```

Three filters must be applied before scoring — `m1_from_detector_windows.py`
handles the first, you must apply the other two:

1. **RSU rows only** (§3)
2. **Non-overlapping blocks** — the emitter's grid is stride-5 overlapping; take
   every other window so blocks tile without overlap (`eq:eval_dedup`)
3. **Exclude warm-up** — `w_start >= 30`, per `eq:theta_adapt`: *"Warm-up windows
   are excluded from all FPR and DR computations."*

## 5. Current result (the number to quote)

**Q6 full system, 90 s, 60 %, seed 1:**

```
AGGREGATE M1 = 0.2721          FPR (RSU) = 65.16 %   [gate <= 1 % — VIOLATED]

  variant   MCC_s,RSU     DR%     FPR%
  A1           0.3676    87.1     53.5
  A2           0.3118    80.7     45.9
  A3           0.0000    50.8     50.8
  A4           0.5159    89.1     40.2
  A5           0.2366    98.1     86.0
  A6           0.2784    98.6     84.8
  A7           0.2307    96.2     82.5
  A8           0.2421    95.4     80.0
```

**Recall is not the problem — precision is.** DR runs 80.7–98.6 %; A5–A8 detect
95–99 % of attacks, better than the published table. Every point of MCC is lost to
false positives. A3 sitting at DR ≈ FPR ≈ 50.8 % (MCC 0.000) is the signature of a
detector carrying no information at all.

## 6. Why the old 0.895 table is not comparable either

The task-6.5 table (mean MCC 0.895, FPR 0.27 %) came from
`lstm_pipeline/src/evaluator.py`, which scores **the LSTM alone** with
warm-up-adapted per-RSU thresholds.

`D_RSU` is `S2f ∨ S5 ∨ S6 ∨ S7 ∨ S8 ∨ flag_LSTM`. **OR-ing detectors monotonically
increases false positives.** The composite therefore inherits every LSTM false
positive on top of the signatures' own, which is why FPR is 40–86 % here and
0.00–1.00 % there. DR is comparable between the two (80–99 % vs 84–93 %); only FPR
diverges.

So the three numbers you may encounter are:

| number | what it is |
|---|---|
| **0.895** | LSTM alone, offline, adapted θ, deduplicated — `evaluator.py` |
| **0.272** | full-system composite, paper M1 — **this is M1** |
| 0.264 / 0.219 | per-node diagnostic — **not M1, do not quote** |

None contradicts the others once you know what each measures.

## 7. Pitfalls that have already cost time

- **A 30 s run cannot produce M1.** Warm-up exclusion (30 cycles) removes the whole
  run. Use ≥ 90 s.
- **The per-node matrix understates threshold fixes.** `is_detected_node[][]` is a
  sticky latch, so false positives accumulated during warm-up are permanent and no
  later threshold change can retract them. The paper avoids this by excluding
  warm-up windows; the per-node matrix cannot express that.
- **Don't compare suppression counts across run lengths.** The paper's 14,000+
  figure is a 300 s number; a 30 s run's ceiling is 64 × 30 = 1,920. Compare
  per-cycle rates.
- **`detector_windows_*.csv` is overwritten** by any run with the same
  attack/pct/seed. Copy the files aside before re-running a comparison, or you
  lose the baseline.

## 8. The per-node matrix is still useful — just not as M1

Keep it for:

- **Per-component attribution.** `record_detection_event(v, n, src)` tags each
  detection with its source (`DSRC_RULE_S1`, `DSRC_LSTM`, `DSRC_WITNESS_DA`,
  `DSRC_BTMM_PACKET`, …), printed as `[SECURITY-SRC]`. That is how we established
  the LSTM contributes 828 false positives against 65 true positives — the single
  most useful diagnostic this session produced.
- **M4 mitigation latency**, which needs per-node `t_onset` / `t_quarantine`.
- **The inline DR/FPR counters** in `MOBIGUARD_*.csv`.

Just never write it in a results table labelled MCC or M1.
