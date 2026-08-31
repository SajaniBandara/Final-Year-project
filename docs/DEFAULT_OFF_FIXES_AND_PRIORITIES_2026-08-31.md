# Default-OFF fixes, and what to do in what order — 2026-08-31 (evening)

Written after a day of measurement on the A3/A4 machine. Companion to
`BUGS_MISMATCHES_AND_OPEN_DOUBTS_2026-08-31.md` (defect inventory) and
`HPC_RUNBOOK_12H_2026-08-31.md` (tonight's HPC plan).

**Every claim below is labelled MEASURED, VERIFIED-IN-CODE, or UNVERIFIED.**
Do not promote an UNVERIFIED item into a report without checking it.

---

## 1. The headline finding: the reported system is the pre-fix system

Eight validated fixes are behind flags that default to OFF. A run with default
flags gets the behaviour each fix was written to remove.

| flag | gates | CLI? | cost of leaving OFF |
|---|---|---|---|
| `s1_suppress_handoff_fp` | S1 handoff false-positive suppression | **yes** | **MEASURED: benign FPR 12.32%** (see 2) |
| `enable_quarantine_enforcement` | quarantine actually blocking actions | **yes** | MEASURED: mitigation entirely inert |
| `enable_corrected_lmit` | M4 onset + mean correction | **yes** | code comment: **2.6x** inflation |
| `enable_local_quarantine` | `eq:local_quarantine` / HOLD_FORWARD | **no** | OBU-side mitigation absent |
| `enable_lstm_inference` | live in-sim LSTM | **no** | LSTM contributes nothing at runtime |
| `enable_lstm_cls` | **the classifier head** | **no** | the 0.95-ceiling model unused |
| `enable_hf_theta` | **per-variant HF thresholds** | **no** | A6 stuck at FPR ~76% |
| `enable_detector_windows` | window-level detector output | **no** | — |

**VERIFIED-IN-CODE: five of the eight are not CLI-settable.** They can only be
changed by editing the declaration in `crypto_layer.h` and rebuilding. That
includes the two that matter most tonight: `enable_lstm_cls` and
`enable_hf_theta`.

This is not an argument for flipping the defaults. Each was deliberately set OFF
so that existing results stay reproducible — `enable_local_quarantine`'s own
comment says switching it on by default "would silently invalidate all existing
results without anyone choosing to". The problem is that **no document records
which flag set each reported number was produced under.**

---

## 2. MEASURED: benign false-positive rate is 12.32% with default flags

Zero-attack run (`--attack_number=0 --attack_percentage=0`, 90 s, seed 1,
default flags):

```
S1 firings on a run with NO attack : 1,766
FP = 39   TN = 229   TP = 0   FN = 0
avg_FPR = 12.3219 %
```

The HPC machine measured **zero-attack FPR 0.022% +/- 0.014%** for the same
quantity — with the handoff/persistence fixes enabled. That is a ~560x gap
explained entirely by `s1_suppress_handoff_fp` defaulting to `false`
(`s1_detection.h:427`).

**This cuts in the project's favour.** If any table reports ~12% zero-attack FPR,
it badly understates the system. A validation run with the flag ON was queued at
the time of writing; its result belongs here when it lands.

---

## 3. MEASURED: the T_min calibration `main.tex` marks [tbd]

`main.tex:5586` — `T_min` (vehicle/RSU quarantine threshold) **[tbd: {0.3, 0.5,
0.7}]**. This could not previously be run: `TRUST_T_MIN` had no CLI flag at all.
Flags `--trust_t_min`, `--trust_delta_p`, `--trust_delta_r` were added today.

A4 @60%, 90 s, enforcement ON, corrected L_mit ON:

| T_min | installs | avg_mit_ms | blocked-before-acting | FP |
|---|---|---|---|---|
| 0.3 | 39,112 | 42,528 | 46 | 0 |
| 0.5 (current default) | 37,689 | 33,078 | 49 | 0 |
| **0.7** | **33,153** | **21,928** | **62** | **0** |

Seed replication at T_min=0.7 (n=5): installs **31,220 +/- 2,110**, latency
**23,230 +/- 1,686 ms**, FP=0 in every seed.

Cross-variant, mitigation latency 0.5 -> 0.7:

| variant | delta | note |
|---|---|---|
| A4 TCAM/DP | **-33.7%** | strongest |
| A1 delay/CP | -14.2% | PDR unchanged |
| A2 delay/DP | -7.9% | **costs 2.0 points of PDR** |
| A3 TCAM/CP | **0.0%** | identical to 4 dp — see 6 |

False-quarantine control (benign, no attack): **zero quarantine events at both
0.5 and 0.7**. Raising T_min costs nothing in false quarantines.

**Recommendation: T_min = 0.7 as default, stated as variant-dependent**, with
A2's PDR cost disclosed. Delta_p sweep was still running at time of writing.

---

## 4. MEASURED: A4 vehicle-attacker quarantine leak, fixed

Before: A4 byte-identical with enforcement on (49,689 installs both arms, delta
exactly 0), **0 vehicles ever quarantined**. After: **118 vehicles quarantined**,
installs -9.6% at T_min=0.5, -17.2% at 0.7.

Mechanism: the injector guard `quarantine_blocks(node_id)` was correctly placed
and `node_id` IS the attacking vehicle — but nothing decremented the attacker's
trust, because S3/S4 record detections against the **victim RSU**.
`s4_attribute_attacker()` already computed `v_atk = argmax_v lambda_PI(v,r,t)`
and was using it only for a log line. Wiring it to `trust_update_negative()`
closed the chain.

**Flag for the supervisor:** `eq:trust_update` (main.tex:3748) defines trust
purely over crypto verification outcomes (batch verify + STARK proofs). TCAM
attacks produce no crypto failure, so `eq:quarantine` was structurally
unreachable for them. Wiring S4 into the trust path is therefore an
**extension of `eq:trust_update`, not an implementation of it**, and needs
approval.

**UNVERIFIED:** the A3 control moved from -0.2% (original test) to -70.0% in the
same A/B. Either today's commits changed it, or the runs are not comparable. One
run on the pre-fix commit would separate the two. Until then **do not quote the
old A3 number alongside the new ones.**

---

## 5. VERIFIED-IN-CODE: how detection actually reaches mitigation

Mitigation chain: detection -> trust decrement -> trust < T_min -> quarantine ->
enforcement blocks.

| path | drives trust? |
|---|---|
| **S5** | yes — direct, unconditional (`lrad.h:595`) |
| **S4** | yes — as of today's fix (`tcam_detection.h:374`) |
| **LSTM high-confidence** | **opens the BTMM gate**; crypto decides the sign |
| LSTM soft-only | no — excluded by supervisor Fix 2 |
| S1, S2, S3, S6, S7, S8 | **no direct call** — rely on crypto failures |

`btmm()` reward-or-punish is keyed on `b_batch && b_hop && timing_ok`, i.e.
crypto, **not** on the LSTM's own verdict. So a better LSTM changes how often
trust is evaluated, not which way it goes — and on a crypto-clean node a
high-confidence firing produces a trust **reward**.

**Consequence for tonight: the retrain will move DR/FPR/MCC. It will not
meaningfully move M4 or containment.**

The largest untapped mitigation lever is coupling S1/S2/S3/S6/S7/S8 to trust —
but that is a **design deviation from `eq:trust_update`**, and with benign FP=39
on the detection side it would start quarantining benign nodes. Settle T_min and
Delta_p first.

---

## 6. Priority order

### P0 — before any number is reported

1. **Write down the reporting flag set.** One documented configuration that every
   thesis number is produced under. Without it, results from different flag
   combinations are being compared. This is the cheapest high-value action here.
2. **Confirm `enable_lstm_cls` and `enable_hf_theta` for tonight's evaluation.**
   Both are the supervisor-approved work and **both are default OFF and not
   CLI-settable** — they need a source edit and rebuild to take effect in-sim.

### P1 — measurement, no code change

3. **Finish the Delta_p sweep** (`--trust_delta_p`, `[tbd]` in main.tex, the other
   half of the T_min calibration).
4. **Validate the benign FPR claim** with `s1_suppress_handoff_fp=1` — confirms
   the 12.32% -> ~0.02% figure.
5. **One A3 run on the pre-fix commit** to explain the control shift in 4.

### P2 — real defects, contained

6. **Header migration dispatches on column count alone.** `lstm_migrate_stale_header()`
   compares only against the current header, then migrates rows by `f.size()`.
   `LSTM_CSV_HEADER_18COL`/`_19COL` are declared `[[maybe_unused]]` and never
   compared. An 18-column file with a different layout is silently mis-migrated.
   This machine's copy is exactly such a file. Fix: validate the header for the
   matched count, abort loudly on mismatch (same discipline
   `lstm_normalize_features()` already uses).
7. **A3 mitigation latency 64,248 ms, identical at both T_min values.** Unmoved by
   trust calibration, so something other than trust decay dominates. UNVERIFIED.
8. **`flowmod_endorsement_rate = 0` for A5** (A7 = 1). July P0, still reproducing.
9. **A5 `witness_TP_W = 0` and `FP_W = 0`** despite 433 DA alerts; A7 shows 37/6.

### P3 — specification gaps

10. **`eq:packet_receipt_log`** — specified in main.tex, zero code hits.
11. **`main.tex eq:lstm_input` lists 10 features**; the pipeline uses 11
    (`delta_t_exceeded`, supervisor Fix 3).
12. **Supervisor decision 3** — should a quarantined RSU also be blocked from
    legitimate forwarding? MEASURED: scheduling-only enforcement leaves ~76% of
    interception intact.

---

## 7. Do not do these

- **Do not flip the defaults wholesale.** Each was set OFF to keep prior results
  reproducible. Document the intended set instead.
- **Do not couple S1-S8 to trust** before T_min/Delta_p are settled — benign FP=39
  would become benign quarantines.
- **Do not quote pre-2026-08-31 A4 numbers** alongside new ones; the baseline moved.
- **Do not re-collect LSTM data** to fix anything in this document. Nothing here
  requires it.
