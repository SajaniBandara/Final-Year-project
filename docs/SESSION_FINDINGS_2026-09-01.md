# Session findings — 2026-08-31 night / 2026-09-01

Everything below was measured on this machine. Q6 (full system, nothing
ablated), 8 attack variants, 300 s, 60%, **seed 1**, `--enable_detector_windows=1`.
M1 via `scripts/m1_local.py` — a re-implementation (see §7), so **arm-to-arm
deltas are valid; absolute values are not comparable to the historical 0.2721**.

---

## 1. Headline

**M1 went 0.3836 → 0.7477 (+95 %) without changing any detection logic.**
FPR 55.2 % → 17.2 %; DR 90.8 % → 91.8 % (recall slightly *improved*). Every gain
came from correcting how detection was *measured*, not from improving detectors.

| arm | config | M1 | note |
|---|---|---|---|
| A | autoencoder (`enable_lstm_cls=0`) | 0.3836 | baseline |
| B | classifier head (`=1`) | 0.3806 | **−0.003 — no effect** |
| C | + `require_lstm_high_conf=1` | 0.3876 | +0.007 — LSTM is not the FP driver |
| D | + `dw_mark_suspect=1` (unscoped) | **0.5556** | +45%; A3/A4 regressed |
| E | + `dw_mark_suspect=1` **scoped** | **0.5881** | best measured |
| E+F | + HF latch + TCAM live truth | **0.7477** | **final**; FPR 17.2 %, DR 91.8 % |

A binary-equivalence control (A5, new binary, gates off) came back
**byte-identical** to arm B — so cross-binary comparison is sound.

---

## 1b. Final numbers at 60 %, seed 1, Q6

**MEASURED — arm E (scoped attribution, truth semantics unchanged):**

| variant | MCC | DR | FPR |
|---|---|---|---|
| A1 | 0.5694 | 86.2 % | 20.2 % |
| A2 | 0.7027 | 83.5 % | 13.1 % |
| A3 | 0.4985 | 64.2 % | 15.4 % |
| A4 | 0.6560 | 86.6 % | 18.4 % |
| A5 | 0.5538 | 100.0 % | 41.6 % |
| A6 | 0.5988 | 97.9 % | 41.2 % |
| A7 | 0.5651 | 99.6 % | 39.9 % |
| A8 | 0.6514 | 97.5 % | 32.6 % |
| **ALL** | **0.5881** | **88.2 %** | **28.8 %** |

**MEASURED — arm F: + HF latched truth + TCAM live truth, in-simulator:**

| variant | MCC | DR | FPR |
|---|---|---|---|
| A1 | 0.5694 | 86.2 % | 20.2 % |
| A2 | 0.7027 | 83.5 % | 13.1 % |
| **A3** | **0.7742** | **100.0 %** | 15.9 % |
| **A4** | **0.7055** | **99.9 %** | 33.7 % ⚠ |
| **A5** | **0.8240** | 93.3 % | 11.1 % |
| **A6** | **0.7462** | 92.4 % | 18.7 % |
| **A7** | **0.8133** | 93.0 % | 11.9 % |
| **A8** | **0.7499** | 86.0 % | 8.4 % |
| **ALL** | **0.7477** | **91.8 %** | **17.2 %** |

**FINAL: M1 0.3836 → 0.7477 (+95 %), FPR 55.2 % → 17.2 %, DR 90.8 % → 91.8 %.**
Recall did not merely hold, it improved slightly, while FPR fell by two thirds —
and no detection logic changed.

Arm F vs the offline projection below: six variants match exactly or within
0.001, validating both reconstructions. **A6 (+0.076) and A8 (+0.085) came out
BETTER in-simulator**, because the in-sim latch accumulates `g_hf_send_flag_last`
directly while the offline proxy took a cumulative max of the windowed `truth`
column and missed some fires. The real implementation is the more accurate of
the two.

**PROJECTED (superseded by arm F above; kept to show the two agree)** —
+ HF latched truth + TCAM live truth, reconstructed offline:

| variant | MCC | DR | FPR |
|---|---|---|---|
| A1 | 0.5694 | 86.2 % | 20.2 % |
| A2 | 0.7027 | 83.5 % | 13.1 % |
| **A3** | **0.7753** | **100.0 %** | 15.9 % |
| **A4** | **0.7063** | **100.0 %** | 33.7 % ⚠ |
| **A5** | **0.8240** | 93.3 % | 11.1 % |
| A6 | 0.6705 | 87.6 % | 18.8 % |
| **A7** | **0.8133** | 93.0 % | 11.9 % |
| A8 | 0.6645 | 80.7 % | 9.3 % |
| **ALL** | **0.7279** | **89.9 %** | **17.4 %** |

*(the projection above is superseded by arm F's measured 0.7477)*

⚠ **Unpredicted and unexplained:** A4's FPR *rises* 18.4 % → 33.7 % under live
truth. Removing the latch converts previously-"correct" positives into negatives
the detector still fires on. MCC still improves (recall → 100 %), but this was
not predicted and should not be reported as a clean win until understood.

### Temporal behaviour — M1 is not stationary

Pooled M1 per 10 s window across a 300 s run (arm E):

| window | M1 | DR | FPR | FN |
|---|---|---|---|---|
| 40–50 s | **0.6958** (peak) | 98.3 % | 30.5 % | 4 |
| 110–120 s | 0.5480 | 85.0 % | 28.8 % | 30 |
| 270–280 s | 0.5139 | 84.3 % | 32.5 % | 34 |

The decay is **pure recall** — FPR is flat (23–33 %, no trend) while FN grows
8.5×. Dominated by A3 (MCC 0.783 → 0.433, DR 93 % → 58 %), which is the TCAM
latch of §3. **Confirmed: arm F's `--tcam_truth_live` takes A3 to DR 100.0 %,
eliminating that decay entirely.**

**Consequence: any M1 quoted from a short run is inflated.** The runbook's note
that "a 30 s run cannot produce M1" understates it — even 90 s samples only the
favourable early window. Always state run length beside an M1 figure.

**Separately: A1/A2 show their own unexplained recall decay** (DR 96 %→74 % and
88 %→74 %). Not the TCAM latch — they have legitimate event gates — and none of
tonight's three corrections addresses it. This is the next thing to investigate.

---

## 2. The central discovery: one defect class, three faces

Three separate "detector failures" turned out to be **the same defect** — truth
and detector evaluated on **mismatched time semantics**.

| case | truth | detector | symptom | fix |
|---|---|---|---|---|
| A5–A8 | event-gated | latched (state) | 1,432 spurious **FP** | latch the truth |
| A3/A4 | **latched** | live | 298 spurious **FN** | make truth live |
| A1–A4 vs A5–A8 | inconsistent gates | — | families answered oppositely | pick one rule |

Each was initially mistaken for a detection problem. **The rule the project has
never stated: truth and detector must be evaluated on the same time semantics.**

---

## 3. What happened with the TCAM attack (A3/A4)

The longest thread of the session, and the most instructive.

### The symptom
A3 was the worst variant: **MCC 0.4985, DR 64.2%, 298 FN**, flat across every
persistence value — and its MCC *decayed over the run*: 0.783 (0–60 s) → 0.433
(240–300 s), with DR collapsing 93% → 58%.

### Three hypotheses, all tested, all wrong
1. **Predicate mismatch** — that truth counts `is_malicious` while the detector
   needs `counts_capacity && !authorized && orphan`, making some entries
   invisible. **Disproven:** every malicious entry satisfies all three
   conditions (`is_malicious` is set only by `tcam_install_malicious`, which
   also sets `counts_capacity=true`, `authorized=false`, and never inserts into
   `g_tcam_installed`).
2. **Blockchain endorsement failure** — `flowmod_endorsement_rate = 1.0000` for
   A3/A4 looked like "everything endorsed, so S3 can never fire". **Disproven:**
   that field defaults to `1.0` on an *empty* pool (`routing.cc:118092`), and
   A3/A4 inject via `tcam_install_malicious()`, which bypasses the controller
   FlowMod path entirely. The 1.0 was a sentinel, not a measurement.
3. **Detection never computed** — because A1–A4 emit no `tcam_*` files.
   **Disproven:** `ComputeTcamDetection()` is called per-cycle from
   `routing.cc:118055`, not from the snapshot dumper.

### The actual cause
`tcam_install_malicious()` sets `is_malicious_node[v][victim_rsu] = true` and
**nothing ever clears it** for variants 2/3 (only variant 1 is reset,
`attack_declaration.h:176`). So `lstm_rsu_ground_truth_label()`'s first term is a
**latch**, and the live scan it documents as the definition is never reached.

Malicious entries age out on idle/hard timeout. Measured from the preserved
snapshots: the footprint decays **32 RSUs (t=10) → 16 (t≥100)**. The 16 recovered
RSUs keep truth=1 while S3 correctly goes silent.

**The evidence is unambiguous:** of A3's 298 false negatives, **298 are on RSUs
holding zero malicious entries in that window, and 0 are on RSUs that actually
held one.** S3 was never wrong.

### The fix and its value
`--tcam_truth_live` uses only the live scan for variants 2/3:

| A3 | MCC | DR | FPR | FN |
|---|---|---|---|---|
| latched truth (current) | 0.4985 | 64.2% | 15.4% | 298 |
| **live truth** | **0.7753** | **100.0%** | 15.9% | **0** |

Once entries are evicted the RSU genuinely is no longer under TCAM exhaustion;
labelling it positive forever creates windows no detector could catch — the
artefact Supervisor Decision 4 removed for other variants.

### A separate defect found on the way: TCAM diagnostics were being destroyed
`tcam_snapshot_dump()` builds its own filename — **no `_d{X}ms` segment**, plus
`_cpint{X}` (A3) / `_n{N}` (A4). The ablation launcher's aux-rename globs
`*{sim_tag}.csv` built from the MOBIGUARD name, which *does* carry `_d80ms`. They
never matched, so `tcam_snapshots_*` and `tcam_occupancy_*` were never tagged and
**every run overwrote the previous config's TCAM diagnostics** — for exactly the
two variants whose diagnosis needed them. Fixed (with a tightened matcher that
does not sweep up other experiments' files); arm E's data was preserved to
`armE_tcam_preserved_2026-09-01/` before it was lost.

---

## 4. What arm F is

Arm F = arm E's scoped attribution **+ HF latched truth + TCAM live truth** —
all three semantic corrections in one run, computed in-simulator rather than
reconstructed offline.

Launched 08:52 on binary 08:51:53, ~70 min. Predictions to check:
- **A3's DR curve should flatten to ~100%** instead of decaying 93% → 58%
- A5–A8 keep the attribution gain and shed the dormant-attacker FPs
- pooled M1 ~0.70

If the in-simulator A3 number disagrees with the offline projection (0.7753),
that discrepancy is worth chasing, not smoothing over.

---

## 5. Other confirmed defects

| # | defect | evidence | status |
|---|---|---|---|
| 5.1 | **Observer attribution** — `dw_mark_rsu()` marks the RSU *processing* the packet, so a node is penalised for correctly detecting a malicious neighbour. The 2026-08-22 "mark the suspect" fix went only to `score_primary`. | non-attacker FP share 44.7% → 11.7% | fixed, `--dw_mark_suspect` |
| 5.2 | **S5–S8 are oracle-gated** — all four early-return unless `active_/passive_hf_malicious_nodes[prev_sender]`, the attacker-assignment array. `eq:sig_s5`'s five conjunctions do **not** include it. | 100% of A5/A6/A8 primary FPs are declared attackers | **open — specification question** |
| 5.3 | **`cls_theta` doesn't transfer** offline → in-sim: fitted for FPR≤1%, fires at **6.85%** on benign in-sim traffic | 57,216 benign rows | recalibrated to 0.87% (`cls_theta_insim.json`) |
| 5.4 | **`LSTM_HC_MULT` broken under the classifier head** — `high_conf = score > 2.0 × θ`, but P(attack) ≤ 1.0 and θ median 0.940 ⇒ bar 1.88 | unreachable for **44/64 RSUs** | open |
| 5.5 | **`metrics/` package does not exist** on this host — canonical M1 unreproducible | absent from both trees and all git history | `m1_local.py` written as a stand-in |
| 5.6 | **Duplicate `AddValue`** for `trust_t_min`/`trust_delta_p`/`trust_delta_r` | registered in both `crypto_layer.h` and `routing.cc` | cosmetic, unfixed |
| 5.7 | **M-numbering conflict** — main.tex vs `evaluator.py` disagree on M2/M3/M5/M7/M8 | "M8" = poisoning vs UCR | reporting convention needed |
| 5.8 | `lstm_inference.h` missing `<iostream>` — §5 verify wouldn't compile | — | fixed |

---

## 6. Non-M1 results

- **End-to-end classifier head** (`--unfreeze`): macro-MCC **0.3142 → 0.6781**,
  A1 DR 11.3% → 41.3%, A2 37.1% → 85.1%. Confirms §6a's untested hypothesis that
  the *frozen latent*, not head capacity, was the binding constraint. **Deviates
  from "do not touch the encoder" — present it, don't ship it.** Offline only.
- **A1/A2 label leak fixed** in `train_cls_head.py`: the target was built from
  `delta_t_exceeded`, a `FEATURES` column. Worth **+0.249 MCC on A1** —
  i.e. 0.5083 was inflated, 0.2597 is defensible.
- **`T_hold` calibrated**: floor measured at exactly **1 ms** (= the RSU.Confirm
  RTT); timeouts appear below it and vanish at it. Set to **0.01 s** (10× margin,
  9.74 ms mean hold vs the old default's 99.78 ms for identical containment).
- **Per-variant HF θ**: A6 FPR 75.3% → 4.1%; A6 binds at only 34/64 RSUs (A5 11,
  A8 8, A7 5). Not deployable in-sim — `lstm_logger.h` loads `hf_theta.json` as a
  **single scalar**, and collapsing to one value forfeits most of the gain.
- **Temporal**: M1 peaks at **t=40–50 s (0.6958)** and decays to 0.51–0.55.
  The decay is pure recall (FN 4 → 34; FPR flat 23–33%), dominated by A3.
  **Any M1 quoted from a short run is inflated.**
- **A1/A2 have a separate, unexplained recall decay** (DR 96%→74%, 88%→74%) that
  none of tonight's corrections address. Next thing to investigate.

---

## 7. Corrections to my own earlier claims

Recorded because several were quoted before being checked.

| claimed | actual |
|---|---|
| "LSTM fires on 21.8% of windows in-sim" | **6.85%.** The 21.8% was `score=1 & score_primary=0`, which counts non-primary *signatures* too |
| "LSTM contributes 53–100% of FPs" | Wrong, same conflated metric. Arm C settled it: gating the LSTM out moved M1 by **+0.007** |
| "A1–A4 produce zero `tcam_*` files" | They exist; the launcher's rename never matched them and they were being overwritten |
| "A3/A4 predicate mismatch is the highest-value fix" | Disproven — predicates coincide |
| "Use persistence M=8" | Wrong. M=8 maximises *pooled* MCC while collapsing A1–A4 to 0.3988 and leaving a variant at 10% DR. **Use M=3** |
| "`cls_theta` transfer gap is ~20×" | ~7× (1% → 6.85%) |

`score` and `score_primary` differ in **two** ways — detector set *and*
attribution node — so their difference cannot attribute FPs to either alone.
That single confound produced three of the six errors above.

---

## 8. Backups

- `lstm_pipeline/restore_point_2026-09-01_pre_ddiv/` (410 MB) — full pipeline
  state, verified by reload (X=(489472,10,11), `y_indep` 42.2%, `fc_cls` present)
- `results_analysis_2026-09-01/` — tidy plot-ready CSVs + README
- `results_routing/armA..armE_*_2026-09-01/` — per-arm grids (108 files each)
- `results_routing/armE_tcam_preserved_2026-09-01/` — the TCAM diagnostics that
  the rename bug would otherwise have destroyed

## 9. Caveats on everything above

- **Seed 1 only.** Deltas are far larger than plausible seed noise, but a second
  seed should confirm before publication.
- **M1 is a re-implementation.** Deltas valid; absolute levels not comparable to
  0.2721.
- **`score_primary` is not a deployable ceiling** — it is variant-aware *and*
  (via §5.2) attacker-identity-aware.
- **M4 remains unreportable** — quarantine enforcement is off, so it measures an
  inert flag.
