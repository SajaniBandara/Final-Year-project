# PHANTOM — seed-1 results (finalised config)

Generated 2026-09-25 (updated 2026-09-27). Config: **seed 1, simTime 300 s** (30 s
warm-up + 270 s scored, 27 non-overlapping 10 s blocks), **crypto-off**, enforcement-off
(detection scoring). Metric: **per-window M1** for the proposed method; baselines report
their own per-node/per-RSU MCC. In-sim SFTO-Guard (θ=0.90); FADE/eFADE run cross-attack
via `--fade_force`, scored externally.

**Crypto-off justification (exact test):** on the *identical* full configuration
(S1–S8, LSTM, witness, BTMM all on), toggling `disable_crypto` 0→1 alone leaves the
per-window MCC **byte-identical** (A1 = 0.5143 both ways). This is a *crypto-only* toggle
and is **not** the Full-vs-Lightweight comparison (Table Exp 5), which changes several
components at once (S5–S8, LSTM, witness, BTMM, crypto) — so Full ≠ Lightweight there is
expected and does not contradict crypto-neutrality.

**Exp 3 traces:** the N = 100/200/300 points are **subsets of the single 400-vehicle
base trace** (`mobility_urban_scale400.tcl`, `--N_Vehicles` set down), not separately
generated — vehicle count is the only variable across the scale points.

## Experiment 5 — per-variant SOTA comparison (default, pct 60), MCC

| Variant | Proposed (Full) | Proposed (Lightweight) | TAP | SFTO-Guard | FADE (cross-attack) | eFADE (cross-attack) |
|---|---|---|---|---|---|---|
| A1 (STD/CP)  | 0.571 | 0.544 | 0.195 | 0.00 | 0.00 | 0.00 |
| A2 (STD/DP)  | 0.594 | 0.575 | 0.584 | 0.00 | 0.00 | 0.00 |
| A3 (TCAM/CP) | 0.555 | 0.555 | ~0.19 | 0.472 | 0.00 | 0.00 |
| A4 (TCAM/DP) | 0.684 | 0.655 | ~0.27 | 0.661 | 0.00 | 0.00 |

- Proposed wins on breadth: TAP competitive only on A2 (timing niche), SFTO only on
  A4/A3 (flow-table niche); each collapses off-niche.
- **Full ≈ Lightweight on every variant** — the S1–S4 rule signatures carry PHANTOM's
  detection; crypto/LSTM/witness add negligibly on A1–A4.
- **FADE / eFADE cross-attack = 0.00 across A1–A4 — a deliberate finding, not a bug.**
  Both are duplication-tracking detectors (flow packet-conservation): they flag a node
  only when packets_out > packets_in (traffic duplication). Delay injection (A1/A2) and
  TCAM exhaustion (A3/A4) involve **no packet duplication**, so neither detector has any
  signal to fire on. FADE is the published conservation test (Li et al. 2021); **eFADE is
  our own duplication-aware extension of FADE — an ad-hoc baseline built for this
  comparison, not an independently published method (no external citation).** Report it
  as "we also tested our own more advanced duplication-aware extension," never as a
  third-party method; do not cite eFADE, and do not cite the Hidden-Forwarding paper.

### Wording for the caption / text (per supervisor, 2026-09-27)
> Two duplication-tracking baselines are included as cross-attack references: FADE, the
> published packet-conservation detector, and eFADE, our own more advanced
> duplication-aware extension of it. Both score ≈0 on every PHANTOM variant, as expected:
> a duplication detector cannot observe delay injection or flow-table exhaustion, since
> neither attack duplicates packets.

## Experiment 1 — detection vs attack penetration (macro MCC)

| pct | Full | Lightweight | TAP* | SFTO* | eFADE |
|---|---|---|---|---|---|
| 20  | 0.542 | 0.542 | 0.218 | 0.358 | 0.00 |
| 40  | 0.599 | 0.599 | 0.322 | 0.571 | 0.00 |
| 60  | 0.601 | 0.594 | 0.390 | 0.566 | 0.00 |
| 80  | 0.596 | 0.601 | 0.457 | 0.641 | 0.00 |
| 100 | 0.423 | 0.423 | 0.556 | 0.334 | 0.00 |

*TAP shown as its in-scope A1/A2 macro; SFTO as its A3/A4 macro. Proposed is A1–A4 macro.
Proposed stable ~0.60, drops at 100% (A3 degenerates — no benign RSUs left).

## Experiment 2 — detection vs vehicular speed (macro MCC)

| speed (km/h) | Full | Lightweight |
|---|---|---|
| 10  | 0.574 | 0.574 |
| 60  | 0.571 | 0.571 |
| 100 | 0.580 | 0.580 |
| 140 | 0.582 | 0.582 |

Flat — detection is speed-insensitive.

## Experiment 3 — scalability (macro MCC, Full)

| N vehicles | macro MCC |
|---|---|
| 100 | 0.589 |
| 200 | 0.588 |
| 300 | 0.500 |
| 400 | (dropped — heavy run, deferred) |

TCAM detection weakens as vehicle density rises (fixed 64 RSUs → legit flows dilute the
occupancy signal); timing detection holds.

## Experiment 4 — detection vs observable evidence (AOEI, Lightweight A1/A2)

| targeting ratio | macro MCC |
|---|---|
| 0.10 | 0.467 |
| 0.25 | 0.467 |
| 0.75 | 0.570 |
| 1.00 | 0.585 |

Degrades gracefully as fewer packets carry the injected delay (less evidence).

## Recalibrated baseline line — DONE (and it changes the SOTA conclusion)

Thresholds refit to benign p99 (same method as U_thresh/S1/ε_vol):
- **SFTO θ_recal = 0.121** (benign occupancy p99; default 0.90). NOT ≈ default.
- **TAP margin_recal = 6.06 ms** (benign |v-PPAT| p99; default 1 µs).

**Recalibrated vs default, @ pct 60 — MCC (FPR% shown, since it matters for the comparison):**

| Variant | Proposed (Full) | TAP default | TAP recal | SFTO default | SFTO recal |
|---|---|---|---|---|---|
| A1 (STD/CP)  | **0.57** (FPR 27) | 0.20 (FPR 52) | 0.32 (FPR 24) | — | — |
| A2 (STD/DP)  | 0.59 (FPR 34) | 0.58 (FPR 36) | **0.81** (FPR 14) | — | — |
| A3 (TCAM/CP) | 0.56 (FPR 10) | — | — | 0.47 (FPR 9) | 0.63 (**FPR 44**) |
| A4 (TCAM/DP) | 0.68 (FPR 42) | — | — | 0.66 (FPR 0) | **0.96** (FPR 0) |

**A3 caveat (supervisor 2026-09-27):** SFTO-recal's 0.63 on A3 comes with **44% FPR** — far
outside the ≤1% FPR budget used for every other threshold in the paper (U_thresh/S1/ε_vol).
So it is **not a matched comparison** to Proposed's 0.56 (FPR 10%); reported as-is, not
tuned further. (No search for a better A3 θ — per instruction.)

**Sanity-check vs the baselines' own papers (supervisor 2026-09-27):** TAP's 0.81 (A2) and
SFTO's 0.96 (A4) look high for baseline reproductions. What I can confirm: they are **not
scoring artifacts** — each threshold was fit on benign (pct=0) data and tested on the
attack (no calibration-on-test leakage), and the scores are backed by real detections
(TAP A2: DR 100%, FPR 14%; SFTO A4: DR 98%, FPR 0%). The **likely reason they're high is
our attack aggressiveness** — A2 injects an 80 ms hop delay (≫ TAP's 6 ms recal margin)
and A4 floods the flow table to capacity — so both detectors see an obvious signal, more
detectable than a subtle slow-rate attack. **Cannot confirm the exact gap without the
original papers' reported numbers** (Arsalan 2018 / Tang 2023 figures are NOT in the repo —
the 0.37/0.216 in phantom.tex are OUR reproductions, not their claims). If ours exceed
theirs, the explanation is almost certainly the attack parameters, not the detectors
outperforming their published capability — but the papers' numbers are needed to state it.

**KEY FINDING — after fair recalibration, PHANTOM wins outright only on A1.**
Recalibrated TAP beats PHANTOM on A2 (0.81 vs 0.59), recalibrated SFTO beats it on A4
(0.96 vs 0.68, FPR 0%) and edges A3 (0.63 vs 0.56, at 44% FPR). Recalibration cut the
baselines' FPR (TAP 50→14–26%, keeping DR) so these are genuine gains, not FP inflation
(except A3). SFTO's *predictive* occupancy catches A4 earlier than our S4.

**Proposed's own A2/A4 thresholds — provenance + recalibration (supervisor 2026-09-27):**

**Both A2 and A4: recalibrating Proposed's own signature threshold has NO effect on its MCC**
— because the per-window detection score is a *composite* (S1–S8 + LSTM + witness + trust),
not gated by the single signature threshold. So the baseline comparison is unaffected:
recalibrated TAP (0.81) still beats Proposed A2, recalibrated SFTO (0.96) still beats A4.

- **A2 (S2): `S2_DELTA_MAX = 50 ms`** — fixed proposal constant, never benign-calibrated.
  Made CLI-settable + dumped benign hop-delay (p99 = 5.83 ms, n=1503). **Recalibrated:**

  | Proposed A2 (per-window) | MCC | DR | FPR |
  |---|---|---|---|
  | 50 ms (default) | 0.575 | 89% | 32% |
  | 5.83 ms (benign-p99 recal) | 0.575 | 89% | 32% |

  Identical — S2's gate isn't the binding constraint. (5.83 ms is calibrated on uncongested
  pct=0 benign; under A2's 60% load benign hops are slower, so a tighter S2 wouldn't help FP
  anyway.)
- **A4 (S4): `tcam_util_thresh = 0.20`** — a *sensitivity-optimum* (2026-09-14), not the
  benign-p99. **Recalibrated S4 to benign-p99 (0.121, same value SFTO used):**

  | Proposed A4 | MCC | DR | FPR |
  |---|---|---|---|
  | thresh 0.20 (default) | 0.684 | 99% | 42% |
  | thresh 0.121 (benign-p99 recal) | 0.655 | 87% | 19% |

  **Recalibration did NOT close the A4 gap** — Proposed A4 stays ≈0.66–0.72 regardless of
  threshold, nowhere near SFTO-recal's 0.96.

  **The gap is REAL, not a metric artifact (verified 2026-09-28).** Re-scoring Proposed A4
  on the SAME per-RSU basis as SFTO (latched per-RSU flag, not per-window):

  | A4 per-RSU | MCC | DR | FPR |
  |---|---|---|---|
  | Proposed default (0.20) | 0.676 | 100% | 45% |
  | Proposed recal (0.121)  | 0.716 | 100% | 41% |
  | SFTO recal (0.121)      | **0.961** | 98% | **0%** |

  Even same-metric, Proposed trails SFTO. Cause: Proposed's S4 catches all victims (DR 100%)
  but **falsely flags 40–45% of benign RSUs**; SFTO's *predictive* occupancy has **0% FPR**.
  So SFTO's predictive method is genuinely more precise on A4 — this is a real detector gap,
  **NOT** the earlier (incorrect) "metric mismatch" explanation, which the per-RSU re-score
  disproved. PHANTOM's claim on TCAM-DP is breadth/coverage, not detection superiority.

**Caveat:** PHANTOM = per-window M1; TAP/SFTO = their own per-node/per-cycle MCC — not
the identical metric. So this is detector-vs-detector, not strict like-for-like; but the
direction (recalibration makes specialists competitive-to-superior on their niches) is
unambiguous.

**Implication for the contribution claim:** "beats SOTA on every variant" does NOT survive
fair recalibration. The defensible claim is **breadth + control-plane coverage** — one
detector decent on all four, and the only one handling A1 — not per-variant superiority.
(Narrative framing is a supervisor decision; this doc only reports the numbers.)

## Methodology updates (in phantom.tex)

- Settings table now states simulation time (300 s + warm-up) and seeds (RngRun 1–5).
- SFTO-Guard switched from offline LightGBM to in-sim real-time mechanism (θ=0.90);
  sampling bug fixed.
- eFADE cross-attack via `--fade_force`, scored externally (per-packet HF path untouched).

## Recalibrated-baseline advantage across the penetration sweep (supervisor 2026-09-28)

Does the recalibrated baselines' advantage hold across the sweep, or is it specific to
the aggressive p60 point? (MCC/FPR%, from existing penetration-sweep data — no new runs.)

| pct | Proposed A2 | TAP-recal A2 | Proposed A4 | SFTO-recal A4 | Proposed A3 | SFTO-recal A3 |
|---|---|---|---|---|---|---|
| 20  | 0.51/20 | 0.56/19 | 0.72/13 | 0.97/0 | 0.31/5  | 0.51/42 |
| 40  | 0.60/27 | 0.71/17 | 0.67/17 | 0.96/0 | 0.55/10 | 0.63/44 |
| 60  | 0.59/34 | 0.81/14 | 0.68/42 | 0.96/0 | 0.55/10 | 0.63/44 |
| 80  | 0.62/35 | 0.87/11 | 0.68/16 | 0.96/0 | 0.60/9  | 0.75/38 |
| 100 | 0.62/39 | 0.96/3  | 0.69/17 | 0.96/0 | 0.00/0  | 0.00/0  |

- **A4 — SFTO advantage HOLDS at every penetration (0.96–0.97, FPR 0%).** Does not degrade
  at low intensity → a **real matched loss**; leave as-is pending 5-seed.
- **A2 — TAP advantage is penetration-dependent.** Near-tie at p20 (0.56 vs 0.51), grows to
  0.96 at p100. Concentrated at the aggressive point; at low intensity Proposed nearly matches.
- **A3 — SFTO's higher MCC costs 38–44% FPR** vs Proposed's 5–10% (outside the ≤1% budget) —
  not a matched comparison; at matched FPR Proposed wins A3.

**Gap:** recalibrated baselines were run across **penetration only** (default delay/selectivity).
Recal points across Exp1 delay-intensity {55,200 ms} and Exp4 selectivity {0.10–0.75} were
**not** run — those need new runs to complete the two other sweep axes.

## Pending

- **Vanilla-FADE line:** eFADE cross-attack = 0.00 is *measured* (`--fade_force`). Vanilla
  FADE (conservation-only, no duplication-node localisation) is not yet a separate mode in
  `efade_detection.h`; its A1–A4 score is 0.00 by mechanism (identical conservation test,
  no duplication in delay/TCAM attacks). A distinct vanilla-FADE run to show the explicit
  second line needs a small code mode + one run.
- Recalibrated SFTO (θ=0.121) + TAP (fix flag) runs — need the machine.
- Figure PNG rendering; TAP/SFTO/eFADE lines for speed/AOEI subplots.
- N=400 (Exp 3 4th point); 5-seed significance; VANGUARD-HF — all deferred.

## How to render the figure PNGs (for whoever picks this up)

The numbers above are final; only the plots need generating. Steps:
1. `pip install matplotlib` — it is NOT installed on the handover machine, which is
   why the PNGs are not in this commit.
2. Regenerate the score CSVs the plotters read (`exp1_scores.csv`, `exp4_scores.csv`,
   `exp2_scores.csv`, `sfto_sweep.csv`) from the fresh detector_windows / TAP / SFTO /
   fade_results in `results_routing`. Columns expected by `scripts/plot_phantom_exp14.py`:
   `exp,pen,intensity,arm,attack,MCC,FPR` (arm ∈ {PHANTOM, Lightweight, TAP, SFTO, eFADE}).
   The per-cell values are the ones tabulated above; run tags are `exp1_p*` (Full),
   `lw_p*_Q1` (Lightweight), `*tap` (TAP), `lw_p*_bl` (SFTO/eFADE).
3. `scripts/plot_phantom_exp14.py` / `plot_phantom_exp23.py` currently plot PHANTOM +
   TAP + offline SFTO; add the **Lightweight** and **eFADE (cross-attack)** lines and
   point SFTO at the in-sim `SFTO_metrics` values (offline `sfto_sweep.csv` is retired).
4. Run the plotters → `exp1_mcc.png`, `exp2_speed.png`, `exp3_scale.png`, `exp4_aoei.png`.
