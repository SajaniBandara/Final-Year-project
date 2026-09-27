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

## Recalibrated baseline line (in progress)

- **SFTO θ_recal = 0.121** (benign RSU occupancy p99; default 0.90). NOT ≈ default —
  the benign-percentile method gives a much lower threshold. Recalibrated *run* pending.
- **TAP margin_recal:** pending — `--tap_calib_dump` logging did not write; needs a fix
  + benign run.

## Methodology updates (in phantom.tex)

- Settings table now states simulation time (300 s + warm-up) and seeds (RngRun 1–5).
- SFTO-Guard switched from offline LightGBM to in-sim real-time mechanism (θ=0.90);
  sampling bug fixed.
- eFADE cross-attack via `--fade_force`, scored externally (per-packet HF path untouched).

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
