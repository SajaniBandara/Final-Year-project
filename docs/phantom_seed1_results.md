# PHANTOM — seed-1 results (finalised config)

Generated 2026-09-25. Config: **seed 1, simTime 300 s** (30 s warm-up + 270 s scored,
27 non-overlapping 10 s blocks), **crypto-off** (validated byte-identical MCC to
crypto-on), enforcement-off (detection scoring). Metric: **per-window M1** for the
proposed method; baselines report their own per-node/per-RSU MCC. In-sim SFTO-Guard
(θ=0.90); eFADE run cross-attack via `--fade_force`, scored externally.

## Experiment 5 — per-variant SOTA comparison (default, pct 60), MCC

| Variant | Proposed (Full) | Proposed (Lightweight) | TAP | SFTO-Guard | eFADE (cross-attack) |
|---|---|---|---|---|---|
| A1 (STD/CP)  | 0.571 | 0.544 | 0.195 | 0.00 | 0.00 |
| A2 (STD/DP)  | 0.594 | 0.575 | 0.584 | 0.00 | 0.00 |
| A3 (TCAM/CP) | 0.555 | 0.555 | ~0.19 | 0.472 | 0.00 |
| A4 (TCAM/DP) | 0.684 | 0.655 | ~0.27 | 0.661 | 0.00 |

- Proposed wins on breadth: TAP competitive only on A2 (timing niche), SFTO only on
  A4/A3 (flow-table niche); each collapses off-niche. eFADE cross-attack = 0 on all
  (specialised HF detector does not generalise).
- **Full ≈ Lightweight on every variant** — the S1–S4 rule signatures carry PHANTOM's
  detection; crypto/LSTM/witness add negligibly on A1–A4.

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

- Recalibrated SFTO (θ=0.121) + TAP (fix flag) runs — need the machine.
- Figure PNG rendering; TAP/SFTO/eFADE lines for speed/AOEI subplots.
- N=400 (Exp 3 4th point); 5-seed significance; VANGUARD-HF — all deferred.
