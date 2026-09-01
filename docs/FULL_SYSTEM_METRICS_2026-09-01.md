# Full-system metrics — Q6, 2026-09-01

Config: Q6 (full system), 8 variants, 60% attack, seed 1, simTime 300 s,
`--enable_detector_windows=1`. Binary built 2026-08-31 23:10:39 (`optimized`,
`-O3`, includes the 22:22 merge + A4 quarantine fix). **Both arms ran on this
identical binary** — the only difference is `--enable_lstm_cls`.

**Metric numbering is main.tex's, NOT `evaluator.py`'s.** They conflict on
M2/M3/M5/M7/M8 (evaluator.py uses a legacy scheme where M2=DR, M3=FPR, M7=TVR,
M8=UCR). Quoting a bare "M8" across the two means different things.

---

## Headline: the classifier head does not move full-system M1

| arm | M1 MCC | DR | FPR |
|---|---|---|---|
| A — autoencoder (`--enable_lstm_cls=0`) | **0.3836** | 90.8% | 55.2% |
| B — classifier head (`--enable_lstm_cls=1`) | **0.3806** | 91.2% | 56.1% |

Δ = **−0.0030**. The runbook's §6a called the classifier head "the biggest
available win"; in-simulator it is **no win at all**.

**Verified, not assumed:** arm B's logs show
`[LSTM_INFERENCE] classification head ACTIVE (cls_hidden=32)` with no `fc_cls`
fallback warning, and the two arms' grids differ on 2,396 / 2,216 lines
(identical seed and binary ⇒ the flag took effect).

### Why it didn't help

**LSTM-only firing rate is 21.8% in both arms** (6,481 vs 6,462 of 29,696 RSU
windows). The head changed *which* windows fire, not *how many*.

`cls_theta.json`'s per-RSU thresholds were calibrated offline to **FPR ≤ 1%** on
the latched `y_indep` split. In-simulator the same thresholds fire on **21.8%**
of windows. **The offline calibration does not transfer.** That is the finding —
not that the classifier head is worse, but that its operating point is set by a
calibration measured under conditions the simulator does not reproduce.

This also explains the gap with the offline result (A1 DR 2.7% → 11.3%
window-level): that gain was real on the preprocessed split and simply does not
survive into `D_RSU`, where the LSTM is one disjunct of an OR.

---

## M1 — per variant (arm B, deployed config)

| variant | MCC | DR | FPR |
|---|---|---|---|
| A1 | 0.5384 | 96.6% | 31.1% |
| A2 | 0.6352 | 96.9% | 34.1% |
| A3 | 0.4985 | 64.2% | 15.4% |
| A4 | 0.6560 | 86.6% | 18.4% |
| A5 | 0.2332 | 100.0% | 84.6% |
| A6 | 0.2706 | 100.0% | 85.1% |
| A7 | 0.2805 | 99.6% | 78.1% |
| A8 | 0.3234 | 100.0% | 78.0% |
| **ALL** | **0.3806** | 91.2% | 56.1% |

M1 computed by `scripts/m1_local.py` (RSU rows only, 30 s warm-up excluded,
non-overlapping 10 s blocks). **This is a local re-implementation** — the
canonical `metrics/` package does not exist on this host (see below), so absolute
values are not comparable to the historical M1 = 0.2721. Arm-to-arm deltas are
valid.

## Available headroom on M1 (measured offline on arm A)

| construction | M1 |
|---|---|
| deployed today | 0.3836 |
| + persistence M=8 | **0.5539** |
| + LSTM term gated, M=3 | **0.6870** |
| + A3/A4 recall fixed (est.) | 0.7978 |

Persistence is free — no retraining, no code change, no new runs; it thresholds
`score_cycles`, which the simulator already emits.

## M2 / M3 / M6 / M7 (arm B)

| variant | M2 TVR % | M3 UCR % | M6 L_e2e ms | PDR % |
|---|---|---|---|---|
| A1 | 7.607 | 0.000 | 29.00 | 64.82 |
| A2 | 23.030 | 0.000 | 165.72 | 63.58 |
| A3 | 2.687 | 0.000 | 27.23 | 64.58 |
| A4 | 10.407 | 0.000 | 34.86 | 66.14 |
| A5 | 0.000 | 82.635 | 23.27 | 64.41 |
| A6 | 0.000 | 90.599 | 25.57 | 63.33 |
| A7 | 0.000 | 82.525 | 23.61 | 63.88 |
| A8 | 0.000 | 92.663 | 24.61 | **30.48** |

- **M2 (TVR)** fires only on the timing family (A1–A4) and **M3 (UCR)** only on
  the HF family (A5–A8), which is the designed attack-class separation.
- **M3 is valid only post-`cd6d626`** (the `H(p)` identity + `|P_total|` fix).
  These runs include it; any older UCR figure does not.
- **A8's PDR of 30.5%** is roughly half every other variant's ~64% and warrants
  a look — flagged, not explained.
- **M7** (`o_crypto_bytes_pkt` = 209,427; `t_consensus_ms_avg` ≈ 7.8–9.4 ms):
  the consensus timing is plausible, but 209 kB/packet is not a per-packet
  crypto overhead (ML-DSA-87 signatures are ~4.6 kB). **Units unverified — do
  not report M7 until the column's semantics are confirmed.**

## M4 — BLOCKED, deliberately

`avg_mit_ms` reads 5–111 s across variants, but **must not be reported**:
`enable_quarantine_enforcement` is OFF, so M4 measures the latency of a flag
with no effect on the data path, which is exactly the supervisor's objection.
`enable_corrected_lmit` (documented 2.6× inflation) is also OFF. Both must be
enabled before any M4 number is meaningful.

## M5 / M8 — not collected

M5 (controller failover) is ablation-only. M8 (poisoning resistance) needs
`pipeline.py --from-step 5`, independent of these runs.

---

## Tooling gap found this session

`scripts/m1_from_detector_windows.py` builds a combined grid and then instructs
`python3 -m metrics.run_metrics`. **That package exists nowhere on this host** —
not in `ns3_g13`, not in `ns3_g13_apsari`, never in git history — despite
`detector_windows.h` citing `metrics/config.py` throughout. So the canonical M1
is currently unreproducible here, and `scripts/m1_local.py` was written to close
the gap. Recovering the real `metrics/` package should be a priority: it is the
only way to reconcile against M1 = 0.2721.
