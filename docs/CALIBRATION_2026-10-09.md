# Calibration package (2026-10-09)

Setup: build tag `ada087a` (clean), **validation seeds 2 and 3** (the reported seed is 1), 180 s, detection only (enforcement off), LSTM off, benign runs and attack runs at p=40, 20 runs. All rates are per RSU node-cycle after the 45 s warm-up, pooled over the two seeds; "per decision" divides by the detector's own decision count. Raw tables: `docs/calibration/stage1.json`, `stage2_s1_0.json`, `stage2_s1_1.json`; scripts `scripts/run_calibration.py`, `scripts/calibrate.py`.

## 1. S1 setting (your choice; nothing is frozen until you pick)
| setting | false-alarm rate per decision (benign) | per node-cycle (benign) | A1 DR | A1 FPR | A1 M1 (seed 2, 3) | false quarantines (seed 2, 3) | S1 alarm node-cycles per 15 s bin after warm-up (benign, mean of 2 seeds; bins from 45 s) |
|---|---|---|---|---|---|---|---|
| S1 jitter suppression **OFF** | S1 5.23 % / S4 3.99 % | S1 8.54 % / S4 3.96 % | 93.4 % | 11.1 % | [0.4998, 0.5043] | benign [61, 67], A1 [21, 43] (true [23, 21]) | [108.5, 95.0, 80.0, 73.0, 78.5, 78.5, 66.0, 80.0, 78.0] |
| S1 jitter suppression **ON** | S1 0.00 % / S4 3.99 % | S1 0.00 % / S4 3.96 % | 91.9 % | 4.2 % | [0.6817, 0.6895] | benign [61, 67], A1 [21, 43] (true [23, 21]) | [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0] |

- With suppression ON, S1 raises **no** false alarm on benign traffic in either seed (0 of 120694 decisions); every benign S1 alarm with suppression OFF comes from packets that carry the injected 50 to 300 ms handoff jitter.
- A1 DR falls from 93.4 % to 91.9 % (-1.5 points); A1 FPR falls from 11.1 % to 4.2 %.
- With suppression OFF the S1 alarms do not decay after the warm-up (bins stay at 66 to 108 node-cycles per 15 s), so this is not a start-up transient.
- **False quarantines are identical in both settings** (benign [61, 67]), so they do not come from S1. They were measured at the old U_thresh 0.20; I cannot recompute them offline, and will measure them again in the verification runs below.

## 2. U_thresh by the paper's rule: best MCC subject to FPR <= 1 %
Pooled over benign + A3 + A4 (both seeds), S4 flag = occupancy > U_thresh, A3/A4 positives by the state label, 99 thresholds from 0.01 to 0.99.
| U_thresh | TP | FP | FN | TN | MCC | FPR | DR |
|---|---|---|---|---|---|---|---|
| 0.10 | 16418 | 3163 | 2021 | 30110 | 0.7854 | 9.51 % | 89.0 % |
| 0.20 | 16062 | 1104 | 2377 | 32169 | 0.8523 | 3.32 % | 87.1 % |
| 0.30 | 15814 | 452 | 2625 | 32821 | 0.8707 | 1.36 % | 85.8 % |
| 0.35 | 15721 | 333 | 2718 | 32940 | 0.8723 | 1.00 % | 85.3 % |
| 0.36 | 15708 | 304 | 2731 | 32969 | 0.8731 | 0.91 % | 85.2 % |
| 0.37 | 15690 | 283 | 2749 | 32990 | 0.8733 | 0.85 % | 85.1 % |
| 0.38 | 15647 | 260 | 2792 | 33013 | 0.8726 | 0.78 % | 84.9 % |
| 0.40 | 15627 | 230 | 2812 | 33043 | 0.8732 | 0.69 % | 84.7 % |
| 0.50 | 15304 | 121 | 3135 | 33152 | 0.8651 | 0.36 % | 83.0 % |
| 0.60 | 14800 | 49 | 3639 | 33224 | 0.8482 | 0.15 % | 80.3 % |

- **Result: U_thresh = 0.37** (MCC 0.8733, FPR 0.85 %, DR 85.1 %). A feasible threshold exists (FPR <= 1 % is reachable), so no fallback was used.
- The current default 0.20 gives MCC 0.8523, FPR 3.32 %, i.e. it violates the 1 % budget by 3.3x.
- At 0.37 the benign S4 rate is 0.95 % per node-cycle (it was 3.96 % at 0.20).

## 3. Baselines matched to LRAD on the same seeds (stage 2, U_thresh = 0.37)
| LRAD setting | target: LRAD benign FPR per node-cycle (U_thresh 0.37) | TAP | SFTO | eFADE |
|---|---|---|---|---|
| S1 suppression **OFF** | 9.19 % | TAP margin 2.661 ms (FPR 9.17 %; default 1 us gives 28.98 %) | SFTO theta 0.19 (FPR 9.24 %; default 0.90 gives 0.25 %) | eFADE: 0.00 %, no threshold knob |
| S1 suppression **ON** | 0.97 % | TAP margin 5.623 ms (FPR 0.98 %; default 1 us gives 28.98 %) | SFTO theta 0.59 (FPR 0.97 %; default 0.90 gives 0.25 %) | eFADE: 0.00 %, no threshold knob |

- Matching is by benign false-alarm rate per node-cycle; TAP's margin and SFTO's theta are searched on a fine grid (40 steps per decade for TAP, 0.01 for theta).
- eFADE has no threshold: its count-conservation test gave 0 benign false alarms. It cannot be set to LRAD's rate; its FPR is simply reported.
- SFTO's highest reachable rate is 39.22 %, so both targets are reachable. TAP's largest benign timing deviation was 12.70 ms.

## 4. What happens next
1. You choose the S1 setting. 2. I set U_thresh = 0.37, the chosen S1 setting, and the matching TAP margin and SFTO theta as the compiled defaults, commit and tag. 3. **Verification:** two benign runs and two A1/A3 runs on the same validation seeds on the frozen tag confirm the false-alarm rates and measure the false quarantines at the new U_thresh. 4. LSTM collection, training and the reruns start from that tag only.
