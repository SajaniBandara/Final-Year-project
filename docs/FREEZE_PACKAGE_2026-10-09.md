# Freeze and verify package (2026-10-09, night 2)

Frozen build tag **`6d4ddd4`** (clean). Frozen on the default trace and never reset for speed, N or p: **U_thresh 0.37, S1 handoff suppression ON, T_min 0.30**, plus TAP margin 5.623 ms and SFTO theta 0.59 (provisional: matched to LRAD *without* the LSTM; re-matched after the LSTM).
Verification: the 22 gate-2 runs on seed 2 plus a benign closed loop on seeds 2 and 3 (24 runs, simTime 181, cycles 45 to 179 = exactly 135 scored cycles). **311 of 313 assertions pass; the 2 failures are one rule, AB7 "never contained > 0" (section 7).** Nothing else is blocked; LSTM data collection is running.

## 1. S1 suppression (answers to your question)
- **Trigger:** `handoff_just_occurred(vehicle)` from `handoff_tracker.h`: the originating vehicle's serving RSU (strongest DSRC link) changed since the previous routing cycle. **Window: one routing cycle (1 s)**, only the cycle in which the change is detected.
- **Observable by a real RSU:** yes, the serving-RSU change is something the RSUs involved in a handoff know. It does not depend on the injected jitter's value. **But the old code tested a local variable set inside the branch that adds the synthetic 50 to 300 ms jitter (the injector's flag).** The value was identical, the dependency was not. Fixed: the suppression now reads the tracker itself (commit 8ec2e6d).
- **Consumers:** the S1 flag and the controller delay evidence / trust update were already covered (both are driven by S1's return value). **The LSTM input was not**: the jitter-inflated delay still fed the LSTM's mean, max and `obs_exceeded_dmax` features. Fixed: with suppression ON a handoff-explained packet is excluded from those too. **One consumer left unchanged, for you to decide:** S1's own EWMA baseline and variance still include those samples (excluding them narrows sigma and would raise S1's false alarms on the other packets; I did not change a calibrated quantity unasked).

## 2. M7 and M6
- **Constants measured once on one idle machine: Intel Core i9-14900K (32 threads), 2026-10-09**, median per-operation wall time from a 40 s crypto-on run: ML-DSA-87 verify **40.65 us**, STARK hop commitment 0.06 us, consensus round 6,071 us, batch verify = 41.6 + 48.05 x B us. Used unchanged on all six machines (`--crypto_const`, default on).
- **M6 is two columns:** `avg_lat_ms` (simulated delivery time) and `m6_crypto_ms` (constants for the verifications on the delivered packet's own path: the distinct nodes that verified it since its transmission started, x (verify + STARK)); `m6_total_ms` is their sum. Typical benign value: about 10 verifications, 0.4 ms. Per-cycle versions are in `series<tag>.csv`.
- **Crypto flag:** every events file has a `# cfg` header (seed, attack, p, N, speed, trace, **crypto**, lstm, s1_suppress, u_thresh, t_min, enforcement, ...). The batch assertion requires crypto ON in every run except an arm marked as ablating crypto (AB4, N3 No Crypto) and the configuration equal across the arms of a figure apart from the swept variables. Exp 2 previously ran with crypto off; every final run has it on.

## 3. VANGUARD-HF ablations and the corrected run count
AB1 to AB12 on S5 to S8, no AB13. AB3 pi_hop, AB4 hop proof, AB6 witness, AB5 poisoned fraction (offline), AB11 steps after revocation (per-time series from one run per arm), the rest sweep p. **Simulations: 224** (122 detection-only, 102 closed-loop: AB1 20, AB4 20+20, AB6 20, AB7 20+20, AB8 10+10 (CP variants), AB9 8+8, AB10 16, AB11 16, AB12 8+8, full-arm closed loop 20). AB2, AB3, AB5 are offline (57 trainings in total, no simulation).
**Corrected total: 1,780 simulations (1,009 detection-only, 771 closed-loop) plus 57 offline trainings** (PHANTOM 525, VANGUARD-HF 635, Hydra 192, NEXUS 350, LSTM collection 78). About 13.7 h on one machine like mine, 2.3 h on six if they match. `scripts/run_count.py`.

## 4. Speed traces and the N sweep
Routes now repeat (a vehicle at the end of its route drives it back, until the horizon). Limits 10 to 150 km/h (label the axis with the road speed limit; measured means in the table):
| trace (limit km/h) | mean, moving | p95 | max |  moving % at 50 s | 100 s | 150 s |
|---|---|---|---|---|---|---|
| 10 | 5.3 | 9.8 | 10.3 | 86.0 | 58.0 | 59.0 |
| 40 | 19.2 | 38.4 | 41.3 | 61.5 | 60.5 | 66.0 |
| 70 | 34.0 | 67.7 | 73.3 | 55.0 | 53.0 | 62.0 |
| 100 | 47.6 | 96.6 | 104.7 | 65.5 | 57.5 | 60.5 |
| 130 | 62.4 | 125.7 | 136.1 | 60.5 | 55.0 | 62.5 |
| 150 | 71.7 | 145.0 | 157.0 | 61.5 | 56.0 | 65.0 |
| default (mobility_urban_150, not looped) | | | | 59.0 | 67.0 | 53.0 |
| base 60 (not looped) | | | | 59.0 | 68.5 | 52.0 |

- **The assertion "share moving at 50, 100, 150 s within 5 points across the six traces" FAILS as worded: spreads 31.0, 7.5 and 7.0 points.** Causes: at 50 s the 10 km/h trace is still in the start-up transient (86 % moving, every vehicle accelerating out of its start), and each trace has its own stop-and-go phase at a given second. With 200 vehicles the share also has about +/-3.5 points of sampling noise, so six traces span about 9 points by chance alone. **Averaged over the scored window (45 to 179 s) the six traces agree to 4.2 points (58.7 to 62.9 %), and no vehicle parks (in-trip 100 %).** Which of the two should the assertion be?
- **N sweep:** `mobility_urban_N400_perm.tcl` = the 400-vehicle trace with its ids permuted in a fixed random order (seed 20261009), looped; N = 100, 160, 220, 280, 340, 400 are its first N vehicles (nested); last departure 32 s (inside 44 s). The permutation is saved in `docs/N400_perm_order.json`. Note: N = 200 is not in the plan's list, so the default-point runs of Exp 5 cannot come from the Exp 3 runs unless 200 is added.

## 5. The benign false quarantines (your problem)
| run (benign, seed 2, detection only) | S1 suppress | U_thresh | T_min | nodes quarantined | decrements behind them from S4 attribution | whole-run decrements (all from S4 attribution) | quarantine times |
|---|---|---|---|---|---|---|---|
| repro_old_A0_s2 | 0 | 0.2 | 0.7 | 60 ({'vehicle': 60}) | 143 of 143 | 335 on 130 nodes | 49.0 to 177.0 s |
| tm07_A0_s2 | 1 | 0.37 | 0.7 | 14 ({'vehicle': 14}) | 29 of 29 | 74 on 52 nodes | 113.0 to 177.0 s |

- **Every benign quarantine is a vehicle and 100 % of the trust decrements behind it come from one path: the S4 attribution** (when S4 fires on an RSU, the vehicle with the highest packet-in rate there is penalised). Batch/signature, hop proof, delay proof, witness, S5 attribution and controller penalty are all **zero**. That is why S1 on/off never changed the counts (61 / 67), and why S4's few alarming RSUs can still quarantine many vehicles: every S4 firing blames a vehicle.
- At the calibration settings (U_thresh 0.20) a benign run quarantines 60 vehicles; at the frozen U_thresh 0.37 it is 14 with T_min 0.7. With T_min 0.30 (below): 0 and 2 in the two benign closed-loop verification runs (seeds 2 and 3).
- **T_min** (seeds 2 and 3, benign + A1 + A3, detection only, best MCC of "node quarantined vs attacker" subject to <= 5 % of honest nodes quarantined):
| T_min | TP | FP | FN | TN | MCC | honest quarantined (pooled) | benign | A1 | A3 |
|---|---|---|---|---|---|---|---|---|---|
| 0.3 | 106 | 32 | 22 | 1424 | 0.7791 | 2.20 % | 0.38 % | 3.23 % | 3.23 % |
| 0.5 | 108 | 120 | 20 | 1336 | 0.5911 | 8.24 % | 3.79 % | 9.70 % | 11.85 % |
| 0.7 | 108 | 178 | 20 | 1278 | 0.5112 | 12.23 % | 6.25 % | 12.93 % | 18.32 % |

Only 0.3 satisfies the 5 % limit, so the rule is satisfied and I did not stop. **T_min = 0.30.**

## 6. The 128 missing node-cycles
Six runs give 51,840 = 6 x 64 x 135; the calibration pooled 51,712. The missing 128 are the two A3 runs (seeds 2 and 3) at **cycle 179**: the routing loop is `for (t = 1.03; t < simTime - 1; ...)`, so with simTime 180 the last data cycle starts at 178.03 and cycle 179 never runs; A0 and A4 still had a row there only because the per-second TCAM snapshot loop is independent of the routing cycle. **Fix: every run uses simTime 181**, so cycles 45 to 179 are all real routing cycles (asserted: all 135 present, clean exit).

## 7. Verification results (frozen tag, seed 2; benign closed loop seeds 2 and 3)
| run | mode | TP+FN | DR | FPR | M1 | nodes quarantined | honest quarantined | controllers revoked (compromised) | contained by quarantine / revocation / never | UFCR % |
|---|---|---|---|---|---|---|---|---|---|---|
| full_A1_enfon | cl | 9 | 1.0 | 0.0 | 1.0 | 28 | 1.29 % | [0, 1] ([0, 1]) | 6 / 6 / 0 | 100 |
| full_A1_enfoff | do | 463 | 0.892 | 0.0393 | 0.6888 | 25 | 1.72 % | [] ([0, 1]) | 21 / 0 / 4 | 100 |
| ab7abl_A1_enfon | cl | 422 | 0.908 | 0.0414 | 0.6742 | 0 | 0.0 % | [0, 1] ([0, 1]) | 0 / 13 / 0 | 100 |
| ab7abl_A1_enfoff | do | 463 | 0.892 | 0.0393 | 0.6888 | 0 | 0.0 % | [] ([0, 1]) | 0 / 0 / 25 | 100 |
| ab9abl_A1_enfon | cl | 9 | 1.0 | 0.0 | 1.0 | 28 | 1.29 % | [] ([0, 1]) | 25 / 0 / 3 | 100 |
| ab12abl_A1_enfon | cl | 9 | 1.0 | 0.0 | 1.0 | 28 | 1.29 % | [] ([0, 1]) | 25 / 0 / 3 | 0 |
| ab9abl_A1_enfoff | do | 463 | 0.892 | 0.0393 | 0.6888 | 25 | 1.72 % | [] ([0, 1]) | 21 / 0 / 4 | 100 |
| ab12abl_A1_enfoff | do | 463 | 0.892 | 0.0393 | 0.6888 | 25 | 1.72 % | [] ([0, 1]) | 21 / 0 / 4 | 0 |
| full_A3_enfon | cl | 2410 | 1.0 | 0.0083 | 0.9852 | 83 | 28.88 % | [0, 1] ([0, 1]) | 0 / 32 / 0 | 100 |
| full_A3_enfoff | do | 4320 | 1.0 | 0.0211 | 0.9792 | 39 | 3.02 % | [] ([0, 1]) | 32 / 0 / 0 | 100 |
| ab7abl_A3_enfon | cl | 2410 | 1.0 | 0.0165 | 0.9712 | 0 | 0.0 % | [0, 1] ([0, 1]) | 0 / 32 / 0 | 100 |
| ab7abl_A3_enfoff | do | 4320 | 1.0 | 0.0211 | 0.9792 | 0 | 0.0 % | [] ([0, 1]) | 0 / 0 / 32 | 100 |
| ab9abl_A3_enfon | cl | 4320 | 1.0 | 0.012 | 0.988 | 139 | 46.12 % | [] ([0, 1]) | 32 / 0 / 0 | 100 |
| ab12abl_A3_enfon | cl | 4320 | 0.981 | 0.012 | 0.9688 | 139 | 46.12 % | [] ([0, 1]) | 32 / 0 / 0 | 0 |
| ab9abl_A3_enfoff | do | 4320 | 1.0 | 0.0211 | 0.9792 | 39 | 3.02 % | [] ([0, 1]) | 32 / 0 / 0 | 100 |
| ab12abl_A3_enfoff | do | 4320 | 1.0 | 0.0211 | 0.9792 | 39 | 3.02 % | [] ([0, 1]) | 32 / 0 / 0 | 0 |
| ab8abl_A3_enfon | cl | 4320 | 0.981 | 0.012 | 0.9688 | 139 | 46.12 % | [] ([0, 1]) | 32 / 0 / 0 | 0 |
| ab8abl_A3_enfoff | do | 4320 | 1.0 | 0.0211 | 0.9792 | 39 | 3.02 % | [] ([0, 1]) | 32 / 0 / 0 | 0 |
| anchor_lrad_enfon | cl | 0 | None | 0.0086 | None | 0 | 0.0 % | [] ([]) | 0 / 0 / 0 | 0 |
| anchor_lrad_enfoff | do | 0 | None | 0.0086 | None | 0 | 0.0 % | [] ([]) | 0 / 0 / 0 | 0 |
| anchor_tap | do | 0 | None | 0.0098 | None | 92 | 34.85 % | [] ([]) | None / None / None | None |
| anchor_sfto | do | 0 | None | 0.0101 | None | 0 | 0.0 % | [] ([]) | 0 / 0 / 0 | 0 |
| benign_cl_s2 | cl | 0 | None | 0.0086 | None | 0 | 0.0 % | [] ([]) | 0 / 0 / 0 | 0 |
| benign_cl_s3 | cl | 0 | None | 0.011 | None | 2 | 0.76 % | [] ([]) | 0 / 0 / 0 | 0 |

**Passing:** commit == 6d4ddd4 and clean; frozen thresholds equal in every run; all 135 cycles; clean exit; invariants; TP+FN equal across arms in detection-only (A1 463, A3 4,320); AB7, AB9, AB12 detection-only counts identical to the full arm; AB8 S3 raw 0 and DR/M1 equal to the full arm; AB9 closed loop no revocation; AB8 UFCR 0; AB12 UFCR 0 (collapses from 100); **no honest controller is ever revoked** (revoked = compromised in every run); configuration equal across arms; crypto on.
**Failing (2 checks, one rule): AB7 "never contained > 0".** With quarantine off, **controller revocation still contains every attacker** (A1: 13, A3: 32, never contained 0). Quarantine-contained is 0 as asserted. The "infinite M4" only exists in detection-only AB7 (25 and 32 attackers never contained). With your M4 definition (whichever of quarantine or revocation comes first) the AB7 figure should instead show contained-by-quarantine = 0 and all containment by revocation, with its later latency. Say if you want the assertion rewritten that way.

## 8. A problem the table shows: closed-loop honest quarantines on A3
In closed loop on A3, **28.9 % of honest nodes are quarantined in the full arm (83 nodes, 32 of them attackers) and 46.1 % in the AB8, AB9 and AB12 arms (139 nodes)**; the same runs in detection only give 3.0 %. The S4 attribution blames the top packet-in vehicle each time S4 fires; with enforcement on that vehicle is then blocked, the next one becomes the top, and the blame cascades through honest vehicles until the attack ends (the arms without revocation last longer, hence 46 %). A1 closed loop is clean (1.3 %). The 5 % limit was applied to detection-only runs, so T_min 0.3 does not protect closed-loop A3. This will show in every false-quarantine and prevention-rate figure for A3 and A4. Options, none applied: attribute S4 penalties only to vehicles whose packet-in rate exceeds a benign p99 (a per-vehicle test), skip the penalty for a vehicle that is already blocked, or cap the penalty per S4 episode. Your call.

## 9. LSTM (collection running)
Split changed to **train seeds 6, 7, 8 (benign), validate 2 and 3, test 1** (`preprocessor.py`; cycle filter 45 to 180; labels are the event / state `ev_label`; files without it are refused). Collection on the frozen tag: **78 detection-only runs** (benign on seeds 6, 7, 8, 2, 3, 1; A1 to A8 at p = 20, 40, 60 on seeds 2, 3, 1), `--training=1`, the old `lstm_training` directory moved aside. Next: preprocess, train 3 times offline, report the spread, turn the LSTM on, measure the full LRAD benign rate on seeds 2 and 3, **re-match TAP and SFTO to it, freeze again.**

## 10. Housekeeping
The disk filled during the first T_min batch (253 GB in `results_routing`, 170 GB of it `tcam_snapshots`), killing those runs at cycle ~30. I deleted 22 GB of auxiliary logs of my own runs and added `--aux_logs=0` (all final runs; about 0.6 GB per run saved). 149 GB of older auxiliary logs from earlier sweeps remain; deleting them is your decision.


## 11. LSTM: split, training noise, in-simulation behaviour, re-match (2026-10-09, after the freeze)
**Final frozen build: tag `a52e9fa`** (= `6d4ddd4` plus the regenerated `LSTM_HC_THETA`), model artifacts committed in `8fffe6b`. Run headers now carry `lstm_model=5a538c47` (FNV-1a of the weights file). U_thresh 0.37, S1 ON, T_min 0.30, TAP 5.623 ms, SFTO 0.59 are **unchanged** (re-match below).
- **Data and split:** 78 detection-only runs on the frozen build; train seeds 6, 7, 8 (4,800 benign windows), validation seeds 2 and 3 (80,000), test seed 1 (40,000); cycles 45 to 180; labels are the event / state `ev_label`. All old LSTM data moved aside (`lstm_training_ARCHIVED_20261009_pre_final`).
- **Training noise (3 trainings, seeds 1 to 3, about 3 min each on the GPU; overall MCC 0.610, range 0.609 to 0.612).** Offline window-level scores on the test seed (the model's own per-RSU threshold, not the in-simulation bar):

| variant | MCC mean (range over 3 trainings) | DR | FPR |
|---|---|---|---|
| A1 CP-SelectiveDelay | 0.585 (0.582 to 0.588) | 48.4 % | 2.04 % |
| A2 DP-SelectiveDelay | 0.694 (0.693 to 0.696) | 71.8 % | 5.66 % |
| A3 CP-TCAM | 0.798 (0.798 to 0.798) | 80.4 % | 0.18 % |
| A4 DP-TCAM | 0.704 (0.704 to 0.704) | 64.5 % | 0.37 % |
| A5 CP-ActiveHF | 0.440 (0.436 to 0.444) | 47.2 % | 7.40 % |
| A6 DP-ActiveHF | 0.705 (0.703 to 0.707) | 66.3 % | 2.01 % |
| A7 CP-PassiveHF | 0.433 (0.428 to 0.437) | 44.3 % | 6.73 % |
| A8 DP-PassiveHF | 0.613 (0.611 to 0.617) | 54.3 % | 2.15 % |
| Overall (LSTM: attacks 1,2,5-8) | 0.610 (0.609 to 0.612) | 58.4 % | 4.46 % |

  The spread is at most 0.004 MCC on any variant, so differences below that are training noise. Deployed model: the seed-1 training. (The first attempt at seed 3 crashed at start-up with a CUDA segfault on the shared GPU and was rerun unchanged.)
- **In-simulation threshold:** the simulator raises an LSTM detection only above `LSTM_HC_THETA`, the 99.9th percentile of benign validation reconstruction error (the old 39.82 belonged to the old model): **386.744** (55,866 benign validation windows).
- **LRAD full benign false-alarm rate with the LSTM on** (seeds 2 and 3, after warm-up): **0.978 % per node-cycle, all of it from S4; the LSTM contributes none.** Benign quarantines: [0, 2]. Matched baselines: TAP margin 5.623 ms gives 0.990 %; SFTO theta 0.59 gives 0.990 % (highest reachable 39.5 %). **Both are the values already frozen, so the second freeze changes nothing.**
- **What the LSTM does in the simulator (4 attack runs, p=40, seed 2, detection only):** it raises alarms only on **A1** (142 alarm entries: DR 89.2 % to 92.9 %, FPR 3.9 % to 4.3 %, M1 0.689 to 0.694). On A3, A5 and A8 it raises **zero** alarms, so those results are identical to LSTM-off (A3 M1 0.979 unchanged; A5 DR 59.3 %, FPR 8.7 %, M1 0.245; A8 DR 69.4 %, FPR 10.7 %, M1 0.485). The 99.9th-percentile bar is never crossed on the hidden-forwarding variants. For VANGUARD-HF this means the in-simulation detector there is the rule set alone. If you want the LSTM to carry HF, the bar needs a different operating point (for example the per-RSU theta with persistence), which would be a new calibration decision, not applied.
- **Not done / not used:** the classification head and `hf_theta`/`cls_theta` (old, stale) are off with the default flags (`--enable_lstm_cls`, `--enable_hf_theta` not passed); the scripts that train them still use the old latched labels and were not rerun.
