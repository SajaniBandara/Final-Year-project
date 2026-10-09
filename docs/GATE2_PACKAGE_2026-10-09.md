# Gate 2 package (2026-10-09)

**Status: GATE 2 PASSED. Every acceptance check passes (section 1).** I stopped here: no rerun has been started.
Binary tag **`91587e1`** (clean: no `+dirty`; commit "event-based scoring, detection-only mode, Gurobi constant-velocity solver"). The tag is in the header of every events file and in the trailing `build_commit` column of every MOBIGUARD CSV.
Setup: 22 runs, p=40, 180 s, seed 1, default SUMO trace, LSTM **off**, crypto on, warm-up 45 s (one value for all runs, after the last vehicle start at 44 s). Scoring: event-based per node-cycle, every node scored in every cycle (rule 4 dropped), A3/A4 state label, A1/A2/A5-A8 action label.

## 1. Acceptance checks
| check | result | numbers |
|---|---|---|
| (b) AB7 A1 detection-only: same TP+FN as full | **PASS** | 533 vs 533 |
| (b) AB7 A1: counts identical, or every difference explained | **IDENTICAL** | dTP=0 dFP=0 dFN=0 dTN=0; M1 0.5651 vs 0.5651 |
| (b) AB9 A1 detection-only: same TP+FN as full | **PASS** | 533 vs 533 |
| (b) AB9 A1: counts identical, or every difference explained | **IDENTICAL** | dTP=0 dFP=0 dFN=0 dTN=0; M1 0.5651 vs 0.5651 |
| (b) AB12 A1 detection-only: same TP+FN as full | **PASS** | 533 vs 533 |
| (b) AB12 A1: counts identical, or every difference explained | **IDENTICAL** | dTP=0 dFP=0 dFN=0 dTN=0; M1 0.5651 vs 0.5651 |
| (c) AB9 A1 closed-loop: M5 undefined (no failover) | **PASS** | failover events 0 (full 2), M5 0 ms (full 12) |
| (c) AB12 A1 closed-loop: UFCR collapses | **PASS** | UFCR 0 % (0/178 blocked, 178 legitimised); full 100 |
| (c) AB7 A1 closed-loop: M4 infinite (acted attackers never contained) | **PASS** | lmit_inf=1, scored_n=0, uncontained=25; full: scored_n=26, latency 2130.85 ms, prevention 0 |
| (b) AB7 A3 detection-only: same TP+FN as full | **PASS** | 4288 vs 4288 |
| (b) AB7 A3: counts identical, or every difference explained | **IDENTICAL** | dTP=0 dFP=0 dFN=0 dTN=0; M1 0.8736 vs 0.8736 |
| (b) AB9 A3 detection-only: same TP+FN as full | **PASS** | 4288 vs 4288 |
| (b) AB9 A3: counts identical, or every difference explained | **IDENTICAL** | dTP=0 dFP=0 dFN=0 dTN=0; M1 0.8736 vs 0.8736 |
| (b) AB12 A3 detection-only: same TP+FN as full | **PASS** | 4288 vs 4288 |
| (b) AB12 A3: counts identical, or every difference explained | **IDENTICAL** | dTP=0 dFP=0 dFN=0 dTN=0; M1 0.8736 vs 0.8736 |
| (a) AB8 A3 detection-only: same TP+FN as full | **PASS** | 4288 vs 4288 |
| (a) AB8 A3: S3 raw firings 0 | **PASS** | s3_fired_count=0, S3 alarms post-warm-up=0 |
| (a) AB8 A3: ablated DR and M1 not above full beyond CI | **PASS** | DR 1.0000 vs 1.0000; M1 0.8736 vs 0.8736; CI 0.0086 |
| (c) AB9 A3 closed-loop: M5 undefined (no failover) | **PASS** | failover events 0 (full 2), M5 0 ms (full 12) |
| (c) AB12 A3 closed-loop: UFCR collapses | **PASS** | UFCR 0 % (0/178 blocked, 178 legitimised); full 100 |
| (c) AB8 A3 closed-loop: UFCR 0 | **PASS** | UFCR 0 % (0/178 blocked); full 100 |
| (c) AB7 A3 closed-loop: M4 infinite (acted attackers never contained) | **PASS** | lmit_inf=1, scored_n=0, uncontained=32; full: scored_n=16, latency 15998.1 ms, prevention 0 |

- (b) is stronger than required: the AB7, AB9 and AB12 detection-only arms are **identical to the full arm in all four counts**, not only in TP+FN.
- AB8: the composite M1 and DR are identical to the full arm because S3 and S4 raise alarms in the same node-cycles in A3. The composite therefore cannot show AB8. S3 alone, full arm: TP 4,288, FP 0, FN 0 (DR 1.0, FPR 0); S4 alone: TP 4,288, FP 233 (FPR 5.4 %); S1 alone: DR 0.10, FPR 0.10. In the ablated arm S3 has 0 firings, so its S3-only recall is 0. Use S3-only recall as the AB8 observable, as for AB10.

## 2. Build items a to g
- **a) Answers 1 to 4 + TP+FN check.** Enforcement OFF is now detection only: no quarantine action, no controller revocation / failover / isolation, no TAP list effect. Rule 4 is gone. A3/A4 use the state label. AB12: a legitimised FlowMod counts as committed and its TCAM entry is authorised (`f_unauth = 0`), and the cancelled penalty means no revocation. `event_scorer.check_same_positives()` flags any two arms with different TP+FN; the gate acceptance uses it.
- **b) Baselines score the raw decision.** TAP used to stop evaluating a sender once it was on its Defaulter List, so its alarm stream ended after about 1 s. It now evaluates every packet. Benign anchor: TAP false-alarm rate is **30.9 % per node-cycle** (the earlier 0.04 % was the artifact), with **261 nodes on its list** (counted separately). SFTO and eFADE alarms are raw per-cycle / per-epoch decisions. TP+FN equals LRAD's: TAP vs LRAD on A2 (15 s smoke) 221 = 221; eFADE vs LRAD on A6 166 = 166; SFTO shares the LRAD run (identical by construction). **Not yet checked on a 180 s attack run**: that comes with the reruns.
- **c) Vehicles inactive until their first move; one warm-up.** Done (195 of 264 nodes inactive at t=1 s, 139 at t=10 s). Warm-up is 45 s for every run.
- **d) M4.** Measured to the SC.Quarantine event, as the pair (prevention rate, mean latency over attackers that acted and were contained) plus the count of acting attackers never contained. AB7 ablated: 0 contained, 25 (A1) and 32 (A3) uncontained, so latency is infinite (`lmit_inf = 1`). The earlier 1,375 ms was measured from detection.
- **e) Smoke 15 s on A1 to A8, eFADE and TAP.** Per-cycle TP+FP+FN+TN = 64 scored nodes every cycle, per-cycle sums equal the pooled counts, TP+FN changes over time, variant and commit are in each header. All pass.
- **f) Gurobi non-OPTIMAL solves.** Across the 22 gate runs: 220 of 20,203,040 solves (0.001 %), all status 13 (SUBOPTIMAL), all on quasi-stationary pairs (closed-form lifetime 1.3e6 to 8.2e6 s), relative error against the closed form at most 3.9e-6. The code accepts a SUBOPTIMAL incumbent only if it agrees with the closed form to 1e-3, logs every such solve (`solver_nonoptimal<tag>.csv`), and **stops the run** on any other status or any disagreement. No silent fallback.
- **g) Witness alerts as alarms.** In the simulator they were never alarms (they only feed trust). They are now logged as their own alarm source and the scorer excludes them unless `--include-witness` is given, so AB6 can use them for S7 and S8. Indicative effect (15 s smoke, not a result): A5 FP 143 to 286, DR 0.89 to 1.00, M1 0.32 to 0.25; A6 M1 0.62 to 0.55; A8 M1 0.45 to 0.47.

## 3. Detection-only arms (M1, DR and FPR come from these)
| run (detection only) | TP | FP | FN | TN | TP+FN | DR | FPR | M1 | per-cycle MCC ± 95 % CI | undefined cycles | FP by source | S3 raw |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| full_A1_enfoff | 499 | 795 | 34 | 7312 | 533 | 0.9362 | 0.0981 | 0.5651 | 0.5614 ± 0.0279 | 27 | {"S1": 795} |  |
| ab7abl_A1_enfoff | 499 | 795 | 34 | 7312 | 533 | 0.9362 | 0.0981 | 0.5651 | 0.5614 ± 0.0279 | 27 | {"S1": 795} |  |
| ab9abl_A1_enfoff | 499 | 795 | 34 | 7312 | 533 | 0.9362 | 0.0981 | 0.5651 | 0.5614 ± 0.0279 | 27 | {"S1": 795} |  |
| ab12abl_A1_enfoff | 499 | 795 | 34 | 7312 | 533 | 0.9362 | 0.0981 | 0.5651 | 0.5614 ± 0.0279 | 27 | {"S1": 795} |  |
| full_A3_enfoff | 4288 | 581 | 0 | 3771 | 4288 | 1.0000 | 0.1335 | 0.8736 | 0.8736 ± 0.0086 | 1 | {"S1": 433, "S4": 233} | 32 |
| ab7abl_A3_enfoff | 4288 | 581 | 0 | 3771 | 4288 | 1.0000 | 0.1335 | 0.8736 | 0.8736 ± 0.0086 | 1 | {"S1": 433, "S4": 233} | 32 |
| ab9abl_A3_enfoff | 4288 | 581 | 0 | 3771 | 4288 | 1.0000 | 0.1335 | 0.8736 | 0.8736 ± 0.0086 | 1 | {"S1": 433, "S4": 233} | 32 |
| ab12abl_A3_enfoff | 4288 | 581 | 0 | 3771 | 4288 | 1.0000 | 0.1335 | 0.8736 | 0.8736 ± 0.0086 | 1 | {"S1": 433, "S4": 233} | 0 |
| ab8abl_A3_enfoff | 4288 | 581 | 0 | 3771 | 4288 | 1.0000 | 0.1335 | 0.8736 | 0.8736 ± 0.0086 | 1 | {"S1": 433, "S4": 233} | 0 |

Per-cycle MCC is over cycles after warm-up; "undefined" cycles have no positives or no negatives.

## 4. Closed-loop arms (UFCR, M4, M5 come from these; M1 is not read from them)
| run (closed loop) | UFCR % (blocked / attempts) | legitimised | M4 prevention | M4 latency ms (n acted and contained) | M4 uncontained | M4 inf | M5 ms (failover events) | quarantines true/false | actions blocked |
|---|---|---|---|---|---|---|---|---|---|
| full_A1_enfon | 100 (178/178) | 0 | 0 | 2130.85 (26) | 2 | 0 | 12 (2) | 26/51 | 2443 |
| ab7abl_A1_enfon | 100 (178/178) | 0 | 0 | 0 (0) | 25 | 1 | 12 (2) | 0/0 | 0 |
| ab9abl_A1_enfon | 100 (178/178) | 0 | 0 | 5028.73 (27) | 1 | 0 | 0 (0) | 27/36 | 2249 |
| ab12abl_A1_enfon | 0 (0/178) | 178 | 0 | 5028.73 (27) | 1 | 0 | 0 (0) | 27/36 | 2249 |
| full_A3_enfon | 100 (178/178) | 0 | 0 | 15998.1 (16) | 16 | 0 | 12 (2) | 16/119 | 51048 |
| ab7abl_A3_enfon | 100 (178/178) | 0 | 0 | 0 (0) | 32 | 1 | 12 (2) | 0/0 | 0 |
| ab9abl_A3_enfon | 100 (178/178) | 0 | 0 | 16091.8 (32) | 0 | 0 | 0 (0) | 32/156 | 100668 |
| ab12abl_A3_enfon | 0 (0/178) | 178 | 0 | 16091.8 (32) | 0 | 0 | 0 (0) | 32/156 | 100668 |
| ab8abl_A3_enfon | 0 (0/178) | 0 | 0 | 16091.8 (32) | 0 | 0 | 0 (0) | 32/156 | 100668 |

With enforcement on, the positives differ from the detection-only run: A1 TP+FN is 5 against 533 (131 cycles have no positives, so M1 is undefined for most of the run), and A3 is 2,393 against 4,288 (the state label keeps a node positive while its entries persist, but fewer RSUs attack because the revoked controller's RSUs stop). M1 is therefore not comparable between closed-loop arms; it is taken from the detection-only runs, as instructed.

## 5. Benign anchor (p=0, 180 s), no tuning
| detector (benign p=0, 180 s) | false-alarm rate per decision (after 45 s) | per node-cycle (after 45 s) | share of alarms in first 60 s | concentration |
|---|---|---|---|---|
| LRAD, detection only: S1 | 5.00 % (3221 / 64427) | 8.38 % (724 / 8,640) | 42.0 % | 44 RSUs; 21 give 80 % |
| LRAD, detection only: S4 | 4.19 % (359 / 8576) | 4.16 % (359 / 8,640) | 1.1 % | 10 RSUs; 6 give 80 % |
| LRAD, closed loop: S1 | 5.07 % (3315 / 65418) | 8.33 % (720 / 8,640) | 42.1 % | 44 RSUs; 20 give 80 % |
| LRAD, closed loop: S4 | 4.20 % (360 / 8576) | 4.17 % (360 / 8,640) | 1.1 % | 10 RSUs; 6 give 80 % |
| SFTO (own alarms; same run as LRAD) | n/a | 0.23 % (20 / 8,640) | 0.0 % | 5 RSUs; 2 give 80 % |
| TAP (own run; raw decision) | 74801 violations after warm-up | 30.86 % (2666 / 8,640) | 43.4 % | 61 RSUs; 27 give 80 % |

- LRAD overall false-alarm rate: **11.3 % per node-cycle** after warm-up (S1 8.4 %, S4 4.2 %). Per decision: **S1 5.0 %, S4 4.2 %**. The 1 % S4 calibration is not met in this configuration. Per-cycle FPR for LRAD, SFTO and TAP: `docs/gate2/anchor_fpr_per_cycle.csv`.
- S1 puts 42 % of its alarms in the first 60 s (a third of the run); S4 puts 1 %. S4 is concentrated: 10 RSUs raise all its alarms and 6 give 80 %.
- False quarantines at p=0: LRAD 60 (detection only; state only, no action) / 55 (closed loop); TAP list 261; SFTO run 60.
- Scored on: LRAD detection-only and SFTO are separate runs with identical S1/S4 numbers; SFTO is scored on its own alarms only. TAP is its own run (`--enable_tap=1`, LRAD off).

## 6. Answers to your questions
- **What the 178 FlowMods are.** Synthetic probes, not the attack's FlowMods. `ufcr_attempt_unauthorized_flowmod` submits one fake FlowMod per second (flow id 0xFFFF, zero honest endorsers) to the commit quorum in control-plane runs, so the count is the run length in seconds and does not depend on attackers. UFCR is therefore the quorum's verdict on that probe.
- **The 485 S3 "false positives" in the full arm.** All 485 sit on 16 RSUs, the RSUs of the revoked controller, in cycles after their last attack action (still holding unauthorised entries). Under the state label they are true; S3 alone has FPR 0.
- **Why TP+FN differed before.** Controller revocation ran with enforcement off (the full arm lost 16 of 32 attackers). Detection-only removes that; TP+FN is now identical (4,288 for A3, 533 for A1).

## 7. Speed traces (item 5)
Method: time-scale the SUMO trace with a 60 km/h road limit (`mobility_urban_60.tcl`, max exactly 60.0 km/h) by k = target / 60. Each vehicle keeps its departure time, path and waypoint positions; segment durations are divided by k and speeds multiplied by k. So the same traffic follows the same routes k times faster and the trace limit equals the target. Departures are not scaled, so the insertion pattern and the 45 s warm-up are the same everywhere. Caveat: a faster trace finishes trips earlier and the vehicle then stays parked at its last waypoint. Built by `scripts/make_speed_traces.py` into `mobility/mobility_urban_v<target>.tcl`; the simulator loads them through `--mobility_trace_file` (12 s smoke on v150 passes). The default trace is unchanged.

| target (max) km/h | mean over all samples | mean, moving only | median, moving | p95, moving | max |
|---|---|---|---|---|---|
| 10 | 2.6 | 4.9 | 4.5 | 9.7 | 10.0 |
| 40 | 10.3 | 18.9 | 16.9 | 38.6 | 40.0 |
| 70 | 18.0 | 32.6 | 29.1 | 67.6 | 70.0 |
| 100 | 25.7 | 46.0 | 41.0 | 96.5 | 100.0 |
| 130 | 33.5 | 59.5 | 53.0 | 125.4 | 130.0 |
| 150 | 38.6 | 68.2 | 60.8 | 144.7 | 150.0 |
| (default, limit 60) | 15.4 | 28.0 | 25.0 | 57.9 | 60.0 |

The plan's speed values are therefore the trace speed limit; plotted against the measured moving mean the axis is 4.9, 18.9, 32.6, 46.0, 59.5, 68.2 km/h. Not yet used in any run.

## 8. LSTM (item 6): not started
Needs, in order: (1) switch the LSTM training label from the latched `lstm_rsu_ground_truth_label` to the new event / state labels (code change, not made yet); (2) collect training data in detection-only mode on the final build; (3) train three times offline and report the spread; (4) turn `--enable_lstm_inference=1` on for all final runs. Off in gate 2 as instructed.

## 9. Run counts and ETA (estimates, assumptions stated)
Configs from the existing runners (dry-run counts): PHANTOM Exp 1 = 72, Exp 2 + 3 = 42, Exp 4 = 24 (Exp 5 and the matching points of Exp 1 to 3 share runs); AB1/4/7 to 13 = 132 + 48 (AB13); VANGUARD Exp 1 to 4 = 232; Hydra = 192 (8 variants x 4 configs x 6 p, run separately and pooled); NEXUS about 112 (N1 48, N2 32, N3 32). Total about **854 configurations**.
- Detection-only runs (M1, DR, FPR for Exp 1 to 5, SOTA tables, AB1 to AB5): one per configuration that reports detection quality.
- Closed-loop runs (all other metrics): one per configuration that reports them. If every configuration needs both, the upper bound is about **1,708 runs**; the lower bound is 854.
- Measured: 5.6 min per 180 s run with 12 runs in parallel on this 32-core machine (about 128 runs per hour per machine). I do not know the other five machines; if they match, six machines give about 770 runs per hour: **1.1 h (854 runs) to 2.2 h (1,708 runs)** of compute, or 6.7 to 13.3 h on this machine alone. LSTM inference overhead is not measured yet and is not included; the Hydra and NEXUS counts are my own estimates.

## 10. Still open (not done)
LSTM relabel / retrain (section 8); items 2b (per-event series for M7, M10, M11, witness precision / recall), 2d (UCR definition), 2e (latency constants), 2f (plot DR at p=100), 2i (node-array cap for N = 220 to 400); the Hydra dwell window; the Manhattan trace; the N, SOTA and flat-result items. Files: `docs/gate2/` (tables), `scripts/score_gate2.py`, `scripts/event_scorer.py`, `scripts/test_event_scorer.py`.
