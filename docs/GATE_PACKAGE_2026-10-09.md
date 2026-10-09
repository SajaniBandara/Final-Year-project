# Event-based scoring: package and gate result (2026-10-09)

**Status: GATE NOT PASSED. Stopped as instructed. No full rerun started.** Binary tag `610d3ed+dirty.330cf1d0` (uncommitted tree; the tag is the HEAD hash plus a hash of the tracked diff; it is written into every events file and into a trailing `build_commit` column of the MOBIGUARD CSV).

Supersedes every earlier M1/DR/FPR number (latched scoring). Nothing from the old scoring is quoted below except in the "old" columns, which sit next to the new numbers from the **same run**.

## 1. What was built
- `scratch/event_log.h`: raw per-cycle event log, one file per run (`results_routing/events_<run>.csv`): ACT, ALM1/ALM10, QUA, FIRE, WIT, ATK. Cycle = floor(sim seconds).
- `scripts/event_scorer.py`: the six rules. `scripts/test_event_scorer.py`: tests. `scripts/run_gate.py`, `scripts/score_gate.py`: gate runner and table. `scripts/stamp_build.sh`: build tag. Raw data: `docs/gate/gate_runs.csv`, `docs/gate/anchor_fpr_per_cycle.csv`.
- Run-tag rule: the gate runner deletes any existing output for a tag before launch; the events file is opened truncating.

## 2. Definitions per attack variant (scored node = RSU; a vehicle is attributed to its covering RSU, as the LSTM labels already do)
- **A1 (CP selective delay).** Positive: in a cycle, an RSU holding the poisoned FlowMod scheduled a safety-critical packet for the injected delay (counted after the quarantine-enforcement check, so an aborted injection is not an action). Alarms: S1 per packet at the raw decision, before its first-detection latch; LSTM (window 10).
- **A2 (DP selective delay).** Positive: the malicious node (RSU, or vehicle -> covering RSU) buffered a safety-critical packet. Alarms: S2 per packet (raw, before the latch), LSTM.
- **A3 (CP TCAM).** Positive: a compromised controller's RSU attempted a malicious FlowMod install (TABLE_FULL refusals count, quarantine-blocked attempts do not). Alarms: S3 and S4 every cycle their flag is true; LSTM.
- **A4 (DP TCAM).** Same as A3 with a vehicle attacker; positive is keyed to the victim RSU holding the target table. Alarms: S3/S4, LSTM.
- **A5/A7 (CP hidden forwarding).** Positive: the malicious RSU scheduled a hidden duplicate/copy to the eavesdropper. Alarms: S5 / S7, R_anom rule, LSTM; raw per-packet decision before the latch.
- **A6/A8 (DP hidden forwarding).** Positive: the relay (RSU or vehicle -> covering RSU) scheduled the hidden copy. Alarms: S6 / S8, R_anom, LSTM.
- Not alarms (logged only): witness alerts, BTMM trust decay. Trust-path quarantines are logged in MOBIGUARD runs only; in a TAP-only or FADE-only run only the baseline's own mitigation (TAP defaulter list) counts as a quarantine.
- A5 to A8 were smoke-tested only (A5, 15 s); the gate covers A1 and A3.

## 3. Tests
- (a) Synthetic log: **PASS** (18 checks, `scripts/test_event_scorer.py`): A is TP in cycles 3,4,5, not scored from 6, no FP in 6; B gives one FP in cycle 4 and TN elsewhere.
- (b) Invariants **PASS**: TP+FP+FN+TN = scored nodes every cycle; per-cycle sums = pooled counts; flag nothing / everything -> MCC 0; flag exactly the positives -> MCC 1; no positives -> undefined. 15 s simulator smoke (A1, A3, A5): TP+FN and TN+FP now change over time (A3: 0, 0, 32, 32, ... 16 positives).
- MCC convention: undefined only when a class is absent; 0 when both classes exist but the detector flags nothing or everything. Undefined cycles are counted in the tables.

## 4. Gate (p=40, 180 s, seed 1)
Enforcement switch: `--enable_quarantine_enforcement`. **OFF turns off only quarantine_blocks(): a quarantined node is no longer denied its attack action; trust, quarantine state, controller revocation/failover and every detector keep running.** (This last point matters below.) AB7's ablated arm (quarantine disabled) is moot under enforcement, so it is one run used for both columns.

### 4.1 Acceptance checks
| check | result | numbers |
|---|---|---|
| (a) AB8: S3 fires 0 times in ablated arm | **PASS** after fixing the substitute | S3 raw firings 0 (before the fix 32 / 4,768). Cause: `tcam_flowmod_authorized()` ignored `ab8_single_rsu`; it now uses the same endorsement result as the commit path |
| (a) AB8: enf OFF, ablated M1 not above full | **FAIL** | A3 0.8662 vs full 0.7341 (per-cycle CI about 0.014 / 0.022) |
| (b) AB9: enf OFF, ablated M1 not above full | A1 **PASS** (0.5645 vs 0.5684); A3 **FAIL** (0.8662 vs 0.7341) | |
| (c) AB7: enf OFF, ablated = full | **PASS** when scored without the quarantine stop: A1 0.5684 = 0.5684, A3 0.7341 = 0.7341, identical counts. With rule 4 they differ (A1 0.0716 vs 0.5684) because only the quarantine arm loses nodes from the scored set | |
| (c) AB12: enf OFF, ablated = full | A1 **PASS** (0.5645 vs 0.5684); A3 **FAIL** (0.8662 vs 0.7341) | |
| (d) enf ON: AB9 M5 undefined | **PASS** | failover 0 ms / 0 events vs 12 ms / 2 events |
| (d) enf ON: AB8 M11 up | **PASS** | unauthorised FlowMods blocked 178/178 -> 0/178 (UFCR 100 -> 0) |
| (d) enf ON: AB12 M11 up | **FAIL** | UFCR stays 100, blocked 178/178, while 178 are logged as legitimised: the metric does not move |
| (d) enf ON: AB7 M4 unbounded | **NOT VERIFIABLE** | avg mitigation latency is finite in the ablated arm (A1: 1,375 ms; full 5,470 ms) because it is computed from the detection time; needs the per-event M4 series (item 2b) |

### 4.2 Observations behind the failures (facts only, not conclusions)
- **The arms do not have the same attackers even with enforcement OFF.** A3 positives: full arm and AB7 ablated TP+FN = 2,400 (16 attacking RSUs); AB8/AB9/AB12 ablated TP+FN = 4,800 (32 attacking RSUs). Controller revocation/failover runs with enforcement off (full arm: 2 events, M5 12 ms), and the AB9/AB12/AB8 substitutes suppress it (0 / 0 / 1 events). So the ablated arms have twice the positives, and MCC rises with prevalence at similar FP.
- **S3 alarms are state-like.** In the A3 full arm (enf OFF) false positives by source: S1 653, S3 485, S4 236. S3 raises its alarm while an unauthorised entry sits in the table (entries age out over 30 to 120 s), i.e. in cycles with no new install, which the action label counts as FP. In the ablated arm S3 is absent (fp: S1 503, S4 232), so M1 rises when S3 is removed.
- S1 is the largest FP source everywhere (A1 931 of 931 FPs; benign anchor 848).
- With enforcement ON an attack is stopped within a few cycles, so almost no positives remain after warm-up (A3: TP+FN = 0, M1 undefined in all 150 cycles) while S3/S4 keep alarming on the leftover entries (3,540 FP). M1 is therefore not comparable with enforcement on, as the supervisor said.
- Rule 4 shrinks the scored set heavily: benign false quarantines are frequent (A1: 38 to 53 benign nodes quarantined; A3 enf ON: 120 to 149; benign anchor: 60 to 62).

### 4.3 Which old scoring path gave the inverted AB8/AB9 numbers
The **block scorer** (`m1_local.py` on `detector_windows`): AB8 A3 0.57 (full) vs 0.93 (ablated, enf ON), 0.57 vs 0.86 (enf OFF), as in the gate table. `avg_MCC`/`cur_MCC` (CSV) are identical across arms (0.94382 for all A3 arms) and are not the source. Both read latched state: `avg_MCC`/`cur_MCC` come from `calculate_security_detection_metrics()`, which recounts `is_malicious_node` x `is_detected_node`; the block scorer's truth is `lstm_rsu_ground_truth_label()`, which for A3/A4 returns the `is_malicious_node` latch (never cleared for variants 2/3) unless `tcam_truth_live` is set. The new event M1 still shows the inversion for A3 (4.1), for the reasons in 4.2, so the latch is not the only cause.

## 5. Per-arm tables (counts without quarantine stop; rule 4 in its own column)
| run | TP | FP | FN | TN | M1 new (no q-stop) | M1 new (rule 4) | per-cycle MCC ±CI | undef. cycles | M1 old (block scorer) | avg_MCC old (CSV) |
|---|---|---|---|---|---|---|---|---|---|---|
| ab12abl_A1_enfoff | 595 | 939 | 40 | 8026 | 0.5645 | 0.0903 | 0.5460±0.0283 | 29 | 0.5639 | 0.67967 |
| ab12abl_A1_enfon | 8 | 836 | 0 | 8756 | 0.0930 | 0.1224 | 0.4617±0.2754 | 145 | 0.5521 | 0.671714 |
| ab12abl_A3_enfoff | 4768 | 644 | 32 | 4156 | 0.8662 | nan | 0.8683±0.0142 | 0 | 0.8562 | 0.94382 |
| ab12abl_A3_enfon | 0 | 5357 | 0 | 4243 | nan | nan | nan±nan | 150 | 0.9268 | 0.94382 |
| ab7abl_A1 | 592 | 931 | 35 | 8042 | 0.5684 | 0.5684 | 0.5586±0.0262 | 27 | 0.5786 | 0.680261 |
| ab7abl_A3 | 2384 | 1236 | 16 | 5964 | 0.7341 | 0.7341 | 0.7491±0.0223 | 0 | 0.5653 | 0.94382 |
| ab8abl_A3_enfoff | 4768 | 644 | 32 | 4156 | 0.8662 | nan | 0.8683±0.0142 | 0 | 0.8562 | 0 |
| ab8abl_A3_enfon | 0 | 5357 | 0 | 4243 | nan | nan | nan±nan | 150 | 0.9268 | 0 |
| ab9abl_A1_enfoff | 595 | 939 | 40 | 8026 | 0.5645 | 0.0903 | 0.5460±0.0283 | 29 | 0.5639 | 0.67967 |
| ab9abl_A1_enfon | 8 | 836 | 0 | 8756 | 0.0930 | 0.1224 | 0.4617±0.2754 | 145 | 0.5521 | 0.671714 |
| ab9abl_A3_enfoff | 4768 | 644 | 32 | 4156 | 0.8662 | nan | 0.8683±0.0142 | 0 | 0.8562 | 0.94382 |
| ab9abl_A3_enfon | 0 | 5357 | 0 | 4243 | nan | nan | nan±nan | 150 | 0.9268 | 0.94382 |
| full_A1_enfoff | 592 | 931 | 35 | 8042 | 0.5684 | 0.0716 | 0.5586±0.0262 | 27 | 0.5786 | 0.680261 |
| full_A1_enfon | 8 | 828 | 0 | 8764 | 0.0935 | 0.1224 | 0.3941±0.0816 | 144 | 0.5274 | 0.672546 |
| full_A3_enfoff | 2384 | 1236 | 16 | 5964 | 0.7341 | nan | 0.7491±0.0223 | 0 | 0.5653 | 0.94382 |
| full_A3_enfon | 0 | 3540 | 0 | 6060 | nan | nan | nan±nan | 150 | 0.5735 | 0.94382 |

| run | FP by alarm source | S3 fired (raw) | quarantines true/false | actions blocked | M11 UFCR % | M4 avg mit. latency ms | M5 failover ms |
|---|---|---|---|---|---|---|---|
| ab12abl_A1_enfoff | {'S1': 939} |  | 23/27 | 0 | 100 (178/178 blocked, 178 legitimised) | 6265.76 | 0 (0 events) |
| ab12abl_A1_enfon | {'S1': 836} |  | 29/38 | 2236 | 100 (178/178 blocked, 178 legitimised) | 4274.51 | 0 (0 events) |
| ab12abl_A3_enfoff | {'S1': 503, 'S4': 232} | 32 | 32/64 | 0 | 100 (178/178 blocked, 178 legitimised) | 168007 | 0 (0 events) |
| ab12abl_A3_enfon | {'S1': 732, 'S3': 4768, 'S4': 4999} | 32 | 32/149 | 100276 | 100 (178/178 blocked, 178 legitimised) | 167998 | 0 (0 events) |
| ab7abl_A1 | {'S1': 931} |  | 0/0 | 0 | 100 (178/178 blocked, 0 legitimised) | 1374.92 | 12 (2 events) |
| ab7abl_A3 | {'S1': 653, 'S3': 485, 'S4': 236} | 16 | 0/0 | 0 | 100 (178/178 blocked, 0 legitimised) | 109154 | 12 (2 events) |
| ab8abl_A3_enfoff | {'S1': 503, 'S4': 232} | 0 | 32/64 | 0 | 0 (0/178 blocked, 0 legitimised) | 168007 | 11 (1 events) |
| ab8abl_A3_enfon | {'S1': 732, 'S4': 4999} | 0 | 32/149 | 100276 | 0 (0/178 blocked, 0 legitimised) | 167998 | 0 (0 events) |
| ab9abl_A1_enfoff | {'S1': 939} |  | 23/27 | 0 | 100 (178/178 blocked, 0 legitimised) | 6265.76 | 0 (0 events) |
| ab9abl_A1_enfon | {'S1': 836} |  | 29/38 | 2236 | 100 (178/178 blocked, 0 legitimised) | 4274.51 | 0 (0 events) |
| ab9abl_A3_enfoff | {'S1': 503, 'S4': 232} | 32 | 32/64 | 0 | 100 (178/178 blocked, 0 legitimised) | 168007 | 0 (0 events) |
| ab9abl_A3_enfon | {'S1': 732, 'S3': 4768, 'S4': 4999} | 32 | 32/149 | 100276 | 100 (178/178 blocked, 0 legitimised) | 167998 | 0 (0 events) |
| full_A1_enfoff | {'S1': 931} |  | 24/53 | 0 | 100 (178/178 blocked, 0 legitimised) | 9925.86 | 12 (2 events) |
| full_A1_enfon | {'S1': 828} |  | 29/38 | 2312 | 100 (178/178 blocked, 0 legitimised) | 5470.15 | 12 (2 events) |
| full_A3_enfoff | {'S1': 653, 'S3': 485, 'S4': 236} | 16 | 16/58 | 0 | 100 (178/178 blocked, 0 legitimised) | 109154 | 12 (2 events) |
| full_A3_enfon | {'S1': 769, 'S3': 2860, 'S4': 2620} | 16 | 16/120 | 50632 | 100 (178/178 blocked, 0 legitimised) | 111286 | 12 (2 events) |

Firing counts of every rule flag, per run, are in `docs/gate/gate_runs.csv` (`fires`, post warm-up). LSTM firings are 0 by configuration: the gate runs do not pass \`--enable_lstm_inference=1\` (the weights file exists), so the gate measures the rule flags only. Witness alerts are logged (WIT rows) but are not alarms. Say if the LSTM should be on for the final runs.

## 6. Benign anchor p=0 (per-cycle FPR: `docs/gate/anchor_fpr_per_cycle.csv`)
| method | scored on | FP / node-cycles after warm-up | FPR | false quarantines |
|---|---|---|---|---|
| LRAD, enf ON | same run | 1,107 / 9,600 | 11.5 % (S1 857, S4 361) | 62 |
| LRAD, enf OFF | same run | 1,099 / 9,600 | 11.4 % (S1 848, S4 364) | 60 |
| SFTO | **same run as LRAD** (full stack on), SFTO alarms only, no MOBIGUARD quarantine stop | 20 / 9,600 | 0.21 % | n/a |
| TAP | **own run** (`--enable_tap=1`, LRAD off), TAP alarms, defaulter list = quarantine | 4 / 9,600 (no q-stop) | 0.04 % | **260 nodes put on the Defaulter List within the first seconds** (t = 1.1 s onward), so under rule 4 only 775 node-cycles remain scored |

FADE: not in the gate (HF only); it also runs on its own run (`--fade_force`, LRAD off). Its hook is in (`efade_detection.h`) but untested.

## 7. Step 1 items
- a) Before/after: `docs/STEP1_GUROBI_NOTE_2026-10-08.md` (M1 columns there are invalid, old scoring; PDR, latency, wall time and solver counts stand). Solver: **Gurobi 13.0.2, restricted size-limited licence** (the WLS licence has expired); model is the constant-velocity convex 1-variable QCP; 956,554 of 956,564 solves OPTIMAL.
- b) Link lifetime by speed (3 benign 60 s runs, 264 nodes, 69,432 ordered pairs per call). Share reaching the solver = optimiser pairs / all ordered pairs; after t = 30 s:
| speed | in-range pairs/call | reach solver | mean lifetime (solver pairs) | median | median incl. stationary |
|---|---|---|---|---|---|
| 10 km/h | 5,644 | 5,212 (7.5 %) | 453.7 s | 97.3 s | 100.0 s |
| 60 km/h | 5,962 | 4,763 (6.9 %) | 699.0 s | 31.4 s | 45.5 s |
| 140 km/h | 5,998 | 4,784 (6.9 %) | 599.0 s | 30.9 s | 44.0 s |
  **The 60 and 140 km/h rows are the same traffic.** Speed distributions of the SUMO traces behind `--maxspeed`: 60/100/140/150 all have a moving-vehicle mean of about 28 km/h, p95 about 58 km/h and max 60 to 78 km/h; only the 10 km/h trace differs (mean 7.8, max 10). So Exp 2's speed axis {10, 60, 100, 140} contains two distinct conditions, whatever the solver does. This is a candidate cause of the flat Exp 2 results, independent of Gurobi.
- c) Pairs with a vehicle at (0,0): **none** (0 inactive nodes in every one of the 178 + 58 solver calls checked; all 200 trace start positions are non-zero). Vehicles not yet inserted: **not excluded**: 192 of 200 vehicles make their first move after t > 1 s, 130 after t > 10 s, the last at 44 s, and until then they sit parked at their start point and form stationary (100 s) links. Proposal, not applied: mark a vehicle inactive until its first setdest time. Also: the 9,364 in-range pairs are **ordered** pairs over all 264 nodes (13.5 % of 69,432 ordered pairs, 27 % of the 34,716 unordered), not 47 % of vehicle pairs. Startup checks are in (C++ aborts rc=2 on non-finite state; solver aborts rc=3 on non-finite state or when no pair reaches it).

## 8. Open points needing a decision
1. Enforcement OFF still runs controller revocation/failover, so ablated arms have different attacker sets. Options: make "enforcement OFF" also disable revocation/isolation; or fix the attacker set per run and compare DR/FPR instead of MCC; or only compare arms that share the attacker set.
2. S3 (state-like alarm) versus action labels: either S3's alarm is credited over its entry lifetime as a window (rule 3 style), or S3 is judged on the cycles of installs only. Not changed.
3. Rule 4 with false quarantines: say whether benign false-quarantined nodes should keep being scored (it hides FPs in the baselines, e.g. TAP).
4. AB12's M11 does not reflect the legitimisation (UFCR stays 100); needs a metric that counts legitimised commits.
5. Speed axis: build traces with genuinely different speeds before Exp 2 is rerun.
