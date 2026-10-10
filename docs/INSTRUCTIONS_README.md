# Supervisor instructions: working README

Source: supervisor messages of 2026-10-08 (15:09 and 15:40), reply to `STATUS_REPORT_4PAPERS_2026-10-08.md`.
**This file is the single tracker. Update it after every completed task** (tick the box, add a line to the Log at the bottom).

**Priority rule: PHANTOM first.** PHANTOM is the author's own paper. When two tasks compete, do the PHANTOM one.
Paper order for runs and write-up: PHANTOM, VANGUARD-HF, Hydra, NEXUS.

## Papers

| Paper | Source file | Scope |
|---|---|---|
| **PHANTOM** (priority) | [phantom_updated.tex](phantom_updated.tex) | Selective time delay, S1-S4, Exp 1-5, AB1-13 |
| VANGUARD-HF | [Vanguard hf.tex](Vanguard%20hf.tex) | Hidden forwarding, S5-S8 |
| Hydra (IEEE Networking Letter) | [ieee letter.tex](ieee%20letter.tex) | 8-variant taxonomy, compromise x mobility |
| NEXUS / selective (IEEE) | [ieee selective.tex](ieee%20selective.tex) | Joint-detection / selective-delay article |

Older drafts for reference only: `phantom.tex`, `main_original_paper.tex`, `main_patched_2026-09-13.tex`.

## Standing rules

- **No full reruns until Step 1 and Step 2 are done.** Any sweep running before that is invalid and must be stopped.
- Final runs: **180 s, seed 1**, a **10 s smoke check before every batch**.
- Tag the binary and write its **commit hash into every output**.
- Exp 5 and the matching points of Exp 1-3 must come from the **same runs**; add a check that flags one config giving different numbers.
- **Opposite-direction ablation = bug until proven otherwise.** Do not reword, do not explain away, do not plot. Send per arm and per p: TP, FP, FN, TN, firing count of every detector flag (rules, LSTM, witness), quarantine events, actual value of the ablated variable. Also run the pair once with enforcement OFF.
- Report **block-level M1** for every method (TAP, SFTO, FADE included) with the **same benign-p99 recalibration**. No handicapping, no tuning against baselines, do not tune the 14-42 % FPR; fix counters (2a), report, disclose FPR in tables. Supervisor decides the narrative after the numbers.
- Do not make design changes to penetration scaling without asking; propose only.
- Wording: variants are **simulated separately and pooled**. Never write "simultaneous" or "concurrent".
- Shared host: check `uptime` / `pgrep -af scratch/routing/routing` before launching. Disk is ~97 % full.

## Step 1: Gurobi (first; send before/after note when done)

- [x] Fill velocity and acceleration from the mobility model in solver inputs
- [x] Drop inactive vehicles (rows at 0,0)
- [x] Startup checks: abort if velocities not finite, or if no pairs reach the optimiser
- [x] Compare **3 configurations before vs after**, including **180 s wall time** (optimiser now actually runs)
- [x] State solver version (bundled licence OK for 4-variable models) for the paper
- [ ] Re-check Exp 2 speed sensitivity afterwards (link lifetimes were carrying no mobility info)
- [x] **Send the supervisor a short note with before/after numbers** -> drafted in [STEP1_GUROBI_NOTE_2026-10-08.md](STEP1_GUROBI_NOTE_2026-10-08.md), not yet sent

## Step 2: logging and metric fixes (before any rerun)

- [ ] **2a** `cur_*` = true per-cycle deltas; `avg_*` excludes warm-up; 95 % CI from post-warm-up per-cycle values
- [ ] **2b** Per-cycle/per-event series for M4, M7, M10, M11, witness precision/recall
- [ ] **2c** Runner refuses/deletes an existing `run_tag`; **delete the 210 contaminated files** (done, see log); score from raw run files only; delete stale score files (done, see log)
- [ ] **2d** UCR = duplicates reaching an unauthorised destination **undetected** (fix code, keep the paper definition)
- [ ] **2e** Latency: replace wall-clock crypto timings with constants measured once on an idle host, injected as simulated delays
- [ ] **2f** p=100: no benign RSUs so MCC undefined; plot DR there
- [ ] **2g** Ground-truth labels: check how positives are labelled per block; labels must be event-based (positive only if an attack action was attempted in that block). **Report findings to the supervisor BEFORE changing scoring.** Likely cause of inverted AB8/AB9.
- [ ] **2h** Archive old results (disk 97 % full; 49 GB is `bc_detection_log*`)
- [ ] **2i** Fix node-array cap so N = 220, 280, 340, 400 run (Exp 3, all papers)

## Step 3: reruns (only after Steps 1-2)

- [ ] PHANTOM Exp 1-5 at 180 s, seed 1
- [ ] VANGUARD-HF Exp 1-5 at 180 s, seed 1
- [ ] Hydra, NEXUS via the pooled design below

### Flat or odd results

- [ ] Exp 1 intensity: lines for A1 and A2 only; metric = detection delay or S1 recall per level (TVR is binary); add one level near the detector threshold
- [ ] Exp 1 penetration: report whether penetration scales malicious RSUs/flows for A1/A3 (p=40 == p=60 via controller ladder). **Propose, do not implement**
- [ ] Exp 2: report benign false violations and baseline FPR by speed; split TVR into benign and attack parts (10 km/h > 140 km/h looks inverted); recheck after Gurobi
- [ ] Exp 4: use six AOEI values (0.10, 0.28, 0.46, 0.64, 0.82, 1.0); confirm raw files differ before scoring
- [ ] VANGUARD: report FADE FPR; call the baseline "adapted FADE" and describe the adaptation in setup

### Ablations

- [ ] **AB8**: verify S3 flag firing count is 0 in ablated arm (f_unauth forced to 0 in rule engine and LSTM input); fix substitute if not. Final figure: M11 plus unauthorised FlowMods committed/blocked vs p (p=0 n/a). M1 only if comparable
- [ ] **AB7, AB9, AB12**: find why M1 rises when defence is removed (AB9 0.78 vs 0.62), labelling (2g) first. Figures: M4, M5 (infinite in ablated arm is the result), M11, M6 for AB7. No M1 line unless comparable
- [ ] **AB10**: compromised controller accepts every invalid proof (currently 31-47 % at p=40, substitute wrong; fix). Measure S2 flag recall on forged-key packets
- [ ] **AB11**: probe through the real verifier with real key material; accepted proofs feed the detector; plot S2 recall vs time after revocation
- [ ] **AB1**: confirm RSU-only mode gets the same inputs; redo substitute if RSU needs OBU output for S1/S2
- [ ] **AB5**: planned grid rho = 0, 0.05-0.25 (extras fine); show rho=0 against retraining spread; disclose 50x scaling replaced sign flip
- [ ] **AB13**: S1 only; delays ~18, 21, 25 ms at 10, 60, 140 km/h; false violations vs detector's own threshold, plus S1 recall
- [ ] **AB3**: zeroed column (not dropped). **AB2**: count raw rows leaving each RSU for M10
- [ ] AB2/3/5: recollect at 180 s after Gurobi fix, retrain; retrain final model **3x offline** to measure training noise
- [ ] Text: AB4 proof cost is a modelled commitment, not a real STARK; AB12 overlaps AB9

### Hydra / NEXUS

- [ ] Joint 8-variant mode **cancelled**. Run each variant separately (same trace, seed, p, 180 s, same models), pool: macro MCC over 8 plus per-variant. Out-of-scope baseline = zero detection
- [ ] NEXUS N3: run each of the four configurations the same way (switches exist)
- [ ] Manhattan: small real OSM extract (a few km2, osmWebWizard), same vehicle counts as LA, no netgenerate stand-in
- [ ] Hydra: implement dwell window w = 2R/s for DP attackers; compromise removes it


## Supervisor reply 2026-10-08 night (BINDING; supersedes earlier wording where it differs)

**Nothing from the latched scoring may be quoted again** (incl. the 300 s SOTA table, the 14-42 % FPR, all M1/DR/FPR to date). AB8/AB9 inversions count as explained only when the gate passes. M1 is **not** a valid before/after check for Gurobi (old scoring). Build in **one tagged build**; send **one package** (definitions per variant, test results, gate table, Step 1 items). Do not wait for the supervisor before building.

### Package item: Step 1 extras
- [x] a) before/after table + solver version (in STEP1 note; M1 columns invalid)
- [x] b) (done: 60 and 140 km/h traces are the same traffic) mean and median link lifetime at 10, 60, 140 km/h and share of pairs reaching the solver (can speed matter now?)
- [x] c) (done: none at 0,0; parked-not-yet-moving vehicles are NOT excluded, proposal in package) confirm no pair involves a vehicle at (0,0) or not yet inserted (9,364 in-range pairs = 47 % of pairs?) and that startup checks are in

### Event-based labels (2a + 2g are one change)
1. Unit = node x routing cycle. A 10 s block = sum of its cycles, one flag per node per cycle.
2. **Positive**: node performed an attack action in that cycle that reached an honest node, even if blocked afterwards. Unauthorised FlowMod rejected by quorum still counts (committed vs blocked = M11). Attempts that never leave a quarantined node are not positives.
3. **Flagged**: any detector alarm on the node. An alarm covering a window is credited to every cycle of its window in which the node attacked. If it did not attack anywhere in the window, FP in the cycle the alarm was raised. A late alarm after quarantine must never become an FP.
4. A quarantined node is **not scored from the next cycle**. Report false quarantines of benign nodes as a count.
5. Scoring reads **no latched state**. TAP, SFTO, FADE emit per-cycle alarms and go through the same scorer (not their own running MCC/latched flags). **Tell the supervisor whether each is scored on the same run as LRAD (quarantine active) or on its own run.**
6. Log per cycle as plain integers: TP, FP, FN, TN, firing count of every flag (rule flags, LSTM, witness), quarantine events. Headline M1 = MCC of counts summed after warm-up. CI from per-cycle values, skipping cycles where MCC undefined (**report how many**). MCC undefined at p=0 and p=100: plot FPR at p=0, DR at p=100.

### Tests before any batch
- [x] a) (PASS, scripts/test_event_scorer.py) Synthetic log: A attacks cycles 3-5, quarantined end of cycle 5; one alarm raised in cycle 6 covers cycles 3-6; benign B flagged only in cycle 4. Expect A TP in 3,4,5, not scored from 6, no FP in 6; B one FP in cycle 4, TN elsewhere.
- [~] b) (scorer invariants PASS in test_event_scorer.py; 15 s sim smoke A1/A3/A5 PASS: TP+FN and TN+FP vary per cycle, sum = scored nodes) 10 s smoke: TP+FN and TN+FP change over time (today constant 27 / 441); TP+FP+FN+TN = scored nodes every cycle; per-cycle sums = pooled counts; flag nothing/everything -> MCC 0; flag exactly the positives -> MCC 1.

### GATE before any full rerun
PHANTOM **AB7, AB8 (A3), AB9, AB12** at p=40, 180 s, seed 1: full and ablated arm, each with enforcement ON and OFF. Say in one line what the enforcement-off switch turns off. Add benign anchor p=0 and send per-cycle FPR for LRAD, TAP, SFTO.
Per arm send: TP, FP, FN, TN, firing count of every flag, quarantine events, actual value of the ablated variable, M11, M4, M5, old latched M1 next to new M1 from the same run. Say which scoring path gave the inverted AB8/AB9 numbers (avg_MCC, cur_MCC or the block scorer) and show it reads latched state.
Accept the fix only if:
- a) AB8: S3 firing count = 0 in ablated arm; with enforcement off, ablated M1 not above full arm.
- b) AB9: enforcement off, ablated M1 not above full arm beyond the CI.
- c) AB7 and AB12 (mitigation only): enforcement off -> both arms same M1 within CI. AB7 ablated = full arm with quarantine suppressed, so must match full arm with enforcement off; if not, say what differs.
- d) Enforcement on: AB7 M4 unbounded, AB9 M5 undefined, AB8 and AB12 M11 up. M1 stays out of these figures (not comparable with enforcement on).
If any check fails: bug in substitute or scoring. **Stop, send the table, do not explain away, do not start full reruns.**

2b-2f, 2h, 2i and the SOTA / flat-result / ablation / NEXUS / Hydra items stand (no tuning against baselines or FPR).


## Supervisor reply 2026-10-09 (BINDING; supersedes the rules above where it differs, incl. rule 4)

**Answers to the six questions**
1. **Enforcement OFF = detection only**: no quarantine, revocation, failover or isolation, and none of the baselines' own mitigation (TAP defaulter list). Compare M1 between two runs only if **TP+FN is identical**; show **DR and FPR beside M1**. (Full arm at its own DR/FPR scores 0.83 with 32 attackers instead of 16: attacker count explains most of the 0.73 vs 0.87 gap.)
2. **A3 and A4 get a STATE label** (S3/S4 test table state): a node is positive from its first unauthorised install until the last unauthorised entry has aged out or been removed (A4: the victim RSU). Alarms inside that interval are true. A1, A2, A5-A8 keep action labels. Check whether the 485 S3 FPs in the full arm sit on the revoked controller's RSUs (counted true they lift the full arm to 0.835).
3. **DROP RULE 4** (supervisor's mistake). Score every node in every cycle. Report false quarantines, and TAP's list size, as a separate count.
4. **M11 = UFCR = share of unauthorised FlowMods blocked**: AB8 ablated should read 0, AB12 should collapse. AB12 today only logs. A legitimised FlowMod must set f_unauth to 0 for that entry, count as committed in UFCR, and the cancelled penalties must stop the quarantine. **Say what the 178 FlowMods are** (same count in every run).
5. **Speed traces: yes, before any speed run.** Plan sets speedFactor 1.0, so road limits cap the traces (max 60-78 km/h). Raise limits to the target or time-scale the trace. Use **10, 40, 70, 100, 130, 150 km/h**; send **mean, p95, max per trace**, plot against the measured mean, state the method. Feeds AB13, Hydra, NEXUS. Default trace stays.
6. **LSTM on in every final run.** It must be retrained on the new labels (its labels are latched for A3/A4): collect in detection-only mode on the final build, train 3x offline, report the spread. **Off in gate 2.**

**What changes**: with enforcement ON attacks stop inside the warm-up (A3: 0 positives, A1: 8), so M1 cannot be read from closed-loop runs. **M1/DR/FPR for Exp 1-5, the SOTA tables and AB1-AB5 come from detection-only runs; every other metric from closed-loop runs.** Send run count and ETA for both on the six machines.

**BUILD (one commit, no "+dirty" in anything reported)**
- [x] a) answers 1-4 + a check that flags any two arms with different TP+FN
- [x] b) baselines score the RAW decision before their own latch/list (TAP's 0.04 % was an artifact: 260 nodes on its list from 1.1 s). TP+FN must equal LRAD's
- [x] c) vehicles inactive until their first move; ONE warm-up for all runs, after the last start (45 s for N=200)
- [x] d) M4 as in the PHANTOM Discussion (prevention rate, and mean latency over attackers that acted before containment), measured to the quarantine event; AB7 ablated = infinite (1,375 ms was measured from detection)
- [x] e) invariants + 15 s smoke on A2, A4, A6, A7, A8 and FADE
- [x] f) the 10 Gurobi solves that were not OPTIMAL: status, what the code does then, **no silent fallback**
- [x] g) before VANGUARD-HF: do witness alerts count as alarms? (AB6 needs it for S7/S8)

**GATE 2**: same 20 runs, LSTM off, plus the benign anchor. Accept if:
- a) AB8 off: same TP+FN as full arm, S3 raw 0, ablated DR and M1 not above full beyond the CI
- b) AB7, AB9, AB12 off: same TP+FN as full arm, counts identical or every difference explained
- c) ON: AB9 M5 undefined, AB8 UFCR 0, AB12 UFCR collapses, AB7 M4 infinite
- Anchor, no tuning: S1 and S4 false-alarm rate **per decision** and per node-cycle, share in the first 60 s, how many RSUs give 80 % of them (paper says S4 calibrated at 1 % and discloses 19.17 % at the OBU stage: state the FPR correctly).
- If anything fails: **stop and send the table; do not start the reruns.**


## Supervisor reply 2026-10-09 (late): GATE 2 ACCEPTED. This message is the whole plan.

**ORDER OF WORK**
1. - [x] (done: commit 3683114, tag clean; calibration tooling ada087a; smoke passes) **One commit, one new tag, no +dirty**: LSTM label switch; items 2b, 2d, 2e, 2f, 2i; the M4 change below; gate-2 acceptance checks as **automatic assertions at the end of every batch**, with **TP+FN equality for TAP and eFADE on 180 s runs** added. If one fails: stop only that experiment, send its table, carry on with the rest. Then a 15 s smoke.
2. - [~] (stage 1 + stage 2 done on seeds 2,3, docs/CALIBRATION_2026-10-09.md; WAITING for the supervisor's S1 setting, then freeze + tag + verification runs) **Calibrate once, on validation seeds that are NOT the reported ones.** U_thresh by the paper's own rule (best MCC at FPR <= 1 %). S1 with handoff-jitter suppression ON and OFF. Send per setting: S1 and S4 false-alarm rate **per decision and per node-cycle**, A1 DR, false quarantines, S1 alarms per 15 s bin after warm-up. **Supervisor chooses the S1 setting the same day.** Then set **TAP, SFTO and eFADE on the same seeds to LRAD's false-alarm rate per node-cycle.** Freeze thresholds in the build and tag it. ("No tuning against the FPR" meant the reported runs, not this.)
3. - [ ] **LSTM**: collect in detection-only mode on the frozen tag, train 3x offline, report the spread, then LSTM ON in every final run.
4. - [~] (corrected run count computed: 1,779 simulations = 998 DO + 781 CL, plus 57 offline trainings; scripts/run_count.py) **Reruns on the frozen tag, seed 1, both families (detection-only and closed-loop), order: PHANTOM, VANGUARD-HF, Hydra, NEXUS.** Send each paper's tables as it finishes. **First send a corrected run count**: the 854 left out the VANGUARD-HF ablations, the TAP and eFADE runs, and the retrains for AB2, AB3, AB5. The rest of section 10 of the gate-2 package comes with its paper.

**M4 (supervisor's mistake)**: for an attacker served by a controller that gets revoked, containment is the revocation if it comes first. Full A3 shows 16 of 32 uncontained and AB8/AB9/AB12 show 0 (reads as the ablations containing more). Expected: the 16 are the revoked controller's RSUs; **tell if not**. **Report "contained by quarantine" and "contained by revocation" as two counts.**

**SPEED TRACES**: ignore the "plot against measured mean" line. Label the axis with the road speed limit 10-150, say so in the paper, give measured means in a table. **Before Exp 2 send the share of vehicles still moving at 50, 100 and 150 s for each trace** (they park after their trips).


## Supervisor reply 2026-10-09 (night 2): three answers, ONE PROBLEM TO SOLVE BEFORE FREEZING

**ANSWERS**
1. **S1 ON.** ON must reach every consumer of S1 timing evidence: the flag, the trust update and the LSTM input. **Tell what triggers the suppression, its window length, and confirm it uses only what a real RSU can observe, not the jitter injector's flag. If it uses the injector's flag: STOP and tell.**
2. **M7 constants accepted, no crypto-delay injection; leave the simulator clock alone.** Measure M7 once on ONE idle machine, state the CPU, use those constants on all six. **M6 = simulated delivery time + constants for the verifications on the packet's path, shown as TWO columns.** Every final run has crypto ON except an arm that ablates crypto (AB4, N3 No Crypto). **Put the crypto flag in the run header and assert it is equal across the arms of a figure.**
3. **VANGUARD-HF ablations = AB1 to AB12 on S5 to S8, no AB13.** AB3 = pi_hop, AB4 = the hop proof, AB6 = the witness, AB5 sweeps the poisoned fraction, AB11 the steps after revocation, the rest sweep p. Make the list match and **send the count**. **Parked vehicles: in every speed trace a vehicle that reaches the end of its route drives it back, repeating until the run ends. Assert that the share moving at 50, 100 and 150 s is within 5 points across all six speed traces; send the table with the default trace added.**

**THE PROBLEM**: benign false quarantines are identical with S1 on/off ([61, 67]) and A1 true quarantines too (23, 21): quarantine does not read the S1 flag, and S4 cannot explain 61/67 (its alarms sat on 10 RSUs in gate 2). A benign run with 60 quarantines is the first thing a reviewer sees.
- On a **benign run, seed 2**, log each quarantine: node, node type, time, and the **trust decrements behind it by source** (each S flag, witness, batch verify, delay proof, hop proof, controller penalty). **Send the breakdown.**
- Run **T_min = 0.3, 0.5, 0.7 on seeds 2 and 3 (benign, A1, A3)**; take the value with the best MCC of "node quarantined" vs "node is an attacker", pooled over those runs, **subject to at most 5 % of honest nodes quarantined. If none reaches 5 %, STOP and send the table.**

**FREEZE AND VERIFY**: freeze U_thresh 0.37, S1 ON and the T_min result. **Rerun the 22 gate-2 runs on seed 2, plus a benign closed loop on seeds 2 and 3.** All assertions pass, plus: every run has **exactly 135 scored cycles and a clean exit** (calibration pooled 51,712 node-cycles where six runs give 51,840: **say which 128 are missing**); **no honest controller is ever revoked**; **AB7 asserts quarantine-contained = 0 and never-contained > 0**. Thresholds are set ONCE on the default trace and never reset for speed, N or p.

**LSTM AND BASELINES**: the LSTM trains on **seeds 6 to 8 only** and validates on **2 and 3**. With it ON, measure the full LRAD benign rate on seeds 2 and 3, **match TAP and SFTO to that rate, and freeze again** (current matches are for LRAD without the LSTM).

**N SWEEP**: N = **100, 160, 220, 280, 340, 400** (not 300). **Nested subsets of one 400-vehicle trace (fixed random order), all departing within 0 to 44 s**, so the 45 s warm-up holds for every N.


## Supervisor reply 2026-10-10: package accepted; TWO FIXES (3, 4) FIRST, THEN START THE RERUNS WITHOUT WAITING

**ANSWERS**
1. Speed assertion = **window average**.
2. AB7: assert **contained by quarantine = 0**; report contained-by-revocation with its latency; **drop "never contained > 0" for closed loop**.
3. **S4 cascade**: blame the vehicle with the highest packet-in rate **only if that rate is above the benign p99 (seeds 2 and 3), and never a vehicle already blocked.** Then closed-loop **A3 and A4 on seeds 2 and 3 must show <= 5 % honest nodes quarantined, attackers still contained.** Keep T_min 0.30 if that holds.
4. **LSTM: use the paper's rule = the classification head with a per-RSU benign quantile threshold (alpha 0.01, floor 0.05).** The current bar is only its high-confidence tier. The head needs attack windows: **run A1-A8 at p 20, 40, 60 on seeds 6-8, detection only, and retrain on the new labels. Keep head or bar, whichever gives the better pooled MCC on seeds 2 and 3. Re-match TAP and SFTO, retag.**
5. S1 baseline: **leave it.**
6. **N = 200: no**; Exp 5 gets its own default runs.
7. **Start: yes.**

**START**: 5 s smokes are too short (scoring starts at 45 s). **Smoke = one full 181 s run per paper.** Go when fixes 3, 4 and the smokes pass, without waiting. **Order: PHANTOM, VANGUARD-HF, Hydra, NEXUS.**
At the end of EACH paper print: (i) failed assertions; (ii) ablation points where the ablated arm beats the full arm on its own metric by more than the CI; (iii) series flatter than their CI. Explain each in one line or fix it. **Flat by design: AB7, AB9, AB12 M1 in detection-only; AB8 composite M1 on A3.** Stop only the paper that fails.

**AUDIT, in parallel with the runs**: one person per paper, 3 h box. Compare LaTeX and code equation by equation and parameter by parameter. **One page per paper: paper says / code does / same or different.** Where different, build the paper's version behind a flag, run seeds 2 and 3, keep the better, ties to the paper. **Seed 1 never decides.** A kept change means retag and rerun the papers it touches. Send each paper's tables with its audit page. Check first:
- a. S5-S8 scored against the **accused node, not the RSU that saw it** (paper: suspect, not observer). A5 and A8 false alarms of 8.7 % and 10.7 % vs 0.9 % benign look like the wrong node.
- b. Witness: **2f+1 distinct verified alerts (f = 1, window 10 s)** issue the penalty and count in the S7 and S8 score. AB6 switches both off. If AB6 leaves S7/S8 M1 unchanged, it is not wired.
- c. Eleven LSTM features with the corrected destination diversity; rule conjuncts and windows as written (S6 30 s, S7 10 s); contained nodes no longer accused; NEXUS N3 substitutes as in the plan; Hydra with no defence.
- d. **TAP quarantines 92 honest nodes (34.85 %) in a benign run: say why in one line.**
- Do not tune a baseline to win a row. If one beats us, send the row.

**Delete the 149 GB of old logs. Tell me when the Manhattan extract is ready; Hydra and NEXUS wait for it.**

## Log (newest last)

- 2026-10-08 17:10: Wrote this README. Archived and deleted the 210 contaminated MOBIGUARD CSVs (restarted cycle counters, 46 MB) to `~/ns3_g13/archive/contaminated_MOBIGUARD_20261008.tgz`. Archived and deleted stale score CSVs (`phantom_exp23/exp1..4_scores`, `exp3_scale_scores`, `exp5_table`, `exp_ci_180`; `vanguard_exp23/exp2,3_scores`, `exp5_table`) to `~/ns3_g13/archive/stale_score_csvs_20261008.tgz`. Clean 180 s ablation score files kept.
- 2026-10-08 17:48: Misaligned Exp 2/3 sweep and all routing sims stopped (host idle, load 0.35). Partial output from that sweep is unreliable (pre-Gurobi-fix, cumulative cur_*) and must not be scored.
- 2026-10-08 20:10: Step 1 done except Exp 2 recheck. Solver input from mobility model, checks added, plus Threads=1 and SUBOPTIMAL handling. Optimiser now sees ~5,490 pairs/call. 180 s run now ~63 min vs ~4.5 min (94 % in solver). Note in docs/STEP1_GUROBI_NOTE_2026-10-08.md. Decision needed on solver speed-up before reruns.
- 2026-10-08 20:56: Supervisor chose constant-velocity solver (acceleration dropped; out-of-range pairs were already skipped). Gurobi QCP validated vs closed form (0/9364 mismatches). 180 s run back to ~265 s wall (solver 57 s). Step 1 complete except the Exp 2 speed recheck (a 4-run batch, to do with the first PHANTOM rerun). Next: Step 2.
- 2026-10-08 21:10: Step 2a/2g investigation (read-only). `cur_MCC/DR/FPR` come from `calculate_security_detection_metrics()` (routing.cc ~117570), which each cycle zeroes sec_TP/FP/TN/FN and recounts them over ALL nodes from `is_malicious_node[v][n]` and `is_detected_node[v][n]`. Both are latched node STATES (a node stays detected once flagged; stays malicious while it is an attacker, A1/A2 gated by a latch that only ever turns on). So `cur_*` is a state snapshot, not a count of events in the cycle, and a true "delta of the counters" does not exist. 2a and 2g are the same fix: per-cycle event labels. Awaiting supervisor go-ahead before changing scoring.
- 2026-10-09: Supervisor approved event-based labels (see section above). Working order: implement labels+logging in one tagged build, synthetic test, 10 s smoke, then the AB7/8/9/12 gate.
- 2026-10-09: Event-based scoring BUILT (build tag in scratch/build_tag.h via scripts/stamp_build.sh). Pieces: scratch/event_log.h (raw per-cycle events: ACT from the existing send-side ground-truth counters, ALM from record_detection_event / TAP / SFTO / FADE raw decisions, QUA, FIRE, WIT), scripts/event_scorer.py (rules 1-6), scripts/test_event_scorer.py (18 checks pass). Positives = attack actions after the quarantine-enforcement check; scored node = RSU (vehicle attackers/alarms attributed to covering RSU). MOBIGUARD CSV gets a trailing build_commit column. Next: gate runs (AB7/8/9/12, p=40, 180 s, enforcement on/off).
- 2026-10-09: Gate run (20 runs) and package written: docs/GATE_PACKAGE_2026-10-09.md. GATE NOT PASSED (AB8 A3, AB9 A3, AB12 A3 M1 above full arm with enforcement off; AB12 M11 does not move; AB7 M4 not verifiable). Fixed on the way: alarms were latch-gated (now emitted at raw decision sites); AB8 substitute did not apply f_unauth=0 to S3 (now does, S3 count 0). Stopped; no full rerun. Awaiting supervisor decision on the 5 open points.
- 2026-10-09 (reply 2): Supervisor answers received. Rule 4 dropped; enforcement-off = detection only; A3/A4 state labels; AB12 must collapse UFCR; speed traces to be rebuilt; LSTM on for final runs (retrain). Working on BUILD a-g, then gate 2.
- 2026-10-09 (gate 2): BUILD a-g done and committed (91587e1, clean tag). GATE 2 PASSED all checks (22 runs). Package: docs/GATE2_PACKAGE_2026-10-09.md. Also done: speed traces (scripts/make_speed_traces.py, mobility_urban_v10..v150.tcl), 485 S3 FPs explained (revoked controller's RSUs), 178 FlowMods = 1/s synthetic probes. NOT done: LSTM relabel/retrain, 2b, 2d, 2e, 2f, 2i, Hydra dwell window, Manhattan. No rerun started; waiting for supervisor.
- 2026-10-09 (plan 3): Gate 2 accepted. Plan received (see section above): commit incl. LSTM label switch + 2b/2d/2e/2f/2i + M4 two counts + batch assertions; calibration on validation seeds; LSTM collect/train; corrected run count; reruns PHANTOM -> VANGUARD-HF -> Hydra -> NEXUS.
- 2026-10-09 (plan 3 progress): Commit 3683114 (LSTM ev_label + preprocessor, M4 two counts, UCR per paper, idle-host M7 constants, series file, node cap, batch assertions) + ada087a (calibration series). 15 s smoke passes incl. TAP/eFADE TP+FN equality (221=221, 166=166) and N=220/300/400 (needs --mobility_trace_file=mobility_urban_scale400.tcl; nv300/nv400 files are stubs). FINDING: simulated latency never contained wall-clock crypto time (same run idle vs under load: latency, PDR, TP/FP bit-identical; t_batch 1.07 vs 1.95 ms); the 17 vs 28 ms gap is crypto-off (Exp 2) vs crypto-on (Exp 3). --crypto_sim_delay NOT implemented (would flip the retry logic and TAP's 1 us claimed-timestamp test). FINDING (M4): full A3 closed loop: the 16 uncontained attackers ARE the revoked controller's RSUs (attacks stopped early); AB8/AB9/AB12 quarantine all 32; AB7 ablated: 16 stopped by revocation, 16 never. Speed traces: share still moving at 150 s: v130 42 %, v150 30 % (others about 55 %), docs/speed_trace_moving_share.csv. Calibration: U_thresh 0.37 (MCC 0.873 at FPR 0.85 %; the old 0.20 gives 3.3 %); S1 suppression ON removes all benign S1 alarms (benign LRAD FPR 9.2 % -> 1.0 % at U 0.37), A1 DR 93.4 -> 91.9 %.
- 2026-10-09 (reply 3): S1 ON chosen; M7 constants accepted (no injection); HF ablations AB1-AB12 on S5-S8; problem: ~60 benign quarantines unexplained -> breakdown + T_min sweep before freezing; then freeze/verify on seed 2; LSTM seeds 6-8 train / 2,3 val; N sweep 100,160,220,280,340,400 from nested subsets.
- 2026-10-09 (night 2 progress): tag 8ec2e6d (S1 suppression reads the tracker + LSTM input, trust-decrement attribution, M6 two columns, cfg header); 83fa3c7 (--aux_logs=0; the disk filled and killed the first T_min batch); FROZEN 6d4ddd4 (U_thresh 0.37, S1 ON, T_min 0.30, TAP 5.623 ms, SFTO 0.59 provisional). Quarantine breakdown: 100 % of benign quarantines (vehicles) come from the S4 attribution path. T_min: 0.3 is the only value <= 5 % honest quarantined (2.2 %). The 128 missing node-cycles = A3 cycle 179 (loop stops at simTime-1); runs now use simTime 181. Verification 311/313 pass; the 2 fails = AB7 'never contained > 0' (revocation contains all). FINDING: closed-loop A3 quarantines 28.9 % (full) / 46 % (AB8/9/12) of honest nodes (S4 attribution cascade). Speed-trace assertion fails per time point (31/7.5/7.0 points), passes on window mean (4.2). N sweep trace built. LSTM split 6-8 / 2,3 / 1; collection of 78 runs running. Package: docs/FREEZE_PACKAGE_2026-10-09.md.
- 2026-10-09 (LSTM): collection of 78 runs done; preprocess (train 4,800 / val 80,000 / test 40,000 windows); 3 trainings overall MCC 0.610 +/- 0.001; LSTM_HC_THETA 386.744; LRAD full benign rate with LSTM 0.978 % per node-cycle (all S4, LSTM adds none); TAP 5.623 ms / SFTO 0.59 re-matched = unchanged. FINAL FROZEN TAG a52e9fa (+ model artifacts 8fffe6b). In-sim the LSTM fires only on A1 (DR 89.2->92.9 %); zero alarms on A3, A5, A8. Next (waiting on the supervisor): approval to start the reruns, decisions on AB7 assertion, speed assertion, S4-attribution cascade, LSTM operating point for HF.
- 2026-10-10: Package accepted. Start reruns after: fix 3 (S4 attribution only above benign p99 and never an already-blocked vehicle; closed-loop A3/A4 seeds 2,3 <= 5 % honest quarantined), fix 4 (classification head, per-RSU benign quantile alpha 0.01 floor 0.05; attacks A1-A8 p20/40/60 seeds 6-8; head vs bar by pooled MCC on seeds 2,3; re-match TAP/SFTO; retag), smoke = one full 181 s run per paper. Delete 149 GB old logs. Audit pages a-d per paper. Manhattan extract: tell when ready.

### 2026-10-10 (later): Fix 4 decided, rebuilt as 29b8e87
- Attack windows A1-A8 at p 20/40/60 on seeds 6-8 collected (72 runs, detection only); preprocessor rebuilt (240,000 windows, 30.4% positive; train 6-8 / val 2,3 / test 1).
- `train_cls_event.py`: encoder frozen, `fc_cls` trained on event/state labels, per-RSU benign quantile theta (alpha 0.01, floor 0.05).
  Pooled MCC (A1, A2, A5-A8 + benign), val seeds 2,3: **head 0.429** (DR 0.266, FPR 0.0087) vs **bar 0.272** (DR 0.101, FPR 0.0012) vs recon-only 0.347. Test seed 1: head 0.435, bar 0.287. Head kept.
  The head is weak on A1, A5, A7 (per-attack val MCC 0.36 / 0.24 / 0.26) and strong on A3 (0.97) and A4 (0.72). Reported as is.
- `enable_lstm_cls` now defaults to true; `rerun_lib.LSTM_FLAGS` passes it; weights exported (`lstm_weights_cpp.bin`, recon-only copy kept).
- Solver call retries once in C++ before stopping the run. Witness alarm moved to the quorum crossing. Commit 29b8e87, binary verified to carry the tag.
- Running now: TAP/SFTO re-match to the head's benign alarm rate (seeds 2,3). Next: apply re-match, retag, smokes, PHANTOM reruns.

### 2026-10-10 (evening): re-match done, tag 24dff13, PHANTOM smoke passed
- **Bug found and fixed (6b3d481):** LSTM and R_anom alarms were logged only while an attack variant was active, so benign runs never recorded their false alarms. The first re-match (LRAD 0.978%, S4 only) was therefore too low. After the fix, on seeds 2,3: LRAD benign false-alarm rate 1.0995% per RSU node-cycle (S4 0.978%, LSTM head 0.122%); 0 benign quarantines.
- Re-match: TAP margin stays 5.623 ms (0.990%); **SFTO theta 0.59 -> 0.56** (1.0995%). Commit 24dff13; binary verified to carry the tag.
- PHANTOM smoke (A1 p40 seed 1, detection only, 181 s, tag 24dff13): rc 0, 181 series rows, event log complete to cycle 181, no solver errors. M1 0.730, DR 0.982, FPR 0.049 (FPs: S1 301, LSTM 123 cycles). Note: 52 honest nodes appear in `quarantined_false` even with enforcement 0; to be explained on the audit page (item d) together with TAP's 92.
- VANGUARD-HF, Hydra, NEXUS have no runner yet (`rerun_vanguard/hydra/nexus.py`), so their smokes are not done; Hydra and NEXUS also wait for the Manhattan extract. Rerun launch is therefore not started.
