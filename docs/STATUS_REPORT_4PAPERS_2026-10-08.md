# Status report: four papers (PHANTOM, VANGUARD-HF, NEXUS, Hydra), 2026-10-08

Scope: implement the missing experimental scenarios, 5 s smoke-test the never-run ones, and audit every existing result against the
four questions (SOTA win, ablation direction and metric, flatness, implausible/inverted values).
Binary: optimized, -O3 confirmed, rebuilt 14:08 with the new knob. Host idle. Disk is 95 % full (48 GB free) - watch this before any 180 s sweep.

**Bottom line.** Nothing currently in the repo is at the binding 180 s / seed 1 setting except the AB1/4/7-13 ablation reruns. All PHANTOM Exp 1-5
and VANGUARD Exp 2-3 numbers are 60 s or 300 s, and several of them are internally inconsistent. NEXUS and Hydra have no results because the
simulator has no joint 8-variant mode. I did not build one (reasons in section 2).

---

## 1. Implementation status per paper

| Paper | Experiment | Status | Evidence |
|---|---|---|---|
| PHANTOM | Exp 1-5, AB1-13 | runnable; Exp 1/2/3/4/5 data exist at 60/300 s only | sections 3-5 |
| VANGUARD | Exp 2, 3, 5 | run at 60 s (not 180 s) | `docs/vanguard_exp23/` |
| VANGUARD | **Exp 1** (forwarding intensity {25,50,100} %) | **implemented this session**: `--hf_forward_intensity`, gated at both duplicate sites in routing.cc (S5/S6 and S7/S8); runner extended (`run_vanguard_exp23.py --exp 1 4 --sim 180`, 176 jobs) | 5 s smoke: "intercepted packet" count at intensity 0.25 vs 1.0 = 1 vs 11 (A5), 7 vs 69 (A6), 1 vs 10 (A7), 2 vs 48 (A8); all rc=0 |
| VANGUARD | **Exp 4** | targeting axis wired (same knob). **d_div axis (copy-destination divergence) has no CLI knob; not built.** Paper itself withholds Exp 4 pending the data-provenance question | - |
| Hydra | 4 configs x p, pooled breach | **surrogate only**: `scripts/run_hydra_exp.py` runs the 8 variants separately and pools breach (chi_tau=cur_TVR for S1-S4, chi_D=cur_UCR for S5-S8). Not the paper's concurrent design | 5 s smoke, p=40, 32 jobs, 0 failures. Result shows the design gap (section 4) |
| NEXUS | N1 joint detection | **blocked: no joint mode** (`attack_declaration.h:144` says "future") | - |
| NEXUS | N2 scale {100..400} | N=300 and N=400 **segfault at t=0** (node-array cap, known). N<=200 only | 5 s smoke rc=139 both |
| NEXUS | N3 layer ablation | arms run individually: `--disable_crypto=1` ok, `--enable_lstm_inference=0` ok, `--N_Controllers=1` ok and the single controller is now compromisable ("1 of 1 compromised"). Joint attack and Manhattan trace still missing | 5 s smoke rc=0 x5 |
| NEXUS | Manhattan trace | **absent**. SUMO is installed; an OSM Manhattan extract is not in the repo. Needs a download or a `netgenerate` grid stand-in (your call: a stand-in is not the paper's claim) | `find` |

### Why I did not build the joint mode
It is not one flag. 88 `active_attack_variant == N` gates in routing.cc plus lstm_logger.h, hf_attack_helper.h and tcam_attack_helper.h assume a
single armed variant; the four HF arming functions share `passive_hf_rsu_to_eavesdropper` and the malicious-RSU pool; the CP variants share one
`controller_compromised[]` ladder; the MOBIGUARD CSV, detector_windows and M4 all key on a single `active_attack_variant`. A quick version would run
and produce numbers that are silently wrong, which is the failure mode CLAUDE.md warns about. Estimated 3-5 days of careful work plus a regression
check that every single-variant run stays byte-identical. Say if you want me to start it.

---

## 2. Per-cycle CSV logging (your requirement)

`MOBIGUARD_Attack*.csv` writes one row per routing cycle with `cur_*` and `avg_*` pairs for PDR, latency, MCC, DR, FPR, mitigation latency, TVR and UCR. So the
instantaneous-plus-running-average requirement is met for those eight. Problems that affect the 95 % CIs:

1. **`cur_*` is not instantaneous.** TP/FP/TN/FN are cumulative (FP climbs 3, 13, 20, 41 over cycles 10/20/30/58; TP+FN=27 and TN+FP=441 constant), and cur_DR/cur_FPR are
   computed from them. A VANGUARD A5 run shows cur_DR frozen at 96.3 % from cycle 20 to 58. Cycle-to-cycle values are therefore strongly autocorrelated and a mean +/- std across cycles
   **understates** the uncertainty. Either log true per-cycle counts (delta of the counters) or compute CIs over the 10 s M1 blocks (what the scorer's `M1_blk_mean/std` does).
2. **`avg_*` includes the warm-up zeros** (avg_MCC 0.57 at cycle 58 while cur_MCC has been 0.7-0.8 since cycle 20). Scorers that read the last `avg_*` row inherit this.
3. **No per-cycle series** for M4 prevention rate, M7 (only `*_avg`), M10, M11, witness precision/recall. These are single end-of-run numbers, so no CI is possible for them.
4. **Contaminated files:** a reused `run_tag` appends. 210 of 1050 MOBIGUARD files contain restarted cycle counters, among them every PHANTOM Exp 1/2/4 A3/A4 file
   (e.g. `Attack3_40_seed1_exp1_p40.csv` 578 rows = two runs) and the benign anchor `Attack0_0_seed1_exp1_p0.csv` (2616 rows, 892 restarts). That is why Exp 1 p=0 is blank in `exp1_scores.csv`.
   The 180 s ablation files are clean. **Fix:** the runner must delete or refuse an existing tag before launch.
5. The raw A1/A2 files for PHANTOM Exp 1/2/4 are **not in results_routing any more** (only lambda_l_true files remain), so those scores cannot be re-derived or CI-ed from what is on disk.

---

## 3. Q1: does the proposed method beat the SOTA baselines?

**PHANTOM (vs TAP for S1/S2, SFTO-Guard for S3/S4; seed 1, 300 s, `phantom_seed1_results.md`)**

| | PHANTOM | best baseline, default | best baseline, recalibrated (benign p99) |
|---|---|---|---|
| A1 | 0.57 (FPR 27 %) | TAP 0.20 | TAP 0.32 -> **wins** |
| A2 | 0.59 (FPR 34 %) | TAP 0.58 | TAP **0.81** (FPR 14 %) -> **loses** |
| A3 | 0.56 (FPR 10 %) | SFTO 0.47 | SFTO 0.63 but FPR 44 % -> not matched |
| A4 | 0.68 (FPR 42 %) | SFTO 0.66 | SFTO **0.96** (FPR 0 %) -> **loses** |

The 60 s data in `docs/phantom_exp23/` is worse for the claim: SFTO MCC = 1.00 on S3 and S4 against PHANTOM 0.985 / 0.798.
Honest reading: PHANTOM wins on breadth (each baseline is ~0.1-0.2 off its own niche) and clearly wins only on A1. After fair recalibration it loses A2 and A4.
The abstract/conclusion sentence "sustains macro MCC of X against Y for the strongest baseline" will not survive for per-variant claims.
Comparability caveats: PHANTOM is scored by M1 (per-RSU deduped 10 s blocks); TAP by its own running `avg_MCC`; SFTO by latched per-RSU. Three different scoring rules. Also FPR 14-42 % for PHANTOM is far from the 1 % budget.

**VANGUARD-HF (vs FADE; seed 1, 60 s, p=40, `docs/vanguard_exp23/`)**: VANGUARD 0.61-0.80 per variant against FADE 0.12-0.21 -> large margin and it holds at every speed and scale point.
Caveats before claiming it: (a) the "FADE" arm is the repo's own eFADE extension (`--fade_force` / lrad off), not the published FADE; (b) VANGUARD's LSTM is trained on the same simulator, FADE is not;
(c) VANGUARD FPR is 22-34 %, FADE FPR is not reported; (d) 60 s, not 180 s.

**NEXUS, Hydra:** no data. Hydra is a taxonomy letter and makes no baseline comparison except "neither" as the literature stand-in.

## 4. Q3: flat results (independent variable not reaching the dependent variable)

| Experiment | What is flat | Cause (verified unless marked) |
|---|---|---|
| PHANTOM Exp 1 intensity 55/100/200 ms | macro MCC 0.5888 / 0.5878 / 0.5898 at p=20; same at p=40 | (a) A3/A4 are single runs copied into every intensity column (`run_phantom_exp14.py` docstring: "S3,S4 run once per penetration"); they have no delay knob. (b) The delay-intensity metric is TVR, which is a **binary** over-threshold count: A1 TVR is 4.6-5.3 % at 55, 100 and 200 ms alike (AB13 runs). Any delay above Delta_max counts once |
| PHANTOM Exp 1 penetration | p=40 and p=60 give **identical** A1/A3 MCC (0.6457, 0.5548) and identical AB7 rows | CP variants use a 3-band controller ladder (p<33:1, <66:2, else 3, plus 4 at 100). Five penetration points collapse to four distinct experiments for A1/A3 |
| PHANTOM Exp 2 speed | macro 0.688 / 0.678 / 0.677 / 0.675 | The paper calls this the primary experiment. Detection is speed-insensitive and so is the attack: TVR is *higher* at 10 km/h (7.6 %) than at 140 (4.8 %) in the 180 s runs |
| PHANTOM Exp 4 AOEI | ratio 0.10 and 0.25 identical for all 4 attacks **and for TAP to 6 digits** | A3/A4 constant by construction. For A1/A2 the knob is live (5 s smoke: ratio 0.1 vs 0.25 gives different CSVs, same delayed-line count 298), so the identical scores point to the scoring step or the missing raw files. **Unverified; rerun at 180 s** |
| AB13 static vs adaptive threshold | M1 equal to 4 decimals at every speed (e.g. 0.7320 vs 0.7320 at 10 km/h) | Wrong observable: M1 and TVR are composite/detector-independent. Recalibrating S1/S2 thresholds also left M1 unchanged earlier (A2/A4). Need an S1-only benign FPR and a sub-Delta_max attack |
| Hydra compromise axis | `compromise` == `neither` and `both` == `mobility` **to 4 decimals** in the 5 s smoke | `--ab_compromise_model` is "model only; no attack change" for DP variants, and CP variants are compromised by definition. The sim attacker is also not confined to the dwell window w=2R/s, so speed barely matters (S1 TVR 0.036 -> 0.017). The letter's central predictions (mobility only > neither, compromise only > mobility only) **cannot appear** until the attacker implements the window and the compromise removes it |
| VANGUARD Exp 2 | macro 0.685 / 0.624 / 0.696 / 0.653, not monotone | Noise of +/-0.04 on one seed; the predicted passive-vs-active speed split is not visible |
| VANGUARD Exp 3 | 0.656 / 0.644 / 0.690 | Flat as the paper predicts, but a flat line also can't distinguish "robust" from "insensitive" |

## 5. Q2 and Q4: ablations (expected direction, correct metric) and implausible results

| AB | Expected | Measured (180 s unless noted) | Right metric? | Verdict / fix |
|---|---|---|---|---|
| AB1 OBU pre-filter | S1/S2 MCC drops; latency unaffected? | M6/M4 unchanged; M1 0.634->0.407 (p20), 0.864->0.333 (p100) | M1 is the right one for a detection-quality component | OK. Note p=40 and p=60 identical rows |
| AB2 federated vs central | comparable MCC, privacy gain | MCC 0.457 vs 0.468 (central slightly better) | **No.** M10 not measured ("architectural/qualitative") | Count raw rows leaving each RSU (central N, federated 0). Data still 300 s |
| AB3 ZKP features | MCC lower without | 0.292 vs 0.316 overall, single run, no CI | Partly | Plan says "constant zero column"; code **drops** two columns (`FIVE_FEATURE_IDX`). Different substitute. Rerun with zeroed columns, several training seeds |
| AB4 STARK | M1 equal; M10, M7 differ | M1 identical; M10 0 vs 20-24 k raw timestamps; M7 proof 2.7x plain compare | Yes, after 08a69a5 | OK, but M7 is a modelled SHA3 commitment (6.6e-5 ms), not a real STARK cost. Say so |
| AB5 BRFA vs FedAvg | BRFA degrades less | FedAvg collapses at rho=0.1; BRFA holds to 0.3, fails at 0.4. At rho=0 BRFA 0.517 > FedAvg 0.469 | Yes (M8) | The sign-flip attack was dropped because "too weak to degrade FedAvg" and replaced by 50x scaling: that is attack selection to produce a gap. Disclose. BRFA > FedAvg at zero poison is implausible (noise); needs seeds |
| AB7 quarantine | M4 unbounded, M6 up without | M4 unbounded; M6 26 vs 42-93 ms | Yes | OK |
| AB8 f+1 quorum | M11 rises | 0 % vs 100 %; M1 for A3 is **higher with the ablation** (findings file: 0.61 vs 0.94 at p=40; the 300 s run shows 0.55 vs 0.87) | M11 yes; M1 no | M1 is **inverted** and confounded: the unblocked attacker is never penalised, so positives persist. Report M11 only, and M1 only with enforcement OFF |
| AB9 failover | undefined without | 12 ms vs undefined; **M1 higher without isolation (0.78 vs 0.62)** | M5 yes; M1 no | Same confound: isolating the attacker removes its positives. Inverted by construction |
| AB10 DKG | forged proofs accepted | 27-100 % accepted; S1/S2 MCC not lower | forged-accept share yes; MCC no | MCC not collapsing is expected if verification results never feed detection. Not verified in code: check where a failed proof is consumed |
| AB11 rotation | replay accepted without rotation | 0 % vs 100 % | **Tautological** | The probe replays under a pre-revocation key and acceptance is *defined* by whether rotation retired it, so it measures the flag, not emergent behaviour. Needs a path where a stale key is accepted by the real verifier |
| AB12 RSU-only writes | M11 rises | 0 % -> 100 %; M4/M1 identical to AB9 | M11 yes | Cancelled penalties give no revocation, so it duplicates AB9. Fine, but state it |
| AB13 mobility baseline | adaptive beats static away from 60 km/h | identical to 4 decimals | **No** | See section 4. Sub-Delta_max point and S1-only FPR needed |

Other implausible or inverted values:
- **FPR 14-42 % (PHANTOM), 22-34 % (VANGUARD)** against a 1 % budget stated in the paper. The abstract's MCC claims are bought with this.
- **p=100 collapses MCC** (A3 degenerate: "no benign RSUs left"). That is a property of the scoring, not the detector.
- **UCR 70-80 % while DR is 96 %** (VANGUARD A5). The paper defines UCR as duplicates that reach an unauthorized destination *undetected*; the code (`calculate_ucr_metric`) computes eavesdropped / all-seen packets, which is detector-independent. Metric and definition disagree.
- **Three different values for "A1 at defaults"**: Exp 5 CSV 0.509, Exp 1 p40 0.646, seed1 md 0.571. Exp 5 S3/S4 (0.985, 0.798) are the Exp 3 N=200 60 s numbers, whereas Exp 1 gives A3 0.555 at the nominal same config. Run length alone (60 vs 300 s) moves S3 by 0.4.
- Exp 3: two score files disagree (`exp3_scores.csv` A3 = 1.0 at N=100; `exp3_scale_scores.csv` A3 = 0.56).
- **Latency 17 ms vs 28 ms** for VANGUARD at the same N=200 (Exp 2 at 140 km/h vs Exp 3). End-to-end latency contains wall-clock crypto timings, so it likely depends on host load. Hypothesis, not checked.
- PHANTOM A2 "latency" 100-156 ms includes the injected 100 ms attack delay, so comparing it with the 100 ms safety bound mixes attack and system cost.

## 6. Smoke tests run this session (all 5 s, seed 1, attack_start_time=2)
17 single runs plus the 32-job Hydra surrogate; all completed except the two N>200 cases that segfault: HF intensity x 4 attacks x 2 levels (8), PHANTOM ratio A2 (2), N3 arms (5), N=300/400 (2, rc=139).
A 5 s run has 3 cycles, so these prove plumbing only; no number from them should be quoted.

## 7. What needs your decision
1. Build the joint 8-variant mode? Blocks all of NEXUS and the real Hydra design. Roughly 3-5 days.
2. Hydra: implement the dwell-window w=2R/s on DP attackers and a compromise that removes it, or restate the letter's predictions as analytic only.
3. Manhattan trace: download an OSM extract, or accept a `netgenerate` grid stand-in with that stated in the paper.
4. Are the `cur_*` columns to be redefined as true per-cycle values? That changes every CI.
5. Scoring: one convention for PHANTOM vs TAP/SFTO (same block-level M1 applied to the baselines' alarms), or keep three.
6. Disk: 48 GB free; earlier sweeps wrote ~27 GB of logs (182 MB bc_detection_log per 150 s run). Archive old results first.

Files touched: `scratch/selective_time_delay.h`, `scratch/routing.cc` (knob + 2 gates + CLI), `scripts/run_vanguard_exp23.py` (Exp 1/4, `--sim`), `scripts/run_hydra_exp.py` (new). Not committed.
