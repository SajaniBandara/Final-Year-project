# Step 1 note: Gurobi inputs fixed, before/after (2026-10-08)

**UPDATE (supervisor decision): acceleration term removed, constant-velocity model s = s0 + v t.** The in-range condition is then a convex quadratic in one variable, solved by Gurobi as a 1-variable QCP (every pair that is in range and moving still goes through Gurobi). Out-of-range pairs were already skipped before the solver (~62,000 of 69,696 per call). Verified against the closed form on all 9,364 in-range pairs of a real input: 0 mismatches, max relative error 1e-9. 956,554 of 956,564 models OPTIMAL (10 SUBOPTIMAL). **180 s run: 259-277 s wall (was ~3,760 s with the acceleration model, 258-294 s in the original broken-input runs); solver total 57 s per run.** Final table is the last one below ("constant velocity"); the acceleration-model sections are kept for the record.


## What was wrong (confirmed) and what changed
1. **Solver input** (`write_csv_status_lifetime`, routing.cc) copied velocity/acceleration from the controller table, which is never filled in architecture 3 (uninitialised, |v| ~ 1e-309). Now position and velocity are read from the mobility model; acceleration = velocity change since the previous solver call (0 on the first call).
2. **Inactive nodes** (position exactly (0,0) or non-finite) are written with nodeid = -1 and get no links. In these runs no vehicle was inactive at the solver calls (`inactive_pairs` = 0 throughout); the 80 rows at (0,0) seen earlier came from the controller table, not the mobility model.
3. **Startup checks:** C++ aborts (rc=2) on any non-finite position/velocity/acceleration; the solver aborts (rc=3) on non-finite state, or if no pair reaches the optimiser.
4. **Two further bugs found while verifying** (not in the request):
   - Gurobi defaulted to every core. With several sims running, load hit ~97 and one call stalled for 56 min. Now `Threads=1`, `TimeLimit=5`.
   - 63 % of models return status 13 (SUBOPTIMAL, nonconvex tolerance). The old code mapped every status other than OPTIMAL/INFEASIBLE to "stable, 100 s". Now the incumbent `l.X` is used. Check: on 400 sampled status-13 models, Gurobi's value matches the analytic last-in-range time within 10 % in 100 % of cases.
5. Per-call counts are logged to `results_routing/solver_pairs<tag>.csv` (pairs out of range / stationary / optimised, status counts).

## Optimiser workload (per solver call, 264 nodes, 69,696 pairs)
| | before | after |
|---|---|---|
| pairs reaching optimiser | **0** | **~5,490** |
| stationary-shortcut pairs | 40,312 | ~1,584 |
| out of range | 29,384 | ~62,000 |

Over a 180 s run: 977,398 models solved, 570,818 SUBOPTIMAL (58 %), 406,580 OPTIMAL, 150 other.

## Before / after, 3 configurations (180 s, seed 1, same binary logic, 3 runs in parallel)
M1 = scripts/m1_local.py (block level). avg_* are the end-of-run running averages from the CSV (still the old cumulative definitions; step 2a not done yet).

| Config | M1 before | M1 after | PDR % before | after | latency ms before | after | wall s before | after |
|---|---|---|---|---|---|---|---|---|
| A1 p60 d100 | 0.638 | 0.531 | 63.6 | 67.6 | 36.3 | 50.7 | 258 | 3750 |
| A3 p60 | 0.614 | 0.578 | 63.6 | 67.7 | 28.0 | 27.3 | 264 | 3763 |
| A5 p40 | 0.684 | 0.554 | 64.0 | 66.8 | 25.1 | 22.6 | 294 | 3774 |

A1 detail: DR 100 % -> 99.1 %, FPR 22.8 % -> 38.0 %. A3: DR 69.6 -> 66.7, FPR 9.6 -> 10.5. A5: DR 95.3 -> 89.5, FPR 16.6 -> 19.7.

## Run time
**~14x slower: 3,750-3,774 s (about 63 min) per 180 s run, against 258-294 s.** The solver accounts for ~3,545 s of that (94 %): 178 calls of ~20 s each. Single-threaded Gurobi, 5,490 models per call, ~3.6 ms per model. The whole PHANTOM + VANGUARD 180 s plan is affected (Exp 1-5 are hundreds of runs). Options, not applied: (a) solve only pairs within a margin of range, (b) reuse the previous solution for pairs whose relative state has not changed, (c) use the closed form for the 4-term quartic (validated above) and run Gurobi on a sampled subset as a check. Needs your decision before reruns.

## Caveats
- Single seed, single run per config; the M1 drops (0.03-0.13) are of the size the one-seed noise noted earlier, so do not read them as a causal effect of the fix yet.
- Exp 2 speed sensitivity was **not** rechecked in this step (needs the 4 speed runs; held for your decision on run time).
- "Before" binary = commit of the pre-fix tree; the fix is uncommitted.
- Solver: Gurobi 13.0.2, restricted size-limited licence (WLS licence expired).

## Final: constant-velocity model (acceleration removed), 3 configs, 180 s, seed 1
| Config | M1 original (no real solver input) | M1 accel model | M1 const-velocity | PDR % (orig / accel / cv) | latency ms (orig / accel / cv) | wall s (orig / accel / cv) |
|---|---|---|---|---|---|---|
| A1 p60 d100 | 0.638 | 0.531 | 0.579 | 63.6 / 67.6 / 65.0 | 36.3 / 50.7 / 44.6 | 258 / 3750 / 259 |
| A3 p60 | 0.614 | 0.578 | 0.565 | 63.6 / 67.7 / 66.2 | 28.0 / 27.3 / 27.9 | 264 / 3763 / 266 |
| A5 p40 | 0.684 | 0.554 | 0.562 | 64.0 / 66.8 / 65.9 | 25.1 / 22.6 / 23.3 | 294 / 3774 / 277 |

Constant-velocity detail: A1 DR 99.5 %, FPR 29.6 %; A3 DR 66.5 %, FPR 11.4 %; A5 DR 87.3 %, FPR 18.4 %.
Per call: ~5,373 pairs reach Gurobi; 178 calls; 57 s total solver time. Paper text must say the link-lifetime model assumes constant relative velocity over the prediction horizon (acceleration dropped).
Single seed: the M1 shifts from the original (0.02-0.12) are within the size of one-seed noise seen earlier; not a claimed effect.
