# Gurobi check and endorsement fix — 2026-10-08

## Gurobi
- `import gurobipy` failed in every earlier production run (PATH `python3` had no gurobipy), so the link-lifetime
  solver never ran; the simulator printed "Solution not found" and carried on.
- Two interpreters have gurobipy 13.0.2 (pyenv 3.10.14, oqs-env). **The WLS licence (ID 2818952) has expired.**
  gurobipy's bundled size-limited licence ("restricted, non-production use", expires 2027-11-29, limit 2000 variables)
  works: each of our models has 4 variables and solves in ~0.1 ms. The simulator now uses it by default
  (`SDVN_GUROBI_LICENSE=restricted`; `=file` forces ~/gurobi.lic once renewed). If the thesis needs a full licence,
  the supervisor/university must renew the WLS licence.
- Code: explicit interpreter (`SDVN_PYTHON`, default pyenv 3.10.14); non-zero solver exit or an empty solution
  stops the run (`[SOLVER-ERROR]`, rc=2). `--allow_solver_fallback=1` restores the old tolerant behaviour only for
  comparison and labels the run `FALLBACK(no solver)`. Every run writes `results_routing/solver_used<tag>.txt` and the
  results CSV has `solver_used, solver_calls` columns.
- Note: the ns-3 tree's `scratch/optimization*.py` were stale regular files, not the symlinks CLAUDE.md describes;
  they are now symlinks to the repo.

### Gurobi vs fallback (same binary, 180 s, seed 1)
| Config | M1 gurobi | M1 fallback | PDR gurobi | PDR fallback | avg latency ms (g/f) |
|---|---|---|---|---|---|
| A1 p60 d100 | 0.638 | 0.644 | 63.6% | 68.4% | 36.3 / 51.0 |
| A3 p60 | 0.614 | 0.595 | 63.6% | 68.1% | 28.0 / 31.1 |
| A5 p40 | 0.684 | 0.651 | 64.0% | 68.5% | 25.1 / 27.0 |
Detector windows differ between paths. So earlier numbers change modestly (M1 by up to 0.03, PDR by about -5 points).

## Endorsement
Each RSU now checks a FlowMod's content hash against the authorised-policy hash itself; the first f=floor((N_RSUs-1)/3)=21
RSUs are Byzantine and endorse everything (`--byz_rsu_count`, default f). The f+1=22 quorum in bc_commit_flowmod is the only
thing that blocks an unauthorized commit; the ground-truth override is removed (ground truth only decides what the attacker
injected). Per-round `committed` is reset, endorser list reset per cycle, duplicate endorsers rejected.
Check: with 21 Byzantine RSUs 8/8 unauthorized FlowMods blocked; with `--byz_rsu_count=22` 0/8 blocked (quorum breached).
S5 detection still fires (50 triggers in a 10 s debug run).

## Follow-up (supervisor: "does this Gurobi present the correct output?") — checked 2026-10-08
Verified on a real run's solver input (`optimization_link_lifetime_data_*`, 264 nodes, 69,696 pairs):
- Gurobi itself works (13.0.2, restricted licence; same engine as a full licence, size-limited only).
- **The optimiser is never invoked.** 29,384 pairs are out of range (0 s) and 40,312 take the "zero relative motion" shortcut
  (fixed 100 s). 0 pairs reach the optimisation model. Reason: the velocity/acceleration columns written for the solver are
  uninitialised memory (max |v| = 1.06e-309 for all nodes, in every run checked), so every pair looks stationary.
- 80 of 200 vehicle rows have position (0,0) (vehicles not yet reporting / departed), and the node-id column holds odd
  values (0 and 50000). Inactive vehicles at the origin form a phantom clique of in-range 100 s links.
- Source: the controller's `routing_data_at_controller_inst` table is filled from `CustomStatusDataUplinkTag1`
  (routing.cc ~95350); in architecture 3 (vehicle->RSU->controller relay) velocity/acceleration arrive unset. Not yet traced further.
- Consequence: "Gurobi path" lifetimes = in-range graph with a constant 100 s; they carry no mobility information. The
  Gurobi-vs-fallback differences (M1 up to 0.03, PDR -5 pts) therefore come from having a populated in-range matrix vs the
  old fallback, not from solving link-lifetime optimisation.
Not yet done: populate velocity/acceleration from the mobility model, exclude inactive vehicles, rerun, and compare.
