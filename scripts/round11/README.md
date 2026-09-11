# Round 11 orchestration (2026-09-11)

The exact scripts that produced the round 11 retrain, calibration and final Q1-Q6
table (`docs/RESULTS_FINAL_Q1Q6_round11.txt`). Kept as a record, not as reusable
tooling: every script hardcodes that session's scratchpad directory
(`O=/tmp/claude-1001/.../scratchpad/orch`) for its logs and gate files, so edit `O`
before running any of them again.

| Script | Role |
|---|---|
| `orchestrate.sh` | Original run: retrain steps A1-A7 (preprocess, local training, federated aggregation, classifier head, evaluator, `calibrate_hc_theta.py`, rebuild), then C (C++ export and verification) and D (in-sim classifier threshold calibration). |
| `resume.sh` | Resumed from A6 after two aborts: the evaluator (A5) crashed on appended MOBIGUARD files, then A6 hit CUDA OOM. Runs A6 on CPU; A5 was rerun separately on a clean copy of the results. |
| `q_chain.sh` | Q1-Q6 chain: per seed, the non-LSTM configs, then Q3/Q6 once gate `D_PASS` exists. Written for seeds 5, 6, 7. |
| `q_chain_seed5_finish.sh` | Replaced `q_chain.sh` at 13:20: seeds 6 and 7 were cancelled (single-seed table). Waits for the seed-5 runner, runs seed-5 Q3/Q6, touches `Q_DONE`. |
| `end_watcher.sh` | Waits for `Q_DONE` and runs the collector. |
| `collect_results.py` | Scores the tagged `detector_windows_*_Q*.csv` files with `scripts/m1_local.py`. Writes the results bundle and copies it to `docs/` when the output lands in `O`. `COLLECT_SEEDS` / `COLLECT_OUT` allow dry runs. |

Done by hand that day, not by these scripts:
- 12:28 rebuild adding `LSTM_HC_THETA_CLS` (see `lstm_pipeline/src/calibrate_hc_theta_cls_insim.py`), after all non-LSTM runs had started and before any Q3/Q6 run.
- Stopping `q_chain.sh` (SIGTERM to the chain script only; its seed-5 runner was left running).
- The corrected offline evaluator run on a clean copy of the regeneration's results.
