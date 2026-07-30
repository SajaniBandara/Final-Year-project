# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

MOBIGUARD — a zero-trust security framework for Software-Defined Vehicular Networks (SDVN), simulated in NS-3.35. It models 200 vehicles, 64 RSUs (8×8 grid), and 4 SDVN controllers over a SUMO-derived Los Angeles mobility trace, and implements 8 attack variants (Selective Time Delay + Hidden Forwarding + TCAM exhaustion) alongside their MOBIGUARD detection signatures (S1–S8), a post-quantum crypto integrity layer (ML-DSA-87 + HMAC-SHA3-512 + STARK-style timing proofs), a modeled blockchain consensus layer, and a federated LSTM anomaly detector. It is a Final Year thesis project (`docs/main.tex`).

## Repo vs. NS-3 tree

The actual NS-3 build lives outside this repo, at `~/ns3_g13/ns-allinone-3.35/ns-3.35/`. Every file in `scratch/` here is **symlinked** (not copied) into `~/ns3_g13/ns-allinone-3.35/ns-3.35/scratch/routing/` — editing either path edits the same file, and `./waf build` there picks up changes immediately. `scratch/wscript` (already present, linking `oqs`, `ssl`, `crypto`) is what makes the crypto layer link correctly; don't recreate it.

Result CSVs, per-op crypto timing logs, and LSTM training CSVs all land in `~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/` — not inside this repo.

## Build

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
./waf build
```

Incremental builds after touching `routing.cc` take ~15-20s. First-time setup (liboqs + OpenSSL dev headers) is documented in `README.md` §2.1 — not needed on the existing HPC environment where liboqs is already installed system-wide.

## Running a single simulation

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
./waf --run-no-build "scratch/routing/routing \
  --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --architecture=3 \
  --simTime=40 --attack_number=1 --attack_percentage=40 --sim_seed=1"
```

Use `--run-no-build` (not `--run`) whenever launching several instances concurrently — concurrent implicit build checks race on `build/compile_commands.json`'s post-build hook and can crash a run before it starts simulating. Run a single `./waf build` first, then `--run-no-build` for every actual simulation.

`attack_number` (1–8) is the current selector; `active_attack_variant` is legacy (`attack_number - 1`) — don't use it for new runs. See `README.md` §7/§10 for the full attack/CLI table.

## Sweep launchers (`scripts/`)

- `run_std_attacks.py` — Attacks 1–4 (Selective Time Delay CP/DP, TCAM CP/DP), parallel `ThreadPoolExecutor`, `--build`/`--clean`/`--delay`/`--seed` flags.
- `run_hf_attacks.py` — Attacks 5–8 (Hidden Forwarding).
- `run_training_attacks.py` / `run_training_sweep.py` — LSTM training-data collection (`--training=1`, writes `results_routing/lstm_training/RSU_*/A{attack}_pct{pct}_seed{seed}.csv`). `attack=0` means benign (omits `--attack_number` entirely, keeping `active_attack_variant=-1`). `run_training_attacks.py` invokes the binary directly (no waf wrapper, no build-race risk); `run_training_sweep.py` uses `./waf --run` per job and is more prone to the race above at high worker counts.
- `run_tcam_sweep.py` — TCAM-specific parameter sweeps.
- `scripts/crypto_scripts/`, `scripts/treshold_calibration/` — crypto timing verification and S3/S4 threshold calibration.

All of these hardcode `NS3_DIR = ~/ns3_g13/ns-allinone-3.35/ns-3.35` — this is the HPC path, already correct here.

Every launcher that runs many simulations at once should be watched for shared-host etiquette: check `uptime`/`pgrep -af "scratch/routing/routing"` before launching a wide sweep, since this is a shared machine.

## Architecture

**`scratch/routing.cc`** (~144k lines) is the entire simulation: topology/mobility setup, SDVN routing and flow scheduling (Dijkstra-style path/delay computation — `compute_path_delay`, `run_stable_path_finding`/`update_stable`), attack injection dispatch, and the per-packet pipeline that calls out to the header modules below. It's included from a synced/symlinked `scratch/routing/` subdirectory in the NS-3 tree, not built as a bare `.cc` in `scratch/`.

Everything else in `scratch/` is a header included into `routing.cc`, organized by concern:
- **Attack injection**: `attack_declaration.h`, `attack_variables.h`, `selective_time_delay.h` (Attacks 1–2), `tcam_attack_helper.h`/`tcam_flow_generator.h` (Attacks 3–4), `hf_attack_helper.h` (Attacks 5–8).
- **Detection signatures**: `s1_detection.h`/`s2_detection.h` (Selective Time Delay), `tcam_detection.h` (S3/S4, TCAM), `s5–s8_detection.h` + `efade_detection.h` (Hidden Forwarding), `tap_detection.h` (TAP baseline comparator, Attack 2 only), `lrad.h`/`lrad_hmac.h` (lightweight rule-based OBU/RSU detection, gated by `--enable_lrad_obu`/`--enable_lrad_rsu`).
- **Crypto/integrity**: `crypto_layer.h` (ML-DSA-87 sign/verify, STARK-style timing proofs, batch verification), `crypto_event_log.h` (per-op wall-clock timing → `crypto_timing_log.csv`), `dkg_setup.h` (one-time distributed key generation).
- **Blockchain**: `bc_blockchain_helper.h` — modeled/simulated consensus and FlowMod endorsement latency, **not** a real network call to Hyperledger Fabric in the default simulation path (no `system()`/`exec`/gRPC calls in this file); the real Fabric integration described in `README.md` §13 is a separate, optional bridge process that tails simulation logs.
- **LSTM data plumbing**: `lstm_logger.h` (writes per-cycle feature/label CSVs when `--training=1`), `lstm_inference.h` (hand-rolled C++ forward pass of the *trained* model, for in-sim inference — validated against the Python model by `lstm_inference_test.cpp` / `lstm_pipeline/src/gen_cpp_validation_case.py`).
- **Mobility**: `handoff_tracker.h` (RSU handoff detection, feeds S1's jitter compensation).

**Debug logging convention**: several high-frequency per-packet `cout` sites are gated behind file-local `static bool` flags — `CRYPTO_DEBUG_LOG` (`crypto_layer.h`), `ROUTING_DEBUG_LOG` (`routing.cc`, near the `flow_size` declaration — gates the `[DELTA TABLE]` flow-scheduling dump), `DETECTION_DEBUG_LOG_S1`/`DETECTION_DEBUG_LOG_S2` (`s1_detection.h`/`s2_detection.h`). All default `false`. Rare/high-importance events (attack TRIGGERED, detection-event recording, DKG, blockchain commits) print unconditionally regardless of these flags. Flipping any of these to `true` measurably slows a run — `ROUTING_DEBUG_LOG=true` alone was once ~84% of a run's total log volume.

**LSTM pipeline** (`lstm_pipeline/`) is a separate, GPU-accelerated (CUDA/RTX 5090) offline pipeline, orchestrated by `lstm_pipeline/src/pipeline.py`:
1. `preprocessor.py` — loads `results_routing/lstm_training/RSU_*/*.csv`, Z-score normalizes (fit on benign training split only), builds sliding windows (`W=10`, `stride=5`). Seed split is fixed: `TRAIN_SEEDS={1,2,3}` (benign only), `VAL_SEEDS={4}`, `TEST_SEEDS={5}`.
2. `local_trainer.py` — per-RSU hyperparameter grid search (targets MCC subject to FPR≤1%; will fall back to lowest-FPR combo with a `WARNING` when no combo clears 1%).
3. `fed_aggregator.py` — federated training rounds with BRFA-v2 Byzantine-robust aggregation (Krum-style, rejects statistically distant updates before averaging).
4. `evaluator.py` — per-attack-variant MCC/DR/FPR (M1–M8, legacy numbering) → `evaluation_results.json`.
5. `poison_sweep.py` (run explicitly via `--from-step 5`) — BRFA-v2 vs. naive FedAvg under sign-flip poisoning, sweeping malicious-RSU fraction.

`lstm_pipeline/models/*.pt` are gitignored; back them up (`cp -r models models_backup_<date>`) before a pipeline run that will overwrite them if you might need to compare against the previous checkpoint.

## Result/log locations

- `~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/MOBIGUARD_Attack<N>_<pct>_d<delay>ms.csv` — per-attack metrics (S1/S2/TAP; TCAM attacks append extra columns — see `README.md` §9).
- `~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/RSU_*/A<attack>_pct<pct>_seed<seed>.csv` — LSTM training/eval data, one row per routing cycle.
- `~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/crypto_timing_log.csv` — per-crypto-op wall-clock timing (only populated when a run actually reaches per-packet crypto calls).
- `logs/` (this repo, gitignored) — per-run launcher stdout/stderr.

## Known gotchas

- Python `print()` output redirected to a file via `subprocess`/`nohup` is fully block-buffered, not line-buffered — a launcher log can show zero progress for a long-running sweep even though jobs are completing; check output CSVs directly (row counts) rather than trusting the log file mid-run.
- `data_transmission_frequency` is fixed at 1.0 (one routing cycle/sec) by design — don't change it; higher values cause proportional slowdown.
- The S1 EWMA baseline needs ~10s of benign traffic to converge — this is why `attack_start_time` defaults to 10.0s.
