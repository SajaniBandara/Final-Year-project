"""
pipeline.py — MOBIGUARD Federated LSTM full pipeline orchestrator

Steps:
  1. preprocessor.py  — load CSVs, Z-score, window, split
  2. local_trainer.py — per-RSU LSTM autoencoder training
  3. fed_aggregator.py — BRFA-v2 Byzantine-robust FedAvg
  4. evaluator.py     — M1–M8 metrics (evaluator.py's own pre-revision
                        numbering: MCC/DR/FPR/L_mit/PDR/L_e2e/TVR/UCR —
                        not the current proposal's M8 = poisoning resistance)
  5. poison_sweep.py  — M8 (current numbering) Delta_poison(rho_mal) sweep,
                        BRFA-v2 vs naive FedAvg (optional, run explicitly)

Run all steps (1-4):
  python3 pipeline.py

Run from a specific step:
  python3 pipeline.py --from-step 3

Run the M8 poisoning sweep (after steps 1-2 have produced clean rsu_*.pt):
  python3 pipeline.py --from-step 5

GPU is used automatically when available (RTX 5090 / CUDA).
"""

import argparse, subprocess, sys, time
from pathlib import Path

REPO    = Path(__file__).resolve().parents[2]
SRC     = REPO / "lstm_pipeline" / "src"
PYTHON  = sys.executable


STEPS = [
    (1, "preprocessor.py",  [],                        "Load CSVs → Z-score → windows"),
    (2, "local_trainer.py", ["--epochs", "30"],        "Per-RSU LSTM training (GPU)"),
    (3, "fed_aggregator.py",["--gamma_factor", "2.0"], "BRFA-v2 federated aggregation"),
    (4, "evaluator.py",     [],                        "M1–M8 metric evaluation (legacy numbering)"),
    (5, "poison_sweep.py",  [],                        "M8 Delta_poison(rho_mal) sweep, BRFA-v2 vs FedAvg"),
]


def run_step(script: str, extra_args: list, description: str) -> bool:
    path = SRC / script
    cmd  = [PYTHON, str(path)] + extra_args
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"  {' '.join(cmd)}")
    print(f"{'='*60}")
    t0  = time.time()
    ret = subprocess.run(cmd, cwd=str(SRC))
    elapsed = time.time() - t0
    if ret.returncode != 0:
        print(f"\n[ERROR] {script} failed (exit {ret.returncode}) after {elapsed:.1f}s")
        return False
    print(f"\n[OK] {script} completed in {elapsed:.1f}s")
    return True


def main(args):
    start_step = args.from_step
    print(f"\nMOBIGUARD Federated LSTM Pipeline")
    print(f"Starting from step {start_step}")

    for step_num, script, extra, desc in STEPS:
        if step_num < start_step:
            print(f"  [skip] Step {step_num}: {desc}")
            continue
        ok = run_step(script, extra, f"Step {step_num}: {desc}")
        if not ok:
            print(f"\nPipeline aborted at step {step_num}.")
            sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Pipeline complete.")
    print(f"  Results → lstm_pipeline/evaluation_results.json")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-step", type=int, default=1, choices=[1, 2, 3, 4, 5],
                    help="Resume from this step (1=preprocess, 2=train, 3=federate, "
                         "4=evaluate, 5=M8 poisoning sweep)")
    main(ap.parse_args())
