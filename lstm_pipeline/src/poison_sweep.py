"""
poison_sweep.py — M8 Federated Model Poisoning Resistance (eq:delta_poison)

Sweeps the fraction of malicious RSUs rho_mal submitting poisoned model
updates through BRFA-v2 (proposed, alg:brfa_v2) and naive FedAvg (AB5-A
baseline), evaluates each resulting global model's MCC on the held-out
test split, and reports the poisoning degradation:

    Delta_poison(rho_mal) = MCC_clean - MCC(rho_mal)

Target (main.tex M8): Delta_poison(rho_mal) ~= 0 for rho_mal < 1/3 under
BRFA-v2; naive FedAvg has no such guarantee and is expected to degrade
monotonically with rho_mal.

Requires local_trainer.py to have already produced clean rsu_{k}.pt models
(run `pipeline.py --from-step 1` through step 2, or the full pipeline once).

Usage:
  python3 poison_sweep.py --rho 0.0 0.1 0.2 0.3 --modes brfa fedavg
"""

import argparse, json
import numpy as np
import torch
from pathlib import Path
from sklearn.metrics import matthews_corrcoef

from lstm_model import LSTMAutoencoder, N_FEATURES
from fed_aggregator import run_aggregation

REPO   = Path(__file__).resolve().parents[2]
PRE    = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def evaluate_mcc(global_state_dict: dict, theta: float) -> float:
    """Minimal in-memory re-implementation of evaluator.py's LSTM inference
    + MCC. Duplicated (rather than imported from evaluator.py) because
    evaluator.py's main() is disk-file-oriented (reads global.pt once);
    sweeping many candidate models in one process is far cheaper in-memory
    and this keeps evaluator.py's existing CLI/behavior untouched."""
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(global_state_dict)
    model.eval()

    X = np.load(PRE / "test_X.npy")
    y = np.load(PRE / "test_y.npy")
    bs = 512
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    y_pred = (scores > theta).astype(np.int8)
    return float(matthews_corrcoef(y, y_pred))


def main(args):
    results = {}
    for mode in args.modes:
        results[mode] = {}
        mcc_clean = None
        for rho in args.rho:
            summary = run_aggregation(
                gamma_factor=args.gamma_factor,
                poison_fraction=rho,
                poison_mode=args.poison_mode,
                mode=mode,
                trust_min=args.trust_min,
                out_suffix=None,   # sweep: evaluate in-memory, don't touch disk
            )
            mcc = evaluate_mcc(summary["global_state_dict"], summary["global_theta"])
            if rho == 0.0:
                mcc_clean = mcc
            delta = (mcc_clean - mcc) if mcc_clean is not None else None

            results[mode][f"rho_{rho}"] = {
                "MCC":            round(mcc, 4),
                "delta_poison":   round(delta, 4) if delta is not None else None,
                "n_accepted":     summary["n_accepted"],
                "n_total":        summary["n_total"],
                "poisoned_rsus":  summary["poisoned_rsus"],
                "accepted_rsus":  summary["accepted_rsus"],
            }
            delta_str = f"{delta:+.4f}" if delta is not None else "  (clean baseline)"
            print(f"  [{mode:6s}] rho_mal={rho:.2f}  MCC={mcc:+.4f}"
                  f"  accepted={summary['n_accepted']}/{summary['n_total']}"
                  f"  Delta_poison={delta_str}")

    out_path = REPO / "lstm_pipeline" / "poison_sweep_results.json"
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nM8 poisoning sweep results -> {out_path}")

    # Target check (main.tex M8): Delta_poison(rho_mal < 1/3) ~= 0 for BRFA-v2
    if "brfa" in results:
        f_bound = 1.0 / 3.0
        print(f"\nTarget check — BRFA-v2 Delta_poison(rho_mal < {f_bound:.3f}) ~= 0:")
        for rho in args.rho:
            if rho == 0.0 or rho >= f_bound:
                continue
            d = results["brfa"][f"rho_{rho}"]["delta_poison"]
            status = "PASS" if abs(d) < 0.05 else "CHECK"
            print(f"    rho_mal={rho:.2f}  Delta_poison={d:+.4f}  [{status}]")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rho", type=float, nargs="+", default=[0.0, 0.1, 0.2, 0.3],
                    help="Malicious RSU fractions rho_mal to sweep (eq:delta_poison)")
    ap.add_argument("--modes", nargs="+", default=["brfa", "fedavg"],
                    choices=["brfa", "fedavg"],
                    help="Aggregation modes to compare (AB5: BRFA-v2 vs naive FedAvg)")
    ap.add_argument("--poison_mode", default="sign_flip",
                    choices=["sign_flip", "scale", "random"])
    ap.add_argument("--gamma_factor", type=float, default=2.0)
    ap.add_argument("--trust_min", type=float, default=0.50)
    main(ap.parse_args())
