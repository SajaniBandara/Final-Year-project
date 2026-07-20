"""
brfa_param_sweep.py — BRFA-v2 gamma / T_min grid sweep (AB5, spec Sec. 4.2)

main.tex marks both parameters [tbd], to be "selected for best M8
(Delta_poison at rho_mal=0.25) on the validation split under ablation AB5":
  gamma (Krum outlier threshold multiplier): {1.5, 2.0, 2.5, 3.0}
  T_min (BRFA-v2 trust gate threshold):      {0.3, 0.5, 0.7}

Previously only the fixed defaults (gamma_factor=2.0, T_min=0.5) had ever
been run — this sweep actually performs the selection the spec calls for.
Reuses poison_sweep.py's run_aggregation()/evaluate_mcc() against the same
already-trained local models (rsu_{k}.pt) — no new NS-3 simulations or
LSTM retraining needed.

Usage:
  python3 brfa_param_sweep.py
"""

import json
from pathlib import Path

from fed_aggregator import run_aggregation
from poison_sweep import evaluate_mcc

REPO = Path(__file__).resolve().parents[2]
TRUST_PATH = REPO / "lstm_pipeline" / "rsu_trust_scores.json"

GAMMA_GRID    = [1.5, 2.0, 2.5, 3.0]
TMIN_GRID     = [0.3, 0.5, 0.7]
RHO_AB5       = 0.25   # AB5's fixed adversarial fraction (16/64 RSUs)
POISON_MODE   = "sign_flip"


def main():
    results = []
    trust_path = str(TRUST_PATH) if TRUST_PATH.exists() else None
    print(f"Sweeping gamma x T_min ({len(GAMMA_GRID)}x{len(TMIN_GRID)}={len(GAMMA_GRID)*len(TMIN_GRID)} "
          f"combos), rho_mal={RHO_AB5} (AB5), poison_mode={POISON_MODE}")
    print(f"Trust scores: {trust_path or '(none found — Step 1 no-op, all RSUs trusted)'}\n")

    for gamma in GAMMA_GRID:
        for t_min in TMIN_GRID:
            clean = run_aggregation(gamma_factor=gamma, poison_fraction=0.0,
                                     poison_mode=POISON_MODE, mode="brfa",
                                     trust_scores_path=trust_path,
                                     trust_min=t_min, out_suffix=None)
            mcc_clean = evaluate_mcc(clean["global_state_dict"], clean["global_theta"])

            poisoned = run_aggregation(gamma_factor=gamma, poison_fraction=RHO_AB5,
                                        poison_mode=POISON_MODE, mode="brfa",
                                        trust_scores_path=trust_path,
                                        trust_min=t_min, out_suffix=None)
            mcc_poisoned = evaluate_mcc(poisoned["global_state_dict"], poisoned["global_theta"])

            delta_poison = mcc_clean - mcc_poisoned
            row = {"gamma": gamma, "t_min": t_min,
                   "mcc_clean": round(mcc_clean, 4),
                   "mcc_poisoned": round(mcc_poisoned, 4),
                   "delta_poison": round(delta_poison, 4),
                   "n_accepted_poisoned": poisoned["n_accepted"],
                   "n_total": poisoned["n_total"]}
            results.append(row)
            print(f"  gamma={gamma:.1f}  T_min={t_min:.1f}  "
                  f"MCC_clean={mcc_clean:+.4f}  MCC(rho=0.25)={mcc_poisoned:+.4f}  "
                  f"Delta_poison={delta_poison:+.4f}  accepted={poisoned['n_accepted']}/{poisoned['n_total']}")

    best = min(results, key=lambda r: r["delta_poison"])
    print(f"\nSelected: gamma={best['gamma']}, T_min={best['t_min']} "
          f"(Delta_poison={best['delta_poison']:+.4f} at rho_mal={RHO_AB5}, AB5)")

    out = {"rho_ab5": RHO_AB5, "poison_mode": POISON_MODE,
           "grid": results, "selected": best}
    out_path = REPO / "lstm_pipeline" / "brfa_param_sweep_results.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"Results -> {out_path}")


if __name__ == "__main__":
    main()
