"""
Recalibrate the LSTM high-confidence tier (supervisor round 8).

THE DEFECT. lstm_logger.h gated the HC tier on

    score > LSTM_HC_MULT * theta_used        (LSTM_HC_MULT = 2.0)

`score` is a bounded probability in [0,1], but theta is already near its
ceiling -- global_theta = 0.7378 (fed_summary.json), theta_hf = 0.7895
(hf_theta.json). So the bar sits at 2.0*0.7378 = 1.476 and 2.0*0.7895 =
1.579, both ABOVE the maximum attainable score. The tier is unreachable:
it has never fired, and no multiplier > 1/theta ever can.

Per the supervisor's instruction, this is NOT patched with an offset --
that would still tie the tier's behaviour to theta's scale, which is the
root of the problem. Instead the tier gets its OWN threshold, calibrated
the same way the main threshold is: an empirical cut on the benign
validation split, at a stricter operating point.

theta_HC = percentile(HC_PCT) of anomaly scores over benign (y==0)
validation windows. HC_PCT = 99.9 against theta's ~99, i.e. a 0.1% benign
false-alarm budget for the tier that is allowed to reach BTMM trust
evaluation, versus 1% for ordinary detection.

Unlike theta/theta_HF -- which use the Gaussian mu + Z_ALPHA*sigma form
because the raw calibration population was not saved (evaluator.py:150) --
this is a TRUE percentile: val_X.npy is on disk, so the empirical tail is
available and no Gaussian assumption is needed. That matters here: an
anomaly-score distribution with a heavy right tail is exactly where the
Gaussian form misplaces a 99.9th-percentile cut.
"""
import json
import numpy as np
import torch
from pathlib import Path

from evaluator import load_global_model

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
OUT  = REPO / "lstm_pipeline" / "hc_theta.json"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
HC_PCT = 99.9


def main():
    print("Loading global model …")
    model, per_rsu_theta, global_theta = load_global_model()

    X_val = np.load(PRE / "val_X.npy")
    y_val = np.load(PRE / "val_y.npy")
    quiet = (y_val == 0)
    print(f"benign validation windows: {int(quiet.sum())} of {len(y_val)}")

    model.eval()
    with torch.no_grad():
        xv = torch.from_numpy(X_val[quiet]).float().to(DEVICE)
        errs = model.anomaly_score(xv).cpu().numpy()

    theta_hc = float(np.percentile(errs, HC_PCT))
    p99      = float(np.percentile(errs, 99.0))
    print(f"benign score: min={errs.min():.6f} max={errs.max():.6f} "
          f"mean={errs.mean():.6f}")
    print(f"p99={p99:.6f}  theta_HC(p{HC_PCT})={theta_hc:.6f}")
    print(f"global_theta={global_theta:.6f}  old dead bar=2.0*theta={2.0*global_theta:.6f}")

    reachable = theta_hc < 1.0
    stricter  = theta_hc > global_theta
    print(f"reachable (<1.0): {reachable}   stricter than theta: {stricter}")

    json.dump({
        "theta_hc": theta_hc,
        "hc_percentile": HC_PCT,
        "benign_p99": p99,
        "global_theta": global_theta,
        "old_dead_bar": 2.0 * global_theta,
        "n_calibration_windows": int(quiet.sum()),
        "reachable": bool(reachable),
        "stricter_than_theta": bool(stricter),
        "note": ("Replaces LSTM_HC_MULT * theta_used, which was unreachable "
                 "because score is bounded by 1.0 while 2.0*theta >= 1.47. "
                 "True empirical percentile, not the Gaussian mu+z*sigma "
                 "form used for theta/theta_HF, because val_X.npy is on "
                 "disk and the tail can be measured directly."),
        "generated": "calibrate_hc_theta.py, 2026-09-07",
    }, open(OUT, "w"), indent=2)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
