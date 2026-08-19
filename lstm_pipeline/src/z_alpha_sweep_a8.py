"""
z_alpha_sweep_a8.py — Supervisor Fix C follow-up (2026-08-19).

compute_theta()'s formula (fed_aggregator.py) is theta^(k) = mu_a + Z_ALPHA *
sig_a, already computed on the fresh windowed-max feature distribution during
this session's clean retrain -- re-running that exact formula (literal Fix C)
is a no-op, since it already ran and produced A8's FPR=56.1%. What CAN move
the number is re-sweeping the Z_ALPHA constant itself (3.5, tuned 2026-07-29
against the OLD mean-delta_t distribution) against the NEW windowed-max
distribution, same method as the original 2.326->3.5 tuning.

Scoped to A8 only: A5/A6/A7's TN=0 is a separate, non-threshold-fixable
labeling-population issue (d_div>1 spike criterion pervasive at 92-96% of
rows for those variants vs 54% for A8 -- see session diagnosis) and is not
touched here.

Runs inference ONCE (single GPU forward pass over the test split), then
sweeps Z_ALPHA in pure Python/numpy against the cached raw scores -- no
retraining, no repeated GPU passes.
"""
import numpy as np
import torch
from pathlib import Path

from evaluator import load_global_model, predict_test as _predict_raw
from fed_aggregator import Z_ALPHA as OLD_Z_ALPHA

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

A8 = 8


def raw_scores(model):
    """Same inference evaluator.py's predict_test() does, but return the
    unthresholded scores directly instead of applying a fixed theta."""
    X    = np.load(PRE / "test_X.npy")
    y    = np.load(PRE / "test_y.npy")
    meta = np.load(PRE / "test_meta.npy")
    bs = 512
    scores = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    return y, scores, meta


def confusion(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
    dr  = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    denom = np.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc = ((tp*tn - fp*fn) / denom) if denom > 0 else 0.0
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, FPR=fpr, DR=dr, MCC=mcc)


def main():
    print("Loading global federated model + per-RSU mu_a/sig_a …")
    model, per_rsu_theta, global_theta = load_global_model()

    import json
    fed = json.load(open(REPO / "lstm_pipeline" / "fed_summary.json"))
    per_rsu = fed["per_rsu"]
    mu_a  = {int(k): v["mu_a"]  for k, v in per_rsu.items()}
    sig_a = {int(k): v["sig_a"] for k, v in per_rsu.items()}
    global_mu  = float(np.mean(list(mu_a.values())))
    global_sig = float(np.mean(list(sig_a.values())))

    print("Running inference once on TEST split (seed5) …")
    y_true, scores, meta = raw_scores(model)
    rsu_ids = meta[:, 0].astype(int)
    av      = meta[:, 1].astype(int)

    a8_mask = av == A8
    print(f"A8 windows in test split: {int(a8_mask.sum())} "
          f"(pos={int(y_true[a8_mask].sum())}, neg={int((1-y_true[a8_mask]).sum())})")

    print(f"\n{'z_alpha':>8} {'TP':>6} {'FP':>6} {'FN':>6} {'TN':>6} "
          f"{'FPR%':>7} {'DR%':>7} {'MCC':>7}")
    print("-" * 60)
    for z in [2.3263, 2.8, 3.0, 3.2, 3.5, 3.8, 4.0, 4.2, 4.5, 5.0]:
        theta_arr = np.array([
            mu_a.get(r, global_mu) + z * sig_a.get(r, global_sig)
            for r in rsu_ids
        ])
        y_pred = (scores > theta_arr).astype(np.int8)
        m = confusion(y_true[a8_mask], y_pred[a8_mask])
        flag = "  <- current" if abs(z - OLD_Z_ALPHA) < 1e-6 else ""
        print(f"{z:8.4f} {m['TP']:6d} {m['FP']:6d} {m['FN']:6d} {m['TN']:6d} "
              f"{100*m['FPR']:7.2f} {100*m['DR']:7.2f} {m['MCC']:7.4f}{flag}")

    print("\nTarget: FPR <= 1% (spec-wide budget), report the smallest z "
          "clearing it and its DR/MCC cost -- same acceptance rule as the "
          "original Z_ALPHA=3.5 tuning (2026-07-29).")


if __name__ == "__main__":
    main()
