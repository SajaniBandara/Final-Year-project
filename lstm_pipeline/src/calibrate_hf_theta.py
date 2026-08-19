"""
calibrate_hf_theta.py — variant-aware theta for A5-A8 (2026-08-20).

Root cause (established this session): the standard per-RSU theta
(fed_summary.json, compute_theta() in fed_aggregator.py) is calibrated on a
pool that's 94% A1-A4 traffic. A5 contributes zero quiet-calibration windows
anywhere; A8 contributes 35, all at pct80. Both are structurally different
traffic from what the calibration pool represents, which is why raising the
z-alpha multiplier alone never helped (validated: z=2.3..5.0 sweep, A8 FPR
plateaus at 45-49%) -- the base population itself is wrong for these
variants, not just the multiplier.

Tested fix (test_stratified_theta_a8.py, 2026-08-19): pool ALL HF-context
quiet windows (A5-A8 combined, ignoring which specific variant) into one
shared calibration population, since per-RSU HF sample sizes are individually
too sparse (87 windows / 64 RSUs) to split further. Result: A8 FPR
48.28%->0.00%, DR -0.4pt, MCC 0.518->0.805.

This script computes and writes that calibration to a SEPARATE file
(hf_theta.json), not fed_summary.json -- avoids a schema change to the
production calibration file, and evaluator.py / the C++ inference side only
need to know to check this file for A5-A8 specifically. A1-A4's existing
per-RSU theta in fed_summary.json is completely untouched.

theta_HF is a single value (not per-RSU): the same architectural reason
blending per-RSU stayed live-incompatible (test_blend_theta_a8.py: damaged
A1-A4, e.g. A4 DR 91%->6%, because the live C++ side has no per-attack-variant
theta lookup) means a per-RSU HF theta can't be selectively applied at
inference time without that same lookup infrastructure. A single shared
theta_HF, read ONLY when the caller explicitly asks for HF-mode (the
supervisor's --hf_mode flag proposal), sidesteps that: it's an alternate
threshold, not a per-RSU personalization, so no new lookup keyed on
(rsu, variant) is needed -- just a mode switch.
"""
import json
import numpy as np
import torch
from pathlib import Path

from evaluator import load_global_model
from fed_aggregator import Z_ALPHA

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
OUT  = REPO / "lstm_pipeline" / "hf_theta.json"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
HF_VARIANTS = {5, 6, 7, 8}


def main():
    print("Loading global model …")
    model, per_rsu_theta, global_theta = load_global_model()

    X_val    = np.load(PRE / "val_X.npy")
    y_val    = np.load(PRE / "val_y.npy")
    meta_val = np.load(PRE / "val_meta.npy")
    av_val   = meta_val[:, 1].astype(int)

    hf_quiet_mask = (y_val == 0) & np.isin(av_val, list(HF_VARIANTS))
    n_hf_quiet = int(hf_quiet_mask.sum())
    print(f"HF-context calibration pool: {n_hf_quiet} quiet windows "
          f"(A5-A8 combined, VAL split)")
    if n_hf_quiet < 10:
        raise SystemExit(f"Too few HF-quiet windows ({n_hf_quiet}) to calibrate on.")

    per_variant = {}
    for v in sorted(HF_VARIANTS):
        n = int(((av_val == v) & (y_val == 0)).sum())
        per_variant[f"A{v}"] = n
    print(f"  breakdown by variant: {per_variant}")

    model.eval()
    with torch.no_grad():
        xv = torch.from_numpy(X_val[hf_quiet_mask]).float().to(DEVICE)
        errs = model.anomaly_score(xv).cpu().numpy()
    mu_hf, sig_hf = float(errs.mean()), float(errs.std())
    theta_hf = mu_hf + Z_ALPHA * sig_hf
    print(f"mu_hf={mu_hf:.6f} sig_hf={sig_hf:.6f} "
          f"theta_hf={theta_hf:.6f} (z_alpha={Z_ALPHA})")

    out = {
        "theta_hf": theta_hf,
        "mu_hf": mu_hf,
        "sig_hf": sig_hf,
        "z_alpha": Z_ALPHA,
        "n_calibration_windows": n_hf_quiet,
        "per_variant_window_counts": per_variant,
        "applies_to_variants": sorted(HF_VARIANTS),
        "note": ("Single shared threshold for A5-A8 inference, NOT per-RSU. "
                 "Computed on pooled HF-context quiet windows because "
                 "per-RSU HF sample sizes are too sparse to calibrate "
                 "individually (87 windows / 64 RSUs). A1-A4 are "
                 "unaffected -- they keep the standard per-RSU theta in "
                 "fed_summary.json. Validated offline "
                 "(test_stratified_theta_a8.py, 2026-08-19): A8 FPR "
                 "48.28%->0.00%, DR -0.4pt, MCC 0.518->0.805. NOT YET "
                 "wired into evaluator.py or the C++ inference path -- "
                 "this file is the calibration artifact only."),
        "generated": "calibrate_hf_theta.py, 2026-08-20",
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote -> {OUT}")


if __name__ == "__main__":
    main()
