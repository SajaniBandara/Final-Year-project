#!/usr/bin/env python3
"""
calibrate_cls_theta_insim.py — fit cls_theta on IN-SIMULATOR scores (2026-09-01)

THE PROBLEM THIS SOLVES
-----------------------
`cls_theta.json`'s per-RSU thresholds are fitted offline, on the preprocessed
val split, targeting FPR <= 1%. Measured 2026-09-01 in the Q6 A/B: those same
thresholds fire on **21.8%** of RSU windows in-simulator -- indistinguishable
from the autoencoder's 21.8%, which is why swapping in the classification head
moved full-system M1 by -0.003 despite a real offline gain (A1 DR 2.7% ->
11.3%).

The head is not the problem. Its OPERATING POINT is: a threshold fitted on one
score distribution and applied to a different one. The offline split comes from
`--training=1` collection runs; the deployed scores come from a Q6-configured
run with witness/BTMM/crypto/live-LSTM all active. Same model, different input
distribution, so the quantile the threshold was chosen at does not survive.

THE FIX
-------
Fit the threshold on the distribution it will actually be applied to.

`lstm_logger.h:1088-1092` already computes the in-sim P(attack) per RSU per
cycle and logs it as `lstm_anomaly_score` -- but only writes the row when
`--training=1` (`if (!do_training_log) return;`). So a BENIGN run with

    --training=1 --enable_lstm_inference=1 --enable_lstm_cls=1

yields exactly the per-RSU benign score distribution needed. Set each RSU's
threshold at the (1 - target_fpr) quantile of its own in-sim benign scores and
the target FPR is achieved by construction on the deployed distribution.

USAGE
  # 1. collect (benign only -- attack runs must NOT enter the benign quantile)
  #    see scripts/collect_insim_cls_scores.sh
  # 2. fit
  python3 calibrate_cls_theta_insim.py --tag INSIMCAL --target-fpr 0.01 \
      --out ../cls_theta_insim.json

Then point the simulator at the new file (or copy over cls_theta.json) and
re-run. Verify by re-measuring the in-sim firing rate: it should now land near
the target instead of 21.8%.

WHY BENIGN-ONLY
---------------
The threshold is a false-positive control, so it must be fitted on windows whose
label is negative. Using attack runs would mix true positives into the quantile
and push the threshold up, suppressing detections. This mirrors
`fit_scaler()`'s benign-only rule in preprocessor.py, for the same reason.
"""

import argparse, glob, json, os, sys
from pathlib import Path

import numpy as np

BASE = Path(os.environ.get("HOME", "")) / \
       "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", default="",
                    help="run_tag substring identifying the calibration runs "
                         "(keeps them separate from the offline training set)")
    ap.add_argument("--attack", type=int, default=0,
                    help="attack variant to calibrate on; MUST be benign (0)")
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--floor", type=float, default=0.05,
                    help="minimum threshold; guards an RSU whose benign scores "
                         "are all ~0 from getting a threshold that fires on noise")
    ap.add_argument("--out", default="../cls_theta_insim.json")
    ap.add_argument("--base", default=str(BASE))
    a = ap.parse_args()

    if a.attack != 0:
        print(f"WARNING: calibrating on attack={a.attack}, not benign. The "
              f"quantile will include true positives and the threshold will be "
              f"too high.", file=sys.stderr)

    pat = f"{a.base}/RSU_*/Attack{a.attack}_*{a.tag}*.csv" if a.tag \
          else f"{a.base}/RSU_*/Attack{a.attack}_*.csv"
    files = sorted(glob.glob(pat))
    if not files:
        print(f"ERROR: no files matching {pat}", file=sys.stderr)
        return 1

    per_rsu = {}
    n_rows = 0
    for f in files:
        rsu = int(Path(f).parent.name[4:])
        try:
            import csv
            with open(f) as fh:
                rd = csv.DictReader(fh)
                if "lstm_anomaly_score" not in (rd.fieldnames or []):
                    continue
                for row in rd:
                    v = row.get("lstm_anomaly_score", "")
                    if v in ("", None):
                        continue
                    per_rsu.setdefault(rsu, []).append(float(v))
                    n_rows += 1
        except Exception as e:                      # noqa: BLE001
            print(f"  skip {f}: {e}", file=sys.stderr)

    if not per_rsu:
        print("ERROR: no lstm_anomaly_score values found. The runs must set "
              "--training=1 AND --enable_lstm_inference=1 (and "
              "--enable_lstm_cls=1 for the score to be P(attack) rather than "
              "reconstruction error).", file=sys.stderr)
        return 1

    allv = np.concatenate([np.asarray(v) for v in per_rsu.values()])
    nz = float((allv > 0).mean())
    print(f"collected {n_rows:,} benign score rows across {len(per_rsu)} RSUs "
          f"from {len(files)} files")
    print(f"  score range {allv.min():.4f}..{allv.max():.4f}  "
          f"mean {allv.mean():.4f}  nonzero {100*nz:.1f}%")
    if nz < 0.001:
        print("  WARNING: scores are almost all zero -- the model may not have "
              "bootstrapped (LSTM_WINDOW cycles) or the weights failed to load.",
              file=sys.stderr)

    q = 1.0 - a.target_fpr
    thr, thin = {}, []
    for rsu, vals in sorted(per_rsu.items()):
        v = np.asarray(vals, dtype=np.float64)
        if len(v) < 20:
            thin.append(rsu)
        t = float(np.quantile(v, q))
        thr[str(rsu)] = max(t, a.floor)

    tv = np.array(list(thr.values()))
    print(f"\nthreshold: min {tv.min():.4f}  median {np.median(tv):.4f}  "
          f"max {tv.max():.4f}   (target FPR {100*a.target_fpr:.1f}%, "
          f"floor {a.floor})")
    if thin:
        print(f"  {len(thin)} RSUs had <20 benign samples: {thin[:10]}"
              f"{' ...' if len(thin) > 10 else ''}")

    # achieved FPR on the calibration set itself (sanity, not validation)
    ach = np.mean([np.mean(np.asarray(per_rsu[r]) > thr[str(r)])
                   for r in per_rsu])
    print(f"  achieved FPR on the calibration data: {100*ach:.2f}% "
          f"(in-sample -- confirm on a held-out benign seed)")

    out = Path(a.out)
    json.dump({"per_rsu_threshold": thr,
               "source": "calibrate_cls_theta_insim.py (IN-SIM scores)",
               "target_fpr": a.target_fpr,
               "floor": a.floor,
               "n_rows": n_rows,
               "n_rsus": len(thr),
               "note": "Fitted on in-simulator lstm_anomaly_score from BENIGN "
                       "runs, so the operating point matches the distribution "
                       "the detector actually sees. Replaces the offline "
                       "preprocessed-split calibration, which fired on 21.8% "
                       "of windows in-sim against a 1% target."},
              open(out, "w"), indent=2)
    print(f"\nwrote {out}")
    print("Deploy: cp that over lstm_pipeline/cls_theta.json, re-run, and "
          "re-measure the in-sim firing rate (was 21.8%).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
