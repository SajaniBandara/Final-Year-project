#!/usr/bin/env python3
"""
High-confidence tier threshold for the CLASSIFIER-HEAD path (round 11, 2026-09-11).

Why a second threshold. lstm_logger.h scores a window one of two ways:
  * reconstruction path (--enable_lstm_cls=0): score = the autoencoder's anomaly
    score, unbounded. LSTM_HC_THETA (calibrate_hc_theta.py -> hc_theta.json) is
    on this scale.
  * classifier path (--enable_lstm_cls=1): score = P(attack), in [0, 1].
The HC tier compared both against LSTM_HC_THETA, so under the classifier head the
bar (12.63 from 7 Sep, 39.82 after the 11 Sep retrain) sat above the largest
attainable score and the tier could never fire -- the same unreachability round 8
fixed for the old 2*theta form. Nothing in the tree flagged it: hc_theta.json
records "reachable": false for both values.

Method. Same operating point as calibrate_hc_theta.py (99.9th percentile of benign
scores), taken over the in-simulator benign P(attack) that cls_theta.json's per-RSU
thresholds were fitted on (the INSIMCAL runs), so both classifier-path thresholds
come from one calibration population. Rows before an RSU's first full window carry
score 0.0 -- no score exists yet -- and are excluded.

In-sample: the fire rate printed below is on the calibration data itself.
"""
import argparse
import csv
import glob
import json
import os
from datetime import date

import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("--dir", required=True, help="directory holding RSU_*/*_<tag>.csv")
ap.add_argument("--tag", default="INSIMCAL")
ap.add_argument("--pct", type=float, default=99.9)
ap.add_argument("--out", required=True)
a = ap.parse_args()

vals, files, warm = [], 0, 0
for f in sorted(glob.glob(os.path.join(a.dir, "RSU_*", f"*_{a.tag}.csv"))):
    files += 1
    with open(f, newline="") as fh:
        for row in csv.DictReader(fh):
            s = float(row["lstm_anomaly_score"])
            if s == 0.0:
                warm += 1
                continue
            vals.append(s)
if not vals:
    raise SystemExit(f"no scored rows under {a.dir} for tag {a.tag}")

v = np.asarray(vals, dtype=np.float64)
theta = float(np.percentile(v, a.pct))
fire = float((v > theta).mean())
p99 = float(np.percentile(v, 99.0))
print(f"{files} files, {len(v):,} scored benign windows ({warm:,} pre-window rows excluded)")
print(f"P(attack): min={v.min():.4f} p50={np.median(v):.4f} p99={p99:.4f} max={v.max():.4f}")
print(f"theta_hc_cls = p{a.pct:g} = {theta:.6f}; benign fire rate {fire:.3%} (in-sample)")

json.dump({
    "theta_hc_cls": theta,
    "hc_percentile": a.pct,
    "benign_p99": p99,
    "benign_max": float(v.max()),
    "benign_fire_rate_in_sample": fire,
    "n_calibration_windows": int(len(v)),
    "n_files": files,
    "n_prewindow_rows_excluded": warm,
    "source_dir": a.dir,
    "tag": a.tag,
    "reachable": bool(theta < 1.0),
    "applies_to": "classifier-head path only (--enable_lstm_cls=1); the reconstruction "
                  "path keeps LSTM_HC_THETA from hc_theta.json",
    "generated": f"calibrate_hc_theta_cls_insim.py, {date.today().isoformat()}",
}, open(a.out, "w"), indent=2)
print(f"wrote {a.out}")
