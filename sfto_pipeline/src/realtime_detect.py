"""
realtime_detect.py
-------------------
Streaming replay of an already-trained SFTO-Guard detector against a
single TCAM-snapshot CSV, processed in temporal order (t = 0, 1, 2, ...)
exactly as a live SDN controller would see it -- one snapshot at a time,
no shuffling, no peeking at future rows.

run_pipeline.py trains + evaluates with a random 75/25 split, which
answers "can the model separate attack from normal snapshots at all".
This script answers the question the offline pipeline can't: replayed
in causal order, how many seconds after the attack actually starts does
the model raise its first alert (time-to-detect), and does it ever
false-alarm on the pre-attack / baseline traffic.

Usage (paths relative to this repo's sfto_pipeline/ folder; --stream points at
your local ns-3 sim output, which lives outside the repo and is regenerated
per machine/run):
    python realtime_detect.py \
        --model    ../results/routing_attack3/lgbm_detector.pkl \
        --metrics  ../results/routing_attack3/metrics.json \
        --stream   /home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/backup/tcam_snapshots_attack3.csv \
        --attack_start_time 10 \
        --output   sfto_results_realtime_attack3/

    # Sanity check on pure baseline traffic (should report 0 false alarms):
    python realtime_detect.py \
        --model    ../results/routing_attack3/lgbm_detector.pkl \
        --metrics  ../results/routing_attack3/metrics.json \
        --stream   /home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/tcam_snapshots_baseline.csv \
        --attack_start_time 999999 \
        --output   sfto_results_realtime_baseline/
"""

import argparse
import os
import json
import sys

import joblib

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from loader import _load_csv
from features import compute_per_rule_features, aggregate_features


def replay(model, selected_features, csv_path, attack_start_time, threshold):
    df = _load_csv(csv_path)
    df["label"] = (df["t"] >= attack_start_time).astype(int)
    df["source"] = "stream"
    df = compute_per_rule_features(df)

    # One row per (source, t) snapshot, already ordered by t -- this is
    # the live arrival order a real controller would observe.
    feature_df = aggregate_features(df).sort_values("t").reset_index(drop=True)

    X = feature_df[selected_features].values
    y_proba = model.predict_proba(X)[:, 1]
    y_pred = (y_proba >= threshold).astype(int)

    log = feature_df[["t", "label"]].rename(columns={"label": "true_label"}).copy()
    log["proba"] = y_proba
    log["pred"] = y_pred

    alerts = log[(log["pred"] == 1) & (log["t"] >= attack_start_time)]
    detect_t = float(alerts["t"].iloc[0]) if len(alerts) else None
    latency = (detect_t - attack_start_time) if detect_t is not None else None

    false_alarms = log[(log["pred"] == 1) & (log["t"] < attack_start_time)]

    return log, detect_t, latency, false_alarms


def main():
    parser = argparse.ArgumentParser(
        description="Streaming (temporal-order) replay of a trained SFTO-Guard model"
    )
    parser.add_argument("--model", required=True, help="Path to lgbm_detector.pkl")
    parser.add_argument("--metrics", required=True,
                        help="Path to metrics.json (for selected_features)")
    parser.add_argument("--stream", required=True,
                        help="TCAM snapshot CSV to replay in time order")
    parser.add_argument("--attack_start_time", type=float, default=10.0)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--output", default="sfto_results_realtime")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    model = joblib.load(args.model)
    with open(args.metrics) as f:
        selected_features = json.load(f)["selected_features"]

    print(f"Replaying : {args.stream}")
    print(f"Model     : {args.model}")
    print(f"Features  : {selected_features}")

    log, detect_t, latency, false_alarms = replay(
        model, selected_features, args.stream, args.attack_start_time, args.threshold
    )

    log_path = os.path.join(args.output, "realtime_log.csv")
    log.to_csv(log_path, index=False)

    lines = [
        f"Stream: {args.stream}",
        f"Snapshots replayed: {len(log)}",
        f"Attack start (ground truth): t={args.attack_start_time}",
    ]
    if detect_t is not None:
        lines.append(f"First detection: t={detect_t}  (latency = {latency:.2f}s)")
    else:
        lines.append("First detection: NONE -- attack was never flagged")
    lines.append(f"False alarms before attack start: {len(false_alarms)}")
    if len(false_alarms):
        lines.append(f"  at t = {sorted(false_alarms['t'].tolist())}")

    summary = "\n".join(lines)
    print("\n" + summary)

    with open(os.path.join(args.output, "realtime_summary.txt"), "w") as f:
        f.write(summary + "\n")

    print(f"\nSaved: {log_path}")
    print(f"Saved: {os.path.join(args.output, 'realtime_summary.txt')}")


if __name__ == "__main__":
    main()
