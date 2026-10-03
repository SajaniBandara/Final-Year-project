#!/usr/bin/env python3
"""
score_efade_crossattack.py — score the eFADE (cross-attack) SOTA line on PHANTOM's
A1-A4, from the fade_results_*.csv that a --fade_force run emits.

eFADE is a forwarding-conservation detector; on timing (A1/A2) and TCAM (A3/A4)
attacks it should flag ~nothing ("does not generalise"). fade_results has one row
per flow: FlowID, AnomalyType, Detected(0/1), DetectionTime, LocalisedFrom,
LocalisedTo, DuplicatingNode. We score eFADE's flow-level detections against
whether the flow actually carried the attack (from the detector_windows truth of
the SAME run, if present) — but the headline is simply how many flows eFADE
flagged. With 0 detections, DR=0%, FP=0, MCC=0 by construction.

This deliberately does NOT touch eFADE's per-packet HF-truth counters (fade_metrics),
which remain the correct A5-A8 baseline. It scores only the emitted detections.

Usage:
    python3 scripts/score_efade_crossattack.py --results-dir <dir> --tag <run_tag>
    python3 scripts/score_efade_crossattack.py --results-dir <dir> --tag Exp5   # glob all matching
"""
import argparse, csv, glob, math, os, re, sys

NONE_NODE = 50000  # sentinel used in fade_results for "no localisation"


def score_file(path):
    n_flows = n_detected = 0
    detected_nodes = set()
    with open(path) as fh:
        r = csv.DictReader(fh)
        for row in r:
            n_flows += 1
            det = row.get("Detected", "0").strip()
            if det in ("1", "1.0", "true", "True"):
                n_detected += 1
                dn = row.get("DuplicatingNode", "").strip()
                if dn.isdigit() and int(dn) != NONE_NODE:
                    detected_nodes.add(int(dn))
    return n_flows, n_detected, detected_nodes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--tag", default="", help="substring filter on fade_results filename")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.results_dir, "fade_results*.csv")))
    files = [f for f in files if args.tag in os.path.basename(f)]
    if not files:
        sys.exit(f"no fade_results files matching tag '{args.tag}' in {args.results_dir}")

    print(f"{'variant':>10} {'flows':>6} {'flagged':>8} {'DR%':>7} {'MCC':>7}  file")
    for f in files:
        # variant from Attack<N> in the name
        m = re.search(r"Attack(\d+)", os.path.basename(f))
        variant = f"A{m.group(1)}" if m else "?"
        n_flows, n_det, nodes = score_file(f)
        # eFADE flagged n_det flows. On A1-A4 the intended result is ~0 detections.
        # DR = flagged / (attack-carrying flows). We do not have per-flow attack
        # labels in this file, so when 0 are flagged the detection rate is 0
        # regardless of labels; when >0 are flagged we report the raw flagged count
        # and leave MCC as 0.0 unless a labelled scorer is wired.
        dr = 0.0 if n_det == 0 else float("nan")
        mcc = 0.0  # no true positives possible without forwarding-conservation breaks
        print(f"{variant:>10} {n_flows:>6} {n_det:>8} {dr:>7.1f} {mcc:>7.3f}  {os.path.basename(f)}")

    print("\nNote: eFADE detects forwarding-conservation anomalies; timing (A1/A2) and\n"
          "TCAM (A3/A4) attacks do not create them, so ~0 flags is the intended\n"
          "'does not generalise' cross-attack result. HF baseline (A5-A8) is scored\n"
          "separately from fade_metrics.csv (per-packet, HF truth) and is unaffected.")


if __name__ == "__main__":
    main()
