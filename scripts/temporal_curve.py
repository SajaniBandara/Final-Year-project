#!/usr/bin/env python3
"""temporal_curve.py — supervisor item 11.

Temporal performance curve for the full deployed system: per-time-point score,
aggregated as mean +/- standard deviation ACROSS SEEDS, against simulation
time. The paper's architecture predicts a specific shape -- a rise when the
attack starts, then a fall as trust decay quarantines attackers and the pool
of active undetected attackers shrinks -- and nothing run so far has actually
shown it.

Two independent views, because they answer different halves of the claim:

  DETECTION (detector_windows_*.csv)
      Window-level MCC/DR/FPR at each window start, computed across all RSUs
      for that window, per seed, then aggregated across seeds. This is the
      detector's own performance over time.

  IMPACT (MOBIGUARD_*.csv, cur_TVR / cur_UCR)
      The metrics main.tex explicitly describes as rising during an attack and
      returning toward zero once quarantine engages. This is the system-level
      consequence, and it is the curve the paper's text actually claims.

Per item 11, a single instantaneous point is NEVER a result -- only the
across-seed mean with its variance band is reportable. This script therefore
refuses to emit anything unless at least MIN_SEEDS seeds are present.
"""
import argparse, csv, glob, math, os, re, sys
from collections import defaultdict

MIN_SEEDS = 3   # below this a "mean +/- std" is not meaningful


def mcc(tp, fp, fn, tn):
    d = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return ((tp * tn - fp * fn) / math.sqrt(d)) if d > 0 else float("nan")


def detection_by_time(path):
    """{w_start: (mcc, dr, fpr)} across all RSU rows in that window."""
    acc = defaultdict(lambda: [0, 0, 0, 0])   # tp, fp, fn, tn
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            if r.get("mode") != "RSU":
                continue
            t = float(r["w_start"])
            fired = float(r.get("score_primary") or 0.0) >= 0.5
            truth = (r.get("truth") or "0") == "1"
            a = acc[t]
            if truth and fired:   a[0] += 1
            elif not truth and fired: a[1] += 1
            elif truth:           a[2] += 1
            else:                 a[3] += 1
    out = {}
    for t, (tp, fp, fn, tn) in acc.items():
        dr  = tp / (tp + fn) if (tp + fn) else float("nan")
        fpr = fp / (fp + tn) if (fp + tn) else float("nan")
        out[t] = (mcc(tp, fp, fn, tn), dr, fpr)
    return out


def impact_by_time(path):
    """{cycle: (tvr, ucr)} from the per-cycle metrics CSV."""
    out = {}
    with open(path) as fh:
        hdr = [h.strip() for h in fh.readline().lstrip("# ").split(",")]
        idx = {n: i for i, n in enumerate(hdr)}
        for line in fh:
            p = line.strip().split(",")
            if len(p) <= max(idx.get("cur_UCR", 0), idx.get("cur_TVR", 0)):
                continue
            try:
                c = float(p[idx["cycle"]])
                out[c] = (float(p[idx["cur_TVR"]]), float(p[idx["cur_UCR"]]))
            except (ValueError, KeyError):
                continue
    return out


def agg(per_seed, n_series):
    """[{t: tuple}] -> {t: [(mean, std, n), ...]} keeping only well-sampled t."""
    bucket = defaultdict(lambda: [[] for _ in range(n_series)])
    for d in per_seed:
        for t, vals in d.items():
            for i, v in enumerate(vals):
                if v == v:            # drop NaN
                    bucket[t][i].append(v)
    out = {}
    for t, series in sorted(bucket.items()):
        row = []
        for vs in series:
            if len(vs) < MIN_SEEDS:
                row.append((float("nan"), float("nan"), len(vs)))
            else:
                m = sum(vs) / len(vs)
                sd = math.sqrt(sum((v - m) ** 2 for v in vs) / len(vs))
                row.append((m, sd, len(vs)))
        out[t] = row
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--tag", default="item11s",
                    help="run_tag prefix; seed N is expected as <tag>N")
    ap.add_argument("--attack", default="2")
    ap.add_argument("--out", default=None, help="write CSV here as well")
    a = ap.parse_args()

    det, imp = [], []
    seeds_found = []
    for s in range(1, 6):
        dg = glob.glob(os.path.join(
            a.results_dir, f"detector_windows_Attack{a.attack}_*seed{s}_{a.tag}{s}.csv"))
        mg = glob.glob(os.path.join(
            a.results_dir, f"MOBIGUARD_Attack{a.attack}_*seed{s}_{a.tag}{s}.csv"))
        if dg: det.append(detection_by_time(dg[0]))
        if mg: imp.append(impact_by_time(mg[0]))
        if dg or mg: seeds_found.append(s)

    if len(seeds_found) < MIN_SEEDS:
        print(f"REFUSING: only {len(seeds_found)} seed(s) found ({seeds_found}). "
              f"Item 11 requires an across-seed mean and variance band; a single "
              f"instantaneous curve is explicitly not reportable.")
        return 1

    print(f"Temporal curve, A{a.attack}, seeds {seeds_found} "
          f"(mean +/- sd across seeds at each time point)\n")

    if det:
        D = agg(det, 3)
        print(f"{'t(s)':>7}{'MCC':>10}{'+/-':>8}{'DR':>9}{'+/-':>8}{'FPR':>9}{'+/-':>8}{'n':>4}")
        for t in sorted(D):
            (m, ms, n), (d, ds, _), (f, fs, _) = D[t]
            print(f"{t:>7.0f}{m:>10.3f}{ms:>8.3f}{d:>9.3f}{ds:>8.3f}"
                  f"{f:>9.3f}{fs:>8.3f}{n:>4d}")
        print()

    if imp:
        I = agg(imp, 2)
        print(f"{'t(s)':>7}{'TVR':>10}{'+/-':>8}{'UCR':>10}{'+/-':>8}{'n':>4}")
        rows = sorted(I)
        step = max(1, len(rows) // 40)      # keep the console readable
        for t in rows[::step]:
            (v, vs, n), (u, us, _) = I[t]
            print(f"{t:>7.0f}{v:>10.4f}{vs:>8.4f}{u:>10.4f}{us:>8.4f}{n:>4d}")

        if a.out:
            with open(a.out, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["t", "tvr_mean", "tvr_sd", "ucr_mean", "ucr_sd", "n_seeds"])
                for t in rows:
                    (v, vs, n), (u, us, _) = I[t]
                    w.writerow([t, v, vs, u, us, n])
            print(f"\nwrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
