#!/usr/bin/env python3
"""
item7_analyse.py — item 7 validation (supervisor, 2026-08-29).

Two things the supervisor asked for before item 7 can be called done:

  1. "best-effort and high-priority traffic may not share the same baseline
     delay shape (preferential queueing). Send mean/median/p99 of both
     populations from the same clean baseline, side by side"
  2. "plus the resulting FPR/recall once live"

(1) is read from s1_pctl_histograms_*.csv (per-RSU raw bin counts for both
populations, written by s1_export_pctl_histograms()). Stats are computed from
the SAME counts the detector itself reads, pooled across RSUs, using the bin
UPPER edge -- the convention s1_update_baseline()'s quantile read uses, so a
p99 printed here is the threshold that arm would actually install.

(2) is read from detector_windows_*.csv. On a zero-attack baseline every
firing is a false positive by definition, so FPR = fired_windows/total_windows.

CENSORING CAVEAT, stated because it changes how (1) must be read: the
high-priority histogram is fed only for samples with
effective_delay <= the CURRENT threshold (s1_detection.h, the sigma
admission gate), while the best-effort histogram is fed unconditionally. The
high-priority population is therefore RIGHT-CENSORED and its p99 is a lower
bound on the true p99; best-effort's is not. The two are not like-for-like at
the top of the distribution, and the gap this script prints is the
*observable* one, not the true one.
"""
import csv, sys, glob, os, gzip
from collections import defaultdict

BIN_S = 0.001   # S1_HIST_BIN_S, seconds per bin (s1_detection.h)


def hist_stats(bins):
    """mean / median / p99 / max from raw bin counts, bin upper edge in ms."""
    n = sum(bins)
    if n == 0:
        return None
    mean = sum(c * (i + 1) * BIN_S for i, c in enumerate(bins)) / n * 1000.0
    def q(p):
        target, cum = p * n, 0
        for i, c in enumerate(bins):
            cum += c
            if cum >= target:
                return (i + 1) * BIN_S * 1000.0
        return len(bins) * BIN_S * 1000.0
    top = max((i for i, c in enumerate(bins) if c > 0), default=0)
    return dict(n=n, mean=mean, median=q(0.50), p99=q(0.99), max=(top + 1) * BIN_S * 1000.0)


def read_hist(path):
    pooled, per_rsu = defaultdict(lambda: [0] * 1000), defaultdict(dict)
    with open(path) as f:
        for r in csv.DictReader(f):
            pop = r["population"]
            bins = [int(r[f"bin{i}"]) for i in range(1000)]
            per_rsu[pop][int(r["rsu_idx"])] = bins
            for i, c in enumerate(bins):
                pooled[pop][i] += c
    return pooled, per_rsu


def window_fpr(path, mode="OBU"):
    tot = fired = tp = fp = 0
    with open(path) as f:
        for r in csv.DictReader(f):
            if r["mode"] != mode:
                continue
            tot += 1
            s = float(r["score"] or 0) > 0
            t = int(r["truth"] or 0) > 0
            fired += s
            tp += (s and t)
            fp += (s and not t)
    return dict(total=tot, fired=fired, tp=tp, fp=fp,
                fpr=100.0 * fp / tot if tot else float("nan"))


def s1_firings(log_path):
    """Count S1 TRIGGERED lines and summarise the threshold each fired against."""
    if log_path and not os.path.exists(log_path) and os.path.exists(log_path + ".gz"):
        log_path += ".gz"          # cleanup compressed it under us
    if not log_path or not os.path.exists(log_path):
        return None
    thr = []
    n = 0
    # logs may be gzipped by the 2026-08-29 disk cleanup; read either form.
    _open = gzip.open if log_path.endswith(".gz") else open
    with _open(log_path, "rt", errors="ignore") as f:
        for line in f:
            if "SIGNATURE S1 TRIGGERED" in line:
                n += 1
                i = line.find("exceeds threshold ")
                if i >= 0:
                    try:
                        thr.append(float(line[i + 18:].split("ms")[0]))
                    except ValueError:
                        pass
    thr.sort()
    if not thr:
        return dict(firings=n)
    return dict(firings=n, thr_mean=sum(thr) / len(thr),
                thr_median=thr[len(thr) // 2], thr_max=thr[-1])


def main(tag, log_path=None):
    R = os.path.expanduser("~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing")
    h = glob.glob(f"{R}/s1_pctl_histograms_*_{tag}.csv")
    w = glob.glob(f"{R}/detector_windows_*_{tag}.csv")
    print("=" * 74)
    print(f"ITEM 7 — arm '{tag}'")
    print("=" * 74)
    if h:
        pooled, per_rsu = read_hist(h[0])
        print(f"\n(1) DELAY DISTRIBUTIONS, pooled over RSUs  [{os.path.basename(h[0])}]\n")
        print(f"  {'population':<14}{'n':>9}{'mean':>10}{'median':>10}{'p99':>10}{'max':>10}")
        print("  " + "-" * 61)
        for pop in ("highprio", "besteffort"):
            st = hist_stats(pooled[pop])
            if not st:
                print(f"  {pop:<14}{'(no samples)':>9}")
                continue
            print(f"  {pop:<14}{st['n']:>9}{st['mean']:>9.2f}m{st['median']:>9.2f}m"
                  f"{st['p99']:>9.2f}m{st['max']:>9.2f}m")
        hp, be = hist_stats(pooled["highprio"]), hist_stats(pooled["besteffort"])
        if hp and be:
            print(f"\n  ratio best-effort/high-priority:  "
                  f"mean {be['mean']/hp['mean']:.2f}x   "
                  f"median {be['median']/hp['median']:.2f}x   "
                  f"p99 {be['p99']/hp['p99']:.2f}x")
            print("  NOTE: high-priority is right-censored by the sigma admission gate;")
            print("        its p99 is a LOWER BOUND. best-effort is uncensored.")
        ready = sum(1 for r, b in per_rsu["besteffort"].items() if sum(b) >= 200)
        print(f"\n  RSUs with n>=200 (s1_pctl_min_n, percentile trusted): "
              f"best-effort {ready}/{len(per_rsu['besteffort'])}, "
              f"high-priority {sum(1 for r,b in per_rsu['highprio'].items() if sum(b)>=200)}"
              f"/{len(per_rsu['highprio'])}")
    else:
        print("  (no s1_pctl_histograms file for this tag)")

    if w:
        print(f"\n(2) WINDOW SCORING  [{os.path.basename(w[0])}]\n")
        for mode in ("OBU", "RSU"):
            d = window_fpr(w[0], mode)
            print(f"  {mode}: windows={d['total']:<6} fired={d['fired']:<6} "
                  f"TP={d['tp']:<5} FP={d['fp']:<5} FPR={d['fpr']:.2f}%")
    else:
        print("\n  (no detector_windows file for this tag)")

    s = s1_firings(log_path)
    if s:
        print(f"\n(3) S1 FIRINGS  [{os.path.basename(log_path)}]\n")
        if "thr_mean" in s:
            print(f"  firings={s['firings']}   threshold at firing: "
                  f"mean {s['thr_mean']:.2f}ms  median {s['thr_median']:.2f}ms  "
                  f"max {s['thr_max']:.2f}ms")
        else:
            print(f"  firings={s['firings']}")
    print()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
