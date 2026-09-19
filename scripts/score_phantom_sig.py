#!/usr/bin/env python3
"""
score_phantom_sig.py — PHANTOM five-seed paired significance test at the default
operating point. Per seed: PHANTOM macro MCC (mean of S1-S4 via m1_local) and
TAP macro MCC (mean of S1-S4 avg_MCC). Paired t-test and Wilcoxon signed-rank
across seeds 1-5 on the per-seed difference. Writes docs/phantom_exp23/
sig_scores.csv and prints the test.
"""
import csv, re, subprocess, sys
from pathlib import Path
import numpy as np
from scipy import stats

REPO = Path(__file__).resolve().parent.parent
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
RES = NS3 / "results_routing"
OUT = REPO / "docs/phantom_exp23"
M1 = REPO / "scripts/m1_local.py"
SEEDS = [1, 2, 3, 4, 5]
PCT, DELAY = 40, 100


def csv_last(path, col):
    if not path.is_file(): return None
    try:
        rows = list(csv.reader(open(path)))
        if len(rows) < 2: return None
        h = [x.strip() for x in rows[0]]
        if col not in h: return None
        i = h.index(col)
        for r in reversed(rows[1:]):
            if len(r) > i and r[i].strip(): return float(r[i])
    except (OSError, ValueError): return None
    return None


def phantom_macro(seed):
    """mean of A1..A4 MCC from m1_local for tag sig_s{seed}."""
    try:
        p = subprocess.run([sys.executable, str(M1), "--results-dir", str(RES),
                            "--tag", f"sig_s{seed}"], capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return None, {}
    per = {}
    for line in p.stdout.splitlines():
        m = re.match(r"\s*(A\d)\s+([\d.]+)\s+[\d.]+%\s+[\d.]+%", line)
        if m: per[m.group(1)] = float(m.group(2))
    vals = [per[f"A{a}"] for a in (1, 2, 3, 4) if f"A{a}" in per]
    return (sum(vals) / len(vals) if len(vals) == 4 else None), per


def tap_macro(seed):
    vals = []
    for a in (1, 2, 3, 4):
        d = f"_d{DELAY}ms" if a in (1, 2) else ""
        f = RES / f"TAP_Attack{a}_{PCT}{d}_seed{seed}_sig_s{seed}tap.csv"
        v = csv_last(f, "avg_MCC")
        if v is not None: vals.append(v)
    return (sum(vals) / len(vals) if len(vals) == 4 else None), vals


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows, ph, tp = [], [], []
    for s in SEEDS:
        p, pper = phantom_macro(s)
        t, _ = tap_macro(s)
        rows.append(dict(seed=s, phantom_macro=p, tap_macro=t,
                         diff=(p - t if (p is not None and t is not None) else None),
                         **{f"phantom_S{a}": pper.get(f"A{a}") for a in (1, 2, 3, 4)}))
        if p is not None and t is not None:
            ph.append(p); tp.append(t)
    # write
    fields = ["seed", "phantom_macro", "tap_macro", "diff",
              "phantom_S1", "phantom_S2", "phantom_S3", "phantom_S4"]
    with open(OUT / "sig_scores.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow(r)

    print("=== per-seed macro MCC (default point: N=200, 40%, 100ms) ===")
    print(f"{'seed':>4} {'PHANTOM':>9} {'TAP':>7} {'diff':>7}")
    for r in rows:
        f = lambda v: (f"{v:.4f}" if isinstance(v, float) else "  -  ")
        print(f"{r['seed']:>4} {f(r['phantom_macro']):>9} {f(r['tap_macro']):>7} {f(r['diff']):>7}")

    ph, tp = np.array(ph), np.array(tp)
    n = len(ph)
    print(f"\nn={n} paired seeds")
    if n >= 2:
        d = ph - tp
        print(f"PHANTOM macro MCC: mean={ph.mean():.4f} sd={ph.std(ddof=1):.4f}")
        print(f"TAP     macro MCC: mean={tp.mean():.4f} sd={tp.std(ddof=1):.4f}")
        print(f"mean paired diff = {d.mean():.4f} (sd {d.std(ddof=1):.4f})")
        t, pt = stats.ttest_rel(ph, tp)
        print(f"paired t-test:  t={t:.3f}  p={pt:.3e}  (df={n-1})")
        try:
            w, pw = stats.wilcoxon(ph, tp)
            print(f"Wilcoxon signed-rank:  W={w:.1f}  p={pw:.3e}")
        except ValueError as e:
            print(f"Wilcoxon: n/a ({e})")
        # Cohen's dz (paired effect size)
        print(f"Cohen's dz = {d.mean()/d.std(ddof=1):.2f}")
    print("\nwrote docs/phantom_exp23/sig_scores.csv")


if __name__ == "__main__":
    main()
