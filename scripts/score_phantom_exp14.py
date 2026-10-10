#!/usr/bin/env python3
"""
score_phantom_exp14.py — aggregate PHANTOM Exp 1 (penetration x intensity) and
Exp 4 (selectivity / AOEI). PHANTOM MCC/FPR via m1_local per tag; TAP via its
avg_MCC column. Writes docs/phantom_exp23/exp1_scores.csv, exp4_scores.csv and
prints tables.

Exp 1 tag scheme: S1/S2 under e180_exp1_p{p}_d{delay}; S3/S4 (intensity-independent)
under e180_exp1_p{p}. Since "e180_exp1_p{p}" is a substring of "e180_exp1_p{p}_d{delay}",
S3/S4 are scored from the e180_exp1_p{p} tag but ONLY variants A3/A4 are taken.
"""
import csv, re, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NS3  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
RES  = NS3 / "results_routing"
OUT  = REPO / "docs/phantom_exp23"
M1   = REPO / "scripts/m1_local.py"

PENS = [0, 20, 40, 60, 80, 100]
INTENSITIES = [55, 100, 200]
RATIOS = [0.10, 0.25, 0.75, 1.00]
SEED = 1


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


def m1_variants(tag):
    """{A1..A4: (MCC,DR,FPR)} from m1_local for a tag."""
    try:
        p = subprocess.run([sys.executable, str(M1), "--results-dir", str(RES), "--tag", tag],
                           capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    out = {}
    for line in p.stdout.splitlines():
        m = re.match(r"\s*(A\d)\s+([\d.]+)\s+([\d.]+)%\s+([\d.]+)%", line)
        if m:
            out[m.group(1)] = (float(m.group(2)), float(m.group(3)), float(m.group(4)))
    return out


def macro(mccs):
    xs = [m for m in mccs if m is not None]
    return sum(xs) / len(xs) if xs else None


def score_exp1():
    rows = []
    for p in PENS:
        s34 = m1_variants(f"e180_exp1_p{p}")     # take A3,A4 only
        for delay in INTENSITIES:
            s12 = m1_variants(f"e180_exp1_p{p}" if p == 0 else f"e180_exp1_p{p}_d{delay}")   # A1,A2 (p=0: single benign run)
            per = {}
            for a, src in ((1, s12), (2, s12), (3, s34), (4, s34)):
                per[a] = src.get(f"A{a}", (None, None, None))
            for a in (1, 2, 3, 4):
                mcc, dr, fpr = per[a]
                rows.append(dict(exp=1, pen=p, intensity=delay, arm="PHANTOM",
                                 attack=a, MCC=mcc, FPR=fpr))
            rows.append(dict(exp=1, pen=p, intensity=delay, arm="PHANTOM", attack="macro",
                             MCC=macro([per[a][0] for a in (1, 2, 3, 4)]),
                             FPR=macro([per[a][2] for a in (1, 2, 3, 4)])))
            for a in (1, 2):
                d = f"_d{delay}ms"
                tf = (RES / f"TAP_Attack0_0_seed{SEED}_e180_exp1_p0tap.csv" if p == 0
                      else RES / f"TAP_Attack{a}_{p}{d}_seed{SEED}_e180_exp1_p{p}_d{delay}tap.csv")
                rows.append(dict(exp=1, pen=p, intensity=delay, arm="TAP", attack=a,
                                 MCC=csv_last(tf, "avg_MCC"), FPR=csv_last(tf, "avg_FPR")))
    return rows


def score_exp4():
    rows = []
    for r in RATIOS:
        rt = str(r).replace(".", "p")
        v = m1_variants(f"e180_exp4_r{rt}")
        per = {a: v.get(f"A{a}", (None, None, None)) for a in (1, 2, 3, 4)}
        for a in (1, 2, 3, 4):
            rows.append(dict(exp=4, ratio=r, arm="PHANTOM", attack=a,
                             MCC=per[a][0], FPR=per[a][2]))
        rows.append(dict(exp=4, ratio=r, arm="PHANTOM", attack="macro",
                         MCC=macro([per[a][0] for a in (1, 2, 3, 4)]),
                         FPR=macro([per[a][2] for a in (1, 2, 3, 4)])))
        for a in (1, 2):
            tf = RES / f"TAP_Attack{a}_40_d100ms_seed{SEED}_e180_exp4_r{rt}tap.csv"
            rows.append(dict(exp=4, ratio=r, arm="TAP", attack=a,
                             MCC=csv_last(tf, "avg_MCC"), FPR=csv_last(tf, "avg_FPR")))
    return rows


def write(rows, path, keys):
    OUT.mkdir(parents=True, exist_ok=True)
    fields = ["exp"] + keys + ["arm", "attack", "MCC", "FPR"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow(r)
    print(f"\n=== {path.name} ===")
    hdr = " ".join(f"{k:>9}" for k in keys)
    print(f"{hdr} {'arm':<8} {'att':<5} {'MCC':>7} {'FPR%':>7}")
    for r in rows:
        fmt = lambda v, p=".3f": (f"{v:{p}}" if isinstance(v, float) else "   -  ")
        kv = " ".join(f"{str(r[k]):>9}" for k in keys)
        print(f"{kv} {r['arm']:<8} {str(r['attack']):<5} {fmt(r['MCC']):>7} {fmt(r['FPR'],'.1f'):>7}")


def main():
    write(score_exp1(), OUT / "exp1_scores.csv", ["pen", "intensity"])
    write(score_exp4(), OUT / "exp4_scores.csv", ["ratio"])
    print("\nDone.")


if __name__ == "__main__":
    main()
