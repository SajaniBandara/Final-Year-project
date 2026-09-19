#!/usr/bin/env python3
"""
score_vanguard_exp23.py — VANGUARD-HF Exp 2 (speed) & Exp 3 (scale). VANGUARD
detection MCC/FPR via m1_local per tag (variants A5-A8); FADE baseline MCC via
its avg_MCC column; M3 = unauthorized copy rate (avg_UCR) and end-to-end latency
from the MOBIGUARD CSV. Exp 2 additionally reports active (S5,S6) vs passive
(S7,S8) macros. Writes docs/vanguard_exp23/exp{2,3}_scores.csv.
"""
import csv, re, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
RES = NS3 / "results_routing"
OUT = REPO / "docs/vanguard_exp23"
M1 = REPO / "scripts/m1_local.py"
SPEEDS = [10, 60, 100, 140]
SCALES = [100, 150, 200]
PCT, SEED = 40, 1


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


def m1v(tag):
    try:
        p = subprocess.run([sys.executable, str(M1), "--results-dir", str(RES), "--tag", tag],
                           capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    out = {}
    for line in p.stdout.splitlines():
        m = re.match(r"\s*(A\d)\s+([\d.]+)\s+([\d.]+)%\s+([\d.]+)%", line)
        if m: out[m.group(1)] = (float(m.group(2)), float(m.group(3)), float(m.group(4)))
    return out


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs)/len(xs) if xs else None


def score(exp, pts, key, tagfmt):
    rows = []
    for pt in pts:
        tag = tagfmt(pt)
        v = m1v(tag)
        per = {a: v.get(f"A{a}", (None, None, None)) for a in (5, 6, 7, 8)}
        for a in (5, 6, 7, 8):
            mcc, dr, fpr = per[a]
            mob = RES / f"MOBIGUARD_Attack{a}_{PCT}_seed{SEED}_{tag}.csv"
            rows.append(dict(exp=exp, **{key: pt}, arm="VANGUARD", attack=f"S{a}",
                             MCC=mcc, FPR=fpr, UCR=csv_last(mob, "avg_UCR"),
                             lat_ms=csv_last(mob, "avg_lat_ms")))
        rows.append(dict(exp=exp, **{key: pt}, arm="VANGUARD", attack="macro",
                         MCC=mean([per[a][0] for a in (5,6,7,8)]),
                         FPR=mean([per[a][2] for a in (5,6,7,8)]), UCR=None, lat_ms=None))
        rows.append(dict(exp=exp, **{key: pt}, arm="VANGUARD", attack="active(S5,S6)",
                         MCC=mean([per[a][0] for a in (5,6)]), FPR=None, UCR=None, lat_ms=None))
        rows.append(dict(exp=exp, **{key: pt}, arm="VANGUARD", attack="passive(S7,S8)",
                         MCC=mean([per[a][0] for a in (7,8)]), FPR=None, UCR=None, lat_ms=None))
        for a in (5, 6, 7, 8):
            # FADE per-run summary lives in fade_metrics_*.csv (col 'mcc'); the
            # FADE_Attack*.csv file is headerless per-cycle detail.
            fade = RES / f"fade_metrics_Attack{a}_{PCT}_seed{SEED}_{tag}fade.csv"
            rows.append(dict(exp=exp, **{key: pt}, arm="FADE", attack=f"S{a}",
                             MCC=csv_last(fade, "mcc"), FPR=None, UCR=None, lat_ms=None))
    return rows


def write(rows, path, key):
    OUT.mkdir(parents=True, exist_ok=True)
    fields = ["exp", key, "arm", "attack", "MCC", "FPR", "UCR", "lat_ms"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow(r)
    print(f"\n=== {path.name} ===")
    print(f"{key:>6} {'arm':<9} {'attack':<14} {'MCC':>7} {'FPR%':>7} {'UCR':>6} {'lat_ms':>8}")
    for r in rows:
        fmt = lambda v, p=".3f": (f"{v:{p}}" if isinstance(v, float) else "  -  ")
        print(f"{str(r[key]):>6} {r['arm']:<9} {str(r['attack']):<14} {fmt(r['MCC']):>7} {fmt(r['FPR'],'.1f'):>7} {fmt(r['UCR'],'.2f'):>6} {fmt(r['lat_ms'],'.1f'):>8}")


def main():
    write(score(2, SPEEDS, "speed", lambda s: f"vg_exp2_s{s}"), OUT / "exp2_scores.csv", "speed")
    write(score(3, SCALES, "nveh", lambda n: f"vg_exp3_nv{n}"), OUT / "exp3_scores.csv", "nveh")
    print("\nDone.")


if __name__ == "__main__":
    main()
