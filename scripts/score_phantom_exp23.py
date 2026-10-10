#!/usr/bin/env python3
"""
score_phantom_exp23.py — aggregate PHANTOM Exp 2 (speed) & Exp 3 (scale) results.

PHANTOM detection quality  = M1 via scripts/m1_local.py (per-RSU, deduped 10s
                             blocks, 30s warm-up) per run_tag -> per-variant
                             A1..A4 MCC/DR/FPR + macro.
PHANTOM end-to-end latency = avg_lat_ms (last row) of the MOBIGUARD_Attack*_<tag>.csv.
TAP baseline (S1/S2 only)  = avg_MCC / avg_lat_ms (last row) of TAP_Attack*_<tag>tap.csv
                             (TAP emits no detector_windows; its in-sim confusion-matrix
                             MCC is the established baseline convention here).

Writes docs/phantom_exp23/exp2_scores.csv and exp3_scores.csv (tidy rows) and
prints readable tables.
"""
import csv, re, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NS3  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
RES  = NS3 / "results_routing"
OUT  = REPO / "docs/phantom_exp23"
M1   = REPO / "scripts/m1_local.py"

SPEEDS = [10, 60, 100, 140]
SCALES = [100, 150, 200]
PCT, SEED, DELAY = 40, 1, 100


def csv_last_val(path: Path, col: str):
    if not path.is_file():
        return None
    try:
        with open(path) as f:
            rows = list(csv.reader(f))
        if len(rows) < 2:
            return None
        hdr = [h.strip() for h in rows[0]]
        if col not in hdr:
            return None
        i = hdr.index(col)
        for r in reversed(rows[1:]):
            if len(r) > i and r[i].strip():
                return float(r[i])
    except (OSError, ValueError):
        return None
    return None


def m1_by_variant(tag: str):
    """Run m1_local for a tag, return {variant: (MCC, DR%, FPR%)} incl 'macro'."""
    try:
        p = subprocess.run([sys.executable, str(M1), "--results-dir", str(RES),
                            "--tag", tag], capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  m1_local failed for {tag}: {e}")
        return {}
    out = {}
    for line in p.stdout.splitlines():
        m = re.match(r"\s*(A\d|ALL\(macro\))\s+([\d.]+)\s+([\d.]+)%\s+([\d.]+)%", line)
        if m:
            out[m.group(1)] = (float(m.group(2)), float(m.group(3)), float(m.group(4)))
    return out


def mob_csv(attack, tag):
    d = f"_d{DELAY}ms" if attack in (1, 2) else ""
    return RES / f"MOBIGUARD_Attack{attack}_{PCT}{d}_seed{SEED}_{tag}.csv"


def tap_csv(attack, tag):
    return RES / f"TAP_Attack{attack}_{PCT}_d{DELAY}ms_seed{SEED}_{tag}tap.csv"


def score(exp, points, point_key, tag_fmt):
    rows = []
    for pt in points:
        tag = tag_fmt(pt)
        m1 = m1_by_variant(tag)                       # PHANTOM per-variant
        mccs, drs, fprs = [], [], []
        for a in (1, 2, 3, 4):
            mcc, dr, fpr = m1.get(f"A{a}", (None, None, None))
            lat = csv_last_val(mob_csv(a, tag), "avg_lat_ms")
            rows.append(dict(exp=exp, **{point_key: pt}, arm="PHANTOM", attack=a,
                             MCC=mcc, DR=dr, FPR=fpr, lat_ms=lat))
            if mcc is not None: mccs.append(mcc)
            if dr  is not None: drs.append(dr)
            if fpr is not None: fprs.append(fpr)
        # macro = unweighted mean over the S1-S4 variants (paper's "macro MCC")
        mean = lambda xs: (sum(xs) / len(xs)) if xs else None
        rows.append(dict(exp=exp, **{point_key: pt}, arm="PHANTOM", attack="macro",
                         MCC=mean(mccs), DR=mean(drs), FPR=mean(fprs), lat_ms=None))
        for a in (1, 2):                              # TAP baseline (timing only)
            rows.append(dict(exp=exp, **{point_key: pt}, arm="TAP", attack=a,
                             MCC=csv_last_val(tap_csv(a, tag), "avg_MCC"),
                             DR=csv_last_val(tap_csv(a, tag), "avg_DR"),
                             FPR=csv_last_val(tap_csv(a, tag), "avg_FPR"),
                             lat_ms=csv_last_val(tap_csv(a, tag), "avg_lat_ms")))
    return rows


def write_and_print(rows, path, point_key):
    OUT.mkdir(parents=True, exist_ok=True)
    fields = ["exp", point_key, "arm", "attack", "MCC", "DR", "FPR", "lat_ms"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"\n=== {path.name} ===")
    print(f"{point_key:>6} {'arm':<8} {'att':<5} {'MCC':>7} {'DR%':>7} {'FPR%':>7} {'lat_ms':>8}")
    for r in rows:
        fmt = lambda v, p=".3f": (f"{v:{p}}" if isinstance(v, float) else "   -  ")
        print(f"{str(r[point_key]):>6} {r['arm']:<8} {str(r['attack']):<5} "
              f"{fmt(r['MCC']):>7} {fmt(r['DR'],'.1f'):>7} {fmt(r['FPR'],'.1f'):>7} {fmt(r['lat_ms'],'.1f'):>8}")


def main():
    e2 = score(2, SPEEDS, "speed", lambda s: f"e180_exp2_s{s}")
    write_and_print(e2, OUT / "exp2_scores.csv", "speed")
    e3 = score(3, SCALES, "nveh", lambda n: f"e180_exp3_nv{n}")
    write_and_print(e3, OUT / "exp3_scores.csv", "nveh")
    print("\nDone.")


if __name__ == "__main__":
    main()
