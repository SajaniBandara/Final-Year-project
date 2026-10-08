#!/usr/bin/env python3
"""
score_phantom_ab_pending.py — score every 180 s ablation run from run_phantom_ab_pending.py
(AB1, AB4, AB7, AB8, AB9, AB10, AB11, AB12, AB13; seed 1). Writes
docs/phantom_exp23/ab_pending_scores.csv, one row per (ablation, arm, attack, pct[, speed, delay]).

Property metrics (supervisor 2026-10-07/08):
  M1   MCC (m1_local, per-RSU deduped 10 s blocks) -- reference; M1_blk_mean/std = mean/std of the
       per-10 s-block MCC (the interval for M1 is across 10 s windows, the finest unit M1 has)
  M2   TVR, % (cur_TVR)            M4  mitigation latency, ms (cur_mit_ms; INF if nothing quarantined)
  M5   controller failover events / max latency ms (INF when ablated)
  M6   end to end latency, ms (cur_lat_ms)
  M7   STARK timing verification overhead, ms per proof (t_stark_ms_avg)
  M10  privacy cost: raw timestamp pairs exposed to verifiers (m10_raw_ts_exposed)
  M11  unauthorized FlowMod commit rate, % = (unauth - blocked + legitimised) / unauth (A1/A3 only)
  AB10 forged-proof share, % = ab10_forged_accepted / ab10_invalid_proofs
  AB11 revoked-key replay acceptance by whole cycles since revocation (ab11_acc*/ab11_att*)
Intervals: M2/M4/M6/FPR are mean and std over the per-routing-cycle values (cycle >= 30 s warm-up) of the
single 180 s seed-1 run.
"""
import csv, math, re, statistics, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RES  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
OUT  = REPO / "docs/phantom_exp23/ab_pending_scores.csv"
M1   = REPO / "scripts/m1_local.py"
SEED, SUF, WARM = 1, "_t180", 30.0
INF = float("inf")


def read(path):
    try: rows = list(csv.reader(open(path)))
    except OSError: return None, None
    if len(rows) < 2: return None, None
    h = [x.strip() for x in rows[0]]
    return h, [dict(zip(h, r)) for r in rows[1:] if len(r) >= len(h) - 1]


def fnum(x):
    try: return float(x)
    except (TypeError, ValueError): return None


def cyc_stats(rows, col):
    """mean/std of a per-cycle column over cycles >= warm-up."""
    xs = [fnum(r.get(col)) for r in rows if (fnum(r.get("# cycle")) or 0) >= WARM]
    xs = [x for x in xs if x is not None]
    if not xs: return None, None
    return statistics.mean(xs), (statistics.pstdev(xs) if len(xs) > 1 else 0.0)


def m1_pooled(tag):
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


def mcc(tp, fp, fn, tn):
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / d if d else 0.0


def m1_blocks(tag, attack):
    """per-10 s-block MCC (same filters as m1_local: RSU rows, 30 s warm-up, non-overlapping lattice)."""
    fs = sorted(RES.glob(f"detector_windows_Attack{attack}_*_{tag}.csv"))
    if not fs: return None, None
    try: rows = list(csv.DictReader(open(fs[0])))
    except OSError: return None, None
    if not rows: return None, None
    t0 = min(float(r["w_start"]) for r in rows)
    blocks = {}
    for r in rows:
        if r["mode"] != "RSU": continue
        ws = float(r["w_start"])
        if ws < t0 + WARM: continue
        k = round((ws - t0) / 5.0)
        if k % 2: continue
        if r.get("truth", "") == "" or r.get("score", "") == "": continue
        pred, tru = int(float(r["score"]) > 0.5), int(float(r["truth"]) > 0.5)
        c = blocks.setdefault(k, [0, 0, 0, 0])
        c[(0 if pred and tru else 1 if pred else 2 if tru else 3)] += 1
    ms = [mcc(*c) for c in blocks.values()]
    if len(ms) < 2: return None, None
    return statistics.mean(ms), statistics.pstdev(ms)


def csv_path(a, pct, tag, delay=100):
    d = f"_d{delay}ms" if a in (1, 2) else ""
    return RES / f"MOBIGUARD_Attack{a}_{pct}{d}_seed{SEED}_{tag}.csv"


def jobs():
    PA, PC = [0, 20, 40, 60, 80, 100], [40, 60, 80, 100]
    for arm in ("ab7full", "ab7off"):
        yield "ab7", arm, 0, 0, 150, 100, ""
        for a in (1, 2, 3, 4):
            for p in PA[1:]: yield "ab7", arm, a, p, 150, 100, ""
    yield "ab1", "ab1sub", 0, 0, 150, 100, ""
    for a in (1, 2, 3, 4):
        for p in PA[1:]: yield "ab1", "ab1sub", a, p, 150, 100, ""
    for p in PA[1:]: yield "ab4", "ab4sub", 2, p, 150, 100, ""
    for arm in ("ab8full", "ab8sub"):
        for a in (1, 3):
            for p in PA[1:]: yield "ab8", arm, a, p, 150, 100, ""
    for a in (1, 3):
        for p in PC: yield "ab9", "ab9sub", a, p, 150, 100, ""
        for p in PC: yield "ab12", "ab12sub", a, p, 150, 100, ""
    for a in (1, 2, 3):
        for p in PC: yield "ab10", "ab10sub", a, p, 150, 100, ""
    for arm in ("ab11rot", "ab11norot"):
        for a in (1, 2, 3, 4):
            for p in (40, 100): yield "ab11", arm, a, p, 150, 100, ""
    for sp in (10, 60, 100, 140):
        for dl in (55, 100, 200):
            for arm in ("ab13full", "ab13sub", "ab13fullE", "ab13subE"):
                yield "ab13", arm, 1, 40, sp, dl, f"_v{sp}_d{dl}"


def main():
    rows = []
    for ab, arm, a, p, sp, dl, tagx in jobs():
        tag = f"{arm}{tagx}_p{p}{SUF}"
        h, cyc = read(csv_path(a, p, tag, dl))
        if cyc is None:
            print(f"MISSING {tag} A{a}"); continue
        last = cyc[-1]
        m1 = m1_pooled(tag).get(f"A{a}", (None, None, None))[0] if a else None
        bm, bs = m1_blocks(tag, a) if a else (None, None)
        unauth, blocked, legit = fnum(last.get("ufcr_unauth_total")), fnum(last.get("ufcr_blocked")), fnum(last.get("ufcr_legitimized"))
        invalid, forged = fnum(last.get("ab10_invalid_proofs")), fnum(last.get("ab10_forged_accepted"))
        qn = fnum(last.get("quarantined_nodes"))
        lat_m, lat_s = cyc_stats(cyc, "cur_lat_ms")
        mit_m, mit_s = cyc_stats(cyc, "cur_mit_ms")
        tvr_m, tvr_s = cyc_stats(cyc, "cur_TVR")
        fpr_m, fpr_s = cyc_stats(cyc, "cur_FPR")
        m4 = fnum(last.get("avg_mit_ms"))
        if a and not qn and arm == "ab7off": m4 = INF
        fo_ev, m5 = fnum(last.get("ctrl_failover_events")), fnum(last.get("ctrl_failover_max_ms"))
        if a and p >= 33 and fo_ev == 0 and arm in ("ab9sub", "ab12sub"): m5 = INF
        r = dict(ablation=ab, arm=arm, attack=a, pct=p, speed=sp, delay=dl, M1=m1, M1_blk_mean=bm, M1_blk_std=bs,
                 M2_TVR_mean=tvr_m, M2_TVR_std=tvr_s, FPR_mean=fpr_m, FPR_std=fpr_s,
                 M4_ms=m4, M4_cyc_mean=mit_m, M4_cyc_std=mit_s, M5_events=fo_ev, M5_max_ms=m5,
                 M6_ms=fnum(last.get("avg_lat_ms")), M6_cyc_mean=lat_m, M6_cyc_std=lat_s,
                 M7_stark_ms=fnum(last.get("t_stark_ms_avg")), M10_raw_ts=fnum(last.get("m10_raw_ts_exposed")),
                 M11_pct=(100.0 * (unauth - blocked + (legit or 0)) / unauth) if unauth else None,
                 forged_share_pct=(100.0 * forged / invalid) if invalid else None,
                 quarantined_nodes=qn, quarantine_block_events=fnum(last.get("quarantine_block_events")),
                 prevention_rate=fnum(last.get("lmit_prevention_rate")), solver=last.get("solver_used", "").strip())
        for k in range(6):
            sfx = f"{k}" if k < 5 else "5plus"
            r[f"ab11_att{k}"], r[f"ab11_acc{k}"] = fnum(last.get(f"ab11_att{sfx}")), fnum(last.get(f"ab11_acc{sfx}"))
        rows.append(r)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
