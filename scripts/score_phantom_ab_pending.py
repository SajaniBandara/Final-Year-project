#!/usr/bin/env python3
"""
score_phantom_ab_pending.py — score the AB7/AB9/AB10/AB12 sweep from run_phantom_ab_pending.py.
Writes docs/phantom_exp23/ab_pending_scores.csv, one row per (arm, attack, pct), with the
property metrics the supervisor specified (2026-10-07):

  M1   macro-reference MCC for the variant (m1_local, per-RSU deduped 10 s blocks)
  M4   mitigation latency, ms (avg_mit_ms). INF when the arm quarantines nothing (AB7 off).
  M5   controller failover: events and max latency ms (INF when an attack is on but failover
       never happens -- the ablated arm)
  M6   end to end latency, ms (avg_lat_ms)
  M11  unauthorized FlowMod commit rate, % = (unauth - blocked + legitimised) / unauth
       (defined only for the control-plane variants A1/A3)
  AB10 forged-proof share, % = ab10_forged_accepted / ab10_invalid_proofs
"""
import csv, math, re, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RES  = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
OUT  = REPO / "docs/phantom_exp23/ab_pending_scores.csv"
M1   = REPO / "scripts/m1_local.py"
SEED, DELAY = 1, 100
INF = float("inf")


def last_row(path):
    try:
        rows = list(csv.reader(open(path)))
    except OSError:
        return None
    if len(rows) < 2: return None
    h = [x.strip() for x in rows[0]]
    return {h[i]: rows[-1][i].strip() for i in range(min(len(h), len(rows[-1])))}


def f(row, k):
    try: return float(row[k])
    except (KeyError, ValueError, TypeError): return None


def m1_variants(tag):
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


def csv_path(a, pct, tag):
    d = f"_d{DELAY}ms" if a in (1, 2) else ""
    return RES / f"MOBIGUARD_Attack{a}_{pct}{d}_seed{SEED}_{tag}.csv"


def jobs():
    PA, PC = [0, 20, 40, 60, 80, 100], [40, 60, 80, 100]
    for arm in ("ab7full", "ab7off"):
        yield "ab7", arm, 0, 0
        for a in (1, 2, 3, 4):
            for p in PA[1:]: yield "ab7", arm, a, p
    for a in (1, 3):
        for p in PC: yield "ab9", "ab9sub", a, p
        for p in PC: yield "ab12", "ab12sub", a, p
    for a in (1, 2, 3):
        for p in PC: yield "ab10", "ab10sub", a, p


def main():
    rows = []
    for ab, arm, a, p in jobs():
        tag = f"{arm}_p{p}"
        r = last_row(csv_path(a, p, tag))
        if r is None:
            print(f"MISSING {arm} A{a} p{p}"); continue
        m1 = m1_variants(tag).get(f"A{a}", (None, None, None))[0] if a else None
        unauth, blocked, legit = f(r, "ufcr_unauth_total"), f(r, "ufcr_blocked"), f(r, "ufcr_legitimized")
        invalid, forged = f(r, "ab10_invalid_proofs"), f(r, "ab10_forged_accepted")
        qn = f(r, "quarantined_nodes")
        m4 = f(r, "avg_mit_ms")
        if a and (qn == 0 or qn is None) and arm == "ab7off": m4 = INF   # nothing ever quarantined
        fo_ev = f(r, "ctrl_failover_events")
        m5 = f(r, "ctrl_failover_max_ms")
        if a and p >= 33 and fo_ev == 0 and arm in ("ab9sub", "ab12sub"): m5 = INF
        rows.append(dict(
            ablation=ab, arm=arm, attack=a, pct=p, M1=m1,
            M4_ms=m4, M5_events=fo_ev, M5_max_ms=m5, M6_ms=f(r, "avg_lat_ms"),
            M11_pct=(100.0 * (unauth - blocked + (legit or 0)) / unauth) if unauth else None,
            forged_share_pct=(100.0 * forged / invalid) if invalid else None,
            quarantined_nodes=qn, quarantine_block_events=f(r, "quarantine_block_events"),
            prevention_rate=f(r, "lmit_prevention_rate")))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
