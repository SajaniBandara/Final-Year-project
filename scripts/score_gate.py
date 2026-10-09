#!/usr/bin/env python3
"""score_gate.py -- builds the supervisor gate table from gate_* runs (event scorer + the legacy paths from the SAME run)."""
import csv, glob, math, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_scorer as es

RES = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "gate"

def last_row(tag):
    fs = sorted(glob.glob(str(RES / f"MOBIGUARD_Attack*_{tag}.csv")))
    if not fs: return None, None
    rows = []
    with open(fs[0]) as f:
        hdr = [h.strip().lstrip("# ").strip() for h in f.readline().split(",")]
        for r in csv.reader(f):
            if len(r) >= 20: rows.append(dict(zip(hdr, [x.strip() for x in r])))
    return rows, fs[0]

def old_block_m1(tag):
    p = subprocess.run([sys.executable, str(REPO / "scripts/m1_local.py"), "--results-dir", str(RES), "--tag", tag],
                       capture_output=True, text=True)
    m = re.search(r"ALL\(pooled\)\s+(-?[\d.]+)", p.stdout)
    return float(m.group(1)) if m else float("nan")

def f(x, d=4):
    return "nan" if x is None or (isinstance(x, float) and math.isnan(x)) else (f"{x:.{d}f}" if isinstance(x, float) else str(x))

def one(tag, attack):
    ev_path = glob.glob(str(RES / f"events_Attack*_{tag}.csv"))
    if not ev_path: return None
    ev = es.parse(ev_path[0])
    if "anchor_sfto" in tag:      # SFTO shares its run with the full stack: score ITS alarms only, no MOBIGUARD quarantine stop
        per, s = es.score(ev, 200, 64, 180, 30.0, False, alarm_mask=1 << 15)
        per2, s2 = per, s
    elif "anchor_tap" in tag:     # TAP run: TAP's alarms and TAP's own defaulter-list quarantine
        per, s = es.score(ev, 200, 64, 180, 30.0, True, alarm_mask=1 << 14)
        per2, s2 = es.score(ev, 200, 64, 180, 30.0, False, alarm_mask=1 << 14)
    else:
        per, s = es.score(ev, 200, 64, 180, 30.0, True)
        per2, s2 = es.score(ev, 200, 64, 180, 30.0, False)
    rows, _ = last_row(tag)
    nq = (s2['TP'], s2['FP'], s2['FN'], s2['TN'])
    L = rows[-1] if rows else {}
    d = dict(tag=tag, commit=ev["commit"], TP=s["TP"], FP=s["FP"], FN=s["FN"], TN=s["TN"], M1_new=s["M1"], M1_new_noqstop=s2["M1"],
             DR=s["DR"], FPR=s["FPR"], FPR_noqstop=s2["FPR"], mcc_undef=s["mcc_cycles_undefined"], mcc_def=s["mcc_cycles_defined"],
             cycle_mcc=s["mcc_cycle_mean"], cycle_ci=s["mcc_cycle_ci95"],
             nq_TP=s2['TP'], nq_FP=s2['FP'], nq_FN=s2['FN'], nq_TN=s2['TN'], nq_DR=s2['DR'], nq_cycle_mcc=s2['mcc_cycle_mean'], nq_cycle_ci=s2['mcc_cycle_ci95'], nq_undef=s2['mcc_cycles_undefined'],
             fp_by_src=s2['fp_by_src'], fires_all=s2['fire_totals'], avg_mit_ms=L.get('avg_mit_ms'), cur_mit_ms=L.get('cur_mit_ms'),
             quar_true=s["quarantined_true"], quar_false=s["quarantined_false"],
             fires={k: v for k, v in s["fire_totals"].items() if v},
             M1_old_block=old_block_m1(tag), avg_MCC_old=L.get("avg_MCC"), cur_MCC_old=L.get("cur_MCC"),
             M11_UFCR=L.get("UFCR"), unauth=L.get("ufcr_unauth_total"), blocked=L.get("ufcr_blocked"),
             legitimized=L.get("ufcr_legitimized"), M4_prev=L.get("lmit_prevention_rate"), lmit_n=L.get("lmit_scored_n"),
             M5_failover_ms=L.get("ctrl_failover_max_ms"), failover_events=L.get("ctrl_failover_events"),
             quarantined_nodes=L.get("quarantined_nodes"), qblock=L.get("quarantine_block_events"),
             s3_fired=L.get("s3_fired_count"), s4_fired=L.get("s4_fired_count"))
    return d, per

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    tags = sorted({re.search(r"_(gate_.+)\.csv$", p).group(1) for p in glob.glob(str(RES / "events_Attack*_gate_*.csv"))})
    res = {}
    for t in tags:
        r = one(t, None)
        if r: res[t] = r
    cols = ["tag","TP","FP","FN","TN","nq_TP","nq_FP","nq_FN","nq_TN","nq_DR","nq_cycle_mcc","nq_cycle_ci","nq_undef","fp_by_src","avg_mit_ms","M1_new","M1_new_noqstop","DR","FPR","FPR_noqstop","mcc_def","mcc_undef","cycle_mcc","cycle_ci","quar_true","quar_false",
            "M1_old_block","avg_MCC_old","cur_MCC_old","M11_UFCR","unauth","blocked","legitimized","M4_prev","lmit_n","M5_failover_ms",
            "failover_events","quarantined_nodes","qblock","s3_fired","s4_fired","fires","commit"]
    with open(OUT / "gate_runs.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(cols)
        for t, (d, per) in res.items(): w.writerow([d.get(c, "") if not isinstance(d.get(c), float) else f(d[c]) for c in cols])
    # anchors: per-cycle FPR series
    anchors = {"LRAD_enf_on": "gate_anchor_lrad_enfon", "LRAD_enf_off": "gate_anchor_lrad_enfoff", "TAP": "gate_anchor_tap", "SFTO": "gate_anchor_sfto"}
    have = {k: res[v][1] for k, v in anchors.items() if v in res}
    if have:
        T = 180
        with open(OUT / "anchor_fpr_per_cycle.csv", "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["cycle"] + list(have))
            for c in range(T):
                row = [c]
                for k, per in have.items():
                    p = per[c]; den = p["FP"] + p["TN"]
                    row.append(f"{p['FP']/den:.4f}" if den else "")
                w.writerow(row)
    print(len(res), "runs scored ->", OUT)
    for t, (d, per) in res.items():
        print(t, {k: (f(v) if isinstance(v, float) else v) for k, v in d.items() if k in ("TP","FP","FN","TN","M1_new","M1_new_noqstop","M1_old_block","avg_MCC_old","M11_UFCR","M4_prev","M5_failover_ms","s3_fired","fires","quar_true","quar_false")})

if __name__ == "__main__":
    main()
