#!/usr/bin/env python3
"""score_gate2.py -- gate 2 table, acceptance checks and benign-anchor analysis (supervisor 2026-10-09)."""
import csv, glob, math, re, subprocess, sys, json
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_scorer as es

RES = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "gate2"
PFX = "gate2_"

def last_row(tag):
    fs = sorted(glob.glob(str(RES / f"MOBIGUARD_Attack*_{tag}.csv")))
    if not fs: return {}
    with open(fs[0]) as f:
        hdr = [h.strip().lstrip("# ").strip() for h in f.readline().split(",")]
        rows = [dict(zip(hdr, [x.strip() for x in r])) for r in csv.reader(f) if len(r) >= 20]
    return rows[-1] if rows else {}

def old_block_m1(tag):
    p = subprocess.run([sys.executable, str(REPO / "scripts/m1_local.py"), "--results-dir", str(RES), "--tag", tag], capture_output=True, text=True)
    m = re.search(r"ALL\(pooled\)\s+(-?[\d.]+)", p.stdout)
    return float(m.group(1)) if m else float("nan")

def fmt(x, d=4):
    if x is None or x == "": return ""
    if isinstance(x, float): return "nan" if math.isnan(x) else f"{x:.{d}f}"
    return str(x)

def run(tag, mask=None):
    ev_path = glob.glob(str(RES / f"events_Attack*_{PFX}{tag}.csv"))
    if not ev_path: return None
    ev = es.parse(ev_path[0])
    per, s = es.score(ev, 200, 64, 180, es.WARMUP_S, False, mask)
    L = last_row(PFX + tag)
    s["row"] = L; s["ev"] = ev; s["per"] = per
    s["M1_old_block"] = old_block_m1(PFX + tag)
    return s

def cell(s, k): return s["row"].get(k, "")

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    tags = sorted({re.search(rf"_{PFX}(.+)\.csv$", p).group(1) for p in glob.glob(str(RES / f"events_Attack*_{PFX}*.csv"))})
    R = {}
    for t in tags:
        mask = (1 << 15) if "anchor_sfto" in t else ((1 << 14) if "anchor_tap" in t else None)
        r = run(t, mask)
        if r: R[t] = r
    # ---------------- per-arm table
    cols = ["run","TP","FP","FN","TN","TP+FN","DR","FPR","M1","cycleMCC","ci95","undef_cycles","M1_old_block","S3_raw","fp_by_src","quar_true/false","blocked_actions",
            "UFCR_pct","unauth","blocked","legitimised","M4_prevention","M4_latency_ms","M4_n_acted_contained","M4_uncontained","M4_inf","M5_ms","failover_events","commit"]
    rows = []
    for t, s in R.items():
        L = s["row"]
        rows.append([t, s["TP"], s["FP"], s["FN"], s["TN"], s["TPFN"], fmt(s["DR"]), fmt(s["FPR"]), fmt(s["M1"]), fmt(s["mcc_cycle_mean"]), fmt(s["mcc_cycle_ci95"]),
                     s["mcc_cycles_undefined"], fmt(s["M1_old_block"]), L.get("s3_fired_count",""), json.dumps(s["fp_by_src"]),
                     f"{s['quarantined_true']}/{s['quarantined_false']}", L.get("quarantine_block_events",""), L.get("UFCR",""), L.get("ufcr_unauth_total",""), L.get("ufcr_blocked",""),
                     L.get("ufcr_legitimized",""), L.get("lmit_prevention_rate",""), L.get("avg_mit_ms",""), L.get("lmit_scored_n",""), L.get("lmit_uncontained_n",""), L.get("lmit_inf",""),
                     L.get("ctrl_failover_max_ms",""), L.get("ctrl_failover_events",""), s["commit"]])
    with open(OUT / "gate2_runs.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(cols); w.writerows(rows)
    # ---------------- acceptance
    acc = []
    def g(t): return R.get(t)
    def ok(b): return "PASS" if b else "FAIL"
    for A in (1, 3):
        full = g(f"full_A{A}_enfoff")
        if not full: continue
        for ab, label in (("ab7abl", "AB7"), ("ab9abl", "AB9"), ("ab12abl", "AB12"), ("ab8abl", "AB8")):
            if ab == "ab8abl" and A != 3: continue
            nm = f"{ab}_A{A}_enfoff"; arm = g(nm)
            if not arm: continue
            same = arm["TPFN"] == full["TPFN"]
            d = {k: arm[k] - full[k] for k in ("TP", "FP", "FN", "TN")}
            ci = max(full["mcc_cycle_ci95"] if not math.isnan(full["mcc_cycle_ci95"]) else 0, arm["mcc_cycle_ci95"] if not math.isnan(arm["mcc_cycle_ci95"]) else 0)
            m1d = arm["M1"] - full["M1"]
            ident = all(v == 0 for v in d.values())
            if ab == "ab8abl":
                s3 = arm["row"].get("s3_fired_count", "")
                acc.append((f"(a) AB8 A{A} detection-only: same TP+FN as full", ok(same), f"{arm['TPFN']} vs {full['TPFN']}"))
                acc.append((f"(a) AB8 A{A}: S3 raw firings 0", ok(str(s3) == "0" and arm["fire_totals"].get("S3", 0) == 0), f"s3_fired_count={s3}, S3 alarms post-warm-up={arm['fire_totals'].get('S3',0)}"))
                acc.append((f"(a) AB8 A{A}: ablated DR and M1 not above full beyond CI", ok(arm["DR"] <= full["DR"] + 1e-9 + ci and m1d <= ci), f"DR {fmt(arm['DR'])} vs {fmt(full['DR'])}; M1 {fmt(arm['M1'])} vs {fmt(full['M1'])}; CI {fmt(ci)}"))
            else:
                acc.append((f"(b) {label} A{A} detection-only: same TP+FN as full", ok(same), f"{arm['TPFN']} vs {full['TPFN']}"))
                acc.append((f"(b) {label} A{A}: counts identical, or every difference explained", "IDENTICAL" if ident else "DIFFERS", f"dTP={d['TP']} dFP={d['FP']} dFN={d['FN']} dTN={d['TN']}; M1 {fmt(arm['M1'])} vs {fmt(full['M1'])}"))
        # (c) closed-loop
        fon = g(f"full_A{A}_enfon")
        for ab, label in (("ab9abl", "AB9"), ("ab12abl", "AB12"), ("ab8abl", "AB8"), ("ab7abl", "AB7")):
            if ab == "ab8abl" and A != 3: continue
            arm = g(f"{ab}_A{A}_enfon")
            if not arm or not fon: continue
            L, F = arm["row"], fon["row"]
            if label == "AB9":
                acc.append((f"(c) AB9 A{A} closed-loop: M5 undefined (no failover)", ok(L.get("ctrl_failover_events") == "0"), f"failover events {L.get('ctrl_failover_events')} (full {F.get('ctrl_failover_events')}), M5 {L.get('ctrl_failover_max_ms')} ms (full {F.get('ctrl_failover_max_ms')})"))
            if label == "AB8":
                acc.append((f"(c) AB8 A{A} closed-loop: UFCR 0", ok(float(L.get("UFCR", "nan")) == 0.0), f"UFCR {L.get('UFCR')} % ({L.get('ufcr_blocked')}/{L.get('ufcr_unauth_total')} blocked); full {F.get('UFCR')}"))
            if label == "AB12":
                acc.append((f"(c) AB12 A{A} closed-loop: UFCR collapses", ok(float(L.get("UFCR", "nan")) < float(F.get("UFCR", "0")) - 1e-9), f"UFCR {L.get('UFCR')} % ({L.get('ufcr_blocked')}/{L.get('ufcr_unauth_total')} blocked, {L.get('ufcr_legitimized')} legitimised); full {F.get('UFCR')}"))
            if label == "AB7":
                acc.append((f"(c) AB7 A{A} closed-loop: M4 infinite (acted attackers never contained)", ok(L.get("lmit_inf") == "1"), f"lmit_inf={L.get('lmit_inf')}, scored_n={L.get('lmit_scored_n')}, uncontained={L.get('lmit_uncontained_n')}; full: scored_n={F.get('lmit_scored_n')}, latency {F.get('avg_mit_ms')} ms, prevention {F.get('lmit_prevention_rate')}"))
    with open(OUT / "gate2_acceptance.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["check", "result", "numbers"]); w.writerows(acc)
    # ---------------- benign anchor: S1 / S4 false alarms
    anchor = {}
    for t in ("anchor_lrad_enfoff", "anchor_lrad_enfon", "anchor_sfto", "anchor_tap"):
        s = R.get(t)
        if not s: continue
        ev, per = s["ev"], s["per"]
        T = 180
        res = {}
        for name, bit in (("S1", 0), ("S4", 3), ("SFTO", 15), ("TAP", 14)):
            if name in ("SFTO",) and t != "anchor_sfto": continue
            if name == "TAP" and t != "anchor_tap": continue
            if name in ("S1", "S4") and t in ("anchor_tap",): continue
            nc = defaultdict(set)            # node -> cycles with an alarm of this source
            for n, lst in ev["alm"].items():
                for (c, w, mask) in lst:
                    if mask >> bit & 1: nc[n].add(c)
            allcyc = sum(len(v) for v in nc.values())
            post = sum(1 for v in nc.values() for c in v if c >= es.WARMUP_S)
            first60 = sum(1 for v in nc.values() for c in v if c < 60)
            counts = sorted((len(v) for v in nc.values()), reverse=True)
            tot = sum(counts); acc80 = 0; k80 = 0
            for k in counts:
                acc80 += k; k80 += 1
                if acc80 >= 0.8 * tot: break
            fire_all = sum(ev["fire"][c].get(bit, 0) for c in ev["fire"])
            fire_post = sum(ev["fire"][c].get(bit, 0) for c in ev["fire"] if c >= es.WARMUP_S)
            dec_all = sum(ev["dec"][c].get(bit, 0) for c in ev["dec"])
            dec_post = sum(ev["dec"][c].get(bit, 0) for c in ev["dec"] if c >= es.WARMUP_S)
            nodecyc_post = 64 * (T - int(es.WARMUP_S))
            res[name] = dict(alarm_nodecycles_all=allcyc, alarm_nodecycles_post=post, rate_per_nodecycle_post=post / nodecyc_post,
                             share_first60s=(first60 / allcyc if allcyc else float("nan")), rsus_with_alarms=len(nc), rsus_for_80pct=(k80 if tot else 0),
                             raw_firings_all=fire_all, raw_firings_post=fire_post, decisions_all=dec_all, decisions_post=dec_post,
                             rate_per_decision_post=(fire_post / dec_post if dec_post else float("nan")), rate_per_decision_all=(fire_all / dec_all if dec_all else float("nan")))
        anchor[t] = dict(res=res, FP=s["FP"], TN=s["TN"], FPR=s["FPR"], quar_false=s["quarantined_false"], list_size=sum(1 for _ in ev["qua"]))
    json.dump(anchor, open(OUT / "anchor_analysis.json", "w"), indent=1, default=str)
    # per-cycle anchor FPR
    have = {t: R[t]["per"] for t in ("anchor_lrad_enfoff", "anchor_lrad_enfon", "anchor_sfto", "anchor_tap") if t in R}
    with open(OUT / "anchor_fpr_per_cycle.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["cycle"] + list(have))
        for c in range(180):
            w.writerow([c] + [fmt(p[c]["FP"] / (p[c]["FP"] + p[c]["TN"])) if (p[c]["FP"] + p[c]["TN"]) else "" for p in have.values()])
    print(len(R), "runs scored ->", OUT)
    for c in acc: print(c)
    print(json.dumps({t: {k: v for k, v in a.items() if k != "res"} for t, a in anchor.items()}, default=str))
    for t, a in anchor.items():
        for nm, r in a["res"].items(): print(t, nm, {k: (round(v, 5) if isinstance(v, float) else v) for k, v in r.items()})

if __name__ == "__main__":
    main()
