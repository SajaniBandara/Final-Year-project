#!/usr/bin/env python3
"""batch_assertions.py -- the gate-2 acceptance checks as automatic assertions at the end of every batch
(supervisor 2026-10-09), plus TP+FN equality for TAP and eFADE on 180 s runs.

A MANIFEST lists the runs of a batch; each entry is a dict:
    tag      run tag (the events / MOBIGUARD files are found through it)
    exp      experiment id (assertions fail per experiment: a failing experiment is STOPPED, the others carry on)
    cfg      configuration id; arms of the same cfg+mode are compared with each other
    arm      'full' | 'tap' | 'sfto' | 'efade' | 'ab7' | 'ab8' | 'ab9' | 'ab12' | ... (free text for other arms)
    mode     'do' detection-only or 'cl' closed loop
    attack   0..8       pct   penetration
    same_positives  (optional, default True for do-runs) the arm must have the same TP+FN as the cfg's 'full' arm
Checks (all machine-evaluated; the table goes to docs/assert/<exp>.md):
  R1 run complete: events file with the expected build commit (no '+dirty'), MOBIGUARD CSV with the same commit, series file
  R2 invariants: TP+FP+FN+TN = scored nodes (N_RSUs) every cycle; per-cycle sums = pooled counts; build commit identical across runs
  R3 TP+FN equality inside a cfg (do-mode): full == ab* == tap == sfto == efade
  R4 gate-2 rules: AB8 S3 raw 0 and DR/M1 not above full beyond CI; AB7/AB9/AB12 counts identical or listed;
     closed loop: AB9 failover events 0, AB8 UFCR 0, AB12 UFCR below full, AB7 M4 infinite (lmit_inf)
"""
import csv, glob, json, math, sys
from pathlib import Path
from collections import defaultdict
sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_scorer as es

RES = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
REPO = Path(__file__).resolve().parent.parent
N_RSUS, N_VEH, SIM = 64, 200, 180

def last_row(tag):
    fs = sorted(glob.glob(str(RES / f"MOBIGUARD_Attack*_{tag}.csv")))
    if not fs: return None
    with open(fs[0]) as f:
        hdr = [h.strip().lstrip("# ").strip() for h in f.readline().split(",")]
        rows = [dict(zip(hdr, [x.strip() for x in r])) for r in csv.reader(f) if len(r) >= 20]
    return rows[-1] if rows else None

def score_run(m, n_veh=N_VEH, cycles=SIM, mask=None):
    ev_path = glob.glob(str(RES / f"events_Attack*_{m['tag']}.csv"))
    if not ev_path: return None
    ev = es.parse(ev_path[0])
    if mask is None:
        mask = {"tap": 1 << 14, "sfto": 1 << 15, "efade": 1 << 16}.get(m["arm"])
    per, s = es.score(ev, n_veh, N_RSUS, cycles, es.WARMUP_S, False, mask)
    s["per"] = per; s["row"] = last_row(m["tag"]) or {}
    s["series"] = bool(glob.glob(str(RES / f"series_Attack*_{m['tag']}.csv")))
    return s

def check_batch(manifest, expected_commit, n_veh=N_VEH, cycles=SIM):
    out = defaultdict(list); runs = {}
    def add(exp, check, ok, nums=""):
        out[exp].append((check, "PASS" if ok is True else ("FAIL" if ok is False else str(ok)), nums))
    for m in manifest:
        s = score_run(m, n_veh, cycles)
        runs[m["tag"]] = s
        if s is None:
            add(m["exp"], f"R1 {m['tag']}: run produced an events file", False, "missing"); continue
        c_ev, c_csv = s["commit"], s["row"].get("build_commit", "")
        add(m["exp"], f"R1 {m['tag']}: build commit == {expected_commit} and clean",
            c_ev == expected_commit and c_csv == expected_commit and "dirty" not in c_ev, f"events={c_ev} csv={c_csv}")
        add(m["exp"], f"R1 {m['tag']}: series file written", s["series"])
        per = s["per"]
        add(m["exp"], f"R2 {m['tag']}: TP+FP+FN+TN = {N_RSUS} scored nodes in every cycle", all(p["TP"] + p["FP"] + p["FN"] + p["TN"] == p["scored"] == N_RSUS for p in per))
        add(m["exp"], f"R2 {m['tag']}: per-cycle sums = pooled counts (post warm-up)",
            all(sum(p[k] for p in per if p["c"] >= es.WARMUP_S) == s[k] for k in ("TP", "FP", "FN", "TN")))
    groups = defaultdict(list)
    for m in manifest: groups[(m["exp"], m["cfg"], m["mode"])].append(m)
    for (exp, cfg, mode), ms in groups.items():
        full = next((m for m in ms if m["arm"] == "full"), None)
        sf = runs.get(full["tag"]) if full else None
        if sf is None: continue
        for m in ms:
            s = runs.get(m["tag"])
            if m is full or s is None: continue
            if mode == "do" and m.get("same_positives", True):
                add(exp, f"R3 {cfg}/{m['arm']} vs full: same TP+FN", s["TPFN"] == sf["TPFN"], f"{s['TPFN']} vs {sf['TPFN']}")
            if mode == "do" and m["arm"] in ("ab7", "ab9", "ab12"):
                d = {k: s[k] - sf[k] for k in ("TP", "FP", "FN", "TN")}
                add(exp, f"R4 {cfg}/{m['arm']} detection-only: counts identical to full or listed", "IDENTICAL" if not any(d.values()) else "DIFFERS", str(d))
            if mode == "do" and m["arm"] == "ab8":
                ci = max([x for x in (sf["mcc_cycle_ci95"], s["mcc_cycle_ci95"]) if not math.isnan(x)] or [0.0])
                add(exp, f"R4 {cfg}/ab8: S3 raw firings 0", str(s["row"].get("s3_fired_count", "")) == "0" and s["fire_totals"].get("S3", 0) == 0, f"s3_fired_count={s['row'].get('s3_fired_count')}")
                add(exp, f"R4 {cfg}/ab8: DR and M1 not above full beyond CI", s["DR"] <= sf["DR"] + ci and s["M1"] <= sf["M1"] + ci, f"DR {s['DR']:.4f} vs {sf['DR']:.4f}, M1 {s['M1']:.4f} vs {sf['M1']:.4f}, CI {ci:.4f}")
            if mode == "cl":
                L, F = s["row"], sf["row"]
                if m["arm"] == "ab9": add(exp, f"R4 {cfg}/ab9 closed loop: M5 undefined (no failover)", L.get("ctrl_failover_events") == "0", f"events {L.get('ctrl_failover_events')} vs full {F.get('ctrl_failover_events')}")
                if m["arm"] == "ab8": add(exp, f"R4 {cfg}/ab8 closed loop: UFCR 0", float(L.get("UFCR", "nan")) == 0.0, f"UFCR {L.get('UFCR')}")
                if m["arm"] == "ab12": add(exp, f"R4 {cfg}/ab12 closed loop: UFCR below full", float(L.get("UFCR", "nan")) < float(F.get("UFCR", "0")), f"{L.get('UFCR')} vs {F.get('UFCR')}")
                if m["arm"] == "ab7": add(exp, f"R4 {cfg}/ab7 closed loop: M4 infinite", L.get("lmit_inf") == "1", f"lmit_inf={L.get('lmit_inf')} uncontained={L.get('lmit_uncontained_n')}")
    return out, runs

def write_report(out, outdir=None):
    outdir = Path(outdir or REPO / "docs" / "assert"); outdir.mkdir(parents=True, exist_ok=True)
    status = {}
    for exp, rows in out.items():
        bad = [r for r in rows if r[1] == "FAIL"]
        status[exp] = "STOPPED (assertion failed)" if bad else "OK"
        with open(outdir / f"{exp}.md", "w") as f:
            f.write(f"# {exp}: {status[exp]}\n\n| check | result | numbers |\n|---|---|---|\n")
            for r in rows: f.write(f"| {r[0]} | **{r[1]}** | {r[2]} |\n")
    return status

if __name__ == "__main__":
    man = json.load(open(sys.argv[1])); commit = sys.argv[2]
    out, runs = check_batch(man, commit)
    st = write_report(out)
    for k, v in st.items(): print(k, v)
    sys.exit(1 if any(v != "OK" for v in st.values()) else 0)
