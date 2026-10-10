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
    s["per"] = per; s["row"] = last_row(m["tag"]) or {}; s["cfg"] = ev.get("cfg", {})
    s["series"] = bool(glob.glob(str(RES / f"series_Attack*_{m['tag']}.csv")))
    return s

# Thresholds are set ONCE on the default trace and never reset for speed, N or p (supervisor 2026-10-09). Pass the frozen values to check_batch.
FROZEN_KEYS = ("u_thresh", "t_min", "s1_suppress")
# cfg keys that may legitimately differ between the arms of one figure (the swept variable and the arm under ablation)
SWEEP_KEYS = {"p", "attack", "seed", "maxspeed", "trace", "n_veh", "delay_ms", "tap", "sfto", "tap_margin", "sfto_theta", "enforcement", "quarantine", "lstm"}

def series_cycles(tag):
    fs = glob.glob(str(RES / f"series_Attack*_{tag}.csv"))
    if not fs: return set()
    return {int(l.split(",", 1)[0]) for l in open(fs[0]) if l[:1].isdigit()}

def check_batch(manifest, expected_commit, n_veh=N_VEH, cycles=SIM, frozen=None, require_135=True):
    out = defaultdict(list); runs = {}
    def add(exp, check, ok, nums=""):
        out[exp].append((check, "PASS" if ok is True else ("FAIL" if ok is False else str(ok)), nums))
    for m in manifest:
        s = score_run(m, n_veh, cycles)
        runs[m["tag"]] = s
        if s is None:
            add(m["exp"], f"R1 {m['tag']}: run produced an events file", False, "missing"); continue
        c_ev, c_csv = s["commit"], s["row"].get("build_commit", "")
        baseline_arm = m["arm"] in ("tap", "efade")      # these runs do not write the MOBIGUARD CSV by design: the events file carries the commit
        add(m["exp"], f"R1 {m['tag']}: build commit == {expected_commit} and clean",
            c_ev == expected_commit and (baseline_arm or c_csv == expected_commit) and "dirty" not in c_ev, f"events={c_ev} csv={c_csv or 'n/a'}")
        add(m["exp"], f"R1 {m['tag']}: series file written", s["series"])
        cfg = s["cfg"] if "cfg" in s else {}
        if require_135:
            sc = series_cycles(m["tag"])
            add(m["exp"], f"R6 {m['tag']}: all 135 scored cycles (45..179) were simulated", set(range(45, 180)) <= sc, f"missing {sorted(set(range(45, 180)) - sc)[:5]}")
            rcf = RES / f"rc_{m['tag']}.txt"
            if rcf.exists(): add(m["exp"], f"R6 {m['tag']}: clean exit (rc 0)", rcf.read_text().strip() == "0", rcf.read_text().strip())
        if frozen:
            for k in FROZEN_KEYS:
                add(m["exp"], f"R7 {m['tag']}: {k} == frozen {frozen[k]}", str(cfg.get(k)) == str(frozen[k]), f"{cfg.get(k)}")
        # no honest controller is ever revoked
        ev_all = es.parse(glob.glob(str(RES / f"events_Attack*_{m['tag']}.csv"))[0])
        bad = [c for c in ev_all["rev"] if ev_all["ctrlc"].get(c, 0) == 0]
        add(m["exp"], f"R8 {m['tag']}: no honest controller revoked", not bad, f"honest revoked {bad}, compromised {[c for c,v in ev_all['ctrlc'].items() if v]}, revoked {sorted(ev_all['rev'])}")
        per = s["per"]
        add(m["exp"], f"R2 {m['tag']}: TP+FP+FN+TN = {N_RSUS} scored nodes in every cycle", all(p["TP"] + p["FP"] + p["FN"] + p["TN"] == p["scored"] == N_RSUS for p in per))
        add(m["exp"], f"R2 {m['tag']}: per-cycle sums = pooled counts (post warm-up)",
            all(sum(p[k] for p in per if p["c"] >= es.WARMUP_S) == s[k] for k in ("TP", "FP", "FN", "TN")))
    groups = defaultdict(list)
    for m in manifest: groups[(m.get("grp", m["exp"]), m["cfg"], m["mode"])].append(m)
    figs = defaultdict(list)                                   # arms of one FIGURE: all runs of an experiment
    for m in manifest:
        if runs.get(m["tag"]) is not None: figs[m["exp"]].append(m)
    for exp, ms in figs.items():
        ref = None
        for m in ms:
            cf = runs[m["tag"]]["cfg"]
            if m.get("ablates_crypto"):                          # AB4 and N3 'No Crypto' are the only arms allowed to turn crypto off
                add(exp, f"R5 {m['tag']}: crypto is OFF only because this arm ablates it", cf.get("crypto") == "off", f"crypto={cf.get('crypto')}")
                continue
            add(exp, f"R5 {m['tag']}: crypto is ON", cf.get("crypto") == "on", f"crypto={cf.get('crypto')}")
            core = {k: v for k, v in cf.items() if k not in SWEEP_KEYS and k != "simTime"}
            if ref is None: ref = (m["tag"], core)
            else:
                diff = {k: (ref[1].get(k), core.get(k)) for k in set(ref[1]) | set(core) if ref[1].get(k) != core.get(k)}
                add(exp, f"R5 {m['tag']}: configuration equals {ref[0]} apart from the swept variables", not diff, f"differences {diff}")
    for (grp, cfg, mode), ms in groups.items():
        full = next((m for m in ms if m["arm"] == "full"), None)
        sf = runs.get(full["tag"]) if full else None
        if sf is None: continue
        for m in ms:
            s = runs.get(m["tag"]); exp = m["exp"]
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
                if m["arm"] == "ab7":
                    # supervisor 2026-10-10: assert contained-by-quarantine == 0; contained-by-revocation is REPORTED with its latency (no "never contained" rule)
                    add(exp, f"R4 {cfg}/ab7 closed loop: contained by quarantine == 0", L.get("lmit_contained_quarantine_n") == "0",
                        f"{L.get('lmit_contained_quarantine_n')}; by revocation {L.get('lmit_contained_revocation_n')} at {L.get('lmit_lat_revocation_ms')} ms, never contained {L.get('lmit_uncontained_n')}")
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
