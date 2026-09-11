#!/usr/bin/env python3
"""Collect every number the final supervisor reply needs into one plain-text file.

Runs after the Q chain completes. Scores the Q1-Q6 table with scripts/m1_local.py's
own load()/mcc() (RSU rows, 30 s warm-up, de-duplicated 10 s blocks), reports
macro (degenerate variants excluded) and pooled MCC, mean/std/min/max over seeds,
per-variant breakdown, the closing-criterion checks, UCR, and the retrain /
verification / calibration facts from the orchestrator's logs and JSON outputs.

Env overrides for dry-testing on older data:
  COLLECT_SEEDS="1"  COLLECT_OUT=/tmp/x.txt
"""
import os, re, json, math, statistics, importlib.util, datetime, glob

P  = "/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project"
R  = "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
LP = P + "/lstm_pipeline"
O  = "/tmp/claude-1001/-home-sdvn-hidden-attacks-ns3-g13-g13-project-repo-Final-Year-project/725a44bf-987f-4a71-837a-5932c950e25b/scratchpad/orch"

# Seed 5 only: seeds 6 and 7 were cancelled on 2026-09-11 (single-seed 300 s table).
SEEDS = [int(s) for s in os.environ.get("COLLECT_SEEDS", "5").split(",")]
OUT   = os.environ.get("COLLECT_OUT", O + "/FINAL_RESULTS.txt")
CFGS  = ["Q1", "Q2", "Q3", "Q4", "Q4R", "Q5", "Q6"]
COLS  = ["score", "score_primary"]
HF    = [5, 6, 7, 8]

spec = importlib.util.spec_from_file_location("m1l", P + "/scripts/m1_local.py")
m1l = importlib.util.module_from_spec(spec); spec.loader.exec_module(m1l)

lines = []
def w(s=""): lines.append(s)
def hdr(t): w(); w("=" * 78); w(t); w("=" * 78)
def fmt(x, nd=4): return "  n/a " if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"
def stats(v):
    v = [x for x in v if x is not None]
    if not v: return (None, None, None, None, 0)
    sd = statistics.stdev(v) if len(v) > 1 else None   # one seed has no spread; print n/a, not 0
    return (statistics.mean(v), sd, min(v), max(v), len(v))

# ---------------------------------------------------------------- file index
rx = re.compile(r"^detector_windows_Attack(\d+)_60(?:_d\d+ms)?_seed(\d+)_(Q\d+R?)\.csv$")
idx = {}
for f in os.listdir(R):
    m = rx.match(f)
    if m and int(m.group(2)) in SEEDS:
        idx.setdefault((m.group(3), int(m.group(2))), {})[int(m.group(1))] = os.path.join(R, f)

def score_cell(cfg, seed, col):
    """-> (macro, pooled, per_variant{v:(mcc,tp,fp,fn,tn)}, excluded[list], nfiles)"""
    fset = idx.get((cfg, seed), {})
    counts = {}
    for v, path in fset.items():
        c = counts.setdefault(v, [0, 0, 0, 0])
        for variant, pred, truth in m1l.load(path, "RSU", col, m1l.WARMUP_S, True):
            k = 0 if (truth and pred) else 1 if (not truth and pred) else 2 if (truth and not pred) else 3
            c[k] += 1
    per, excl, mccs, tot = {}, [], [], [0, 0, 0, 0]
    for v, (tp, fp, fn, tn) in sorted(counts.items()):
        mc = m1l.mcc(tp, fp, fn, tn)
        per[v] = (mc, tp, fp, fn, tn)
        for i, x in enumerate((tp, fp, fn, tn)): tot[i] += x
        if tp + fn == 0: excl.append(v)
        else: mccs.append(mc)
    macro = sum(mccs) / len(mccs) if mccs else None
    pooled = m1l.mcc(*tot) if sum(tot) else None
    return macro, pooled, per, excl, len(fset)

w(f"FINAL RESULTS BUNDLE  generated {datetime.datetime.now():%Y-%m-%d %H:%M}")
w(f"seeds={SEEDS}  configs={CFGS}  simTime=300 s  attack_percentage=60")
w("scorer: scripts/m1_local.py load()/mcc(): RSU rows, 30 s warm-up, non-overlapping")
w("10 s blocks, truth=event. Macro excludes degenerate variants (TP+FN=0).")
w("NOTE: m1_local.py is a local re-implementation; the canonical metrics/ package is")
w("absent on this host, so absolute levels are this scorer's reading.")

# ------------------------------------------------------------- completeness
hdr("1. COMPLETENESS (expected 8 variant files per config x seed)")
missing = []
for cfg in CFGS:
    row = []
    for s in SEEDS:
        n = len(idx.get((cfg, s), {}))
        row.append(f"s{s}:{n}/8")
        if n < 8: missing.append((cfg, s, n))
    w(f"  {cfg:<4} " + "  ".join(row))
w(f"  total files: {sum(len(v) for v in idx.values())} / {8*len(CFGS)*len(SEEDS)}")
w("  MISSING: " + (", ".join(f"{c} s{s} ({n}/8)" for c, s, n in missing) if missing else "none"))

# ----------------------------------------------------------------- main table
results = {}
for col in COLS:
    hdr(f"2. Q1-Q6 TABLE  column={col}  (mean +/- std over seeds [min..max] n)")
    w(f"  {'cfg':<5}{'MACRO':>28}{'POOLED':>30}")
    for cfg in CFGS:
        mac, poo, pervar = [], [], {}
        for s in SEEDS:
            macro, pooled, per, excl, nf = score_cell(cfg, s, col)
            results[(col, cfg, s)] = (macro, pooled, per, excl, nf)
            mac.append(macro); poo.append(pooled)
            for v, t in per.items(): pervar.setdefault(v, []).append(t[0])
        m = stats(mac); p = stats(poo)
        w(f"  {cfg:<5}{fmt(m[0])} +/- {fmt(m[1])} [{fmt(m[2],3)}..{fmt(m[3],3)}] n={m[4]}"
          f"   {fmt(p[0])} +/- {fmt(p[1])} n={p[4]}")
        results[(col, cfg, "macro_stats")] = m
        results[(col, cfg, "pervar")] = {v: stats(x) for v, x in pervar.items()}

    w(); w(f"  per-variant MCC (mean over seeds), column={col}")
    w("  cfg  " + "".join(f"{'A'+str(v):>9}" for v in range(1, 9)))
    for cfg in CFGS:
        pv = results[(col, cfg, "pervar")]
        w(f"  {cfg:<5}" + "".join(f"{fmt(pv[v][0]) if v in pv else '    --':>9}" for v in range(1, 9)))
    w(); w(f"  degenerate (TP+FN=0) exclusions, column={col}:")
    anyx = False
    for cfg in CFGS:
        for s in SEEDS:
            ex = results[(col, cfg, s)][3]
            if ex: anyx = True; w(f"    {cfg} seed {s}: " + ", ".join(f"A{v}" for v in ex))
    if not anyx: w("    none")

# ---------------------------------------------------------- closing criterion
hdr("3. CLOSING CRITERION (supervisor: macro-MCC >= 0.80 and monotonic)")
w("  'monotonic' was not defined precisely in the instruction; three readings checked.")
for col in COLS:
    q6 = results[(col, "Q6", "macro_stats")][0]
    q5 = results[(col, "Q5", "macro_stats")][0]
    others = {c: results[(col, c, "macro_stats")][0] for c in CFGS if c != "Q6"}
    c1 = q6 is not None and q6 >= 0.80
    c2 = q6 is not None and q5 is not None and q6 >= q5
    c3 = q6 is not None and all(v is None or q6 >= v for v in others.values())
    w(f"  column={col}")
    if q6 is None:
        # Never let missing data read as a pass or a clean result.
        w("    Q6: NO DATA - closing criterion cannot be evaluated (see section 1)")
        continue
    w(f"    Q6 macro = {fmt(q6)}  -> >= 0.80 : {'YES' if c1 else 'NO'}")
    w(f"    Q6 >= Q5 (full system not below signatures-only): "
      f"{'n/a - no Q5 data' if q5 is None else ('YES' if c2 else 'NO')}  (Q5={fmt(q5)})")
    w(f"    Q6 >= every other config: {'YES' if c3 else 'NO'}  "
      + " ".join(f"{c}={fmt(v,3)}" for c, v in others.items())
      + ("  [configs with no data are skipped]" if any(v is None for v in others.values()) else ""))
    pv = results[(col, "Q6", "pervar")]
    below = [f"A{v}={fmt(pv[v][0],3)}" for v in sorted(pv) if pv[v][0] is not None and pv[v][0] < 0.80]
    nodata = [f"A{v}" for v in range(1, 9) if v not in pv]
    w(f"    Q6 variants below 0.80: {', '.join(below) if below else 'none'}"
      + (f"   (no data: {', '.join(nodata)})" if nodata else ""))

# ----------------------------------------------------------------------- UCR
hdr("4. UCR (avg_UCR, final cycle) - HF variants, mean over seeds")
urx = re.compile(r"^MOBIGUARD_Attack(\d+)_60(?:_d\d+ms)?_seed(\d+)_(Q\d+R?)\.csv$")
# The MOBIGUARD header is 4 "#"-prefixed lines, so there is no single-line CSV
# header to key on (a DictReader keyed on line 1 never sees avg_UCR, which is on
# line 3). avg_UCR is fixed column 20, as in evaluator.py's SIM_COL_MAP. The
# writer appends and the Q runner renames the whole file after each config, so a
# seed-5 _Q1 file also holds the round-10 regeneration's rows ahead of Q1's own:
# take the final row of the LAST run block (after the last cycle reset), and only
# when that run reached the end of the simulation.
UCR_COL = 20
ucr = {}; ucr_skipped = []
import csv
for f in sorted(os.listdir(R)):
    m = urx.match(f)
    if not m or int(m.group(2)) not in SEEDS or int(m.group(1)) not in HF: continue
    try:
        data = [r for r in csv.reader(open(os.path.join(R, f)))
                if r and not r[0].lstrip().startswith("#")]
        start = 0
        for i in range(1, len(data)):
            if float(data[i][0]) < float(data[i - 1][0]): start = i
        last = data[-1]
        if len(data) - start < 290 or float(last[0]) < 290:
            ucr_skipped.append(f"{f} (last run {len(data) - start} rows, final cycle {last[0].strip()})")
            continue
        ucr.setdefault((m.group(3), int(m.group(1))), []).append(float(last[UCR_COL]))
    except Exception as e:
        ucr_skipped.append(f"{f} ({type(e).__name__}: {e})")
w("  cfg  " + "".join(f"{'A'+str(v):>10}" for v in HF))
for cfg in CFGS:
    w(f"  {cfg:<5}" + "".join(f"{fmt(stats(ucr.get((cfg, v), []))[0], 2):>10}" for v in HF))
w(f"  UCR files skipped: {len(ucr_skipped)}")
for s in ucr_skipped: w(f"    {s}")

# ------------------------------------------------- retrain / verify / calibrate
hdr("5. RETRAIN, VERIFICATION, CALIBRATION FACTS")
def grep(path, pat, maxn=20):
    try:
        return [l.rstrip() for l in open(path, errors="replace") if re.search(pat, l)][:maxn]
    except FileNotFoundError:
        return [f"(missing: {os.path.basename(path)})"]
w("  gates: " + " ".join(sorted(os.listdir(O + "/gates"))) if os.path.isdir(O + "/gates") else "  gates: (none)")
w("  -- orchestrator failures/notes"); [w("    " + l) for l in grep(O + "/orchestrate.log", r"FATAL|FAIL|SKIP|theta_hc|<-|moved")]
w("  -- A1 preprocessor split"); [w("    " + l) for l in grep(O + "/A1_preprocessor.log", r"Loaded|Total windows|train:|val :|test :")]
for name, pat in [("A2_local_trainer", r"WARNING|fallback|FPR|MCC|skip"), ("A3_fed_aggregator", r"round|Round|theta|reject|BRFA|WARNING"),
                  ("A4_cls_head", r"MCC|FPR|DR|thresh|saved|trainable"), ("A5_evaluator", r"MCC|DR|FPR|M1|WARNING")]:
    w(f"  -- {name} (selected lines)"); [w("    " + l[:150]) for l in grep(f"{O}/{name}.log", pat, 14)]
def jload(p):
    try: return json.load(open(p))
    except Exception as e: return {"_error": str(e)}
fs = jload(LP + "/fed_summary.json")
w("  -- fed_summary.json scalars: " + ", ".join(f"{k}={v}" for k, v in fs.items() if isinstance(v, (int, float, str)))[:300])
hc = jload(LP + "/hc_theta.json")
w("  -- hc_theta.json: " + ", ".join(f"{k}={hc.get(k)}" for k in ("theta_hc", "hc_percentile", "benign_p99", "n_calibration_windows", "generated")))
w("  -- C1 export");  [w("    " + l) for l in grep(O + "/C1_export.log", r"bin header|n_features|wrote|Wrote")]
w("  -- C4 C++ vs Python verification"); [w("    " + l) for l in grep(O + "/C4_verify.log", r"Loaded|PASS|FAIL|abs_diff|max")]
w("  -- D INSIMCAL"); [w("    " + l) for l in grep(O + "/orchestrate.log", r"INSIMCAL")]
ci = jload(LP + "/cls_theta_insim.json")
thr = ci.get("per_rsu_threshold", {}) if isinstance(ci, dict) else {}
tv = [float(x) for x in thr.values()] if isinstance(thr, dict) else []
w("  -- cls_theta_insim.json: " + ", ".join(f"{k}={ci.get(k)}" for k in ("source", "target_fpr", "floor", "n_rows", "n_rsus"))
  + (f", thresholds min={min(tv):.3f} median={statistics.median(tv):.3f} max={max(tv):.3f}" if tv else ""))
w("  -- D2 calibrate (tail)"); [w("    " + l[:150]) for l in grep(O + "/D2_calibrate.log", r".", 60)[-12:]]
ev = jload(LP + "/evaluation_results.json")
w("  -- evaluation_results.json (offline, test split seed 5), truncated:")
for l in json.dumps(ev, indent=1).splitlines()[:60]: w("    " + l)

text = "\n".join(lines) + "\n"
open(OUT, "w").write(text)
if OUT.startswith(O):
    open(P + "/docs/RESULTS_FINAL_Q1Q6_round11.txt", "w").write(text)
print(f"wrote {OUT} ({len(lines)} lines)")
