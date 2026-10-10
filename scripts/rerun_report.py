#!/usr/bin/env python3
"""rerun_report.py -- the end-of-paper printout (supervisor 2026-10-10):
  (i) failed assertions   (ii) ablation points where the ABLATED arm beats the FULL arm on its own metric by more than the CI
  (iii) series flatter than their CI.
Each item is listed with a place for a one-line explanation (docs/rerun/<paper>_explanations.json maps item-id -> text); an unexplained item is printed as OPEN.
Flat by design (never printed as a problem): AB7, AB9, AB12 M1 in detection only; AB8 composite M1 on A3.
usage: rerun_report.py <paper> <commit>      paper = phantom | vanguard | hydra | nexus"""
import json, math, sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import batch_assertions as ba, event_scorer as es

REPO = Path(__file__).resolve().parent.parent
FROZEN = dict(u_thresh="0.37", t_min="0.3", s1_suppress="1")
FLAT_BY_DESIGN = {("ab7", "M1"), ("ab9", "M1"), ("ab12", "M1"), ("ab8", "M1_A3")}

def wilson(k, n, z=1.96):
    if n == 0: return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d; return p, h

def summarise(m, n_veh):
    s = ba.score_run(m, n_veh=n_veh, cycles=ba.SIM)
    return s

def main():
    paper, commit = sys.argv[1], sys.argv[2]
    man = json.loads((REPO / "docs" / "rerun" / f"{paper}_manifest.json").read_text())
    expl = {}
    ef = REPO / "docs" / "rerun" / f"{paper}_explanations.json"
    if ef.exists(): expl = json.loads(ef.read_text())
    out_lines = [f"# {paper}: end-of-paper report (commit {commit})", ""]
    # ---- (i) assertions
    done = [m for m in man if (ba.RES / f"rc_{m['tag']}.txt").exists()]
    res, runs = ba.check_batch(done, commit, frozen=FROZEN)
    fails = [(e, r) for e, rows in res.items() for r in rows if r[1] == "FAIL"]
    out_lines += [f"## (i) failed assertions: {len(fails)} of {sum(len(v) for v in res.values())} checks", ""]
    for e, r in fails:
        key = f"assert:{e}:{r[0]}"; out_lines.append(f"- [{e}] {r[0]} -- {r[2]} -- {'**OPEN**' if key not in expl else expl[key]}")
    # ---- (ii) ablated beats full
    out_lines += ["", "## (ii) ablation points where the ablated arm beats the full arm on its own metric by more than the CI", ""]
    by = defaultdict(dict)
    for m in done:
        s = runs.get(m["tag"])
        if s is not None: by[(m.get("grp", m["exp"]), m["cfg"], m["mode"])][m["arm"]] = (m, s)
    n_beats = 0
    for (grp, cfg, mode), arms in sorted(by.items()):
        if "full" not in arms: continue
        mf, sf = arms["full"]
        for arm, (ma, sa) in arms.items():
            if arm in ("full", "tap", "sfto", "efade") or not arm.startswith("ab"): continue
            name = arm.rstrip("0123456789").replace("rot", "") if arm.startswith("ab11") else arm
            checks = []
            if mode == "do":
                ci = math.hypot(*(x if not math.isnan(x) else 0.0 for x in (sf["mcc_cycle_ci95"], sa["mcc_cycle_ci95"])))
                checks.append(("M1", sa["M1"], sf["M1"], ci, True))
            else:
                La, Lf = sa["row"], sf["row"]
                if arm in ("ab8", "ab12"):
                    ta, tf = int(La.get("ufcr_unauth_total", 0) or 0), int(Lf.get("ufcr_unauth_total", 0) or 0)
                    pa, ha = wilson(int(La.get("ufcr_blocked", 0) or 0), ta); pf, hf = wilson(int(Lf.get("ufcr_blocked", 0) or 0), tf)
                    checks.append(("UFCR", pa, pf, math.hypot(ha, hf), True))
                if arm in ("ab7", "ab9"):
                    def contained(L): return int(L.get("lmit_contained_quarantine_n", 0) or 0) + int(L.get("lmit_contained_revocation_n", 0) or 0), int(L.get("lmit_uncontained_n", 0) or 0)
                    (ca, ua), (cf, uf) = contained(La), contained(Lf)
                    pa, ha = wilson(ca, ca + ua); pf, hf = wilson(cf, cf + uf)
                    checks.append(("contained_fraction", pa, pf, math.hypot(ha, hf), True))
            for metric, va, vf, ci, higher in checks:
                if any(math.isnan(x) for x in (va, vf)): continue
                key = f"beats:{grp}:{cfg}:{mode}:{arm}:{metric}"
                if (name, metric) in FLAT_BY_DESIGN or (name == "ab8" and metric == "M1" and "A3" in cfg): continue
                if (va - vf) > ci:
                    n_beats += 1; out_lines.append(f"- {arm} {cfg} {mode}: {metric} ablated {va:.4f} > full {vf:.4f} by {va - vf:.4f} (CI {ci:.4f}) -- {'**OPEN**' if key not in expl else expl[key]}")
    if not n_beats: out_lines.append("- none")
    # ---- (iii) flat series
    out_lines += ["", "## (iii) series flatter than their CI (M1 of the full arm, detection only, across the swept variable)", ""]
    series = defaultdict(list)
    for m in done:
        if m["arm"] != "full" or m["mode"] != "do" or m["exp"] not in ("e1", "e2", "e3", "e4"): continue
        s = runs.get(m["tag"])
        if s is None or math.isnan(s["M1"]): continue
        a, _, rest = m["cfg"].partition("_")
        att = f"A{m['attack']}"
        if m["exp"] == "e1": key = ("e1", att, f"delay{m.get('delay', 100)}"); x = m["pct"]
        else: key = (m["exp"], att, ""); x = m["cfg"]
        series[key].append((x, s["M1"], s["mcc_cycle_ci95"] if not math.isnan(s["mcc_cycle_ci95"]) else 0.0))
    nflat = 0
    for key, pts in sorted(series.items()):
        if len(pts) < 3: continue
        vals = [p[1] for p in pts]; ci = max(p[2] for p in pts)
        if max(vals) - min(vals) < ci:
            nflat += 1; k = "flat:" + ":".join(key); out_lines.append(f"- {key}: M1 range {max(vals) - min(vals):.4f} < CI {ci:.4f} over {len(pts)} points -- {'**OPEN**' if k not in expl else expl[k]}")
    if not nflat: out_lines.append("- none")
    txt = "\n".join(out_lines); (REPO / "docs" / "rerun" / f"{paper}_report.md").write_text(txt); print(txt)
if __name__ == "__main__": main()
