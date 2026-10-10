#!/usr/bin/env python3
"""rerun_phantom.py -- the PHANTOM paper (S1-S4, attacks A1-A4), seed 1, 181 s, frozen build (supervisor 2026-10-10).
Experiments: Exp1 penetration x intensity (delays 25 near-threshold, 55, 100, 200 ms), Exp2 speed (10,40,70,100,130,150 km/h), Exp3 scale (N = 100,160,220,280,340,400
from the nested 400-vehicle trace), Exp4 AOEI (0.10,0.28,0.46,0.64,0.82,1.0), Exp5 default point (its own runs), ablations AB1,AB4,AB7,AB8,AB9,AB10,AB11,AB12,AB13
(AB2, AB3, AB5 are offline). Every LRAD configuration runs in detection-only (DO: M1/DR/FPR) and closed loop (CL: M2,M4,M5,M6,M11); TAP (A1,A2) is DO only; SFTO
rides in the A3/A4 LRAD runs (--enable_sfto, alarms separated by source).   usage: rerun_phantom.py [--count] [--smoke] [--run] [--assert COMMIT]"""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rerun_lib as rl

P5 = [20, 40, 60, 80, 100]; DELAYS = [25, 55, 100, 200]; SPEEDS = [10, 40, 70, 100, 130, 150]; NS = [100, 160, 220, 280, 340, 400]
RATIOS = [0.10, 0.28, 0.46, 0.64, 0.82, 1.0]; DEF_P, DEF_D = 40, 100
ENV = {}   # filled for AB13 (static threshold)

def J(exp, cfg, arm, mode, attack, pct, **kw):
    tag = f"ph_{exp}_{cfg}_{arm}_{mode}".replace(".", "p")
    extra = list(kw.pop("extra", []))
    if arm == "full" and attack in (3, 4) and mode == "do": extra.append("--enable_sfto=1")      # SFTO rides in the A3/A4 detection-only LRAD run
    return dict(tag=tag, paper="PHANTOM", exp=exp, cfg=cfg, arm=arm, mode=mode, attack=attack, pct=pct, extra=extra, **kw)

def trio(exp, cfg, attack, pct, **kw):
    """LRAD DO + CL, plus TAP DO for the timing variants."""
    out = [J(exp, cfg, "full", "do", attack, pct, **kw), J(exp, cfg, "full", "cl", attack, pct, **kw)]
    if attack in (1, 2): out.append(J(exp, cfg, "tap", "do", attack, pct, **kw))
    return out

def jobs():
    L = []
    # ---- Exp1 penetration x intensity
    L += trio("e1", "benign", 0, 0)
    for p in P5:
        for a in (1, 2):
            for d in DELAYS: L += trio("e1", f"A{a}_p{p}_d{d}", a, p, delay=d)
        for a in (3, 4): L += trio("e1", f"A{a}_p{p}", a, p)
    # ---- Exp2 speed (limit label; trace + maxspeed set together)
    for s in SPEEDS:
        kw = dict(speed=s, trace=f"mobility_urban_v{s}.tcl")
        L += trio("e2", f"v{s}_benign", 0, 0, **kw)
        for a in (1, 2, 3, 4): L += trio("e2", f"v{s}_A{a}", a, DEF_P, **kw)
    # ---- Exp3 scale (nested subsets of one 400-vehicle trace)
    for n in NS:
        kw = dict(N=n, trace="mobility_urban_N400_perm.tcl")
        L += trio("e3", f"N{n}_benign", 0, 0, **kw)
        for a in (1, 2, 3, 4): L += trio("e3", f"N{n}_A{a}", a, DEF_P, **kw)
    # ---- Exp4 AOEI (selective target ratio; A3/A4 have no such knob: run once)
    for r in RATIOS:
        for a in (1, 2): L += trio("e4", f"r{r}_A{a}", a, DEF_P, extra=[f"--selective_target_ratio={r}"])
    for a in (3, 4): L += trio("e4", f"A{a}", a, DEF_P)
    # ---- Exp5 default point, own runs
    for a in (1, 2, 3, 4): L += trio("e5", f"A{a}", a, DEF_P)
    # ---- ablations. Full arm = the Exp1 delay-100 runs (same cfg id "A<a>_p<p>_d100" / "A<a>_p<p>").
    def cfg1(a, p): return f"A{a}_p{p}_d100" if a in (1, 2) else f"A{a}_p{p}"
    def abl(name, flags, attacks, pens, modes, exp=None):
        for a in attacks:
            for p in pens:
                for m in modes:
                    j = J("ab", cfg1(a, p), name, m, a, p, extra=flags); j["tag"] = f"ph_{name}_A{a}_p{p}_{m}"; j["exp"] = "ab"; j["grp"] = "e1"; L.append(j)
    abl("ab1", ["--enable_lrad_obu=0"], (1, 2, 3, 4), P5, ("do",))
    abl("ab4", ["--ab4_direct_compare=1"], (2,), P5, ("do", "cl"))
    abl("ab7", ["--enable_quarantine=0"], (1, 2, 3, 4), P5, ("do", "cl"))
    abl("ab8", ["--ab8_single_rsu=1"], (1, 3), P5, ("do", "cl"))
    abl("ab9", ["--ab9_no_isolation=1"], (1, 3), [40, 60, 80, 100], ("do", "cl"))
    abl("ab12", ["--ab12_legitimize=1"], (1, 3), [40, 60, 80, 100], ("do", "cl"))
    abl("ab10", ["--ab10_false_keys=1", "--ab_compromise_model=1"], (1, 2, 3), [40, 60, 80, 100], ("do",))
    for rot in (1, 0):
        for a in (1, 2, 3, 4):
            for p in (40, 100):
                j = J("ab", cfg1(a, p), f"ab11rot{rot}", "cl", a, p, extra=["--ab11_reuse_probe=1", f"--enable_key_rotation={rot}"]); j["tag"] = f"ph_ab11rot{rot}_A{a}_p{p}_cl"; j["exp"] = "ab"; j["grp"] = "e1"; L.append(j)
    # AB13 (S1 only, A1; speeds 10,60,140 x delays 18,21,25 ms x static / adaptive threshold) is added by --ab13 once the static threshold is calibrated.
    return L

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--count", action="store_true"); ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--run", action="store_true"); ap.add_argument("--commit", default=None); a = ap.parse_args(); L = jobs()
    tags = [j["tag"] for j in L]; assert len(tags) == len(set(tags)), "duplicate tags"
    rl.save_manifest(L, REPO_MAN := Path(__file__).resolve().parent.parent / "docs" / "rerun" / "phantom_manifest.json")
    if a.count:
        from collections import Counter
        print("PHANTOM jobs:", len(L), dict(Counter(j["exp"] for j in L)), dict(Counter(j["mode"] for j in L))); return
    if a.smoke:
        sm = [j for j in L if j["tag"] == "ph_e5_A1_full_do"]; rl.run_jobs(sm, a.commit, workers=1); return
    if a.run: rl.run_jobs(L, a.commit)
if __name__ == "__main__": main()
