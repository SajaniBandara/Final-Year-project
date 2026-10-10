#!/usr/bin/env python3
"""rerun_vanguard.py -- the VANGUARD-HF paper (S5-S8, attacks A5-A8), seed 1, 181 s, frozen build (supervisor 2026-10-10).
Exp1 penetration {20..100} x forwarding intensity {25,50,100}% (+ benign), Exp2 speed (6 traces), Exp3 scale (nested 400-vehicle trace), Exp4 targeting axis
(10,25,75,100 %; the copy-destination d_div axis has no knob and is reported as not built), Exp5 default point (own runs). Every LRAD configuration runs in
detection-only (DO: M1/DR/FPR) and closed loop (CL: M2,M4,M5,M6,M11); adapted-eFADE is DO only. Witness runs with the paper's f=1, W=10 s (explicit flags).
HF ablations AB1,AB4,AB6,AB7,AB8,AB9,AB10,AB11,AB12 (AB2, AB3, AB5 are offline; no AB13).   usage: rerun_vanguard.py [--count] [--smoke] [--run] [--commit TAG]"""
import argparse, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rerun_lib as rl

HF = (5, 6, 7, 8); CP = (5, 7)
P5 = [20, 40, 60, 80, 100]; INTENS = [0.25, 0.50, 1.0]; SPEEDS = [10, 40, 70, 100, 130, 150]; NS = [100, 160, 220, 280, 340, 400]
TARGET = [0.10, 0.25, 0.75, 1.0]; DEF_P, DEF_I = 40, 1.0
WIT = ["--witness_f=1", "--witness_window=10"]

def J(exp, cfg, arm, mode, attack, pct, inten=DEF_I, **kw):
    tag = f"vg_{exp}_{cfg}_{arm}_{mode}".replace(".", "p")
    extra = list(kw.pop("extra", [])) + [f"--hf_forward_intensity={inten}"]
    if arm != "efade": extra += WIT
    return dict(tag=tag, paper="VANGUARD-HF", exp=exp, cfg=cfg, arm=arm, mode=mode, attack=attack, pct=pct, extra=extra, **kw)

def trio(exp, cfg, attack, pct, inten=DEF_I, **kw):
    """LRAD DO + LRAD CL + adapted-eFADE DO."""
    return [J(exp, cfg, "full", "do", attack, pct, inten, **kw), J(exp, cfg, "full", "cl", attack, pct, inten, **kw),
            J(exp, cfg, "efade", "do", attack, pct, inten, **kw)]

def jobs():
    L = []
    L += trio("e1", "benign", 0, 0)
    for p in P5:
        for a in HF:
            for it in INTENS: L += trio("e1", f"A{a}_p{p}_i{int(it*100)}", a, p, it)
    for s in SPEEDS:
        kw = dict(speed=s, trace=f"mobility_urban_v{s}.tcl")
        L += trio("e2", f"v{s}_benign", 0, 0, **kw)
        for a in HF: L += trio("e2", f"v{s}_A{a}", a, DEF_P, **kw)
    for n in NS:
        kw = dict(N=n, trace="mobility_urban_N400_perm.tcl")
        L += trio("e3", f"N{n}_benign", 0, 0, **kw)
        for a in HF: L += trio("e3", f"N{n}_A{a}", a, DEF_P, **kw)
    for t in TARGET:
        for a in HF: L += trio("e4", f"t{int(t*100)}_A{a}", a, DEF_P, t)
    for a in HF: L += trio("e5", f"A{a}", a, DEF_P)
    # ---- ablations. Full arm = the Exp1 intensity-100 runs ("A<a>_p<p>_i100"); CL full arm is its CL twin.
    def cfg1(a, p): return f"A{a}_p{p}_i100"
    def abl(name, flags, attacks, pens, modes):
        for a in attacks:
            for p in pens:
                for m in modes:
                    j = J("ab", cfg1(a, p), name, m, a, p, extra=flags); j["tag"] = f"vg_{name}_A{a}_p{p}_{m}"; j["exp"] = "ab"; j["grp"] = "e1"; L.append(j)
    abl("ab1", ["--enable_lrad_obu=0"], HF, P5, ("do",))
    abl("ab4", ["--enable_stark_hop=0"], HF, P5, ("do", "cl"))
    abl("ab6", ["--enable_witness_mechanism=0"], HF, P5, ("do",))
    abl("ab7", ["--enable_quarantine=0"], HF, P5, ("do", "cl"))
    abl("ab8", ["--ab8_single_rsu=1"], CP, P5, ("do", "cl"))
    abl("ab9", ["--ab9_no_isolation=1"], CP, [40, 60, 80, 100], ("do", "cl"))
    abl("ab12", ["--ab12_legitimize=1"], CP, [40, 60, 80, 100], ("do", "cl"))
    abl("ab10", ["--ab10_false_keys=1", "--ab_compromise_model=1"], HF, [40, 60, 80, 100], ("do",))
    for rot in (1, 0):
        for a in (5, 6, 7, 8):
            for p in (40, 100):
                j = J("ab", cfg1(a, p), f"ab11rot{rot}", "cl", a, p, extra=["--ab11_reuse_probe=1", f"--enable_key_rotation={rot}"])
                j["tag"] = f"vg_ab11rot{rot}_A{a}_p{p}_cl"; j["exp"] = "ab"; j["grp"] = "e1"; L.append(j)
    return L

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--count", action="store_true"); ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--run", action="store_true"); ap.add_argument("--commit", default=None); ap.add_argument("--workers", type=int, default=12); a = ap.parse_args(); L = jobs()
    tags = [j["tag"] for j in L]; assert len(tags) == len(set(tags)), "duplicate tags"
    rl.save_manifest(L, Path(__file__).resolve().parent.parent / "docs" / "rerun" / "vanguard_manifest.json")
    if a.count:
        from collections import Counter
        print("VANGUARD-HF jobs:", len(L), dict(Counter(j["exp"] for j in L)), dict(Counter(j["mode"] for j in L)), dict(Counter(j["arm"] for j in L))); return
    if a.smoke:
        sm = [j for j in L if j["tag"] == "vg_e5_A7_full_do"]; rl.run_jobs(sm, a.commit, workers=1); return
    if a.run: rl.run_jobs(L, a.commit, workers=a.workers)
if __name__ == "__main__": main()
