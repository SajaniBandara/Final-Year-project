#!/usr/bin/env python3
"""Corrected run count for the reruns (supervisor 2026-10-09). DO = detection-only run, CL = closed-loop run, one 180 s simulation each.
Counts are derived from the papers' own grids; every assumption is printed. The supervisor's 854 'configurations' left out the VANGUARD-HF
ablations, the TAP and eFADE runs, and the LSTM retrains for AB2 / AB3 / AB5."""
import json
P = [20, 40, 60, 80, 100]          # attacking penetration points; p=0 (benign) is counted separately
SPEEDS, NS = 6, 6                  # speed axis 10/40/70/100/130/150; N = 100, 160, 220, 280, 340, 400 (supervisor 2026-10-09)
AOEI = 6                           # 0.10, 0.28, 0.46, 0.64, 0.82, 1.0 (PHANTOM Exp 4); VANGUARD Exp 4 has 4 AOEI points
rows = []
def add(block, what, do, cl, note=""):
    rows.append(dict(block=block, what=what, DO=do, CL=cl, note=note))
# ---------------- PHANTOM (A1-A4). Baselines: TAP on A1/A2 (own run, DO only); SFTO rides in the A3/A4 LRAD run (alarm-source separated).
add("PHANTOM", "Exp1 LRAD: A1,A2 x 5 p x 4 intensities (3 planned + 1 near threshold); A3,A4 x 5 p; benign p=0", 40 + 10 + 1, 40 + 10 + 1)
add("PHANTOM", "Exp1 TAP: A1,A2 x 5 p x 4 intensities + benign", 41, 0, "TAP has no enforcement; DO only")
add("PHANTOM", "Exp2 speed LRAD: 6 speeds x A1-A4 + 6 benign", 6 * 4 + 6, 6 * 4 + 6)
add("PHANTOM", "Exp2 TAP: 6 speeds x A1,A2 + 6 benign", 6 * 2 + 6, 0)
add("PHANTOM", "Exp3 scale LRAD: 6 N x A1-A4 + 6 benign", NS * 4 + NS, NS * 4 + NS)
add("PHANTOM", "Exp3 TAP: 6 N x A1,A2 + 6 benign", NS * 2 + NS, 0)
add("PHANTOM", "Exp4 AOEI LRAD: 6 x A1,A2 + A3,A4 once", AOEI * 2 + 2, AOEI * 2 + 2)
add("PHANTOM", "Exp4 TAP: 6 x A1,A2", AOEI * 2, 0)
add("PHANTOM", "Exp5: shares the default-point runs of Exp 1-3", 0, 0)
add("PHANTOM", "AB1 (OBU) A1-A4 x 5 p; AB4 (STARK) A2 x 5 p", 20 + 5, 5, "AB4 CL for M7")
add("PHANTOM", "full arm closed loop A1-A4 x 5 p (shared by AB7/8/9/10/11/12)", 0, 20)
add("PHANTOM", "AB7 A1-A4 x 5 p", 20, 20)
add("PHANTOM", "AB8 A1,A3 x 5 p", 10, 10)
add("PHANTOM", "AB9 and AB12: A1,A3 x p>=40 (4) each", 16, 16)
add("PHANTOM", "AB10 A1,A2,A3 x 4 p; AB11 A1-A4 x 2 p", 12, 8)
add("PHANTOM", "AB13: 3 speeds x 3 delays x (static, adaptive) + benign", 24, 0)
# ---------------- VANGUARD-HF (A5-A8). Baseline: eFADE (own run, DO only). TAP/SFTO not applicable.
add("VANGUARD-HF", "Exp1 LRAD: 4 variants x 5 p x 3 intensities + benign", 60 + 1, 60 + 1)
add("VANGUARD-HF", "Exp1 eFADE", 60 + 1, 0)
add("VANGUARD-HF", "Exp2 speed LRAD: 6 speeds x 4 + 6 benign", 30, 30)
add("VANGUARD-HF", "Exp2 eFADE", 30, 0)
add("VANGUARD-HF", "Exp3 scale LRAD: 6 N x 4 + 6 benign", 30, 30)
add("VANGUARD-HF", "Exp3 eFADE", 30, 0)
add("VANGUARD-HF", "Exp4 AOEI LRAD: 4 points x 4 variants", 16, 16, "d_div axis not built")
add("VANGUARD-HF", "Exp4 eFADE", 16, 0)
add("VANGUARD-HF", "Exp5: shares default-point runs", 0, 0)
# HF ablations AB1-AB12 on S5-S8, no AB13 (supervisor 2026-10-09): AB3 = pi_hop, AB4 = hop proof, AB6 = witness, AB5 sweeps the poisoned fraction,
# AB11 the steps after revocation, the rest sweep p. AB2 / AB3 / AB5 are offline (evaluation on the stored per-RSU CSVs), no extra simulations.
add("VANGUARD-HF", "AB1 OBU pre-filter: 4 variants x 5 p; AB6 witness: 4 x 5 p; AB4 hop proof: 4 x 5 p (CL for M7)", 20 + 20 + 20, 20)
add("VANGUARD-HF", "full arm closed loop 4 x 5 p (shared by AB4/7/8/9/11/12)", 0, 20)
add("VANGUARD-HF", "AB7 quarantine: 4 x 5 p", 20, 20)
add("VANGUARD-HF", "AB8 single-RSU quorum: CP variants S5,S7 x 5 p", 10, 10)
add("VANGUARD-HF", "AB9 no isolation and AB12 legitimise: CP S5,S7 x p>=40 (4) each", 16, 16)
add("VANGUARD-HF", "AB10 forged keys: 4 variants x 4 p; AB11 rotation probe: 2 arms x 4 variants x 2 p", 16, 16)
add("VANGUARD-HF", "AB2 federated vs central, AB3 pi_hop zeroed, AB5 poisoned fraction", 0, 0, "offline: no simulation")
# ---------------- Hydra: each of 8 variants run separately under 4 configs x 6 p, pooled (breach metrics: closed loop)
add("Hydra", "8 variants x 4 configs x 6 p (surrogate; dwell window to be implemented)", 0, 8 * 4 * 6)
# ---------------- NEXUS: 8 variants run separately and pooled; baselines in scope only (TAP A1,A2 / SFTO A3,A4 piggy / eFADE A5-A8)
add("NEXUS", "N1: 8 variants x 6 p LRAD; TAP 2 x 6; eFADE 4 x 6", 48 + 12 + 24, 48)
add("NEXUS", "N2: 8 variants x 6 N LRAD; TAP 2 x 6; eFADE 4 x 6", 48 + 12 + 24, 48)
add("NEXUS", "N3: 4 layer configs x 8 variants", 32, 32)
add("NEXUS", "Manhattan trace: 8 variants + in-scope baselines", 8 + 6, 8, "needs the OSM extract")
# ---------------- LSTM data collection (detection-only, training=1, final build)
add("LSTM", "collection: benign seeds 6,7,8 (train), 2,3 (validation), 1 (test); attacks A1-A8 x p in {20,40,60} on seeds 2,3 (validation) and 1 (test)", 6 + 8 * 3 * 3, 0, "train seeds 6-8, validate 2,3 (supervisor 2026-10-09)")
tot = {k: sum(r[k] for r in rows) for k in ("DO", "CL")}
by = {}
for r in rows: by.setdefault(r["block"], [0, 0]); by[r["block"]][0] += r["DO"]; by[r["block"]][1] += r["CL"]
trainings = dict(final_model=3, AB2_centralised=3, AB3_zeroed_column=3, AB5_poison_sweep="8 rho x 2 aggregators x 3 = 48")
if __name__ == "__main__":
    for r in rows: print(f"{r['block']:12s} DO {r['DO']:4d} CL {r['CL']:4d}  {r['what']}" + (f"   [{r['note']}]" if r['note'] else ""))
    print("\nper block (DO, CL, total):", {k: (v[0], v[1], v[0] + v[1]) for k, v in by.items()})
    print("TOTAL simulations: DO", tot["DO"], "CL", tot["CL"], "=", tot["DO"] + tot["CL"])
    print("offline LSTM trainings:", trainings, "= 57")
    per_run_min, par = 5.6, 12
    n = tot["DO"] + tot["CL"]
    for m in (1, 6):
        print(f"{m} machine(s) like this one (12 parallel, {per_run_min} min/run): {n * per_run_min / par / m / 60:.1f} h")
    json.dump(dict(rows=rows, per_block=by, total=tot, trainings=trainings), open("docs/run_count_2026-10-09.json", "w"), indent=1)
