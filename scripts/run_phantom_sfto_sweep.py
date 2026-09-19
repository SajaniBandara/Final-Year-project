#!/usr/bin/env python3
"""
run_phantom_sfto_sweep.py — score the SFTO-Guard baseline across PHANTOM's Exp 1
(penetration) and Exp 3 (scale) points, on the S3/S4 tcam_snapshots those sweeps
already produced (no new ns-3 sims). For each point/variant, runs
sfto_pipeline/src/run_pipeline.py (--skip_shap) against a benign baseline matched
to the config, and collects MCC. Writes docs/phantom_exp23/sfto_sweep.csv.

Benign baselines:
  Exp 1 (all N=200): the single benign snapshot (penetration does not change
    benign traffic).
  Exp 3: benign per N (sfto_benign_nv{100,150}, and the N=200 default benign).
"""
import csv, glob, os, subprocess, sys, time
from pathlib import Path

NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
RES = NS3 / "results_routing"
REPO = Path(__file__).resolve().parent.parent
PIPE = REPO / "sfto_pipeline/src/run_pipeline.py"
OUTD = REPO / "docs/phantom_exp23"
SFTO_RUNS = REPO / "sfto_pipeline/results"

BENIGN_200 = RES / "tcam_snapshots_Attack0_0_seed1_exp5_benign.csv"


def find_attack(atk, tag):
    """Attack snapshot for a given attack number + run_tag (variable suffix,
    non-final)."""
    cands = [f for f in glob.glob(str(RES / f"tcam_snapshots_Attack{atk}_*_seed1_{tag}*.csv"))
             if "final" not in f]
    return cands[0] if cands else None


def run_sfto(baseline, attack, outtag):
    if not (baseline and Path(baseline).is_file()) or not (attack and Path(attack).is_file()):
        return None
    outdir = SFTO_RUNS / f"phantom_{outtag}"
    bt = outdir / "benchmark_table.csv"

    def parse():
        if not bt.is_file():
            return None
        try:
            row = list(csv.DictReader(open(bt)))[0]
            return float(row.get("MCC (M1)", row.get("MCC", "")))
        except (ValueError, IndexError, KeyError):
            return None

    resumed = parse()          # resume: keep an already-good result
    if resumed is not None:
        return resumed

    # PYTHONDONTWRITEBYTECODE + single-thread breaks the intermittent numpy/re
    # import corruption seen when the pipeline's heavy imports race on pyc/threads.
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["OMP_NUM_THREADS"] = "1"; env["OPENBLAS_NUM_THREADS"] = "1"; env["MKL_NUM_THREADS"] = "1"
    for attempt in (1, 2, 3, 4):
        if bt.is_file():
            bt.unlink()
        try:
            p = subprocess.run([sys.executable, str(PIPE), "--baseline", str(baseline),
                                "--attack", str(attack), "--attack_start_time", "10",
                                "--output", str(outdir) + "/", "--skip_shap"],
                               capture_output=True, text=True, timeout=600,
                               cwd=str(PIPE.parent), env=env)
        except (subprocess.TimeoutExpired, OSError):
            time.sleep(3); continue
        got = parse()
        if got is not None:
            return got
        time.sleep(3)
        # failed: stash the tail of stderr for diagnosis on the last attempt
        if attempt == 4:
            (outdir.parent / f"phantom_{outtag}.err").parent.mkdir(parents=True, exist_ok=True)
            with open(SFTO_RUNS / f"phantom_{outtag}.err", "w") as e:
                e.write((p.stderr or "")[-2000:] + "\n----STDOUT----\n" + (p.stdout or "")[-1000:])
    return None


def main():
    OUTD.mkdir(parents=True, exist_ok=True)
    rows = []
    # Exp 1 — penetration, N=200, shared benign
    for p in [20, 40, 60, 80, 100]:
        for atk, var in ((3, "S3"), (4, "S4")):
            atkf = find_attack(atk, f"exp1_p{p}")
            mcc = run_sfto(BENIGN_200, atkf, f"exp1_p{p}_A{atk}")
            rows.append(dict(exp=1, point=p, variant=var, SFTO_MCC=mcc))
            print(f"  Exp1 p={p} {var}: MCC={mcc}", flush=True)
    # Exp 3 — scale, benign per N
    benign = {100: RES / "tcam_snapshots_Attack0_0_seed1_sfto_benign_nv100.csv",
              150: RES / "tcam_snapshots_Attack0_0_seed1_sfto_benign_nv150.csv",
              200: BENIGN_200}
    for nv in [100, 150, 200]:
        for atk, var in ((3, "S3"), (4, "S4")):
            atkf = find_attack(atk, f"exp3_nv{nv}")
            mcc = run_sfto(benign[nv], atkf, f"exp3_nv{nv}_A{atk}")
            rows.append(dict(exp=3, point=nv, variant=var, SFTO_MCC=mcc))
            print(f"  Exp3 nv={nv} {var}: MCC={mcc}", flush=True)

    with open(OUTD / "sfto_sweep.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["exp", "point", "variant", "SFTO_MCC"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print("wrote docs/phantom_exp23/sfto_sweep.csv")


if __name__ == "__main__":
    main()
