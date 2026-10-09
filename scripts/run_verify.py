#!/usr/bin/env python3
"""run_verify.py -- verification of the frozen build (supervisor 2026-10-09, night 2): the 22 gate-2 runs on seed 2 plus a benign closed loop
on seeds 2 and 3, simTime 181 (cycles 45..179 = exactly 135 scored cycles), --aux_logs=0, exit code recorded per run.
Afterwards run:  python3 scripts/run_verify.py --assert <frozen commit>   (writes docs/assert/verify.md; any FAIL stops that experiment)."""
import argparse, glob, json, os, re, shutil, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_gate as rg

SEEDS_EXTRA, SIM = (2, 3), 181
MAN = Path(__file__).resolve().parent.parent / "docs" / "assert" / "verify_manifest.json"

def jobs():
    J = []
    for j in rg.jobs():
        j = dict(j); j["tag"] = j["tag"].replace("gate2_", "ver_"); j["seed"] = 2; J.append(j)
    for s in SEEDS_EXTRA:
        J.append(dict(tag=f"ver_benign_cl_s{s}", attack=0, pct=0, seed=s, extra=["--enable_quarantine_enforcement=1"]))
    return J

def cmd(j):
    c = rg.cmd(dict(j)); c = [x for x in c if not x.startswith("--simTime=") and not x.startswith("--sim_seed=")]
    return c + [f"--simTime={SIM}", f"--sim_seed={j['seed']}", "--aux_logs=0"]

def manifest(J):
    M = []
    for j in J:
        t = j["tag"][len("ver_"):]
        mode = "cl" if t.endswith("_enfon") or t.startswith("benign_cl") else "do"
        m = re.match(r"(full|ab\d+)(?:abl)?_A(\d)", t)
        if t.startswith("anchor_tap"): arm, cfg = "tap", "benign"
        elif t.startswith("anchor_sfto"): arm, cfg = "sfto", "benign"
        elif t.startswith("anchor_lrad"): arm, cfg = "full", "benign"
        elif t.startswith("benign_cl"): arm, cfg = "full", "benign_cl_" + t[-2:]
        else: arm, cfg = m.group(1), "A" + m.group(2)
        M.append(dict(tag=j["tag"], exp="verify", cfg=cfg, arm=arm, mode=mode, attack=j["attack"], pct=j["pct"]))
    return M

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--dry-run", action="store_true"); ap.add_argument("--assert", dest="commit", default=None)
    a = ap.parse_args(); J = jobs()
    MAN.parent.mkdir(parents=True, exist_ok=True); MAN.write_text(json.dumps(manifest(J), indent=1))
    if a.commit:
        import event_scorer as es, batch_assertions as ba
        out, runs = ba.check_batch(json.loads(MAN.read_text()), a.commit, frozen=dict(u_thresh="0.37", t_min="0.3", s1_suppress="1"))
        st = ba.write_report(out); fails = [r for r in out["verify"] if r[1] == "FAIL"]
        print("verify:", st["verify"], "checks", len(out["verify"]), "FAIL", len(fails))
        for r in fails[:25]: print(r)
        return 1 if fails else 0
    if a.dry_run: print(len(J), "jobs"); [print(" ".join(cmd(j)[3:])) for j in J[:2]]; return 0
    rg.LOGS.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = rg.LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    running, queue = [], list(J); print(len(J), "jobs", flush=True)
    while queue or running:
        still = []
        for p, j in running:
            if p.poll() is None: still.append((p, j))
            else: (rg.RES / f"rc_{j['tag']}.txt").write_text(str(p.returncode))
        running = still
        while queue and len(running) < 12 and os.getloadavg()[0] < 28 and shutil.disk_usage("/").free > 15e9:
            j = queue.pop(0)
            for f in glob.glob(str(rg.RES / f"*_{j['tag']}.*")): os.remove(f)
            p = subprocess.Popen(cmd(j), stdout=open(rg.LOGS / (j["tag"] + ".log"), "w"), stderr=subprocess.STDOUT, env=env)
            running.append((p, j)); print("started", j["tag"], flush=True)
        time.sleep(5)
    print("ALL DONE", flush=True)
if __name__ == "__main__": raise SystemExit(main())
