#!/usr/bin/env python3
"""rerun_lib.py -- job specs, a resumable parallel runner and the end-of-paper reports shared by the four reruns (supervisor 2026-10-10).

A job is a dict: tag, paper, exp, cfg, arm, mode ('do' = detection only, 'cl' = closed loop), attack, pct, extra[flags], ablates_crypto.
Every run: seed 1, 181 s (cycles 45..179 = 135 scored cycles), crypto ON (except an arm that ablates it), --aux_logs=0, the frozen thresholds
(compiled in), the LSTM flags decided by the head/bar comparison (LSTM_FLAGS below). The commit tag of the binary is read from the build.
Resumable: a job whose events file reaches cycle 179, whose rc file is 0 and whose commit equals the expected one is skipped."""
import glob, json, os, shutil, subprocess, sys, time
from pathlib import Path
NS3 = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BIN, LIB, RES = NS3 / "build/scratch/routing/routing", str(NS3 / "build/lib"), NS3 / "results_routing"
REPO = Path(__file__).resolve().parent.parent
MOB = Path.home() / "ns3_g13/mobility"
sys.path.insert(0, str(Path(__file__).resolve().parent))

# LSTM configuration of the final runs: set by the head/bar decision (docs/LSTM_HEAD_VS_BAR_2026-10-10.md). "bar" = reconstruction bar only.
LSTM_FLAGS = ["--enable_lstm_inference=1", "--enable_lstm_cls=1"]
SIM, SEED = 181, 1

def cmd(j):
    c = ["nice", "-n10", str(BIN), f"--N_Vehicles={j.get('N', 200)}", "--N_RSUs=64", "--N_Controllers=4", "--mobility_scenario=0",
         f"--maxspeed={j.get('speed', 150)}", "--use_sumo_mobility=1", "--architecture=3", f"--simTime={SIM}",
         f"--attack_percentage={j['pct']}", f"--attack_delay_ms={j.get('delay', 100)}", f"--sim_seed={j.get('seed', SEED)}",
         f"--run_tag={j['tag']}", "--aux_logs=0"]
    if j["attack"] != 0: c.append(f"--attack_number={j['attack']}")
    if j.get("trace"): c.append(f"--mobility_trace_file={MOB / j['trace']}")
    if j["arm"] == "tap": c += ["--enable_tap=1", "--enable_lrad_obu=0", "--enable_lrad_rsu=0"]
    elif j["arm"] == "efade": c += ["--enable_lrad_obu=0", "--enable_lrad_rsu=0"]
    else: c += LSTM_FLAGS
    if j["mode"] == "cl": c.append("--enable_quarantine_enforcement=1")
    if j.get("ablates_crypto"): c.append("--disable_crypto=1")
    if j["attack"] in (1, 2) and j["arm"] != "tap": c.append("--dw_mark_suspect=1")
    return c + list(j.get("extra", []))

def complete(j, commit):
    try:
        if (RES / f"rc_{j['tag']}.txt").read_text().strip() != "0": return False
        ev = glob.glob(str(RES / f"events_Attack*_{j['tag']}.csv"))
        if not ev: return False
        last, c0 = 0, ""
        for l in open(ev[0]):
            if l.startswith("# commit="): c0 = l.strip().split("=", 1)[1]
            elif l[:1].isdigit(): last = max(last, int(l.split(",", 1)[0]))
        return last >= 179 and c0 == commit
    except OSError:
        return False

def run_jobs(jobs, commit, workers=12, logdir=None, min_free_gb=8):
    logdir = Path(logdir or REPO / "logs" / "rerun"); logdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = LIB + ":" + env.get("LD_LIBRARY_PATH", "")
    todo = [j for j in jobs if not complete(j, commit)]
    print(f"{len(jobs)} jobs, {len(jobs) - len(todo)} already complete, {len(todo)} to run", flush=True)
    running, queue = [], list(todo)
    while queue or running:
        still = []
        for p, j in running:
            if p.poll() is None: still.append((p, j))
            else: (RES / f"rc_{j['tag']}.txt").write_text(str(p.returncode))
        running = still
        while queue and len(running) < workers and os.getloadavg()[0] < 28 and shutil.disk_usage("/").free > min_free_gb * 1e9:
            j = queue.pop(0)
            for f in glob.glob(str(RES / f"*_{j['tag']}.*")): os.remove(f)           # run-tag rule: never append
            p = subprocess.Popen(cmd(j), stdout=open(logdir / (j["tag"] + ".log"), "w"), stderr=subprocess.STDOUT, env=env)
            running.append((p, j))
        time.sleep(5)
    print("ALL DONE", flush=True)

def save_manifest(jobs, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True); Path(path).write_text(json.dumps(jobs, indent=1))
