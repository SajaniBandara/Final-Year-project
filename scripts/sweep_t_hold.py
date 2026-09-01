#!/usr/bin/env python3
"""
sweep_t_hold.py — calibrate T_hold (eq:local_quarantine) from measurement.

WHY
---
main.tex defines T_hold only symbolically (symbol table main.tex:1274,
eq:local_quarantine at 2371/2377) and never gives it a number. The simulator's
0.1 s is a provisional default, so any result using HOLD_FORWARD currently rests
on an unjustified constant. This sweep replaces the guess with a measurement.

CRITERION (see crypto_layer.h's T_HOLD declaration)
---------------------------------------------------
The mechanism bounds T_hold from both sides:

  lower — the hold must outlast the RSU.Confirm round trip, or a real attacker
          resumes forwarding before confirmation arrives and mitigation leaks.
          escalate_to_rsu() schedules RSU processing 1 ms out (lrad.h:746) and
          that handler calls rsu_confirm_release() (lrad.h:687), so the floor is
          ~1 ms plus jitter.

  upper — T_hold is the latency penalty paid by any vehicle held in ERROR. A
          false D_OBU costs that vehicle exactly T_hold of deferred forwarding,
          so oversizing degrades delivery in proportion to the OBU FP rate.

  => choose the SMALLEST T_hold at which releases are dominated by RSU.Confirm
     rather than timeout expiry.

The counters that decide this already exist (g_fwd_release_confirm /
g_fwd_release_timeout, crypto_layer.h) and are printed per run as:

  [SECURITY] HOLD-FORWARD: holds=N suspended_pkts=N mean_hold_ms=X
             released_confirm=N released_timeout=N T_hold=Xs

USAGE
  python3 scripts/sweep_t_hold.py                      # default grid
  python3 scripts/sweep_t_hold.py --attack 5 --pct 60 --sim-time 90
  python3 scripts/sweep_t_hold.py --values 0.002,0.01,0.1

NOTE: every run here sets --enable_local_quarantine=1, which by design changes
delivery and latency metrics. These runs are for calibration only -- do not mix
their CSVs into a results set collected with the mechanism off.
"""

import argparse
import concurrent.futures as cf
import re
import subprocess
import sys
from pathlib import Path

NS3_DIR = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35"
BINARY = NS3_DIR / "build/scratch/routing/routing"

LINE_RE = re.compile(
    r"HOLD-FORWARD:\s+holds=(\d+)\s+suspended_pkts=(\d+)\s+"
    r"mean_hold_ms=([\d.eE+-]+)\s+released_confirm=(\d+)\s+"
    r"released_timeout=(\d+)\s+T_hold=([\d.eE+-]+)s")

DEFAULT_VALUES = [0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]


def run_one(t_hold: float, a) -> dict:
    params = {
        "N_Vehicles": 200, "N_RSUs": 64, "N_Controllers": 4,
        "mobility_scenario": 0, "maxspeed": 150, "use_sumo_mobility": 1,
        "architecture": 3, "simTime": a.sim_time,
        "attack_number": a.attack, "attack_percentage": a.pct,
        "sim_seed": a.seed,
        "enable_local_quarantine": 1,
        "T_hold": t_hold,
        "run_tag": f"THOLD{t_hold:g}",
    }
    arg = " ".join(f"--{k}={v}" for k, v in params.items())
    cmd = ["./waf", "--run-no-build", f"scratch/routing/routing {arg}"]
    p = subprocess.run(cmd, cwd=str(NS3_DIR), capture_output=True, text=True)
    m = None
    for line in p.stdout.splitlines():
        mm = LINE_RE.search(line)
        if mm:
            m = mm
    if not m:
        return {"T_hold": t_hold, "ok": False,
                "err": "no HOLD-FORWARD line (mechanism off, or run failed)"}
    holds, susp, mean_ms, conf, tmo, _ = m.groups()
    conf, tmo = int(conf), int(tmo)
    tot = conf + tmo
    return {"T_hold": t_hold, "ok": True, "holds": int(holds),
            "suspended_pkts": int(susp), "mean_hold_ms": float(mean_ms),
            "confirm": conf, "timeout": tmo,
            "timeout_frac": (tmo / tot) if tot else float("nan")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--values", default="",
                    help="comma-separated T_hold values (s); default a log-ish grid")
    ap.add_argument("--attack", type=int, default=1,
                    help="attack variant; 1/2 exercise the OBU S1/S2 path that "
                         "raises D_OBU, which is what HOLD_FORWARD keys on")
    ap.add_argument("--pct", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--sim-time", type=int, default=90)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()

    if not BINARY.exists():
        print(f"ERROR: no binary at {BINARY}. Build first.", file=sys.stderr)
        return 1

    values = ([float(x) for x in a.values.split(",")] if a.values
              else DEFAULT_VALUES)
    print(f"T_hold sweep: {values}")
    print(f"  attack={a.attack} pct={a.pct} seed={a.seed} simTime={a.sim_time}")
    print("  (all runs force --enable_local_quarantine=1)\n")

    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        rows = list(ex.map(lambda t: run_one(t, a), values))
    rows.sort(key=lambda r: r["T_hold"])

    print(f"{'T_hold(s)':>10}{'holds':>8}{'susp_pkts':>11}{'mean_hold_ms':>14}"
          f"{'confirm':>9}{'timeout':>9}{'timeout%':>10}")
    for r in rows:
        if not r["ok"]:
            print(f"{r['T_hold']:>10g}  FAILED: {r['err']}")
            continue
        print(f"{r['T_hold']:>10g}{r['holds']:>8}{r['suspended_pkts']:>11}"
              f"{r['mean_hold_ms']:>14.3f}{r['confirm']:>9}{r['timeout']:>9}"
              f"{100 * r['timeout_frac']:>9.1f}%")

    ok = [r for r in rows if r["ok"] and (r["confirm"] + r["timeout"]) > 0]
    if not ok:
        print("\nNo run produced any hold release. Either D_OBU never fired "
              "(try --attack 1 or 2, which drive the OBU S1/S2 path) or the "
              "mechanism did not engage.")
        return 1
    clean = [r for r in ok if r["timeout"] == 0]
    dirty = [r for r in ok if r["timeout"] > 0]
    print()

    # The naive rule "smallest value with zero timeouts" is DEGENERATE when the
    # whole grid is clean: it just returns min(grid), so widening the grid
    # downward moves the "recommendation" with it. That is grid choice, not
    # calibration. A real floor requires observing where timeouts START.
    if clean and not dirty:
        lo = min(clean, key=lambda r: r["T_hold"])
        print(f"INCONCLUSIVE: every swept value gave ZERO timeout releases, "
              f"down to T_hold={lo['T_hold']:g} s.")
        print("  The confirm path always wins across this grid, so the grid does "
              "not contain the floor and 'smallest clean value' would just be "
              "min(grid) -- an artefact of what was swept, not a calibration.")
        print("  Re-run with values BELOW the RSU.Confirm RTT (~1 ms, "
              "lrad.h:746) to find where timeouts begin, then apply a safety "
              "margin to that floor.")
        return 2

    if dirty and clean:
        floor = max(dirty, key=lambda r: r["T_hold"])   # largest value that still failed
        safe = min((r for r in clean if r["T_hold"] > floor["T_hold"]),
                   key=lambda r: r["T_hold"], default=None)
        print(f"FLOOR MEASURED: timeouts persist up to T_hold="
              f"{floor['T_hold']:g} s ({100*floor['timeout_frac']:.1f}% of "
              f"releases) and vanish at {safe['T_hold']:g} s."
              if safe else
              f"FLOOR MEASURED: timeouts persist up to {floor['T_hold']:g} s.")
        if safe:
            for k in (10, 5, 2):
                cand = [r for r in clean if r["T_hold"] >= k * floor["T_hold"]]
                if cand:
                    rec = min(cand, key=lambda r: r["T_hold"])
                    print(f"\nRECOMMENDATION: T_hold = {rec['T_hold']:g} s "
                          f"-- {k}x the measured floor ({floor['T_hold']:g} s), "
                          f"costing {rec['mean_hold_ms']:.2f} ms mean hold on "
                          f"{rec['suspended_pkts']} suspended packets.")
                    print("  Margin matters because containment fails SILENTLY "
                          "below the floor: a timeout release lets a real "
                          "attacker resume forwarding.")
                    break
        return 0

    best = min(ok, key=lambda r: r["timeout_frac"])
    print(f"NO value eliminated timeout releases. Lowest timeout fraction: "
          f"T_hold={best['T_hold']:g} s at {100*best['timeout_frac']:.1f}%.")
    print("  Extend the grid UPWARD before concluding.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
