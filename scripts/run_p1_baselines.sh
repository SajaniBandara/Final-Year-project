#!/usr/bin/env bash
#
# run_p1_baselines.sh — HPC_PLAN_2026-09-01.md, Priority P1.
#
# Produces the three state-of-the-art baseline datasets:
#   graph 1  TAP  (Arsalan & Rehman FIT 2018)  — attacks 1,2   -> TAP_Attack{1,2}_<pct>_d100ms_seed1.csv
#   graph 2  FADE (eFADE)                       — attacks 5-8   -> FADE_Attack{5,6,7,8}_<pct>_seed1.csv
#   graph 3  SFTO-Guard                          — attacks 3,4   -> offline, NOT run here (see note below)
#
# Percentages {20,60,100}, seed 1, simTime 60 s (plan: "60 s is enough" for baselines).
#
# SAFETY: scripts/run_std_attacks.py and run_hf_attacks.py each run a *pair* per
# (attack,pct) — the isolated baseline run AND a normal MOBIGUARD run that writes
# MOBIGUARD_Attack<N>_<pct>[_d100ms]_seed1.csv, i.e. the SAME filenames as the
# canonical 180 s enforcement-arm data. At simTime=60 that would silently replace
# 180 s results with 60 s ones. This script therefore:
#   1. tars the whole current results_routing CSV set (the portable bundle the
#      plan references is missing on this host), and
#   2. after the sweep, restores every canonical MOBIGUARD_Attack*_seed1.csv from
#      that snapshot, so only the new TAP_*/FADE_* files remain as net change.
#
set -uo pipefail

NS3="$HOME/ns3_g13/ns-allinone-3.35/ns-3.35"
REPO="$HOME/ns3_g13/g13_project_repo/Final-Year-project"
RESULTS="$NS3/results_routing"
STAMP="$(date +%Y%m%d_%H%M%S)"
SNAPDIR="$RESULTS/p1_prerun_snapshot_$STAMP"
TARBALL="$RESULTS/results_routing_csv_snapshot_$STAMP.tar.gz"
LOG="$REPO/logs/p1_baselines_$STAMP.log"

SIMTIME=60
SEED=1
DELAY=100
PERCENTAGES=(20 60 100)
STD_WORKERS=6      # run_std: attacks{1,2} x 2 modes = 4 jobs/pct
HF_WORKERS=10      # run_hf : attacks{5..8} x 2 modes = 8 jobs/pct

mkdir -p "$SNAPDIR" "$REPO/logs"
exec > >(tee -a "$LOG") 2>&1

echo "=================================================================="
echo "P1 baselines  |  $(date)  |  simTime=${SIMTIME}s seed=${SEED} pct={${PERCENTAGES[*]}}"
echo "=================================================================="

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
echo "-- preflight --"
grep -q "BUILD_PROFILE = 'optimized'" "$NS3/build/c4che/_cache.py" \
  && echo "  build profile: optimized OK" \
  || { echo "  ABORT: build profile is not 'optimized'"; exit 1; }
[ -x "$NS3/build/scratch/routing/routing" ] \
  && echo "  binary: present OK" \
  || { echo "  ABORT: routing binary missing"; exit 1; }
echo "  load avg:$(cut -d' ' -f1-3 /proc/loadavg | sed 's/^/ /')   nproc=$(nproc)"
echo "  other routing sims running: $(pgrep -c -f 'scratch/routing/routing' || true)"

# ---------------------------------------------------------------------------
# 1. Snapshot every results_routing CSV (insurance) + copy canonical MOBIGUARD
# ---------------------------------------------------------------------------
echo "-- snapshot --"
# Insurance tarball of the metric CSVs (MOBIGUARD/TAP/FADE/SWEEP), not the
# thousands of bc_*/tcam_* per-op logs. Robust against a long file list.
( cd "$RESULTS" && find . -maxdepth 1 -type f \
    \( -name 'MOBIGUARD_*.csv' -o -name 'TAP_*.csv' -o -name 'FADE_*.csv' -o -name 'SWEEP*.csv' \) \
    -print0 | tar czf "$TARBALL" --null -T - ) 2>/dev/null
echo "  tarball: $TARBALL ($(du -h "$TARBALL" 2>/dev/null | cut -f1))"
cp -p "$RESULTS"/MOBIGUARD_Attack[0-9]*_seed1.csv "$SNAPDIR"/ 2>/dev/null
echo "  canonical MOBIGUARD_*_seed1.csv copied: $(ls "$SNAPDIR" | wc -l) files"

restore_canonical() {
  echo "-- restoring canonical MOBIGUARD_*_seed1.csv from snapshot --"
  cp -p "$SNAPDIR"/MOBIGUARD_Attack*_seed1.csv "$RESULTS"/ 2>/dev/null
  echo "  restored $(ls "$SNAPDIR" | wc -l) files"
}
trap restore_canonical EXIT

# ---------------------------------------------------------------------------
# 2. Build once (sweeps use --run-no-build; concurrent implicit builds race)
# ---------------------------------------------------------------------------
echo "-- build --"
( cd "$NS3" && ./waf build ) 2>&1 | tail -n 3
[ -x "$NS3/build/scratch/routing/routing" ] || { echo "ABORT: build failed"; exit 1; }

# ---------------------------------------------------------------------------
# 3. P1 graph 1 — TAP baseline (attacks 1, 2)
# ---------------------------------------------------------------------------
echo "-- P1 graph 1: TAP (attacks 1,2) --"
for P in "${PERCENTAGES[@]}"; do
  echo "  >>> TAP pct=$P"
  python3 "$REPO/scripts/run_std_attacks.py" \
    --percentage "$P" --delay "$DELAY" \
    --sim-time "$SIMTIME" --seed "$SEED" --workers "$STD_WORKERS"
done

# ---------------------------------------------------------------------------
# 4. P1 graph 2 — FADE baseline (attacks 5-8)
# ---------------------------------------------------------------------------
echo "-- P1 graph 2: FADE (attacks 5-8) --"
for P in "${PERCENTAGES[@]}"; do
  echo "  >>> FADE pct=$P"
  python3 "$REPO/scripts/run_hf_attacks.py" \
    --percentage "$P" \
    --sim-time "$SIMTIME" --seed "$SEED" --workers "$HF_WORKERS"
done

# ---------------------------------------------------------------------------
# 5. Report
# ---------------------------------------------------------------------------
echo "-- new baseline CSVs --"
for P in "${PERCENTAGES[@]}"; do
  for A in 1 2; do ls -la "$RESULTS/TAP_Attack${A}_${P}_d100ms_seed${SEED}.csv" 2>/dev/null || echo "  MISSING TAP_Attack${A}_${P}_d100ms_seed${SEED}.csv"; done
  for A in 5 6 7 8; do ls -la "$RESULTS/FADE_Attack${A}_${P}_seed${SEED}.csv" 2>/dev/null || echo "  MISSING FADE_Attack${A}_${P}_seed${SEED}.csv"; done
done

echo
echo "P1 graph 3 (SFTO-Guard, attacks 3/4) is OFFLINE — no simulation."
echo "  Run separately:  python3 $REPO/sfto_pipeline/...  against tcam_snapshots_Attack{3,4}_*_seed1_*_final.csv"
echo
echo "DONE  $(date).  Full log: $LOG"
echo "Pre-run snapshot tarball kept at: $TARBALL"
