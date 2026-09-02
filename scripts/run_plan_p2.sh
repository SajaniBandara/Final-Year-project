#!/usr/bin/env bash
# run_plan_p2.sh — HPC_PLAN_2026-09-01.md, Priority P2 (ablations).
#
#   AB7  quarantine (enable_quarantine 0/1) ....... attacks 1-8, pct 60
#   AB1  OBU vs RSU engine (AB1A/AB1B) ............ attacks 1-8, pct 60
#   AB4  STARK proofs (AB4A/B/C) ................... attacks 1,2,5,6,7,8, pct 60
#
# seed 1, simTime 180 s (HPC_PLAN "others 180s"). Both arms of each ablation
# are the config's own 0/1 pair. pct is per-ablation per main.tex (AB9 would be
# pct20 but AB9 is not in P2's "AB7 then AB1"). Output files are run_tag / config
# tagged, so canonical un-tagged CSVs are not overwritten; a snapshot of the
# collide-prone pct60 names is taken anyway.
set -uo pipefail
NS3="$HOME/ns3_g13/ns-allinone-3.35/ns-3.35"
REPO="$HOME/ns3_g13/g13_project_repo/Final-Year-project"
R="$NS3/results_routing"
export NS3_DIR="$NS3"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG="$REPO/logs/plan_p2_$STAMP.log"
SNAP="$R/p2_prerun_snapshot_$STAMP"
mkdir -p "$REPO/logs" "$SNAP"
exec > >(tee -a "$LOG") 2>&1

echo "==================== P2 ablations | $(date) ===================="
grep -q "BUILD_PROFILE = 'optimized'" "$NS3/build/c4che/_cache.py" && echo "build: optimized OK" || { echo ABORT bad profile; exit 1; }
grep -q -- "-O3" <(grep '^CXXFLAGS =' "$NS3/build/c4che/_cache.py") && echo "cxxflags: -O3 OK" || { echo ABORT no -O3; exit 1; }
[ -x "$NS3/build/scratch/routing/routing" ] || { echo ABORT no binary; exit 1; }
echo "load:$(cut -d' ' -f1-3 /proc/loadavg)  nproc=$(nproc)  pkgtemp=$(sensors 2>/dev/null | awk '/Package id 0/{print $4}')"

# snapshot collide-prone canonical names (pct 60 + pct 20, d80ms + plain)
cp -p "$R"/MOBIGUARD_Attack[1-8]_{20,60}{,_d80ms,_d100ms}_seed1.csv "$SNAP"/ 2>/dev/null
echo "snapshot: $(ls "$SNAP" | wc -l) canonical pct20/60 MOBIGUARD files -> $SNAP"

# thermal governor — HARD backstop (i9-14900K desktop CPU thermal-throttles
# hard: 8 concurrent sims hit 96C on 2026-09-02). SIGSTOP our routing procs
# at 80C, SIGCONT at 66C. Plus resource_watchdog for load/mem.
GOV_LOG="$REPO/logs/temp_governor_p2_$STAMP.log" GOV_HOT_C=93 GOV_COOL_C=85 GOV_POLL_SECS=3 \
  bash "$REPO/scripts/temp_governor.sh" &
GOV=$!
WATCHDOG_LOG="$REPO/logs/watchdog_p2_$STAMP.log" \
WATCHDOG_LOAD_FRACTION=0.80 WATCHDOG_MEM_SOFT_MB=6000 \
  bash "$REPO/scripts/resource_watchdog.sh" &
WD=$!
trap 'kill $GOV $WD 2>/dev/null; for p in $(pgrep -f "scratch/routing/routing"); do kill -CONT $p 2>/dev/null; done' EXIT
echo "temp_governor pid=$GOV (hot 90C / cool 78C, 3s poll)   watchdog pid=$WD"

# concurrency 12 (ablation_sweep2 self-caps at 10), nice-15, 125W RAPL cap active — see build_cmd in the launchers; ablation_sweep2
# already prepends nice/ionice, ablation_sweep does not, so wrap it.
echo; echo "-------- P2.1  AB7 (quarantine)  --------"
nice -n 15 python3 "$REPO/scripts/run_ablation_sweep2.py" --only ab7 --sim-time 180 --workers 4

echo; echo "-------- P2.2  AB1 + AB4 (engine modes + STARK)  --------"
nice -n 15 python3 "$REPO/scripts/run_ablation_sweep.py" --sim-time 180 --workers 4

echo; echo "-------- P2 result files --------"
ls -1 "$R"/MOBIGUARD_Attack*_seed1_AB7[AB].csv "$R"/MOBIGUARD_Attack*_seed1_AB1[AB].csv "$R"/MOBIGUARD_Attack*_seed1_AB4[ABC].csv 2>/dev/null | sed "s|$R/||" | sort
echo "count: $(ls "$R"/MOBIGUARD_Attack*_seed1_AB{7A,7B,1A,1B,4A,4B,4C}.csv 2>/dev/null | wc -l)"

echo; echo "-------- canonical tripwire (must be unchanged) --------"
CH=0
for f in "$SNAP"/*.csv; do b=$(basename "$f"); cmp -s "$f" "$R/$b" || { echo "  CHANGED: $b"; CH=1; }; done
[ $CH = 0 ] && echo "  OK — all $(ls "$SNAP"|wc -l) canonical files untouched"

echo; echo "==================== P2 DONE $(date) ===================="
echo "log: $LOG"
echo "NEXT: build P2 results doc, then P3 (fill 40%/80%) on your go."
