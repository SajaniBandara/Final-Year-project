#!/usr/bin/env bash
# rerun_a2_tap.sh — re-run ONLY the 3 required Attack-2 TAP baseline points
# after the s2_latch_ground_truth() fix.
#
# TAP-only, direct binary invocation — NOT run_std_attacks.py (which also runs a
# paired MOBIGUARD sim). With --enable_tap=1 the MOBIGUARD CSV is suppressed
# (routing.cc), so no canonical *_d100ms_seed1.csv is touched and no
# snapshot/restore is needed. md5 of the 3 canonical MOBIGUARD A2 files is
# checked before/after as a tripwire only.
set -uo pipefail
NS3="$HOME/ns3_g13/ns-allinone-3.35/ns-3.35"
REPO="$HOME/ns3_g13/g13_project_repo/Final-Year-project"
R="$NS3/results_routing"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG="$REPO/logs/rerun_a2_tap_$STAMP.log"
mkdir -p "$REPO/logs"
exec > >(tee -a "$LOG") 2>&1

FIXED="--routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --architecture=3"
TAPFLAGS="--enable_tap=1 --enable_lrad_obu=0 --enable_lrad_rsu=0"

echo "=== A2 TAP-only re-run | $(date) ==="
before=$(md5sum "$R"/MOBIGUARD_Attack2_{20,60,100}_d100ms_seed1.csv)

run_one() {
  local P="$1"
  local lg="$REPO/logs/A2_TAP_pct${P}_$STAMP.log"
  echo ">>> pct=$P  -> $lg"
  ( cd "$NS3" && ./waf --run-no-build \
      "scratch/routing/routing $FIXED --simTime=60 --attack_number=2 --attack_percentage=$P --sim_seed=1 --sim_run=1 --attack_delay_ms=100 --attack_delay_pseudo_random=1 $TAPFLAGS" ) \
      > "$lg" 2>&1
  echo "<<< pct=$P exit=$? ($(date +%H:%M:%S))"
}

for P in 20 60 100; do run_one "$P" & done
wait

echo
echo "=== canonical MOBIGUARD A2 tripwire (must be UNCHANGED) ==="
after=$(md5sum "$R"/MOBIGUARD_Attack2_{20,60,100}_d100ms_seed1.csv)
if [ "$before" = "$after" ]; then echo "  OK — canonical MOBIGUARD A2 untouched"; else
  echo "  !! CHANGED:"; diff <(echo "$before") <(echo "$after"); fi

echo
echo "=== post-fix A2 TAP results ==="
for P in 20 60 100; do
  f="$R/TAP_Attack2_${P}_d100ms_seed1.csv"
  if [ -f "$f" ]; then
    printf "  pct%-3s rows=%-4s : " "$P" "$(grep -vc '^#' "$f")"
    grep -v '^#' "$f" | awk -F',' '{gsub(/ /,"");T+=$14;F+=$15;N+=$16;n+=$17;dr=$8;mcc=$6}
      END{print "ΣTP="T"  ΣFP="F"  ΣTN="N"  ΣFN="n"   last cur_DR="dr"%  cur_MCC="mcc}'
  else echo "  pct$P : TAP_Attack2_${P}_d100ms_seed1.csv MISSING"; fi
done
echo "DONE $(date).  log: $LOG"
