#!/bin/bash
# Final Q1-Q6 table: 7 configs x 8 variants x seeds 5,6,7 = 168 runs, 300 s.
# Per seed: the 5 non-LSTM configs first, then Q3/Q6 once the LSTM gates pass,
# so a complete single-seed table exists as early as possible.
set -u
P=/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project
O=/tmp/claude-1001/-home-sdvn-hidden-attacks-ns3-g13-g13-project-repo-Final-Year-project/725a44bf-987f-4a71-837a-5932c950e25b/scratchpad/orch
G=$O/gates
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*"; }
mkdir -p "$P/logs/q1q6_ablation"

run(){ local cfg=$1 seed=$2 tag=${1//,/_}
  log "START $cfg seed $seed"
  ( cd "$P" && python3 scripts/run_q1q6_ablation.py --configs "$cfg" --seed "$seed" --workers 12 ) > "$O/q_${tag}_s${seed}.log" 2>&1
  log "END   $cfg seed $seed rc=$?"; }

for s in 5 6 7; do
  run Q1,Q2,Q4,Q5,Q4R "$s"
  while [ ! -f "$G/D_PASS" ] && [ ! -f "$G/D_FAIL" ] && [ ! -f "$G/C_FAIL" ] && [ ! -f "$G/A_FAIL" ]; do sleep 120; done
  if [ -f "$G/D_PASS" ]; then
    run Q3,Q6 "$s"
  else
    log "SKIP Q3,Q6 seed $s: LSTM gates did not pass"
  fi
done
touch "$G/Q_DONE"
log "Q CHAIN COMPLETE"
