#!/bin/bash
# Replaces q_chain.sh from the middle of seed 5 (decision 2026-09-11 ~13:20: one seed,
# 300 s; seeds 6 and 7 cancelled). q_chain.sh was stopped with SIGTERM while its seed-5
# runner (pid 1219093: Q1,Q2,Q4,Q5,Q4R) was left running. This waits for that runner,
# runs seed 5's Q3,Q6 exactly as q_chain.sh would have, and touches Q_DONE so
# end_watcher.sh runs the collector.
set -u
P=/home/sdvn_hidden_attacks/ns3_g13/g13_project_repo/Final-Year-project
R=/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing
O=/tmp/claude-1001/-home-sdvn-hidden-attacks-ns3-g13-g13-project-repo-Final-Year-project/725a44bf-987f-4a71-837a-5932c950e25b/scratchpad/orch
G=$O/gates
RUNNER=1219093
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*"; }

log "q_chain.sh stopped; seed 5 only (300 s), seeds 6 and 7 cancelled. Waiting for seed-5 runner pid $RUNNER"
while kill -0 "$RUNNER" 2>/dev/null; do sleep 30; done
n=$(ls "$R"/detector_windows_Attack[1-8]_60*_seed5_Q4R.csv 2>/dev/null | wc -l)
log "END   Q1,Q2,Q4,Q5,Q4R seed 5 (runner exited; Q4R detector_windows $n/8)"

while [ ! -f "$G/D_PASS" ] && [ ! -f "$G/D_FAIL" ] && [ ! -f "$G/C_FAIL" ] && [ ! -f "$G/A_FAIL" ]; do sleep 120; done
if [ -f "$G/D_PASS" ]; then
  log "START Q3,Q6 seed 5"
  ( cd "$P" && python3 scripts/run_q1q6_ablation.py --configs Q3,Q6 --seed 5 --workers 12 ) > "$O/q_Q3_Q6_s5.log" 2>&1
  log "END   Q3,Q6 seed 5 rc=$?"
else
  log "SKIP Q3,Q6 seed 5: LSTM gates did not pass"
fi
touch "$G/Q_DONE"
log "Q CHAIN COMPLETE (seed 5 only)"
