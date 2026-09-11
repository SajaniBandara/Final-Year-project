#!/bin/bash
# Waits for the Q chain to finish, then runs the results collector.
# Separate process on purpose: the running orchestrate.sh / q_chain.sh are never edited.
O=/tmp/claude-1001/-home-sdvn-hidden-attacks-ns3-g13-g13-project-repo-Final-Year-project/725a44bf-987f-4a71-837a-5932c950e25b/scratchpad/orch
G=$O/gates
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*"; }
log "end watcher waiting for Q_DONE"
while [ ! -f "$G/Q_DONE" ]; do
  if [ -f "$G/A_FAIL" ]; then log "A_FAIL: retrain aborted, Q chain never started; collector not run"; touch "$G/COLLECT_SKIPPED"; exit 0; fi
  sleep 300
done
log "Q_DONE seen; running collector"
if python3 "$O/collect_results.py" > "$O/collect.log" 2>&1; then
  touch "$G/COLLECT_DONE"; log "COLLECT_DONE -> $O/FINAL_RESULTS.txt"
else
  touch "$G/COLLECT_FAIL"; log "COLLECT_FAIL: see $O/collect.log"
fi
