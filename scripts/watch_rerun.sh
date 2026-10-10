#!/bin/bash
# Prints one line when something needs attention: a non-zero rc, free disk < 20 GB, the launcher exiting, or every 100 completed jobs.
R=~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing; last=0
while true; do
  n=$(ls $R/rc_ph_*.txt 2>/dev/null | wc -l)
  bad=$(grep -L '^0$' $R/rc_ph_*.txt 2>/dev/null | head -3 | tr '\n' ' ')
  free=$(df --output=avail -BG / | tail -1 | tr -dc 0-9)
  if [ -n "$bad" ]; then echo "ALERT non-zero rc: $bad (done $n/486)"; exit 0; fi
  if [ "$free" -lt 20 ]; then echo "ALERT disk free ${free}G (done $n/486)"; exit 0; fi
  if ! pgrep -f "rerun_phantom.py --run" >/dev/null; then echo "launcher exited: done $n/486"; exit 0; fi
  if [ $((n/100)) -gt $((last/100)) ]; then echo "progress: $n/486 done, load $(cut -d' ' -f1 /proc/loadavg)"; exit 0; fi
  last=$n; sleep 60
done
