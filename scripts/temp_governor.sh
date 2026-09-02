#!/usr/bin/env bash
# temp_governor.sh — thermal protection for OUR ns-3 `routing` runs on a box
# that thermal-throttles hard. resource_watchdog.sh only watches load/mem; this
# watches CPU package temperature (x86_pkg_temp) and pauses/resumes our own
# routing processes to keep the die away from crit.
#
# Measured 2026-09-02: 17 concurrent `routing` procs drove Package id 0 from
# 46 C to 96 C in ~2 min (crit = 100 C). ns-3 + liboqs is AVX-heavy and
# CXXFLAGS carries -march=native, so power/heat per core is high.
#
#   PAUSE  (SIGSTOP our routing procs) when pkg temp >= HOT_C
#   RESUME (SIGCONT) once pkg temp <= COOL_C
#   logs every transition + a heartbeat line
#
# Env overrides: GOV_HOT_C (default 82) GOV_COOL_C (default 68)
#                GOV_POLL_SECS (5) GOV_LOG
set -u
HOT_C="${GOV_HOT_C:-82}"
COOL_C="${GOV_COOL_C:-68}"
POLL="${GOV_POLL_SECS:-5}"
PAT="scratch/routing/routing"
LOG="${GOV_LOG:-$(dirname "$0")/../logs/temp_governor.log}"
mkdir -p "$(dirname "$LOG")"

zone=""
for z in /sys/class/thermal/thermal_zone*/; do
  [ "$(cat "$z/type" 2>/dev/null)" = "x86_pkg_temp" ] && zone="$z/temp" && break
done
pkg_c() {
  if [ -n "$zone" ] && [ -r "$zone" ]; then awk '{printf "%d", $1/1000}' "$zone"
  else sensors 2>/dev/null | awk -F'[+.]' '/Package id 0/{print $2; exit}'; fi
}
log() { printf '%s  %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
pids() { pgrep -f -- "$PAT" 2>/dev/null; }

log "temp_governor start: hot=${HOT_C}C cool=${COOL_C}C poll=${POLL}s zone=${zone:-sensors}"
trap 'for p in $(pids); do kill -CONT $p 2>/dev/null; done; log "governor stop (resumed all)"; exit 0' TERM INT

paused=0; beat=0
while true; do
  t=$(pkg_c); t=${t:-0}
  if [ "$paused" -eq 0 ] && [ "$t" -ge "$HOT_C" ]; then
    n=0; for p in $(pids); do kill -STOP $p 2>/dev/null && n=$((n+1)); done
    paused=1; log "PAUSE  pkg=${t}C >= ${HOT_C}C  (stopped $n routing procs)"
  elif [ "$paused" -eq 1 ] && [ "$t" -le "$COOL_C" ]; then
    n=0; for p in $(pids); do kill -CONT $p 2>/dev/null && n=$((n+1)); done
    paused=0; log "RESUME pkg=${t}C <= ${COOL_C}C  (resumed $n routing procs)"
  fi
  beat=$((beat+1))
  [ $((beat % 12)) -eq 0 ] && log "heartbeat pkg=${t}C paused=${paused} procs=$(pids | wc -l)"
  sleep "$POLL"
done
