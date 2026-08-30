#!/usr/bin/env bash
# resource_watchdog.sh — protects a SHARED machine from our own ablation
# sweeps (and reports if something else on the box is already in trouble).
#
# This machine runs other people's workloads (e.g. a background LLM
# training job that is NOT ours — 2026-08-30 machine-safety review, ahead
# of starting the AB1/AB4 ns-3 ablation sweeps). This watchdog does NOT
# touch anyone else's processes — it only pauses/resumes OUR OWN `routing`
# (ns-3) processes when the whole machine looks under pressure, so our
# ablation runs never become the thing that tips a shared box into a
# freeze or OOM.
#
# GPU is NOT monitored here: nvidia-smi is currently broken on this machine
# (NVRM kernel module 595.71.05 vs NVML userspace library 595.84 mismatch)
# -- deliberately left alone rather than "fixed" mid-session, since that
# could disrupt someone else's GPU job if one is running. Our own sweeps
# are CPU/RAM-only (ns-3), so this gap doesn't affect what we're doing, but
# it does mean this watchdog cannot protect a concurrent GPU job.
#
# Behaviour:
#   - Polls every $POLL_SECS.
#   - PAUSE (SIGSTOP) our own `routing` processes when load-per-core or
#     memory pressure crosses the soft cap, for as long as the breach lasts.
#   - RESUME (SIGCONT) them once the machine recovers below the cap.
#   - HARD CAP: if available memory falls below $MEM_HARD_MB even with our
#     processes paused, that means something ELSE on the box is consuming
#     it -- log loudly and keep polling (do not touch other users'/other
#     processes' memory; there's nothing safe for us to do about a leak
#     that isn't ours).
#   - Everything is logged with timestamps to $LOG_FILE.
#
# Usage:
#   scripts/resource_watchdog.sh &            # background, logs to default path
#   WATCHDOG_LOG=/path/to.log scripts/resource_watchdog.sh &
#   kill %1                                    # stop it
#
# Exit: runs until killed (SIGTERM/SIGINT trapped for a clean log line).

set -u

POLL_SECS="${WATCHDOG_POLL_SECS:-15}"
# Soft cap: pause our runs once 1-min load average exceeds this fraction of
# nproc (leaves headroom for whatever else is on the box).
LOAD_FRACTION_CAP="${WATCHDOG_LOAD_FRACTION:-0.85}"
# Soft cap: pause our runs once available memory drops below this (MB).
MEM_SOFT_MB="${WATCHDOG_MEM_SOFT_MB:-8000}"
# Hard alarm: log loudly if available memory is this low even with our
# processes paused (means the pressure isn't coming from us).
MEM_HARD_MB="${WATCHDOG_MEM_HARD_MB:-3000}"
PROC_PATTERN="${WATCHDOG_PROC_PATTERN:-scratch/routing/routing}"
LOG_FILE="${WATCHDOG_LOG:-$(dirname "$0")/../logs/watchdog.log}"

mkdir -p "$(dirname "$LOG_FILE")"
NPROC=$(nproc)
LOAD_CAP=$(awk -v n="$NPROC" -v f="$LOAD_FRACTION_CAP" 'BEGIN{printf "%.2f", n*f}')

paused=0
log() { printf '%s  %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }

log "watchdog started: nproc=$NPROC load_cap=$LOAD_CAP mem_soft=${MEM_SOFT_MB}MB mem_hard=${MEM_HARD_MB}MB poll=${POLL_SECS}s pattern='$PROC_PATTERN'"
log "NOTE: GPU not monitored (nvidia-smi driver/library mismatch on this host)."

cleanup() { log "watchdog stopping (signal received)."; exit 0; }
trap cleanup TERM INT

our_pids() { pgrep -f -- "$PROC_PATTERN" 2>/dev/null; }

while true; do
    load1=$(awk '{print $1}' /proc/loadavg)
    mem_avail_mb=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo)

    over_load=$(awk -v l="$load1" -v c="$LOAD_CAP" 'BEGIN{print (l>c)?1:0}')
    over_mem=$(( mem_avail_mb < MEM_SOFT_MB ? 1 : 0 ))

    pids=$(our_pids)

    if { [ "$over_load" = "1" ] || [ "$over_mem" = "1" ]; } && [ -n "$pids" ]; then
        if [ "$paused" = "0" ]; then
            log "CAP BREACH load1=$load1 (cap $LOAD_CAP) mem_avail=${mem_avail_mb}MB (soft floor ${MEM_SOFT_MB}MB) -> PAUSING our routing processes: $pids"
            # shellcheck disable=SC2086
            kill -STOP $pids 2>/dev/null
            paused=1
        fi
        if [ "$mem_avail_mb" -lt "$MEM_HARD_MB" ]; then
            log "HARD ALARM: mem_avail=${mem_avail_mb}MB below hard floor ${MEM_HARD_MB}MB even while our processes are paused -- pressure is NOT from us. Not touching other processes; investigate manually if this persists."
        fi
    elif [ "$paused" = "1" ]; then
        log "recovered: load1=$load1 mem_avail=${mem_avail_mb}MB -> RESUMING: $pids"
        if [ -n "$pids" ]; then
            # shellcheck disable=SC2086
            kill -CONT $pids 2>/dev/null
        fi
        paused=0
    fi

    sleep "$POLL_SECS"
done
