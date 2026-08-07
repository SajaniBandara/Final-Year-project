#!/usr/bin/env bash
# local_path_swap.sh — LOCAL ONLY, NEVER COMMIT THE RESULT.
#
# The repo intentionally stores HPC cluster paths (/home/sdvn_hidden_attacks/ns3_g13/...)
# because the tree is shared with the cluster. This machine uses /home/nipuni/...
# instead, so scratch/routing.cc must be rewritten before a local run and rewritten
# back before committing.
#
# As of 2026-08-03 that is the ONLY difference between the working tree's
# routing.cc and the committed version -- all 509 differing lines are pure path
# swaps, zero genuine code changes. So the safe workflow is:
#
#     ./scripts/local_path_swap.sh local     # before running locally
#     ./scripts/local_path_swap.sh hpc       # before git add / commit
#     ./scripts/local_path_swap.sh status    # show which mode the tree is in
#
# Note: mobility traces are the one case where the local machine does not simply
# mirror the HPC layout -- the per-seed SUMO traces live in the repo itself at
# sumo_sim/seed{1..5}/mobility_urban_150_seed{N}.tcl, not in a flat mobility/ dir.
# 'local' mode does NOT rewrite the per-seed block for that reason; run with
# --sim_seed outside 1-5, or point that block at sumo_sim/ by hand, if you need it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/scratch/routing.cc"

HPC_ROOT='/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/'
LOC_ROOT='/home/nipuni/ns-allinone-3.35/ns-3.35/'
HPC_MOB='/home/sdvn_hidden_attacks/ns3_g13/mobility/'
LOC_MOB='/home/nipuni/mobility/'
HPC_HOME='"/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/"'
LOC_HOME='"/ns-allinone-3.35/ns-3.35/results_routing/"'

case "${1:-status}" in
  local)
    sed -i "s|$HPC_ROOT|$LOC_ROOT|g; s|$HPC_MOB|$LOC_MOB|g; s|$HPC_HOME|$LOC_HOME|g" "$SRC"
    echo "routing.cc -> LOCAL paths (do NOT commit)"
    ;;
  hpc)
    sed -i "s|$LOC_ROOT|$HPC_ROOT|g; s|$LOC_MOB|$HPC_MOB|g; s|$LOC_HOME|$HPC_HOME|g" "$SRC"
    echo "routing.cc -> HPC paths (committable)"
    ;;
  status)
    echo "local-path occurrences: $(grep -c '/home/nipuni/' "$SRC" || true)"
    echo "HPC-path   occurrences: $(grep -c '/home/sdvn_hidden_attacks/' "$SRC" || true)"
    ;;
  *)
    echo "usage: $0 {local|hpc|status}" >&2; exit 2
    ;;
esac
