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

# 2026-08-06: the swap must cover EVERY file with a hardcoded path, not just
# routing.cc. It previously rewrote routing.cc alone, which is how commit
# 149f022 leaked local paths into 17 other files (a `git add -A` staged files
# the script had never touched, and `status` reported clean because it only
# inspected routing.cc). It also breaks local runs: with routing.cc on local
# paths but optimization_lifetime.py left on cluster paths, the helper looks
# for its input CSV under /home/sdvn_hidden_attacks/ and the run aborts.
# FILES() lists every tracked text file containing either path form, minus
# this script (which must keep both to function).
FILES() {
  grep -rIl --exclude-dir=.git \
       -e '/home/sdvn_hidden_attacks/' -e '/home/nipuni/' \
       "$REPO" 2>/dev/null | grep -v 'local_path_swap.sh'
}

HPC_ROOT='/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/'
LOC_ROOT='/home/nipuni/ns-allinone-3.35/ns-3.35/'
HPC_MOB='/home/sdvn_hidden_attacks/ns3_g13/mobility/'
LOC_MOB='/home/nipuni/mobility/'
HPC_HOME='"/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/"'
LOC_HOME='"/ns-allinone-3.35/ns-3.35/results_routing/"'

case "${1:-status}" in
  local)
    n=0
    while IFS= read -r f; do
      sed -i "s|$HPC_ROOT|$LOC_ROOT|g; s|$HPC_MOB|$LOC_MOB|g; s|$HPC_HOME|$LOC_HOME|g" "$f"
      n=$((n+1))
    done < <(FILES)
    echo "$n file(s) -> LOCAL paths (do NOT commit)"
    ;;
  hpc)
    n=0
    while IFS= read -r f; do
      sed -i "s|$LOC_ROOT|$HPC_ROOT|g; s|$LOC_MOB|$HPC_MOB|g; s|$LOC_HOME|$HPC_HOME|g" "$f"
      n=$((n+1))
    done < <(FILES)
    echo "$n file(s) -> HPC paths (committable)"
    ;;
  status)
    loc=$(grep -rIl --exclude-dir=.git -e '/home/nipuni/' "$REPO" 2>/dev/null | grep -vc 'local_path_swap.sh' || true)
    hpc=$(grep -rIl --exclude-dir=.git -e '/home/sdvn_hidden_attacks/' "$REPO" 2>/dev/null | grep -vc 'local_path_swap.sh' || true)
    echo "files with local paths: ${loc:-0}"
    echo "files with HPC   paths: ${hpc:-0}"
    echo "routing.cc: local=$(grep -c '/home/nipuni/' "$SRC" || true) hpc=$(grep -c '/home/sdvn_hidden_attacks/' "$SRC" || true)"
    ;;
  *)
    echo "usage: $0 {local|hpc|status}" >&2; exit 2
    ;;
esac
