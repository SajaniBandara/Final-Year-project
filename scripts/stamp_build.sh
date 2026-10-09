#!/usr/bin/env bash
# Writes scratch/build_tag.h: the commit hash of HEAD, plus "+dirty.<hash of the uncommitted diff>" when anything under
# scratch/ (the only thing the binary is built from) differs from HEAD. A clean tag means: built from exactly that commit.
# Run before every ./waf build whose output will be reported. Every run output carries this tag.
set -e
cd "$(dirname "$0")/.."
h=$(git rev-parse --short HEAD)
if [ -n "$(git status --porcelain --untracked-files=all -- scratch ':!scratch/build_tag.h')" ]; then
  d=$( (git diff HEAD -- scratch; git ls-files --others --exclude-standard -- scratch | grep -v build_tag.h | xargs -r cat) | sha1sum | cut -c1-8)
  h="${h}+dirty.${d}"
fi
printf '#ifndef BUILD_TAG_H\n#define BUILD_TAG_H\n#define SDVN_BUILD_TAG "%s"\n#endif\n' "$h" > scratch/build_tag.h
echo "build tag: $h"
