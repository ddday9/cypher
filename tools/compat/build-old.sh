#!/usr/bin/env bash
# build-old.sh VERSION... — builds released versions (git tags) of cypher
# into tools/compat/.work/bin/cypher-VERSION, plus the working tree as
# cypher-new, for the compatibility scripts.
#   ./build-old.sh v0.1.0 v0.2.3
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$D/../.." && pwd)
mkdir -p "$D/.work/bin"
(cd "$ROOT" && go build -o "$D/.work/bin/cypher-new" ./cmd/cypher)
for v in "$@"; do
  wt="$D/.work/wt-$v"
  rm -rf "$wt"
  git -C "$ROOT" worktree add -q --detach "$wt" "$v"
  (cd "$wt" && go build -o "$D/.work/bin/cypher-$v" ./cmd/cypher)
  git -C "$ROOT" worktree remove --force "$wt"
done
ls -1 "$D/.work/bin"
