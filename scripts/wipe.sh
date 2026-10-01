#!/bin/sh
# Removes everything the build makes: target/ (what `cargo clean` removes) and toolchain/ (the
# cross compilers, which `cargo clean` leaves alone because they take hours to build again; see
# `toolchain_dir` in build.rs). The next `cargo build` starts from nothing.
#
# Usage: scripts/wipe.sh [-y]
#   -y  don't ask first

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

yes=0
case "${1:-}" in
    -y) yes=1 ;;
    "") ;;
    *) echo "usage: scripts/wipe.sh [-y]" >&2; exit 2 ;;
esac

there=""
for d in target toolchain; do
    [ -e "$d" ] && there="$there $d"
done
if [ -z "$there" ]; then
    echo "nothing to remove"
    exit 0
fi

if [ "$yes" -eq 0 ]; then
    du -sh $there 2>/dev/null || true
    printf 'Remove%s? The next build starts from nothing (hours). [y/N] ' "$there"
    read -r answer
    case "$answer" in
        y|Y|yes) ;;
        *) echo "left alone"; exit 1 ;;
    esac
fi

rm -rf $there
echo "removed$there"
