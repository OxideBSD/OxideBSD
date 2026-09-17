#!/bin/sh
# Resyncs one of this project's vendored `third_party/*` forks (musl, busybox, tinycc,
# posixtestsuite, doomgeneric, and now rust) against a newer point in its real upstream history.
#
# Every fork here is pinned deliberately, not tracked continuously (see CLAUDE.md's own notes on
# musl being "frozen at tag v1.2.6" for exactly this reason) -- upstream moves fast enough that
# blindly floating would mean re-verifying every OxideBSD-specific patch on every upstream commit.
# This script exists so a *deliberate* resync (a needed fix, a needed feature) is a known,
# repeatable three-step process instead of something reinvented ad hoc each time:
#
#   1. Make sure an `upstream` remote actually points at the real project (each of these forks is
#      a genuine GitHub fork, so `origin` already carries whatever upstream refs existed *at fork
#      time* -- but GitHub does not keep a fork's refs current automatically, so anything pushed
#      to real upstream *after* the fork needs a real `upstream` remote fetched directly).
#   2. Fetch it.
#   3. Start a rebase of this fork's own `oxidebsd` branch (its real OxideBSD-specific patch
#      commits) onto the new upstream ref -- left as an interactive rebase for a human to resolve
#      conflicts and re-verify each patch still means what it used to (rust-lang/rust's own
#      internal module layout has already been observed to reorganize between nightlies; the same
#      caution applies to any of these forks over a big enough time gap).
#
# Usage: scripts/sync_third_party_fork.sh <submodule-path> <upstream-git-url> <new-upstream-ref>
# Example: scripts/sync_third_party_fork.sh third_party/musl https://github.com/kraj/musl.git v1.2.7
#
# Does NOT commit anything in the outer repo -- after the rebase lands and the fork's own build/
# tests pass, `git add <submodule-path>` here and commit that pointer bump yourself, same as any
# other submodule update.
#
# Not for `third_party/limine`: that one isn't a patched fork at all (confirmed live, 2026-09-17 --
# its `oxidebsd` branch is byte-identical to upstream's old `v11.x-binary` release branch, zero
# local commits), and upstream's own binary-distribution convention changed at v12.x (GitHub
# Release assets, not a dedicated branch) -- resyncing it is a `build.rs` plumbing change
# (`build_limine_deploy_tool`), not a rebase. Handle that one separately.

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <submodule-path> <upstream-git-url> <new-upstream-ref>" >&2
    exit 1
fi

SUBMODULE_PATH="$1"
UPSTREAM_URL="$2"
NEW_REF="$3"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$REPO_ROOT/$SUBMODULE_PATH"

if [ ! -d "$TARGET_DIR/.git" ] && [ ! -f "$TARGET_DIR/.git" ]; then
    echo "sync_third_party_fork.sh: $TARGET_DIR doesn't look like a submodule checkout" >&2
    exit 1
fi

cd "$TARGET_DIR"

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" != "oxidebsd" ]; then
    echo "sync_third_party_fork.sh: expected to be on the 'oxidebsd' branch, got '$CURRENT_BRANCH' -- checkout oxidebsd first" >&2
    exit 1
fi

if ! git remote get-url upstream >/dev/null 2>&1; then
    echo "sync_third_party_fork.sh: adding upstream remote -> $UPSTREAM_URL"
    git remote add upstream "$UPSTREAM_URL"
fi

echo "sync_third_party_fork.sh: fetching upstream..."
git fetch upstream "$NEW_REF"

BEHIND="$(git rev-list --count HEAD..FETCH_HEAD)"
AHEAD="$(git rev-list --count FETCH_HEAD..HEAD 2>/dev/null || echo '?')"
echo "sync_third_party_fork.sh: $SUBMODULE_PATH is $BEHIND commit(s) behind, carrying $AHEAD local commit(s) on oxidebsd"

echo "sync_third_party_fork.sh: starting rebase of oxidebsd onto FETCH_HEAD ($NEW_REF)..."
echo "sync_third_party_fork.sh: resolve any conflicts, verify each patch still applies as intended,"
echo "sync_third_party_fork.sh: then rebuild/retest before pointing the outer repo at the new commit."
git rebase FETCH_HEAD
