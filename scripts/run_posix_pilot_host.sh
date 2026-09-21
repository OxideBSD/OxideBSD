#!/bin/sh
# Runs the same vendored Open POSIX Test Suite (external/gpl2/posixtestsuite) OxideBSD's own pilot
# (tests/posix_conformance_smoke.rs, sys/modules/oxfs/src/posix_conformance.sh) uses, but compiled and
# run directly on *this host* against its real glibc/Linux -- a genuine, apples-to-apples
# comparison point instead of a guess. Same corpus-discovery rule as build.rs's own
# `discover_posix_test_files` (every real conformance/interfaces/*.c file except *-buildonly.c,
# which expect a driver script's own argv[1] this pilot doesn't provide), same t0-wrapped
# real-alarm(40)-per-file timeout, same PASS/FAIL/UNRESOLVED/UNSUPPORTED/UNTESTED/TIMEOUT/CRASH
# classification posix_conformance.sh uses, so the two tallies are directly comparable.
#
# Must run as root: OxideBSD's own pilot always runs as root (see posix_conformance.sh's own doc
# comment), and plenty of these tests behave differently -- or self-skip via UNTESTED -- depending
# on caller uid, so a non-root host run wouldn't be a fair comparison.
#
# Usage: sudo scripts/run_posix_pilot_host.sh [--jobs N]

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (e.g. sudo $0) -- see this script's own header comment for why" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SUITE_DIR="$REPO_ROOT/external/gpl2/posixtestsuite"
INTERFACES_DIR="$SUITE_DIR/conformance/interfaces"
INCLUDE_DIR="$SUITE_DIR/include"
OUT_DIR="$REPO_ROOT/target/host-posix-pilot"
BIN_DIR="$OUT_DIR/bin"
LOG="$OUT_DIR/run.log"

JOBS=$(nproc 2>/dev/null || echo 4)
REBUILD=0
while [ $# -gt 0 ]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        --rebuild) REBUILD=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$BIN_DIR"

echo "=== building t0 ==="
# `-include string.h`: real, found-live friction (confirmed live via a smoke build on this exact
# host) -- t0.c calls strcmp() with no #include <string.h> of its own, a real ~2004-era omission a
# modern GCC's implicit-function-declaration default now hard-errors on.
gcc -include string.h -o "$OUT_DIR/t0" "$SUITE_DIR/t0.c"

echo "=== discovering corpus ==="
MANIFEST="$OUT_DIR/manifest.txt"
find "$INTERFACES_DIR" -type f -name '*.c' ! -name '*buildonly.c' \
    | sed "s|^$INTERFACES_DIR/||" | sort > "$MANIFEST"
total_discovered=$(wc -l < "$MANIFEST")
echo "discovered $total_discovered files"

# Same real, found-live upstream-vs-modern-host-GCC compatibility flags build.rs's own pilot
# compile loop already established (see that file's own doc comment on this exact flag set) --
# this suite's real ~2004-2005-era toolchain assumptions don't hold against a modern strict-by-
# default GCC either way, cross-compiled or native.
COMPAT_FLAGS="-Wno-implicit-function-declaration -Wno-implicit-int -Wno-incompatible-pointer-types -Wno-int-conversion"
COMPAT_INCLUDES="-include stdio.h -include stdarg.h -include stdlib.h -include string.h -include unistd.h -include fcntl.h -include sys/stat.h -include sys/types.h"

if [ "$REBUILD" -eq 0 ] && [ -s "$OUT_DIR/built.txt" ]; then
    # Resume, not rebuild: found live -- sudo needs a real TTY (see this script's own header
    # comment on why it must run outside any non-interactive passthrough), so an interrupted
    # terminal session before this script reached the run phase shouldn't cost the whole ~1700-file
    # parallel compile again. Pass --rebuild to force a fresh build (e.g. after editing a test
    # source).
    built_count=$(wc -l < "$OUT_DIR/built.txt")
    echo "=== reusing $built_count already-built binaries from a prior run (pass --rebuild to force) ==="
else
    echo "=== building corpus (parallel, $JOBS jobs) ==="
    : > "$OUT_DIR/build_failed.txt"
    # A real, standalone helper script -- not a shell function passed through `xargs -P` (some
    # `/bin/sh` implementations, e.g. dash, can't export functions into a subshell at all; this
    # avoids depending on that even where it happens to work, matching this repo's own
    # portable-POSIX-sh convention for every other script here).
    BUILD_ONE="$OUT_DIR/build_one.sh"
    cat > "$BUILD_ONE" <<EOF
#!/bin/sh
rel="\$1"
src="$INTERFACES_DIR/\$rel"
out="$BIN_DIR/\$(echo "\$rel" | tr '/' '_')"
if gcc -I "$INCLUDE_DIR" $COMPAT_FLAGS $COMPAT_INCLUDES -o "\$out" "\$src" -lpthread -lrt -lm 2>/dev/null; then
    echo "\$rel"
else
    echo "\$rel" >> "$OUT_DIR/build_failed.txt"
fi
EOF
    chmod +x "$BUILD_ONE"
    xargs -P "$JOBS" -I{} "$BUILD_ONE" {} < "$MANIFEST" > "$OUT_DIR/built.txt"
    built_count=$(wc -l < "$OUT_DIR/built.txt")
    failed_count=$(wc -l < "$OUT_DIR/build_failed.txt")
    echo "built $built_count of $total_discovered ($failed_count failed to compile -- real upstream issues, see $OUT_DIR/build_failed.txt)"
fi

echo "=== running corpus (sequential, real per-file 40s alarm via t0) ==="
sort -o "$OUT_DIR/built.txt" "$OUT_DIR/built.txt"
PASS=0; FAIL=0; UNRESOLVED=0; UNSUPPORTED=0; UNTESTED=0; TIMEOUT=0; CRASH=0
: > "$LOG"
while IFS= read -r rel; do
    bin="$BIN_DIR/$(echo "$rel" | tr '/' '_')"
    # `&& st=0 || st=$?`, not a bare statement then `st=$?` on the next line: under `set -e`, t0
    # returning *any* nonzero status (FAIL=1/UNRESOLVED=2/UNSUPPORTED=4/... -- the entire point of
    # this loop) as a standalone command aborts the whole script right there, before `st=$?` is
    # ever reached -- the exact same `set -e` trap already found and fixed in
    # run_posix_pilot_supervised.sh's own `wait "$test_pid"` call. Confirmed live: this silently
    # killed the script on the very first non-PASS result, before a single line ever reached
    # run.log.
    "$OUT_DIR/t0" 40 "$bin" > /dev/null 2>&1 && st=0 || st=$?
    case "$st" in
        0) echo "PASS: $rel" >> "$LOG"; PASS=$((PASS + 1)) ;;
        1) echo "FAIL: $rel" >> "$LOG"; FAIL=$((FAIL + 1)) ;;
        2) echo "UNRESOLVED: $rel" >> "$LOG"; UNRESOLVED=$((UNRESOLVED + 1)) ;;
        4) echo "UNSUPPORTED: $rel" >> "$LOG"; UNSUPPORTED=$((UNSUPPORTED + 1)) ;;
        5) echo "UNTESTED: $rel" >> "$LOG"; UNTESTED=$((UNTESTED + 1)) ;;
        142) echo "TIMEOUT: $rel" >> "$LOG"; TIMEOUT=$((TIMEOUT + 1)) ;;
        *) echo "CRASH($st): $rel" >> "$LOG"; CRASH=$((CRASH + 1)) ;;
    esac
done < "$OUT_DIR/built.txt"

total=$((PASS + FAIL + UNRESOLVED + UNSUPPORTED + UNTESTED + TIMEOUT + CRASH))
echo "=== summary (host: $(uname -sr), $(gcc --version | head -1)) ==="
echo "pass: $PASS"
echo "fail: $FAIL"
echo "unresolved: $UNRESOLVED"
echo "unsupported: $UNSUPPORTED"
echo "untested: $UNTESTED"
echo "timeout: $TIMEOUT"
echo "crash: $CRASH"
echo "total: $total"
echo "full per-file results: $LOG"
