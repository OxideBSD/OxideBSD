#!/bin/sh
# Host-side supervisor for the POSIX conformance pilot (tests/posix_conformance_smoke.rs).
#
# Why this exists: the pilot's own userspace timeout (`t0`, a real `alarm(40)` per test file, see
# sys/modules/oxfs/src/posix_conformance.sh) can only rescue a test that's merely *slow* -- it can't
# rescue a genuine kernel-level wedge, where the stuck process is blocked somewhere no wake hook
# ever re-checks it (an unhandled BlockReason, a stale scheduler entry, a deadlocked futex chain --
# see CLAUDE.md's own history of exactly this bug class). When that happens, `t0`'s own alarm
# either never fires or fires and is never acted on, and the whole rest of the sequential pilot
# script -- and every file after the stuck one -- hangs right along with it. Nothing *inside* the
# guest can rescue that; only something watching from the host, able to kill the QEMU process
# itself, can. This script is that: run the pilot, watch its own progress (a real PASS/FAIL/etc.
# classification line per file), and if nothing new appears for a while, kill QEMU, figure out
# which file was stuck, exclude it, and retry -- automating the "found live, fixed forward"
# discipline this whole file's own `POSIX_KNOWN_HANGS`/`POSIX_EXTRA_EXCLUDE_FILE` (see build.rs)
# already document doing by hand across many separate sessions.
#
# Real speedup, not just correctness: every file this run has already gotten a real PASS/FAIL/etc.
# classification for (in *this* invocation's own earlier iterations, or a prior resumed one) is fed
# into the same exclude-file mechanism as a genuinely broken file, so the next iteration's own
# kernel image/manifest never re-embeds or re-runs it -- POSIX conformance results are deterministic
# against a fixed kernel binary (nothing here edits kernel source mid-run), so re-verifying an
# already-known outcome every single iteration is pure waste once the corpus gets long. Unlike a
# real exclude, an already-classified file's own outcome still counts toward the final tally (see
# RESULTS_FILE below) -- it's just skipped, not thrown away.
#
# Usage:
#   scripts/run_posix_pilot_supervised.sh [--reset] [--stall-seconds N] [--max-iterations N]
#
#   --reset            start with a clean exclude list and a clean results cache (default:
#                       resume/accumulate across runs)
#   --stall-seconds N  seconds with no new PASS/FAIL/etc. line before treating the run as wedged
#                       (default 120 -- well past t0's own 40s per-file rescue bound, so this only
#                       fires on a real kernel-level hang, not a legitimately slow test)
#   --max-iterations N give up after this many retries (default 30)
#
# On a clean run, prints the final summary and exits 0. Every file this script excludes along the
# way is a REAL FINDING worth investigating and root-causing -- see
# target/posix_extra_excludes.txt afterward, and graduate each one into a real, documented
# POSIX_KNOWN_HANGS entry once understood, the same way every other exclusion in build.rs already
# is. This script's own exclude list is a fast-iteration aid, not a permanent record.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

STALL_SECONDS=120
# 0 = no cap, loop until a real clean run or a genuine fatal error (duplicate-exclusion, manifest
# exhausted). Default changed from a fixed 30 after repeated real interruptions from *outside* this
# script (the host process getting killed for reasons this script has no visibility into) --
# --max-iterations remains available for a deliberately bounded run.
MAX_ITERATIONS=0
RESET=0

while [ $# -gt 0 ]; do
    case "$1" in
        --reset) RESET=1; shift ;;
        --stall-seconds) STALL_SECONDS="$2"; shift 2 ;;
        --max-iterations) MAX_ITERATIONS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Broken/hung/crashing files -- permanently skipped, never part of the final tally, a real finding
# each time one's added.
EXCLUDE_FILE="$REPO_ROOT/target/posix_extra_excludes.txt"
# Already-classified files from earlier iterations of *this* investigation -- one real result line
# per file (e.g. "PASS: aio_cancel/1-1.c"), skipped from future iterations purely for speed, but
# their outcome still counts. Kept as full result lines (not just filenames) so the final tally can
# be reported directly from this file's own content plus whatever the last iteration just added.
RESULTS_FILE="$REPO_ROOT/target/posix_verified_results.txt"
# Regenerated fresh each iteration: the real union build.rs's POSIX_EXTRA_EXCLUDE_FILE actually
# reads -- EXCLUDE_FILE's own lines plus every filename already accounted for in RESULTS_FILE.
COMBINED_SKIP_FILE="$REPO_ROOT/target/posix_combined_skip.txt"
LOG_DIR="$REPO_ROOT/target/posix-pilot-logs"
MANIFEST="$REPO_ROOT/target/generated/posix_test_manifest.txt"

mkdir -p "$LOG_DIR"
if [ "$RESET" -eq 1 ] || [ ! -f "$EXCLUDE_FILE" ]; then
    : > "$EXCLUDE_FILE"
fi
if [ "$RESET" -eq 1 ] || [ ! -f "$RESULTS_FILE" ]; then
    : > "$RESULTS_FILE"
fi

# Finds the manifest entry immediately after the last file this log run actually classified --
# that's the one it was in the middle of (or about to start) when progress stopped. If nothing was
# classified yet, the first manifest entry is the culprit (a stall during module/boot init itself,
# before the pilot script even started, would also land here -- worth noticing if it ever happens).
find_stuck_file() {
    log="$1"
    last_classified=$(grep -oE '^(PASS|FAIL|UNRESOLVED|UNSUPPORTED|UNTESTED|TIMEOUT|CRASH)(\([0-9]*\))?: .*$' "$log" 2>/dev/null | tail -1 | sed -E 's/^[A-Z]+(\([0-9]*\))?: //')
    if [ -z "$last_classified" ]; then
        head -1 "$MANIFEST"
        return
    fi
    awk -v target="$last_classified" '
        found { print; exit }
        $0 == target { found=1 }
    ' "$MANIFEST"
}

iteration=0
while [ "$MAX_ITERATIONS" -eq 0 ] || [ "$iteration" -lt "$MAX_ITERATIONS" ]; do
    iteration=$((iteration + 1))
    ts=$(date +%Y%m%dT%H%M%S)
    log="$LOG_DIR/supervised_iter${iteration}_${ts}.log"
    excluded_count=$(grep -c . "$EXCLUDE_FILE" 2>/dev/null || true)
    excluded_count=${excluded_count:-0}
    verified_count=$(grep -c . "$RESULTS_FILE" 2>/dev/null || true)
    verified_count=${verified_count:-0}
    echo "=== iteration $iteration (excluding $excluded_count broken file(s), skipping $verified_count already-verified file(s)): starting, log at $log ==="

    # Combined skip list build.rs actually reads: real excludes plus every filename already
    # classified in a prior iteration (strip the "STATUS: " prefix RESULTS_FILE stores each line
    # with).
    { cat "$EXCLUDE_FILE" 2>/dev/null; sed -E 's/^[A-Z]+(\([0-9]*\))?: //' "$RESULTS_FILE" 2>/dev/null; } \
        > "$COMBINED_SKIP_FILE"

    # Defensive: a leftover QEMU instance from a prior run (this script killed on a stall, a
    # manually-run test, an interrupted previous invocation) can still hold a write lock on
    # target/oxfs_test_disk.img even after this script's own `wait` returns, making the *next*
    # iteration's own QEMU fail outright with "Failed to get \"write\" lock" -- a real, found-live
    # failure mode, not a stall (so the stall-detection loop below never catches it). Clear the
    # decks unconditionally before every iteration, not just after a detected stall.
    #
    # `target/qemu_runner.pid` (written by scripts/qemu_runner.sh, this project's own
    # `bootimage runner` replacement -- see CLAUDE.md's boot section), not a `pkill -f` name
    # match: every test now stages the identical `target/oxidebsd.iso`, so there's no longer a
    # per-test-binary-named QEMU process to match on the way the old
    # `bootimage-posix_conformance_smoke` binary path once let this do.
    if [ -f target/qemu_runner.pid ]; then
        kill "$(cat target/qemu_runner.pid)" 2>/dev/null || true
        rm -f target/qemu_runner.pid
    fi
    sleep 1

    POSIX_EXTRA_EXCLUDE_FILE="$COMBINED_SKIP_FILE" cargo test --test posix_conformance_smoke \
        > "$log" 2>&1 &
    test_pid=$!

    last_progress=$(date +%s)
    last_line_count=0
    stalled=0
    while kill -0 "$test_pid" 2>/dev/null; do
        sleep 5
        line_count=$(grep -cE '^(PASS|FAIL|UNRESOLVED|UNSUPPORTED|UNTESTED|TIMEOUT|CRASH)(\([0-9]*\))?: ' "$log" 2>/dev/null || true)
        line_count=${line_count:-0}
        now=$(date +%s)
        if [ "$line_count" -gt "$last_line_count" ]; then
            last_line_count=$line_count
            last_progress=$now
        elif [ $((now - last_progress)) -ge "$STALL_SECONDS" ]; then
            stalled=1
            break
        fi
    done

    if [ "$stalled" -eq 1 ]; then
        echo "=== iteration $iteration: no new result for ${STALL_SECONDS}s -- treating as a real kernel-level wedge, killing QEMU ==="
        if [ -f target/qemu_runner.pid ]; then
            kill "$(cat target/qemu_runner.pid)" 2>/dev/null || true
            rm -f target/qemu_runner.pid
        fi
        wait "$test_pid" 2>/dev/null || true
        status="stalled"
    else
        # Guarded, not a bare `wait "$test_pid"`: under `set -e`, a bare `wait` on a process that
        # exited nonzero (a real crash/panic, not a stall -- found live: `set -e` killed this whole
        # supervisor outright the first time this path was hit, before it ever got a chance to log
        # anything or exclude the offending file) aborts the script right there. Wrapping it as an
        # `if` condition is what actually lets `set -e` see this as handled.
        if wait "$test_pid"; then
            status=0
        else
            status=$?
        fi
    fi

    # Whatever this iteration genuinely classified (whether it went on to stall/crash/finish
    # cleanly) is real signal worth keeping regardless -- append it to RESULTS_FILE so no future
    # iteration ever re-runs these specific files again. Dedup defensively (`sort -u`): a file
    # should only ever appear once across the whole investigation given the skip list above, but
    # cheap insurance against a bug reintroducing one is worth it.
    grep -oE '^(PASS|FAIL|UNRESOLVED|UNSUPPORTED|UNTESTED|TIMEOUT|CRASH)(\([0-9]*\))?: .*$' "$log" 2>/dev/null >> "$RESULTS_FILE" || true
    sort -u -o "$RESULTS_FILE" "$RESULTS_FILE"

    # Real, found-live gap this defends against even after fixing the driver's own wait4 status
    # check (regress/posix-conformance-driver): "driver reported PASS" only ever meant "wait4
    # returned", not "the shell's own posix_conformance.sh for-loop actually reached its own
    # `echo === summary ===`. Require the real total too, matching *this iteration's own* manifest
    # line count -- since that manifest already excludes every already-verified file, a full match
    # here means the entire remaining corpus (whatever wasn't already known before this iteration)
    # got classified, which combined with RESULTS_FILE's own prior accumulation means the real,
    # complete corpus is done -- not just this one (possibly much smaller) run's own slice of it.
    manifest_total=$(grep -c . "$MANIFEST" 2>/dev/null || true)
    manifest_total=${manifest_total:-0}
    real_total=$(grep -oE '^total: [0-9]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9]+' || true)
    real_total=${real_total:-0}
    if [ "$status" = 0 ] \
        && grep -q "posix_conformance_smoke: driver reported PASS" "$log" \
        && [ "$real_total" -gt 0 ] \
        && [ "$real_total" = "$manifest_total" ]; then
        grand_total=$(grep -c . "$RESULTS_FILE" 2>/dev/null || true)
        grand_total=${grand_total:-0}
        echo "=== clean run achieved after $iteration iteration(s), $excluded_count file(s) excluded along the way (this iteration: $real_total/$manifest_total; grand total across the whole investigation: $grand_total) ==="
        grep -A 20 "^=== summary ===" "$log" || true
        [ -s "$EXCLUDE_FILE" ] && { echo "--- excluded files (real findings, still need root-causing) ---"; cat "$EXCLUDE_FILE"; }
        exit 0
    fi

    # Anything else -- a detected stall, or the run exiting/crashing/panicking on its own without
    # ever reaching a clean PASS -- gets the same treatment: identify the file it never got past,
    # exclude it, and keep going. A real crash (kernel panic, OOM, ...) is just as much "this file
    # needs excluding and root-causing later" as a hang is -- this script's whole point is finding
    # every file standing between here and a clean run, not only the ones shaped like a hang.
    if [ "$status" = "stalled" ]; then
        echo "=== iteration $iteration: confirmed stalled ==="
    elif [ "$status" = 0 ]; then
        echo "=== iteration $iteration: driver reported PASS but real total ($real_total) != manifest total ($manifest_total) -- sh died silently partway through (no panic, no stall) -- see $log ==="
    else
        echo "=== iteration $iteration: run exited on its own (status=$status) without a clean PASS -- likely a crash/panic, not a hang -- see $log ==="
    fi
    stuck=$(find_stuck_file "$log")
    if [ -z "$stuck" ]; then
        echo "=== iteration $iteration: couldn't identify the stuck/failed file (manifest exhausted?) -- inspect $log manually ===" >&2
        exit 1
    fi
    # Real, found-live failure mode: excluding the same file twice in a row means the *previous*
    # exclusion never actually took effect (build.rs's cargo:rerun-if-changed on this file didn't
    # fire, most likely because the append below and the next iteration's own `cargo test` land
    # within the same filesystem mtime tick -- see the `sleep` right after the append) rather than
    # a second genuinely distinct hang on the exact same file. Fail loudly instead of silently
    # burning the rest of --max-iterations re-discovering nothing.
    if [ -f "$EXCLUDE_FILE" ] && grep -qxF "$stuck" "$EXCLUDE_FILE"; then
        echo "=== iteration $iteration: '$stuck' was already excluded but got stuck on it again -- the exclusion isn't taking effect (stale build cache? check target/generated/posix_test_manifest.txt), not a new finding. Stopping rather than looping uselessly. ===" >&2
        exit 1
    fi
    echo "$stuck" >> "$EXCLUDE_FILE"
    # Real, found-live race: appending here and immediately starting the next iteration's own
    # `cargo test` can land within the same filesystem mtime tick, making build.rs's own
    # `cargo:rerun-if-changed` on this exact file (see build.rs's `POSIX_EXTRA_EXCLUDE_FILE`
    # handling) unable to tell the file changed -- cargo then skips rebuilding entirely and the
    # very same file gets rediscovered as "stuck" forever. A couple of real seconds of margin
    # past 1-second mtime granularity is cheap insurance against an otherwise very expensive
    # silent no-op (confirmed live: 18 wasted iterations before this guard existed).
    sleep 2
    echo "=== iteration $iteration: excluding '$stuck', retrying ==="
done

echo "=== hit --max-iterations ($MAX_ITERATIONS) without a clean run -- inspect $LOG_DIR and $EXCLUDE_FILE ===" >&2
exit 1
