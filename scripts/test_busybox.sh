#!/usr/bin/env bash
#
# Smoke-tests the BusyBox port in two stages:
#
#   1. Build stage: `cargo build` cross-builds the entire workspace, including every applet in
#      build.rs's BUSYBOX_APPLETS/BUSYBOX_APPLETS_PASS2 roster. build_busybox_applet fails the
#      whole build if a listed applet stops compiling, so a clean build already proves the roster
#      (currently ~300 applets, see OxideBSD-doc/BUSYBOX_APPLETS.md) is intact.
#   2. Boot stage: boots the resulting image headlessly under QEMU for a fixed timeout and checks
#      the serial log for a panic/fault-free boot that actually spawns hush (BusyBox sh) as pid 1
#      and reaches the scheduler, with the freshly built roster embedded in oxfs.
#
# What this script deliberately does NOT do: drive the interactive hush prompt. OxideBSD's stdin
# is real PS/2 keyboard input only (sys/console/stdin.rs) -- there is no serial or other channel a
# backgrounded QEMU process exposes that a script can inject keystrokes into. Verifying individual
# applet behavior (`ls`, `cat`, pipes, ...) needs a human at a real `cargo run` window; this script
# only proves the roster builds and the kernel boots cleanly with it embedded.
#
# Usage: scripts/test_busybox.sh [--build-only] [--timeout SECONDS]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BOOT_TIMEOUT=30
BUILD_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-only)
            BUILD_ONLY=1
            shift
            ;;
        --timeout)
            BOOT_TIMEOUT="$2"
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            echo "usage: $0 [--build-only] [--timeout SECONDS]" >&2
            exit 2
            ;;
    esac
done

KERNEL_ELF="target/x86_64-oxidebsd/debug/oxidebsd"
LOG_FILE="$(mktemp /tmp/oxidebsd-busybox-boot.XXXXXX.log)"
QEMU_PID=""

cleanup() {
    if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

pass() { printf '\033[32m[PASS]\033[0m %s\n' "$1"; }
info() { printf '\033[36m[..]\033[0m %s\n' "$1"; }
fail() {
    printf '\033[31m[FAIL]\033[0m %s\n' "$1" >&2
    echo "--- boot log ($LOG_FILE) ---" >&2
    cat "$LOG_FILE" >&2 2>/dev/null || true
    exit 1
}

info "Building the full workspace (kernel + every BusyBox applet build.rs cross-builds)"
if ! cargo build; then
    printf '\033[31m[FAIL]\033[0m %s\n' "cargo build failed -- an applet in build.rs's BUSYBOX_APPLETS/BUSYBOX_APPLETS_PASS2 roster likely broke; see the compiler output above" >&2
    exit 1
fi
pass "cargo build succeeded (BusyBox roster intact -- a broken applet fails the whole build)"

if [[ "$BUILD_ONLY" -eq 1 ]]; then
    pass "--build-only requested, skipping the boot stage"
    exit 0
fi

[[ -f "$KERNEL_ELF" ]] || fail "expected kernel ELF at $KERNEL_ELF not found after 'cargo build'"

info "Booting headlessly for up to ${BOOT_TIMEOUT}s to confirm hush (pid 1) starts cleanly with the BusyBox roster embedded"
# scripts/qemu_runner.sh stages the hybrid BIOS+UEFI ISO and invokes QEMU itself (see CLAUDE.md's
# boot section) -- BIOS here specifically, since it needs no OVMF firmware dependency for this
# automated check; OXIDEBSD_QEMU_DISPLAY=none keeps this headless the same way the old
# `-display none` flag did.
OXIDEBSD_FIRMWARE=bios OXIDEBSD_QEMU_DISPLAY=none \
    scripts/qemu_runner.sh "$KERNEL_ELF" \
    > "$LOG_FILE" 2>&1 &
QEMU_PID=$!

sleep "$BOOT_TIMEOUT"

if kill -0 "$QEMU_PID" 2>/dev/null; then
    # Still running after the full timeout -- expected: this kernel never exits on its own.
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
else
    set +e
    wait "$QEMU_PID"
    QEMU_EXIT=$?
    set -e
    QEMU_PID=""
    fail "qemu exited early (code $QEMU_EXIT) instead of running for ${BOOT_TIMEOUT}s -- likely a QEMU launch error (check for missing /dev/kvm access, permission denied, etc.)"
fi

info "Checking the boot log for panics/faults"
if grep -qiE "panicked at|double fault|page fault|general protection|EXCEPTION" "$LOG_FILE"; then
    fail "kernel panicked or faulted during boot"
fi
pass "no panic/fault markers in the boot log"

MISSING=0
for marker in \
    '\[boot\] kernel initialization complete' \
    '\[boot\] spawning hush \(BusyBox sh\) as pid 1' \
    '\[boot\] scheduler starting: switching to pid 1'
do
    if ! grep -qE "$marker" "$LOG_FILE"; then
        echo "missing expected boot-log marker: $marker" >&2
        MISSING=1
    fi
done
[[ "$MISSING" -eq 0 ]] || fail "boot did not reach the expected milestones (see above)"
pass "hush (BusyBox sh) spawned as pid 1 and the scheduler started"

echo
pass "BusyBox smoke test passed: full roster builds, image boots, hush reaches the scheduler with no panic"
echo
echo "This script can't drive the interactive hush prompt itself -- to exercise applets, run"
echo "'cargo run' and try them by hand, e.g.:"
echo "  ls /bin | wc -l      # confirm the full roster is present"
echo "  echo hello | cat"
echo "  which <applet-name>"
echo "See OxideBSD-doc/BUSYBOX_APPLETS.md for the full roster and what each applet still needs."
echo
echo "Full boot log saved at: $LOG_FILE"
