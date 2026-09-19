#!/bin/sh
# Cargo's own `runner` for the `x86_64-oxidebsd` target (see `.cargo/config.toml`) -- replaces the
# retired `bootimage runner` now that OxideBSD boots via the Limine protocol instead of the
# `bootloader` crate (see CLAUDE.md's boot section). Cargo invokes this with the just-built
# kernel/test ELF's path as $1 and treats this script's own exit code as the `cargo run`/
# `cargo test` result.
#
# What it does, end to end: stages a fresh hybrid BIOS+UEFI ISO from `target/limine-stage/`
# (populated by build.rs's `build_limine_deploy_tool`) plus the just-built ELF, then boots it under
# QEMU with the same accel/serial/RAM/NIC/real-ATA-disk flags this project's old
# `[package.metadata.bootimage]` `run-args`/`test-args` used, and (for a test binary) translates
# the real `isa-debug-exit` exit code into this script's own pass/fail exit status.
#
# The QEMU-driving parts common to any boot path (firmware/OVMF selection, the fixed IDE topology,
# the isa-debug-exit wedge-guard/exit-code translation) live in `scripts/qemu_common.sh`, shared
# with `scripts/run_multiboot2_smoke.sh` -- see that file's own doc comment. This script's own
# behavior is unchanged by that extraction; only the ISO staging above (Limine-specific) and the
# interactive `cargo run` vs `cargo test` split below stay here.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

KERNEL_ELF="$1"
STAGE_DIR="target/limine-stage"
ISO_ROOT="target/iso_root"
ISO_PATH="target/oxidebsd.iso"

if [ ! -d "$STAGE_DIR" ]; then
    echo "qemu_runner.sh: $STAGE_DIR is missing -- did build.rs's build_limine_deploy_tool run?" >&2
    exit 1
fi

# Test-vs-run discrimination: a `cargo test` binary lands under
# target/x86_64-oxidebsd/debug/deps/<name>-<hash>; the main kernel binary lands at
# target/x86_64-oxidebsd/debug/oxidebsd, with no `/deps/` in its path -- confirmed directly
# (`ls target/x86_64-oxidebsd/debug/deps`).
case "$KERNEL_ELF" in
    */deps/*) IS_TEST=1 ;;
    *) IS_TEST=0 ;;
esac

# --- Stage a fresh ISO root and build the hybrid image ---
rm -rf "$ISO_ROOT"
mkdir -p "$ISO_ROOT/boot/limine" "$ISO_ROOT/EFI/BOOT"
cp "$STAGE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/"
cp "$STAGE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$STAGE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$STAGE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
cp "$STAGE_DIR/BOOTIA32.EFI" "$ISO_ROOT/EFI/BOOT/"
cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel"

# `no-ata` on `kernel_cmdline:` (see `oxidebsd::boot::ata_disabled`'s own doc comment) skips the
# real ATA disk probe entirely -- a deliberate safety gate for a first real-hardware boot attempt
# (oxfs's mount-or-format logic will genuinely *format* whatever real disk it finds on the legacy
# IDE ports it probes). Off by default (this project's own QEMU dev/test workflow relies on the
# real ATA-backed disk), on whenever OXIDEBSD_REAL_HARDWARE is set -- run
# `OXIDEBSD_REAL_HARDWARE=1 cargo run` (this script only ever runs as cargo's own `runner`, so a
# plain `cargo build` alone never regenerates the ISO -- `cargo run` is required to reach this
# code at all, even though the resulting target/oxidebsd.iso, not this script's own subsequent
# QEMU launch, is the actual real-hardware artifact; safe to Ctrl-C the QEMU window once it's
# produced) to get an ISO with this gate genuinely on, rather than hand-editing this file before
# every real-hardware attempt.
KERNEL_CMDLINE=""
if [ -n "${OXIDEBSD_REAL_HARDWARE:-}" ]; then
    KERNEL_CMDLINE="no-ata"
fi

# Deliberately no `resolution:` override here: `console::vga`'s text grid sizes itself
# dynamically at boot from whatever real framebuffer resolution Limine/the firmware's own GOP/VBE
# mode reports (see `console::vga::real_grid_size`'s own doc comment) -- a bigger real display
# shows genuinely more rows/columns of native, unscaled text, not a forced-down resolution or
# stretched characters. (Two earlier, wrong attempts: a fixed 640x400 window centered inside a
# larger real resolution left visible letterboxing; forcing the resolution itself down to
# 640x400 via this exact config key looked fine but defeated the whole point.)
{
    echo "timeout: 0"
    echo "serial: yes"
    echo "/OxideBSD"
    echo "protocol: limine"
    echo "kernel_path: boot():/boot/kernel"
    if [ -n "$KERNEL_CMDLINE" ]; then
        echo "kernel_cmdline: $KERNEL_CMDLINE"
    fi
} > "$ISO_ROOT/boot/limine/limine.conf"

xorriso -as mkisofs -R -r -J \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ISO_ROOT" -o "$ISO_PATH" > /dev/null

"$STAGE_DIR/limine" bios-install "$ISO_PATH" > /dev/null

if [ "$IS_TEST" = 1 ]; then
    QEMU_DISK_IMAGE="target/oxfs_test_disk.img"
else
    QEMU_DISK_IMAGE="target/oxfs_disk.img"
fi
QEMU_ISO_PATH="$ISO_PATH"
QEMU_HEADLESS_TEST="$IS_TEST"
# shellcheck source=./qemu_common.sh
. "$REPO_ROOT/scripts/qemu_common.sh"

# A `cargo run` invocation gets a real display by default (this kernel has a real VGA console);
# a `cargo test` binary always forces `-display none` above regardless. `scripts/test_busybox.sh`
# wants a headless `cargo run`-shaped boot for its own automated boot-log check, hence this
# separate override rather than folding headlessness into the test/run split above.
if [ -n "${OXIDEBSD_QEMU_DISPLAY:-}" ]; then
    set -- "$@" -display "$OXIDEBSD_QEMU_DISPLAY"
fi

if [ "$IS_TEST" = 0 ]; then
    # Real PID (exec keeps it) -- lets a host-side script (e.g. scripts/test_busybox.sh, or a
    # human) find and kill this exact QEMU instance without pattern-matching its argv.
    echo "$$" > target/qemu_runner.pid
    exec qemu-system-x86_64 "$@"
fi

# Test mode: see qemu_common.sh's own doc comment for the wedge-guard/exit-code-translation logic
# this delegates to.
TIMEOUT_SECS="${OXIDEBSD_TEST_TIMEOUT_SECS:-28800}"
qemu_common_run_test_and_translate_exit "$TIMEOUT_SECS" "$@"
