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

# --- Firmware selection: UEFI by default (this project's own choice -- real hardware today is
# UEFI-first), BIOS via OXIDEBSD_FIRMWARE=bios. OVMF itself is a host QEMU prerequisite, like
# qemu-system-x86_64 already is -- not vendored. ---
FIRMWARE="${OXIDEBSD_FIRMWARE:-uefi}"

find_ovmf() {
    if [ -n "${OXIDEBSD_OVMF_PATH:-}" ]; then
        printf '%s\n' "$OXIDEBSD_OVMF_PATH"
        return 0
    fi
    for p in \
        /usr/share/edk2/x64/OVMF.4m.fd \
        /usr/share/edk2-ovmf/x64/OVMF.fd \
        /usr/share/OVMF/OVMF.fd \
        /usr/share/ovmf/x64/OVMF.fd \
        /usr/share/qemu/OVMF.fd
    do
        if [ -e "$p" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

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

# --- QEMU argv. Flags below are this project's own old `[package.metadata.bootimage]`
# `run-args`/`test-args` verbatim (see git history for the removed section's own comments) --
# only the boot-medium attachment changes (a `-cdrom` ISO instead of bootimage's implicit
# primary-IDE-master raw disk). Deliberately never `-M q35`: q35 drops the legacy PIIX IDE
# controller the real ATA disk-persistence `-device ide-hd,bus=ide.1,unit=0` below depends on --
# staying on the default (unstated) `i440fx` machine type keeps that working under both BIOS and
# UEFI, since OVMF loads fine there via a single combined `-bios` image with no `-M` change needed.
set -- -accel kvm -accel tcg -serial stdio -m 8192 -nic user,model=rtl8139

# Opt-in QEMU monitor on a plain TCP port (e.g. OXIDEBSD_QEMU_MONITOR=4445), reachable with any
# raw TCP client (`socat -,raw TCP:127.0.0.1:4445`, or a plain Python `socket`). Real, deliberate
# use case beyond interactive debugging: the monitor's own `sendkey <combo>` command genuinely
# synthesizes guest keystrokes, closing what CLAUDE.md's own test-architecture section otherwise
# documents as "can't be scripted, manual-QEMU-only" for anything needing live keyboard input --
# confirmed live tracking down a real Ctrl+C/Ctrl+D bug (see CLAUDE.md's session/controlling-tty
# section) entirely headlessly, no human at a real display required. Off by default -- nothing
# else in this project's own tooling needs it.
if [ -n "${OXIDEBSD_QEMU_MONITOR:-}" ]; then
    set -- "$@" -monitor "tcp:127.0.0.1:${OXIDEBSD_QEMU_MONITOR},server,nowait"
fi

# Real emulated xHCI controller + USB keyboard, opt-in only via OXIDEBSD_QEMU_USB=1 -- same
# opt-in-env-var shape as OXIDEBSD_FIRMWARE/OXIDEBSD_QEMU_DISPLAY above. Deliberately NOT on by
# default: QEMU's default i440fx machine already wires up a PS/2 keyboard at the hardware-model
# level, so keystrokes typed into the QEMU display window would otherwise reach both the real
# PS/2 IRQ path and this new USB one at once, double-pushing every character into stdin. See
# `src/drivers/usb`'s own module doc comment for the driver this exercises.
if [ "${OXIDEBSD_QEMU_USB:-0}" = 1 ]; then
    set -- "$@" -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
fi

if [ "$IS_TEST" = 1 ]; then
    DISK_IMAGE="target/oxfs_test_disk.img"
    set -- "$@" -device isa-debug-exit,iobase=0xf4,iosize=0x04 -display none
    # Tests keep IDE (tests/ata_smoke.rs drives it directly).
    DISK_DEFAULT=ide
else
    # OXIDEBSD_DISK_IMAGE boots `cargo run` against another image (an existing file of
    # oxfs_disk.img's size), leaving the persistent dev disk alone.
    DISK_IMAGE="${OXIDEBSD_DISK_IMAGE:-target/oxfs_disk.img}"
    DISK_DEFAULT=virtio
fi

# The data disk is IDE or virtio-blk: $OXIDEBSD_QEMU_DISK (`ide`/`virtio`) overrides the default
# above. virtio is modern-only (`disable-legacy=on`), which is all src/drivers/virtio.rs speaks;
# the kernel prefers it when both could be present.
case "${OXIDEBSD_QEMU_DISK:-$DISK_DEFAULT}" in
    virtio) data_disk="virtio-blk-pci,drive=oxfsdisk,disable-legacy=on" ;;
    ide) data_disk="ide-hd,drive=oxfsdisk,bus=ide.1,unit=0" ;;
    *)
        echo "qemu_runner.sh: OXIDEBSD_QEMU_DISK must be ide or virtio" >&2
        exit 1
        ;;
esac

# Real ATA data disk pinned explicitly to the secondary channel's master (ide.1, unit 0) -- see
# CLAUDE.md's "Real disk persistence" section. The boot ISO below must NOT be attached via a bare
# `-cdrom` flag: QEMU's own convenience default for `-cdrom` on this machine type is *also*
# ide.1 unit 0 (secondary master), which collides outright ("IDE unit 0 is in use") -- found live
# on the first real `cargo run` under the new Limine-based runner. Attaching it explicitly to the
# primary channel's master instead (`ide.0`, unit 0) both fixes the collision and matches the old
# `bootimage`-era topology exactly (bootimage always attached the boot image itself as the
# implicit primary master).
set -- "$@" \
    -drive "if=none,id=oxfsdisk,format=raw,file=$DISK_IMAGE" \
    -device "$data_disk" \
    -drive "if=none,id=isocd,media=cdrom,file=$ISO_PATH" \
    -device ide-cd,drive=isocd,bus=ide.0,unit=0

if [ "$FIRMWARE" = "bios" ]; then
    set -- "$@" -boot order=d
elif [ "$FIRMWARE" = "uefi" ]; then
    OVMF_PATH="$(find_ovmf)" || {
        echo "qemu_runner.sh: no OVMF firmware found for UEFI boot (the default)." >&2
        echo "  Install a package providing it (e.g. edk2-ovmf), or set OXIDEBSD_OVMF_PATH." >&2
        echo "  Set OXIDEBSD_FIRMWARE=bios to boot via BIOS instead." >&2
        exit 1
    }
    set -- "$@" -bios "$OVMF_PATH"
else
    echo "qemu_runner.sh: unknown OXIDEBSD_FIRMWARE '$FIRMWARE' (expected 'uefi' or 'bios')" >&2
    exit 1
fi

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

# --- Test mode: a real wedged-boot guard (the same "kill QEMU from the host, since nothing
# inside a genuinely stuck guest can rescue itself" idiom scripts/run_posix_pilot_supervised.sh
# already uses), then translate the real isa-debug-exit exit code (see src/qemu.rs's
# QemuExitCode) into this script's own pass/fail status for cargo. ---
TIMEOUT_SECS="${OXIDEBSD_TEST_TIMEOUT_SECS:-28800}"

qemu-system-x86_64 "$@" &
qemu_pid=$!
# Written for the same reason as the `cargo run` branch above -- a host-side supervisor (see
# scripts/run_posix_pilot_supervised.sh) can read this instead of `pkill`-matching a process name
# that no longer exists post-Limine-migration (every test now stages the identical
# target/oxidebsd.iso, so there's no longer a per-test-binary-named process to match on at all).
echo "$qemu_pid" > target/qemu_runner.pid

elapsed=0
while kill -0 "$qemu_pid" 2>/dev/null; do
    if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
        echo "qemu_runner.sh: test timed out after ${TIMEOUT_SECS}s, killing QEMU (pid $qemu_pid)" >&2
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
        exit 124
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

exit_code=0
wait "$qemu_pid" || exit_code=$?

# QemuExitCode::Success (0x10) -> real QEMU exit code (0x10<<1)|1 = 33; anything else is a failure
# (QemuExitCode::Failed = 0x11 -> 35, or a genuine crash/signal exit).
if [ "$exit_code" -eq 33 ]; then
    exit 0
else
    exit "$exit_code"
fi
