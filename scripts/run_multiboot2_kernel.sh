#!/bin/sh
# Builds and boots the *real* kernel (hush/oxfs/doom/everything -- not just the boot trampoline)
# through the Multiboot2 path, via either Limine's own `protocol: multiboot2` or real GRUB, with a
# real QEMU display + serial-to-stdio so you can drive `hush` interactively (and, e.g., run doom).
# See CLAUDE.md's Multiboot2 section and `oxidebsd::kernel_main`'s own doc comment for why this
# needs its own dedicated crate (`regress/multiboot2-kernel/`) rather than reusing `sys/main.rs`
# directly the way `regress/multiboot2-boot-smoke` reuses `tests/multiboot2_boot_smoke.rs`.
#
# Unlike `scripts/run_multiboot2_smoke.sh` (headless, test-shaped, expects the ELF already built
# by build.rs's own side effect), this script builds its own crate directly and always boots
# interactively -- there is no pass/fail exit-code translation here, just a real, controllable
# QEMU session. Ctrl+C / close the QEMU window to end it.
#
# OXIDEBSD_MULTIBOOT2_LOADER=limine (default) | grub -- same shape as run_multiboot2_smoke.sh's own
# knob. OXIDEBSD_FIRMWARE=bios (default *here*, unlike every other script in this project) | uefi.
#
# **Why BIOS is this one script's own default, not qemu_common.sh's usual `uefi`**: real Multiboot2
# semantics (unlike Limine's own native protocol) force the kernel to load at a *fixed* physical
# address, with no relocation -- so the loader needs one contiguous free hole that size in the
# firmware's own memory map. Confirmed live: booting this real kernel's own ~266 MiB debug image
# (BusyBox/musl/TinyCC/Clang+LLVM/POSIX-corpus content included -- the trampoline-only
# `multiboot2-boot-smoke` test never hit this, it's a few hundred KiB) via Limine-as-multiboot2-
# loader under OVMF/UEFI panics with "Could not find viable load address for executable" --
# real UEFI's own memory map is fragmented enough near the low few hundred MiB that no hole that
# large exists there. Under BIOS/SeaBIOS, real QEMU RAM from 1 MiB onward is one large contiguous
# usable region, comfortably bigger than this image -- confirmed booting clean. GRUB-under-UEFI is
# *separately* known-broken for an unrelated reason (a real, upstream GRUB 2.14 regression -- see
# CLAUDE.md's Multiboot2 section), so BIOS is the only currently-working firmware choice for either
# loader with this real, full-size kernel.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OXIDEBSD_FIRMWARE="${OXIDEBSD_FIRMWARE:-bios}"
export OXIDEBSD_FIRMWARE

CRATE_DIR="regress/multiboot2-kernel"
TARGET_DIR="target/multiboot2-kernel"
KERNEL_ELF="target/multiboot2-kernel.elf"

echo "run_multiboot2_kernel.sh: building the real kernel via $CRATE_DIR (this also rebuilds" >&2
echo "  BusyBox/musl/oxfs's embedded content the first time, or after they change -- can take" >&2
echo "  a while)." >&2
# RUSTFLAGS override, not additive: without this, `.cargo/config.toml`'s own
# `[target.x86_64-oxidebsd] rustflags` (`-Tx86_64-oxidebsd.ld`, for the *plain* Limine kernel)
# still applies to this invocation too (config discovery is based on cwd/target, unaware of which
# crate's own build.rs also wants to supply a linker script) -- fighting with this crate's own
# `regress/multiboot2-kernel/build.rs`-supplied `-Tx86_64-oxidebsd-multiboot2.ld` and producing two
# conflicting `-T` scripts (confirmed live: rust-lld's "unable to place section" errors, sections
# double-assigned). An env `RUSTFLAGS` fully replaces (not merges with) the config-resolved value
# per Cargo's own precedence rules, matching exactly what `build.rs`'s own
# `build_multiboot2_boot_smoke_crate` sets on its nested build for the same reason -- keep the
# `chacha20` soft-backend cfg (still needed, this crate links the real `oxidebsd` lib) but drop the
# `-T` entirely, leaving this crate's own build.rs as the *only* source of a linker script.
RUSTFLAGS='--cfg chacha20_backend="soft"' \
cargo build \
    --manifest-path "$CRATE_DIR/Cargo.toml" \
    --target-dir "$TARGET_DIR"

cp "$TARGET_DIR/x86_64-oxidebsd/debug/multiboot2-kernel" "$KERNEL_ELF"

LOADER="${OXIDEBSD_MULTIBOOT2_LOADER:-limine}"
ISO_ROOT="target/multiboot2_kernel_iso_root"
ISO_PATH="target/multiboot2_kernel.iso"

rm -rf "$ISO_ROOT"

case "$LOADER" in
    limine)
        # Reuses the *same* target/limine-stage/ blobs build.rs's build_limine_deploy_tool already
        # produces for the plain Limine-protocol path -- see run_multiboot2_smoke.sh's own comment
        # for why this is the fast, zero-new-host-deps default.
        STAGE_DIR="target/limine-stage"
        if [ ! -d "$STAGE_DIR" ]; then
            echo "run_multiboot2_kernel.sh: $STAGE_DIR is missing -- did build.rs's build_limine_deploy_tool run?" >&2
            exit 1
        fi
        mkdir -p "$ISO_ROOT/boot/limine" "$ISO_ROOT/EFI/BOOT"
        cp "$STAGE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/"
        cp "$STAGE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
        cp "$STAGE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
        cp "$STAGE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
        cp "$STAGE_DIR/BOOTIA32.EFI" "$ISO_ROOT/EFI/BOOT/"
        cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel"

        {
            echo "timeout: 0"
            echo "serial: yes"
            echo "/OxideBSD (Multiboot2)"
            echo "protocol: multiboot2"
            echo "kernel_path: boot():/boot/kernel"
        } > "$ISO_ROOT/boot/limine/limine.conf"

        xorriso -as mkisofs -R -r -J \
            -b boot/limine/limine-bios-cd.bin \
            -no-emul-boot -boot-load-size 4 -boot-info-table \
            --efi-boot boot/limine/limine-uefi-cd.bin \
            -efi-boot-part --efi-boot-image --protective-msdos-label \
            "$ISO_ROOT" -o "$ISO_PATH" > /dev/null

        "$STAGE_DIR/limine" bios-install "$ISO_PATH" > /dev/null
        ;;
    grub)
        # Same real-second-loader confirmation path as run_multiboot2_smoke.sh -- needs
        # grub-mkrescue + mtools (Arch: `pacman -S grub mtools`; Debian/Ubuntu:
        # `apt install grub-pc-bin mtools`, or grub-efi-amd64-bin for a UEFI-capable
        # grub-mkrescue -- though see the firmware note above, BIOS is the reliable pairing today).
        command -v grub-mkrescue >/dev/null 2>&1 || {
            echo "run_multiboot2_kernel.sh: grub-mkrescue not found (needed for OXIDEBSD_MULTIBOOT2_LOADER=grub)." >&2
            echo "  Arch: pacman -S grub mtools" >&2
            echo "  Debian/Ubuntu: apt install grub-pc-bin mtools" >&2
            exit 1
        }
        mkdir -p "$ISO_ROOT/boot/grub"
        cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel"
        {
            echo "set timeout=0"
            echo "menuentry 'OxideBSD (Multiboot2)' {"
            echo "    multiboot2 /boot/kernel"
            echo "    boot"
            echo "}"
        } > "$ISO_ROOT/boot/grub/grub.cfg"

        grub-mkrescue -o "$ISO_PATH" "$ISO_ROOT" > /dev/null 2>&1
        ;;
    *)
        echo "run_multiboot2_kernel.sh: unknown OXIDEBSD_MULTIBOOT2_LOADER '$LOADER' (expected 'limine' or 'grub')" >&2
        exit 1
        ;;
esac

# The real, persistent disk (same one `cargo run` uses) -- not the always-fresh test disk, so any
# files you create at the hush prompt this session are still there next time.
QEMU_DISK_IMAGE="target/oxfs_disk.img"
QEMU_ISO_PATH="$ISO_PATH"
QEMU_HEADLESS_TEST=0
# shellcheck source=./qemu_common.sh
. "$REPO_ROOT/scripts/qemu_common.sh"

echo "run_multiboot2_kernel.sh: booting via $LOADER (OXIDEBSD_FIRMWARE=$OXIDEBSD_FIRMWARE)." >&2
echo "  Once you reach a hush prompt: 'cd / && doom' launches doomgeneric on the real framebuffer console." >&2
exec qemu-system-x86_64 "$@"
