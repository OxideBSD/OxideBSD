#!/bin/sh
# Boots target/multiboot2-boot-smoke.elf (built by build.rs's build_multiboot2_boot_smoke_crate --
# see smoke/multiboot2-boot-smoke/) as a real Multiboot2 kernel, via either Limine's own
# multiboot2 protocol (fast, zero new host deps, proves the trampoline itself) or real GRUB (the
# independent second-loader confirmation -- proves genuine bootloader-agnosticism, not "Limine
# wearing a different hat"). See CLAUDE.md's Multiboot2 section.
#
# Assumes the ELF is already built -- run `cargo build`/`cargo check` first. Not wired into
# `.cargo/config.toml`: this binary isn't a `cargo test`/`cargo run` target (see build.rs's own
# comment on `build_multiboot2_boot_smoke_crate` for why -- it's a build-script side-effect
# artifact, reachable only via the real `oxidebsd` lib as a dependency), so it's driven directly
# by this script instead of cargo's own `runner=`.
#
# OXIDEBSD_MULTIBOOT2_LOADER=limine (default) | grub -- same opt-in-env-var shape as
# OXIDEBSD_FIRMWARE/OXIDEBSD_QEMU_USB elsewhere in this project's tooling.
# OXIDEBSD_TEST_TIMEOUT_SECS -- default 120s; this is a small, fast smoke test, not the POSIX
# pilot, so qemu_runner.sh's own 8-hour default would be the wrong fallback here.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

KERNEL_ELF="target/multiboot2-boot-smoke.elf"
if [ ! -f "$KERNEL_ELF" ]; then
    echo "run_multiboot2_smoke.sh: $KERNEL_ELF is missing -- run cargo build/check first." >&2
    exit 1
fi

LOADER="${OXIDEBSD_MULTIBOOT2_LOADER:-limine}"
ISO_ROOT="target/multiboot2_iso_root"
ISO_PATH="target/multiboot2_smoke.iso"

rm -rf "$ISO_ROOT"

case "$LOADER" in
    limine)
        # Reuses the *same* target/limine-stage/ blobs build.rs's build_limine_deploy_tool already
        # produces for the plain Limine-protocol path -- this is the whole point of this loader
        # choice: the identical Limine binary, told to speak Multiboot2 to the kernel instead of
        # its own native protocol, fast and with zero new host dependencies.
        STAGE_DIR="target/limine-stage"
        if [ ! -d "$STAGE_DIR" ]; then
            echo "run_multiboot2_smoke.sh: $STAGE_DIR is missing -- did build.rs's build_limine_deploy_tool run?" >&2
            exit 1
        fi
        mkdir -p "$ISO_ROOT/boot/limine" "$ISO_ROOT/EFI/BOOT"
        cp "$STAGE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/"
        cp "$STAGE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
        cp "$STAGE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
        cp "$STAGE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
        cp "$STAGE_DIR/BOOTIA32.EFI" "$ISO_ROOT/EFI/BOOT/"
        cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel"

        # Identical to qemu_runner.sh's own limine.conf except protocol: multiboot2.
        {
            echo "timeout: 0"
            echo "serial: yes"
            echo "/OxideBSD Multiboot2 smoke"
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
        # The independent second-loader confirmation pass -- deliberately not the fast default.
        # New host deps beyond xorriso (already required for the limine path): grub-mkrescue +
        # mtools (Arch: `pacman -S grub mtools`; Debian/Ubuntu: `apt install grub-pc-bin mtools`,
        # or grub-efi-amd64-bin for a UEFI-capable grub-mkrescue).
        command -v grub-mkrescue >/dev/null 2>&1 || {
            echo "run_multiboot2_smoke.sh: grub-mkrescue not found (needed for OXIDEBSD_MULTIBOOT2_LOADER=grub)." >&2
            echo "  Arch: pacman -S grub mtools" >&2
            echo "  Debian/Ubuntu: apt install grub-pc-bin mtools" >&2
            exit 1
        }
        mkdir -p "$ISO_ROOT/boot/grub"
        cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel"
        {
            echo "set timeout=0"
            echo "menuentry 'OxideBSD Multiboot2 smoke' {"
            echo "    multiboot2 /boot/kernel"
            echo "    boot"
            echo "}"
        } > "$ISO_ROOT/boot/grub/grub.cfg"

        grub-mkrescue -o "$ISO_PATH" "$ISO_ROOT" > /dev/null 2>&1
        ;;
    *)
        echo "run_multiboot2_smoke.sh: unknown OXIDEBSD_MULTIBOOT2_LOADER '$LOADER' (expected 'limine' or 'grub')" >&2
        exit 1
        ;;
esac

QEMU_DISK_IMAGE="target/oxfs_test_disk.img"
QEMU_ISO_PATH="$ISO_PATH"
QEMU_HEADLESS_TEST=1
# shellcheck source=./qemu_common.sh
. "$REPO_ROOT/scripts/qemu_common.sh"

TIMEOUT_SECS="${OXIDEBSD_TEST_TIMEOUT_SECS:-120}"
qemu_common_run_test_and_translate_exit "$TIMEOUT_SECS" "$@"
