#!/bin/sh
# mkinstalliso.sh KERNEL OUT.iso [CMDLINE...]: the install medium (OxideBSD-doc INSTALLER.md §3),
# one hybrid image that boots from a CD and, written with dd, from a USB stick, on BIOS and UEFI.
#
#   /boot/kernel, /boot/mfsroot       the kernel, and the root it boots into, compressed
#                                     (build.rs's target/images/mfsroot.uz), passed `mfsroot`
#   /boot/limine/, /EFI/BOOT/         Limine (target/limine-stage)
#   /OxideBSD/<version>/              the sets (target/sets/*.tar.zst) and their MANIFEST
#
# Extra CMDLINE words go on the kernel's command line (the QEMU runner adds -D). The QEMU runner
# makes target/images/install.iso with it at each `cargo run`, unless OXIDEBSD_NO_INSTALLER is set.
set -eu

if [ $# -lt 2 ]; then
    echo "usage: mkinstalliso.sh kernel out.iso [cmdline ...]" >&2
    exit 1
fi
KERNEL="$1"
OUT="$2"
shift 2
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$REPO_ROOT/target/limine-stage"
SETS="$REPO_ROOT/target/sets"
MFSROOT="$REPO_ROOT/target/images/mfsroot.uz"
ROOT="$REPO_ROOT/target/install_root"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | sed -n 1p)

for f in "$MFSROOT" "$SETS/MANIFEST" "$STAGE/limine"; do
    if [ ! -e "$f" ]; then
        echo "mkinstalliso.sh: $f is missing -- run cargo build (without OXIDEBSD_NO_INSTALLER)" >&2
        exit 1
    fi
done

rm -rf "$ROOT"
mkdir -p "$ROOT/boot/limine" "$ROOT/EFI/BOOT" "$ROOT/OxideBSD/$VERSION"
# Hard links where the file system allows: the sets are tens of MiB.
put() { ln -f "$1" "$2" 2>/dev/null || cp "$1" "$2"; }
# Without its debug sections: the boot loader reads the whole file into memory first.
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy"
"$OBJCOPY" --strip-debug "$KERNEL" "$ROOT/boot/kernel"
put "$MFSROOT" "$ROOT/boot/mfsroot"
for f in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin; do
    put "$STAGE/$f" "$ROOT/boot/limine/$f"
done
put "$STAGE/BOOTX64.EFI" "$ROOT/EFI/BOOT/BOOTX64.EFI"
put "$STAGE/BOOTIA32.EFI" "$ROOT/EFI/BOOT/BOOTIA32.EFI"
for f in "$SETS"/*.tar.zst "$SETS/MANIFEST"; do
    put "$f" "$ROOT/OxideBSD/$VERSION/${f##*/}"
done
{
    echo "timeout: 3"
    echo "serial: yes"
    echo "/OxideBSD $VERSION installer"
    echo "protocol: limine"
    echo "kernel_path: boot():/boot/kernel"
    echo "module_path: boot():/boot/mfsroot"
    echo "kernel_cmdline: mfsroot${*:+ $*}"
} > "$ROOT/boot/limine/limine.conf"

xorriso -as mkisofs -R -r -J -V OXIDEBSD_INSTALL \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ROOT" -o "$OUT" > /dev/null 2>&1
"$STAGE/limine" bios-install "$OUT" > /dev/null
