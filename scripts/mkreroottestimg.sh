#!/bin/sh
# mkreroottestimg.sh OUT: the disk tests/reroot_boot.rs boots (RAM_FLOOR.md §5.1.5): two copies of
# the system, `rootfs` (the one the kernel finds through fsconf) and `rootfs2`, each made by the
# host makefs from the sets' specs with its own /etc/rc (regress/reroot/rc.1 and rc.2) and
# rootfs2 with a marker, /REROOT2.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: mkreroottestimg.sh out.img" >&2
    exit 1
fi
OUT="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$REPO_ROOT/target/host-tools/x86_64-unknown-linux-gnu/release"
SETS="$REPO_ROOT/target/sets"
ROOT_IMG="$REPO_ROOT/target/images/root.img"
for f in "$TOOLS/makefs" "$TOOLS/mkimg" "$SETS/base.makefs" "$ROOT_IMG"; do
    if [ ! -e "$f" ]; then
        echo "mkreroottestimg.sh: $f is missing (cargo build makes it)" >&2
        exit 1
    fi
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkreroottestimg.XXXXXX")"
SPEC="$SETS/.mkreroottestimg.$$.makefs"
trap 'rm -rf "$WORK" "$SPEC"' EXIT
OTHER_SETS=""
for set in "$SETS"/*.makefs; do
    case "$set" in
    "$SETS/base.makefs" | "$SETS"/.mk*) ;;
    *) OTHER_SETS="$OTHER_SETS $set" ;;
    esac
done
ROOT_SIZE=$(wc -c < "$ROOT_IMG" | tr -d ' ')

# One root: base.makefs with ./etc/rc's contents replaced by $1, plus the extra lines in $2.
root() {
    rc="$1"
    extra="$2"
    out="$3"
    digest=$(sha256sum "$rc" | cut -d' ' -f1)
    size=$(wc -c < "$rc" | tr -d ' ')
    awk -v f="$rc" -v d="$digest" -v s="$size" '
        $1 == "./etc/rc" {
            for (i = 2; i <= NF; i++) {
                if ($i ~ /^contents=/) $i = "contents=" f
                else if ($i ~ /^sha256digest=/) $i = "sha256digest=" d
                else if ($i ~ /^size=/) $i = "size=" s
            }
        }
        { print }' "$SETS/base.makefs" > "$SPEC"
    if [ -n "$extra" ]; then
        printf '%s\n' "$extra" >> "$SPEC"
    fi
    # shellcheck disable=SC2086 # one word per set spec
    "$TOOLS/makefs" -t oxfs -o label=rootfs -s "$ROOT_SIZE" "$out" "$SPEC" $OTHER_SETS > /dev/null
}

: > "$WORK/marker"
root "$REPO_ROOT/regress/reroot/rc.1" "" "$WORK/root1.img"
root "$REPO_ROOT/regress/reroot/rc.2" "./REROOT2 contents=$WORK/marker gid=0 mode=0644 size=0 type=file uid=0 sha256digest=$(sha256sum "$WORK/marker" | cut -d' ' -f1)" "$WORK/root2.img"
rm -f "$OUT"
"$TOOLS/mkimg" -s gpt -o "$OUT" -p "oxfs/rootfs:=$WORK/root1.img" -p "oxfs/rootfs2:=$WORK/root2.img"
