#!/sbin/init_sh
#
# On-target check for msdosfs (VFS.md §9), seeded as /usr/tests/msdosfs/run.sh. The test disk
# (scripts/mkmsdostestimg.sh) has the same tree on three FAT volumes: /dev/gpt/fat12, fat16 and
# fat32. Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "msdosfs-smoke: ok: $_desc"
	else
		echo "msdosfs-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
is() { [ "$1" = "$2" ] || { echo "  got '$1', want '$2'"; return 1; }; }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
# stat(1) here is BusyBox's without -c: its terse line's fields (name size blocks mode(hex) uid
# gid dev ino nlink major minor atime mtime ctime ...). Names without spaces only.
field() { stat -t "$1" | awk -v f="$2" '{print $f}'; }
perm() { printf '%o' $(( 0x$(field "$1" 4) & 0777 )); }
owner() { echo "$(field "$1" 5):$(field "$1" 6)"; }
mtime() { field "$1" 13; }
links() { field "$1" 9; }
# Whether $3 bytes of $1 from byte $2 are all zeros.
zeros_at() { [ "$(dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | tr -d '\000' | wc -c | tr -d ' ')" = 0 ]; }
# OVMF (UEFI) keeps its variables in NvVars on the first FAT volume it finds: not ours to count.
count_tree() {
	_n=$(find "$1" | grep -v '/NvVars$' | wc -l | tr -d ' ')
	[ "$_n" = "$2" ] && return 0
	echo "  got $_n entries, want $2:"
	find "$1" | sort | uniq -c | sort -rn | head -n 5
	find "$1" | grep -v /many/ | sort
	return 1
}
# The makefs time of every file (-T): 2025-10-09 08:53:20 local, here UTC.
STAMP=1760000000

seq 1 50000 > /tmp/big.expected

# --- Each type, the same tree ------------------------------------------------------------------
for t in 12 16 32; do
	D=/tmp/fat$t
	mkdir -p $D
	check "FAT$t: fsck_msdosfs -n finds it clean" fsck_msdosfs -n /dev/gpt/fat$t
	check "FAT$t: mounts read-only" mount -t msdosfs -o ro /dev/gpt/fat$t $D
	check "FAT$t: listed by mount" eval "mount | grep -q 'on $D (msdosfs'"
	check "FAT$t: an 8.3 name" is "$(cat $D/README.TXT)" "hello, FAT"
	check "FAT$t: a long name" is "$(cat "$D/a long file name.text")" "long"
	check "FAT$t: case preserved" eval "ls $D | grep -qx 'Mixed Case.Txt'"
	check "FAT$t: a lower-case 8.3 name shows lower case" eval "ls $D | grep -qx lower.txt"
	check "FAT$t: lookups ignore case" is "$(cat $D/readme.txt)" "hello, FAT"
	check "FAT$t: ... long names too" is "$(cat "$D/MIXED CASE.TXT")" "mixed"
	check "FAT$t: ... and the short alias" is "$(cat $D/ALONGF~1.TEX)" "long"
	check "FAT$t: a UTF-8 long name" is "$(cat "$D/café.txt")" "café"
	check "FAT$t: a CJK long name" is "$(cat $D/日本語.txt)" "nihongo"
	check "FAT$t: a file over many clusters" cmp $D/sub/big.bin /tmp/big.expected
	check "FAT$t: an empty file" eval "[ -f $D/empty ] && [ ! -s $D/empty ]"
	check "FAT$t: nested directories" is "$(cat $D/sub/deeper/kernel)" "kernel"
	check "FAT$t: a directory of 300 names" is "$(ls $D/many | wc -l | tr -d ' ')" 300
	check "FAT$t: ... each readable" is "$(cat $D/many/file299)" 299
	check "FAT$t: find walks the tree" count_tree $D 314
	check "FAT$t: the read-only attribute clears the write bits" is "$(perm $D/readonly.txt)" 555
	check "FAT$t: modes from the mount point (0755)" is "$(perm $D/README.TXT)" 755
	check "FAT$t: owner root" is "$(owner $D/README.TXT)" 0:0
	check "FAT$t: the stored time" is "$(mtime $D/README.TXT)" $STAMP
	check "FAT$t: no hard links" is "$(links $D/README.TXT)" 1
	check "FAT$t: .. leads back up" is "$(cd $D/sub/deeper/.. && pwd)" "$D/sub"
	check "FAT$t: getcwd inside it" is "$(cd $D/sub/deeper && /bin/pwd)" "$D/sub/deeper"
	check "FAT$t: ... from the root's .. too" is "$(cd $D/sub/.. && ls README.TXT)" README.TXT
	check "FAT$t: df knows it" eval "df $D | grep -q fat$t"
	check "FAT$t: unmounts" umount $D
done

# --- Options and errors ------------------------------------------------------------------------
D=/tmp/fat16
check "uid, gid, mask and dirmask options" mount -t msdosfs -o ro,uid=5,gid=6,mask=640,dirmask=750 /dev/gpt/fat16 $D
check "... owner" is "$(owner $D/README.TXT)" 5:6
check "... file mode" is "$(perm $D/README.TXT)" 640
check "... directory mode" is "$(perm $D/sub)" 750
check "... the read-only attribute still clears write" is "$(perm $D/readonly.txt)" 440
umount $D
check "shortnames shows 8.3 names" mount -t msdosfs -o ro,shortnames /dev/gpt/fat16 $D
check "... the alias" eval "ls $D | grep -qx 'ALONGF~1.TEX'"
check "... not the long name" not eval "ls $D | grep -q 'a long file name'"
umount $D
check "an unknown option is refused" not mount -t msdosfs -o ro,bogus=1 /dev/gpt/fat16 $D
check "a device that isn't FAT is refused" not mount -t msdosfs -o ro /dev/gpt/rootfs $D
check "a missing device is refused" not mount -t msdosfs -o ro /dev/gpt/nosuch $D
mount -t msdosfs -o ro /dev/gpt/fat16 $D
check "the same device twice is refused" not mount -t msdosfs -o ro /dev/gpt/fat16 /tmp/fat12
check "kern.utc_offset moves the times (+60 min)" sysctl kern.utc_offset=60
check "... an hour earlier in UTC" is "$(mtime $D/README.TXT)" $((STAMP - 3600))
sysctl kern.utc_offset=0 > /dev/null
check "statfs counts clusters" eval "df -k $D | tail -1 | awk '{exit !(\$2 > 20000)}'"
umount $D

# --- Writing -----------------------------------------------------------------------------------
for t in 12 16 32; do
	D=/tmp/fat$t
	check "FAT$t: mounts read-write" mount -t msdosfs /dev/gpt/fat$t $D
	check "FAT$t: create and read back" eval "echo new > $D/new.txt && [ \"\$(cat $D/new.txt)\" = new ]"
	check "FAT$t: ... a lower-case 8.3 name keeps its case" eval "ls $D | grep -qx new.txt"
	check "FAT$t: a long name" eval "echo x > '$D/A Long Name, With Commas.data' && ls $D | grep -qx 'A Long Name, With Commas.data'"
	check "FAT$t: a UTF-8 name" eval "echo u > $D/naïve.txt && [ \"\$(cat $D/NAÏVE.TXT)\" = u ]"
	check "FAT$t: a name only differing in case is the same file" eval "echo again > $D/NEW.TXT && [ \"\$(cat $D/new.txt)\" = again ] && [ \$(ls $D | grep -ci '^new.txt\$') = 1 ]"
	check "FAT$t: a name FAT can't hold is refused" not eval "echo > '$D/a:b'"
	check "FAT$t: appending" eval "echo more >> $D/new.txt && [ \$(wc -l < $D/new.txt) = 2 ]"
	check "FAT$t: a file over many clusters" eval "cp /tmp/big.expected $D/big2 && cmp $D/big2 /tmp/big.expected"
	check "FAT$t: overwriting in place" eval "printf 'XYZ' | dd bs=1 seek=100000 1<>$D/big2 2>/dev/null && is \"\$(dd if=$D/big2 bs=1 skip=100000 count=3 2>/dev/null)\" XYZ && is \$(field $D/big2 2) 288894"
	check "FAT$t: truncating" eval ": > $D/big2 && [ ! -s $D/big2 ]"
	check "FAT$t: growing with truncate reads zeros" eval "truncate -s 70000 $D/big2 && [ \$(field $D/big2 2) = 70000 ] && zeros_at $D/big2 69990 4"
	check "FAT$t: writing past the end leaves zeros between" eval "printf 'E' | dd of=$D/sparse bs=1 seek=9000 2>/dev/null && [ \$(field $D/sparse 2) = 9001 ] && zeros_at $D/sparse 4000 2"
	check "FAT$t: mkdir and a file in it" eval "mkdir $D/newdir && echo in > $D/newdir/f && [ \"\$(cat $D/newdir/f)\" = in ]"
	check "FAT$t: ... nested" eval "mkdir -p $D/newdir/a/b/c && [ -d $D/NEWDIR/A/B/C ]"
	check "FAT$t: ... its .. leads back" is "$(cd $D/newdir/a/b/c/.. && /bin/pwd)" "$D/newdir/a/b"
	check "FAT$t: rename within a directory" eval "mv $D/new.txt $D/renamed.txt && [ \"\$(head -n 1 $D/renamed.txt)\" = again ] && [ ! -e $D/new.txt ]"
	check "FAT$t: rename across directories" eval "mv $D/renamed.txt $D/newdir/a/moved.txt && [ -f $D/newdir/a/moved.txt ]"
	check "FAT$t: rename over a file" eval "echo old > $D/target && echo src > $D/source && mv $D/source $D/target && [ \"\$(cat $D/target)\" = src ] && [ ! -e $D/source ]"
	check "FAT$t: rename a directory across" eval "mv $D/newdir/a/b $D/b2 && [ -d $D/b2/c ] && [ \"\$(cd $D/b2/c/../.. && /bin/pwd)\" = $D ]"
	check "FAT$t: rmdir of a non-empty directory is refused" not rmdir $D/newdir
	check "FAT$t: rm and rmdir" eval "rm -r $D/b2 $D/newdir && [ ! -e $D/newdir ]"
	check "FAT$t: a removed file stays readable while open" eval "exec 3< $D/target; rm $D/target; [ \"\$(cat <&3)\" = src ]; exec 3<&-"
	check "FAT$t: 200 new files in a directory (it grows)" eval "mkdir $D/lots && i=0; while [ \$i -lt 200 ]; do echo \$i > $D/lots/a_long_file_name_\$i; i=\$((i+1)); done; [ \$(ls $D/lots | wc -l) = 200 ] && [ \"\$(cat $D/lots/a_long_file_name_199)\" = 199 ]"
	check "FAT$t: chmod a-w sets read-only" eval "chmod a-w $D/sparse && [ \$(perm $D/sparse) = 555 ] && chmod u+w $D/sparse && [ \$(perm $D/sparse) = 755 ]"
	check "FAT$t: chown to another owner is refused" not chown 5 $D/sparse
	check "FAT$t: a write sets the modification time" eval "[ \$(mtime $D/sparse) -gt $STAMP ]"
	check "FAT$t: links are refused" not ln $D/sparse $D/hard
	check "FAT$t: symbolic links are refused" not ln -s sparse $D/soft
	check "FAT$t: unmounts" umount $D
	check "FAT$t: fsck_msdosfs -n finds it clean after" fsck_msdosfs -n /dev/gpt/fat$t
	check "FAT$t: ... and marked clean" eval "[ $t = 12 ] || fsck_msdosfs -n -C /dev/gpt/fat$t | grep -q clean"
	check "FAT$t: remounted, everything is there" eval "mount -t msdosfs -o ro /dev/gpt/fat$t $D && [ \$(ls $D/lots | wc -l) = 200 ] && [ \"\$(cat $D/NAÏVE.TXT)\" = u ] && umount $D"
done

# --- mount_msdosfs's flags --------------------------------------------------------------------
D=/tmp/fat16
check "mount_msdosfs -u user -m 600 -M 700" mount_msdosfs -o ro -u user -m 600 -M 700 /dev/gpt/fat16 $D
check "... the user's uid" eval "[ \$(field $D/README.TXT 5) = \$(id -u user) ]"
check "... modes" eval "[ \$(perm $D/README.TXT) = 600 ] && [ \$(perm $D/sub) = 700 ]"
umount $D
check "mount_msdosfs -D CP932 (a double-byte code page)" mount_msdosfs -D cp932 /dev/gpt/fat16 $D
check "... a CJK name gets a CJK short name" eval "echo j > $D/日本.txt && mount | grep -q fat16"
umount $D
check "... which reads back with -D CP932 -s" eval "mount_msdosfs -o ro -s -D CP932 /dev/gpt/fat16 $D && ls $D | grep -qx '日本.TXT'"
umount $D
check "-D with no such code page is refused" not mount_msdosfs -o ro -D CP99999 /dev/gpt/fat16 $D
check "-L with a code set other than UTF-8 is refused" not mount_msdosfs -o ro -L ru_RU.KOI8-R /dev/gpt/fat16 $D
check "-L with UTF-8 is taken" eval "mount_msdosfs -o ro -L en_US.UTF-8 /dev/gpt/fat16 $D && umount $D"

# --- A volume not marked clean ---------------------------------------------------------------
D=/tmp/fat16
mount -t msdosfs /dev/gpt/fat16 $D
echo crash > $D/crash.txt
sync
# Unmounting would mark it clean: a forced reboot's state is had by copying the device while
# mounted, then checking the copy.
check "the device can't be written while mounted read-write" not dd if=/dev/zero of=/dev/gpt/fat16 bs=512 count=1 seek=100 conv=notrunc 2>/dev/null
dd if=/dev/gpt/fat16 of=/tmp/dirty.img bs=64k 2>/dev/null
umount $D
check "a copy taken while mounted isn't clean" not eval "fsck_msdosfs -p /tmp/dirty.img | grep -q '^/tmp/dirty.img: clean'"
check "fsck_msdosfs -p marks it clean" eval "fsck_msdosfs -p -f /tmp/dirty.img && fsck_msdosfs -p /tmp/dirty.img | grep -q clean"

# The real device made unclean: FAT 0's entry 1 (bytes 514-515 of this FAT16, one reserved
# sector) without its clean bit, 0x8000.
printf '\377\177' | dd bs=1 seek=514 1<>/dev/gpt/fat16 2>/dev/null
check "an unclean volume mounts read-only" eval "mount -t msdosfs /dev/gpt/fat16 $D && mount | grep 'fat16' | grep -q read-only"
check "... and can't be written" not eval "echo x > $D/nope"
umount $D
check "mount -f mounts it read-write" eval "mount -f -t msdosfs /dev/gpt/fat16 $D && echo forced > $D/forced.txt && umount $D"
check "... and unmounting marks it clean" eval "fsck_msdosfs -p /dev/gpt/fat16 | grep -q clean"
check "... the write is there" eval "mount -t msdosfs -o ro /dev/gpt/fat16 $D && [ \"\$(cat $D/forced.txt)\" = forced ] && umount $D"

# --- newfs_msdos -------------------------------------------------------------------------------
check "newfs_msdos FAT12 into a file" newfs_msdos -F 12 -C 2m /tmp/n12.img
check "newfs_msdos FAT16" newfs_msdos -F 16 -C 20m -L DATA /tmp/n16.img
check "newfs_msdos FAT32" newfs_msdos -F 32 -C 40m /tmp/n32.img
check "... fsck_msdosfs agrees" eval "fsck_msdosfs -n /tmp/n12.img && fsck_msdosfs -n /tmp/n16.img && fsck_msdosfs -n /tmp/n32.img"

echo "msdosfs-smoke: $fail failed"
[ $fail -eq 0 ]
