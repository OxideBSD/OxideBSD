#!/sbin/init_sh
#
# On-target check for CD drives on IDE and cd9660 (INSTALLER.md §5.3, §6), seeded as
# /usr/tests/cd9660/run.sh. The runner puts scripts/mkcd9660testimg.sh's discs in the IDE drives:
# ide0 rr.iso (Rock Ridge + Joliet, a FAT image as MBR partition 2), ide1 plain.iso, ide2
# joliet.iso, ide3 empty; the system's disk is virt0. On virtio-scsi: scsi0 the boot medium,
# scsi1 rr.iso again, scsi2 a disk of 4096-byte sectors (GPT partition `k4`), scsi3 a blank disk.
# On AHCI, named by port: sata0.0 a 64 MiB disk (GPT partition `satatest`), sata0.2 rr.iso,
# sata0.4 a 130 GiB disk, sata1.5 (the second controller's) an empty drive. Runs as root; prints
# one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "cd9660-smoke: ok: $_desc"
	else
		echo "cd9660-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
is() { [ "$1" = "$2" ] || { echo "  got '$1', want '$2'"; return 1; }; }
# stat(1) here is BusyBox's without -c: its terse line's fields (name size blocks mode(hex) uid
# gid dev ino nlink major minor atime mtime ctime ...). Names without spaces only.
field() { stat -t "$1" | awk -v f="$2" '{print $f}'; }
perm() { printf '%o' $(( 0x$(field "$1" 4) & 0777 )); }
mounted() { grep -q " $1 cd9660 " /proc/mounts; }
mounted_ro() { grep " $1 cd9660 " /proc/mounts | grep -q "[ ,]ro[ ,]"; }
disk_sysctl() { sysctl -n "kern.disk.$1.$2" 2>&1; }
big_ok() { is "$(sha256sum "$1/$2" | cut -d' ' -f1)" "$(cat "$1/$3")"; }
sector_round_trip() {
	printf '%s' "$2" | dd of="$1" bs=512 seek="$3" conv=notrunc,sync 2>/dev/null &&
		[ "$(dd if="$1" bs=512 skip="$3" count=1 2>/dev/null | tr -d '\000')" = "$2" ]
}
sum() { sha256sum | cut -d' ' -f1; }

mkdir -p /tmp/cd/rr /tmp/cd/joliet /tmp/cd/plain /tmp/cd/empty /tmp/cd/esp

# --- The drives -------------------------------------------------------------------------------
check "kern.disks lists the CD drives" is "$(sysctl -n kern.disks)" "virt0 ide0 ide1 ide2 ide3 sata0.0 sata0.2 sata0.4 sata1.5 scsi0 scsi1 scsi2 scsi3"
check "ide0 is a cd" is "$(disk_sysctl ide0 kind)" cd
check "... of 2048-byte sectors" is "$(disk_sysctl ide0 sectorsize)" 2048
check "... its model the drive's" is "$(disk_sysctl ide0 model)" "QEMU DVD-ROM"
check "... and its size a whole number of sectors" sh -c '[ $(( $(sysctl -n kern.disk.ide0.size) % 2048 )) = 0 ] && [ $(sysctl -n kern.disk.ide0.size) -gt 0 ]'
check "the empty drive is a cd of size 0" is "$(disk_sysctl ide3 kind) $(disk_sysctl ide3 size)" "cd 0"
for d in ide0 ide1 ide2 ide3 ide0s1 ide0s2; do
	check "/dev/$d is there" [ -c /dev/$d ]
done
check "a CD can't be opened for writing" not sh -c 'printf x | dd of=/dev/ide0 conv=notrunc 2>/dev/null'
check "the empty drive reads nothing" is "$(dd if=/dev/ide3 bs=2048 count=1 2>/dev/null | wc -c | tr -d ' ')" 0
check "ide0 reads its volume descriptor" sh -c 'dd if=/dev/ide0 bs=2048 skip=16 count=1 2>/dev/null | grep -q CD001'
check "... and a 512-byte sector inside a CD sector" sh -c '[ "$(dd if=/dev/ide0 bs=512 skip=65 count=1 2>/dev/null | od -An -tx1)" = "$(dd if=/dev/ide0 bs=2048 skip=16 count=1 2>/dev/null | dd bs=512 skip=1 count=1 2>/dev/null | od -An -tx1)" ]'
check "the hybrid's partition 2 is the FAT image" sh -c 'dd if=/dev/ide0s2 bs=512 count=1 2>/dev/null | grep -q FAT12'
check "... which msdosfs mounts read-only (mount -r)" mount -r -t msdosfs /dev/ide0s2 /tmp/cd/esp
check "... and reads" is "$(cat /tmp/cd/esp/hello.txt 2>&1)" esp
umount /tmp/cd/esp

# --- Rock Ridge -------------------------------------------------------------------------------
R=/tmp/cd/rr
check "mount -t cd9660 /dev/ide0" mount -t cd9660 /dev/ide0 $R
check "... is read-only" mounted_ro $R
check "a file reads" is "$(cat $R/README.TXT)" "hello, ISO 9660"
check "a big file reads whole" big_ok $R BIG.BIN BIG.SHA
check "an empty file is empty" is "$(field $R/EMPTY.TXT 2)" 0
check "a long mixed-case name" is "$(cat "$R/Mixed Case Long Name.text")" mixed
check "a directory of many blocks" is "$(ls $R/MANY | wc -l | tr -d ' ')" 300
check "... and a file in it" is "$(cat $R/MANY/F299.TXT)" 299
check "a deep directory" is "$(cat $R/D1/D2/D3/D4/D5/D6/D7/D8/D9/DEEP.TXT)" deep
check ".. goes up" is "$(cd $R/SUB/DEEPER/.. && ls)" DEEPER
check "a symbolic link" [ -L $R/link ]
check "... to its target" is "$(readlink $R/link)" README.TXT
check "... followed" is "$(cat $R/link)" "hello, ISO 9660"
check "a relative link upwards" is "$(readlink $R/SUB/DEEPER/uplink)" ../../README.TXT
check "... followed" is "$(cat $R/SUB/DEEPER/uplink)" "hello, ISO 9660"
check "modes are Rock Ridge's" is "$(perm $R/mode640.txt)" 640
check "owners are Rock Ridge's" is "$(field $R/OWNER.TXT 5)" "$(cat $R/OWNER.TXT)"
check "times are Rock Ridge's" is "$(field $R/README.TXT 13)" 1760000000
check "a directory is one" [ -d $R/SUB ]
check "find walks the tree" is "$(find $R | wc -l | tr -d ' ')" 325
check "files can't be made" not touch $R/new 2>/dev/null
check "... nor written" not sh -c "echo x >> $R/README.TXT" 2>/dev/null
check "... nor removed" not rm -f $R/README.TXT 2>/dev/null
check "mount -u -w is refused" not mount -u -w $R 2>/dev/null
check "a mounted disc's drive is busy for a second mount" not mount -t cd9660 /dev/ide0 /tmp/cd/joliet 2>/dev/null
check "it unmounts" umount $R
check "... and is gone" not mounted $R

# --- Joliet -----------------------------------------------------------------------------------
check "norrip mounts the Joliet tree" mount -t cd9660 -o norrip /dev/ide0 $R
check "... long mixed-case names" is "$(cat "$R/Mixed Case Long Name.text")" mixed
check "... no Rock Ridge modes" is "$(perm $R/mode640.txt)" 555
umount $R
J=/tmp/cd/joliet
check "a Joliet-only disc mounts" mount -t cd9660 /dev/ide2 $J
check "... long mixed-case names" is "$(cat "$J/Mixed Case Long Name.text")" mixed
check "... a big file reads whole" big_ok $J BIG.BIN BIG.SHA
check "... a deep directory" is "$(cat $J/D1/D2/D3/D4/D5/D6/D7/D8/D9/DEEP.TXT)" deep
check "... owned by root, mode 0555" is "$(field $J/README.TXT 5) $(perm $J/README.TXT)" "0 555"
umount $J

# --- Plain ISO 9660 ---------------------------------------------------------------------------
P=/tmp/cd/plain
check "a plain disc mounts" mount -t cd9660 /dev/ide1 $P
check "... names in lower case, versions dropped" is "$(cat $P/readme.txt)" "hello, ISO 9660"
check "... 8.3 names" is "$(cat $P/mixed_ca.tex)" mixed
check "... a name with no extension" is "$(cat $P/noext)" noext
check "... and no symbolic links (no Rock Ridge to keep them)" [ ! -e $P/link ]
check "... a big file reads whole" big_ok $P big.bin big.sha
check "... subdirectories" is "$(cat $P/sub/deeper/kernel.txt)" kernel
umount $P
check "norrip,nojoliet shows the plain names of a Rock Ridge disc" mount -t cd9660 -o norrip,nojoliet /dev/ide0 $P
check "... in lower case" is "$(cat $P/readme.txt)" "hello, ISO 9660"
umount $P

# --- virtio-scsi ------------------------------------------------------------------------------
S=/tmp/cd/scsi
mkdir -p $S /tmp/cd/boot
check "scsi0 and scsi1 are cds" is "$(disk_sysctl scsi0 kind) $(disk_sysctl scsi1 kind)" "cd cd"
check "... scsi2 and scsi3 disks" is "$(disk_sysctl scsi2 kind) $(disk_sysctl scsi3 kind)" "disk disk"
check "scsi0's model is the drive's" is "$(disk_sysctl scsi0 model)" "QEMU QEMU CD-ROM"
check "the boot medium mounts" mount -t cd9660 /dev/scsi0 /tmp/cd/boot
check "... with the kernel on it" [ -s /tmp/cd/boot/boot/kernel ]
check "... and Limine's configuration" [ -s /tmp/cd/boot/boot/limine/limine.conf ]
umount /tmp/cd/boot
check "a disc on virtio-scsi mounts" mount -t cd9660 /dev/scsi1 $S
check "... a big file reads whole" big_ok $S BIG.BIN BIG.SHA
check "... and Rock Ridge" is "$(readlink $S/link)" README.TXT
check "... and can't be written to" not sh -c 'printf x | dd of=/dev/scsi1 conv=notrunc 2>/dev/null'
umount $S
check "scsi2's sectors are 4096 bytes" is "$(disk_sysctl scsi2 sectorsize)" 4096
check "... its GPT in them" sh -c 'dd if=/dev/gpt/k4 bs=512 count=1 2>/dev/null | grep -q PART4K-MARKER'
check "... as scsi2p1" sh -c 'dd if=/dev/scsi2p1 bs=512 count=1 2>/dev/null | grep -q PART4K-MARKER'
# Sectors 12 and 13 share a 4096-byte sector: each write reads it, patches 512 bytes, writes it.
check "512-byte writes inside a 4096-byte sector" sh -c 'printf left | dd of=/dev/scsi2p1 bs=512 seek=12 conv=notrunc,sync 2>/dev/null && printf middle | dd of=/dev/scsi2p1 bs=512 seek=13 conv=notrunc,sync 2>/dev/null'
check "... read back" is "$(dd if=/dev/scsi2p1 bs=512 skip=13 count=1 2>/dev/null | tr -d '\000')" middle
check "... the second leaving the first" is "$(dd if=/dev/scsi2p1 bs=512 skip=12 count=1 2>/dev/null | tr -d '\000')" left
check "... and the partition's start" sh -c 'dd if=/dev/scsi2p1 bs=512 count=1 2>/dev/null | grep -q PART4K-MARKER'
check "scsi3 reads and writes" sh -c 'printf scsi3 | dd of=/dev/scsi3 bs=512 seek=777 conv=notrunc,sync 2>/dev/null && [ "$(dd if=/dev/scsi3 bs=512 skip=777 count=1 2>/dev/null | tr -d "\000")" = scsi3 ]'
check "... its size is 64 MiB" is "$(disk_sysctl scsi3 size)" 67108864

# --- AHCI -------------------------------------------------------------------------------------
A=/tmp/cd/sata
mkdir -p $A
check "sata0.0 is a disk" is "$(disk_sysctl sata0.0 kind)" disk
check "... its model the drive's" is "$(disk_sysctl sata0.0 model)" "QEMU HARDDISK"
check "... of 64 MiB" is "$(disk_sysctl sata0.0 size)" 67108864
check "sata0.2 is a cd" is "$(disk_sysctl sata0.2 kind)" cd
check "... its model the drive's" is "$(disk_sysctl sata0.2 model)" "QEMU DVD-ROM"
check "sata1.5 is an empty cd" is "$(disk_sysctl sata1.5 kind) $(disk_sysctl sata1.5 size)" "cd 0"
check "the empty port between has no disk" not sysctl -n kern.disk.sata0.1.kind 2>/dev/null
check "a port is a level of kern.disk" sh -c 'sysctl -a 2>/dev/null | grep -q "^kern.disk.sata0.4.size"'
for d in sata0.0 sata0.0p1 gpt/satatest sata0.2 sata0.2s1 sata0.2s2 sata0.4 sata1.5; do
	check "/dev/$d is there" [ -c /dev/$d ]
done
check "a drive's minor is its place" sh -c 'ls -l /dev/sata0.2 | grep -q " 251, *12032 "'
check "... on the second controller too" sh -c 'ls -l /dev/sata1.5 | grep -q " 251, *155392 "'
dd if=/dev/urandom of=/tmp/sata.bin bs=64k count=16 2>/dev/null
check "1 MiB written through gpt/satatest (several commands)" dd if=/tmp/sata.bin of=/dev/gpt/satatest bs=64k conv=notrunc 2>/dev/null
check "... reads back the same through sata0.0p1" is "$(dd if=/dev/sata0.0p1 bs=64k count=16 2>/dev/null | sum)" "$(sum < /tmp/sata.bin)"
check "newfs_msdos on it" sh -c 'newfs_msdos -F 16 /dev/gpt/satatest > /dev/null 2>&1'
check "... it mounts" mount -t msdosfs /dev/gpt/satatest $A
check "... takes a file" sh -c "echo on-sata > $A/hello.txt"
umount $A
check "... still there mounted again" sh -c "mount -t msdosfs /dev/gpt/satatest $A && [ \"\$(cat $A/hello.txt)\" = on-sata ]"
umount $A
check "sata0.4 reads and writes below 128 GiB (LBA48 drive)" sector_round_trip /dev/sata0.4 low-sata 1000
check "... above it" sector_round_trip /dev/sata0.4 high-sata 268435500
check "... at its last sector" sector_round_trip /dev/sata0.4 last-sata 272629759
check "... and not past its end" not sh -c 'printf x | dd of=/dev/sata0.4 bs=512 seek=272629760 conv=notrunc,sync 2>/dev/null'
check "a disc on AHCI mounts" mount -t cd9660 /dev/sata0.2 $A
check "... a big file reads whole" big_ok $A BIG.BIN BIG.SHA
check "... and Rock Ridge" is "$(readlink $A/link)" README.TXT
check "... and can't be written to" not sh -c 'printf x | dd of=/dev/sata0.2 conv=notrunc 2>/dev/null'
umount $A
check "the empty AHCI drive doesn't mount" not mount -t cd9660 /dev/sata1.5 $A 2>/dev/null

# --- AHCI hot plug (INSTALLER.md §5.3) ----------------------------------------------------------
# QEMU can't hot plug AHCI: debug.disk.unplug pulls sata0.0 out in software. Its port's task retires
# it (the mount on it unmounted by force, descriptors open on it failing), then finds the drive
# still there and registers it again under the same name.
logged() { dmesg | grep -qF "$1"; }
attached() { dmesg | grep -cF "[disk] sata0.0: attached"; }
check "sata0.0 mounted before the pull" mount -t msdosfs /dev/gpt/satatest $A
exec 3<> $A/hello.txt 4< /dev/sata0.0p1
check "debug.disk.unplug pulls it" sh -c 'sysctl debug.disk.unplug=sata0.0 > /dev/null'
n=0
while [ "$(attached)" = 0 ] && [ $n -lt 30 ]; do
	sleep 1
	n=$((n + 1))
done
check "the kernel logged it detached" logged "[disk] sata0.0: detached"
check "... its file system unmounted by force" logged "[disk] sata0.0: $A unmounted by force"
check "... gone from the mount list" not grep -q " $A msdosfs " /proc/mounts
check "a file open on it reads nothing (deadfs)" is "$(cat <&3)" ""
check "... and can't be written" not sh -c 'printf x | dd >&3 2>/dev/null'
check "its raw device open fails" not dd bs=512 count=1 <&4 > /dev/null 2>&1
exec 3<&- 4<&-
check "it came back, attached again" is "$(attached)" 1
check "... the same name in kern.disks" sh -c 'sysctl -n kern.disks | grep -qw sata0.0'
check "... its partition's nodes again" [ -c /dev/gpt/satatest ]
check "... its file system mounts, the file still on it" sh -c "mount -t msdosfs /dev/gpt/satatest $A && [ \"\$(cat $A/hello.txt)\" = on-sata ]"
umount $A
check "unplugging a disk not on AHCI is refused" not sysctl debug.disk.unplug=virt0 2>/dev/null
check "... and an unknown one" not sysctl debug.disk.unplug=nonesuch 2>/dev/null
check "kern.disk.root_lost is panic by default" is "$(sysctl -n kern.disk.root_lost)" panic
check "... takes eio" sh -c 'sysctl kern.disk.root_lost=eio > /dev/null && [ "$(sysctl -n kern.disk.root_lost)" = eio ]'
sysctl kern.disk.root_lost=panic > /dev/null
check "... and nothing else" not sysctl kern.disk.root_lost=maybe 2>/dev/null

# --- No disc ----------------------------------------------------------------------------------
check "the empty drive doesn't mount" not mount -t cd9660 /dev/ide3 /tmp/cd/empty 2>/dev/null
check "an unknown option is refused" not mount -t cd9660 -o bogus /dev/ide0 $R 2>/dev/null
check "a disk with no ISO 9660 on it doesn't mount" not mount -t cd9660 /dev/ide0s2 $R 2>/dev/null

echo "cd9660-smoke: $fail failed"
[ $fail -eq 0 ]
