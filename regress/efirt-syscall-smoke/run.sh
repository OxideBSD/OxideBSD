#!/sbin/init_sh
#
# On-target check for UEFI variables (EFIRT.md §8.2), installed as /usr/tests/efirt/run.sh: under
# OVMF, /dev/efi and efivar(8) list, read, write, append and delete a variable, and a write outside
# the allow-list is refused until machdep.efi.unsafe_writes is set; and efibootmgr(8) makes, shows,
# changes and deletes a boot entry for a loader on the runner's empty EFI system partition,
# /dev/gpt/esptest. Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "efirt-smoke: ok: $_desc"
	else
		echo "efirt-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
has() { _w=$1; shift; "$@" 2>&1 | grep -q -- "$_w"; }
value() { efivar -A -N -n "$1" 2>&1; }

check "machdep.efi.runtime is 1" [ "$(sysctl -n machdep.efi.runtime)" = 1 ]
check "/dev/efi is root's alone" has "crw-------" ls -l /dev/efi
check "the list has OVMF's BootOrder" has "^8be4df61-93ca-11d2-aa0d-00e098032b8c-BootOrder$" efivar -l
check "the list names the global GUID with -g" has "^global-BootOrder$" efivar -lg
check "BootOrder prints as a hex dump" has "^0000: " efivar -p -n global-BootOrder
check "a variable of OxideBSD's GUID is written" sh -c 'printf hello | efivar -w -n oxidebsd-SmokeTest'
check "and read back" [ "$(value oxidebsd-SmokeTest)" = hello ]
check "appended to" sh -c 'printf " world" | efivar -a -n oxidebsd-SmokeTest'
check "and read back whole" [ "$(value oxidebsd-SmokeTest)" = "hello world" ]
check "deleted" efivar -D -n oxidebsd-SmokeTest
check "and gone" not efivar -q -n oxidebsd-SmokeTest
check "a write outside the allow-list is refused" has "Operation not permitted" sh -c 'printf x | efivar -w -n shell-OxideBSDSmoke'
check "machdep.efi.unsafe_writes=1 allows it" sh -c 'sysctl machdep.efi.unsafe_writes=1 > /dev/null && printf x | efivar -w -n shell-OxideBSDSmoke'
check "and it reads back" [ "$(value shell-OxideBSDSmoke)" = x ]
check "and is deleted" efivar -D -n shell-OxideBSDSmoke
check "unsafe_writes goes back to 0" sh -c 'sysctl machdep.efi.unsafe_writes=0 > /dev/null && [ "$(sysctl -n machdep.efi.unsafe_writes)" = 0 ]'

# efibootmgr(8): an entry for a loader on a fresh ESP.
esp=/mnt/esp
loader=$esp/EFI/OxideBSD/BOOTX64.EFI
check "the test ESP is formatted and mounted" sh -c "newfs_msdos /dev/gpt/esptest > /dev/null && mkdir -p $esp && mount -t msdosfs /dev/gpt/esptest $esp && mkdir -p $esp/EFI/OxideBSD && echo limine > $loader"
check "efibootmgr -u gives the loader's device path" has '^HD(1,GPT,.*)/\\EFI\\OxideBSD\\BOOTX64.EFI$' efibootmgr -u $loader
check "a dry run makes nothing" sh -c "efibootmgr -c -D -a -l $loader -L OxideBSD-smoke > /dev/null && ! efibootmgr -v | grep -q OxideBSD-smoke"
made=$(efibootmgr -c -a -l $loader -L OxideBSD-smoke 2>&1)
n=$(echo "$made" | sed -n 's/^Boot\([0-9A-F]\{4\}\)\*.*/\1/p')
check "efibootmgr -c -a makes an active entry ($made)" [ -n "$n" ]
check "and puts it first in BootOrder" has "^BootOrder  : $n" efibootmgr
check "and lists it" has "^ Boot$n\* OxideBSD-smoke$" efibootmgr
check "-v shows its device path and where it is here" sh -c "efibootmgr -v | grep -q 'HD(1,GPT,' && efibootmgr -v | grep -q '$loader'"
check "efivar decodes it" has "OxideBSD-smoke" efivar --load-option -n global-Boot$n
check "-A deactivates it" sh -c "efibootmgr -A -b $n && efibootmgr | grep -q '^ Boot$n  OxideBSD-smoke$'"
check "-n sets BootNext" sh -c "efibootmgr -n -b $n && efibootmgr | grep -q '^BootNext   : $n$'"
check "-N deletes it" sh -c "efibootmgr -N && ! efibootmgr | grep -q '^BootNext'"
check "-t sets the timeout" sh -c "efibootmgr -t 7 && efibootmgr | grep -q '^Timeout    : 7 seconds$'"
check "-T deletes it" sh -c "efibootmgr -T && ! efibootmgr | grep -q '^Timeout'"
check "-f asks for the setup screens" sh -c "efibootmgr -f && efivar -p -n global-OsIndications | grep -q '^0000: 01 '"
check "-F takes that back" sh -c "efibootmgr -F && efivar -p -n global-OsIndications | grep -q '^0000: 00 '"
others=$(efibootmgr | sed -n 's/^BootOrder  : //p' | tr -d ' ' | sed "s/^$n,\{0,1\}//")
check "-o reorders BootOrder" sh -c "efibootmgr -o $others,$n && efibootmgr | grep -q '^BootOrder  : .*$n$'"
check "-B deletes the entry, from BootOrder too" sh -c "efibootmgr -B -b $n && ! efibootmgr -v | grep -q OxideBSD-smoke && ! efibootmgr | grep -q '^BootOrder.*$n'"
check "an entry outside the ESP is refused" has "not on a mounted EFI system partition" efibootmgr -c -l /etc/rc
umount $esp

if [ "$fail" -ne 0 ]; then
	echo "efirt-smoke: $fail failed"
	exit 1
fi
echo "efirt-smoke: all passed"
