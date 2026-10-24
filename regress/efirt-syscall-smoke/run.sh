#!/sbin/init_sh
#
# On-target check for UEFI variables (EFIRT.md §8.2), installed as /usr/tests/efirt/run.sh: under
# OVMF, /dev/efi and efivar(8) list, read, write, append and delete a variable, and a write outside
# the allow-list is refused until machdep.efi.unsafe_writes is set. Runs as root; prints one line
# per check and exits 0 if all pass.

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

if [ "$fail" -ne 0 ]; then
	echo "efirt-smoke: $fail failed"
	exit 1
fi
echo "efirt-smoke: all passed"
