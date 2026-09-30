#!/sbin/init_sh
#
# On-target check for the loopback interface, seeded as /usr/tests/net/run.sh with the
# loopback-smoke program next to it. Prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "loopback-run: ok: $_desc"
	else
		echo "loopback-run: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}

check "loopback-smoke" /usr/tests/net/loopback-smoke
check "ping 127.0.0.1" ping -c 1 -W 5 127.0.0.1
check "ping the host's own address" ping -c 1 -W 5 10.0.2.15

echo "loopback-run: $fail failed"
[ $fail -eq 0 ]
