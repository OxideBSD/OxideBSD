#!/sbin/init_sh
#
# On-target checks of the kernel's process and descriptor rules, installed as
# /usr/tests/kern/run.sh next to kern-smoke (regress/kern-smoke). Runs as root; each section
# prints one line per check and exits 0 if all of its checks pass. Exits 0 if every section did.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
D=/usr/tests/kern

fail=0
for t in rlimit flock orphan sched users vm core proc inet kthread devctl; do
	if $D/kern-smoke $t; then
		echo "kern: ok: $t"
	else
		echo "kern: FAIL: $t"
		fail=$((fail + 1))
	fi
done
echo "kern: $fail failed"
exit $fail
