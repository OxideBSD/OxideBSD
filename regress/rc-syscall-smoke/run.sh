#!/sbin/init_sh
#
# On-target check for rc(8) and its tools (INIT.md, INIT_SH.md §8.3), seeded as
# /usr/tests/rc/run.sh. Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "rc-smoke: ok: $_desc"
	else
		echo "rc-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
contains() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
# Waits up to 10 seconds for a command to succeed.
eventually() {
	_i=0
	while [ $_i -lt 10 ]; do
		"$@" && return 0
		sleep 1
		_i=$((_i + 1))
	done
	return 1
}

# --- rcorder --------------------------------------------------------------------------------
order=
for f in $(rcorder /etc/rc.d/*); do
	order="$order ${f##*/}"
done
check "rcorder orders /etc/rc.d" [ "$order" = " sysctl tmp cleanvar FILESYSTEMS hostname NETWORKING SERVERS DAEMON LOGIN" ]

mkdir -p /tmp/rcd
printf '#!/sbin/init_sh\n# PROVIDE: a\n# REQUIRE: b\n' > /tmp/rcd/a
printf '#!/sbin/init_sh\nservice b {\n\tkeyword shutdown\n}\n' > /tmp/rcd/b
check "rcorder reads service blocks" [ "$(rcorder /tmp/rcd/a /tmp/rcd/b)" = "$(printf '/tmp/rcd/b\n/tmp/rcd/a')" ]
check "rcorder -k keeps only keyword matches" [ "$(rcorder -k shutdown /tmp/rcd/a /tmp/rcd/b)" = /tmp/rcd/b ]
printf '# PROVIDE: b\n# REQUIRE: a\n' > /tmp/rcd/b
check "rcorder exits 1 on a cycle" not rcorder /tmp/rcd/a /tmp/rcd/b

# --- /etc/rc --------------------------------------------------------------------------------
echo 'hostname="rcsmoke"' > /etc/rc.conf.local
: > /var/run/stale.pid
: > /etc/nologin
out=$(/sbin/init_sh /etc/rc autoboot 2>&1)
status=$?
echo "$out"
check "rc exits 0" [ $status -eq 0 ]
check "rc reports no failures" not contains "$out" "failed"
check "rc.d/hostname sets the host name" [ "$(uname -n)" = rcsmoke ]
check "rc.d/hostname says so" contains "$out" "Setting hostname: rcsmoke."
check "rc.d/cleanvar empties /var/run" [ ! -e /var/run/stale.pid ]
check "rc.d/cleanvar removes a stale /etc/nologin" [ ! -e /etc/nologin ]

# --- rc.subr built-ins, through a classic rc.d script -----------------------------------------
cat > /etc/rc.d/smoked <<'EOF'
#!/sbin/init_sh
#
# PROVIDE: smoked
# KEYWORD: shutdown

. /etc/rc.subr

name="smoked"
rcvar="smoked_enable"
command="/bin/sleep"
command_args="1000 &"
pidfile="/var/run/smoked.pid"
start_postcmd='echo $! > $pidfile'
extra_commands="hello"
hello_cmd='echo "hello from $name"'

load_rc_config $name
: ${smoked_enable:=NO}
run_rc_command "$1"
EOF
chmod 755 /etc/rc.d/smoked
out=$(/etc/rc.d/smoked start 2>&1)
check "a disabled service doesn't start" [ ! -e /var/run/smoked.pid ]
check "and says how to start it" contains "$out" "Cannot 'start' smoked"
check "onestart" /etc/rc.d/smoked onestart
check "onestatus: running" /etc/rc.d/smoked onestatus
check "onestart again fails: already running" not /etc/rc.d/smoked onestart
check "extra command" [ "$(/etc/rc.d/smoked onehello)" = "hello from smoked" ]
check "onestop" /etc/rc.d/smoked onestop
check "onestatus: stopped" not /etc/rc.d/smoked onestatus
echo 'smoked_enable="YES"' >> /etc/rc.conf.local
check "an enabled service starts" /etc/rc.d/smoked start
check "rcvar" contains "$(/etc/rc.d/smoked rcvar)" 'smoked_enable="YES"'
check "rc.shutdown exits 0" /sbin/init_sh /etc/rc.shutdown
check "rc.shutdown stopped the shutdown-keyword service" not /etc/rc.d/smoked status
echo 'smoked_enable="sure"' >> /etc/rc.conf.local
out=$(/etc/rc.d/smoked start 2>&1)
check "a bad YES/NO value warns" contains "$out" 'smoked_enable="sure" is not YES or NO'
check "and counts as NO" contains "$out" "Cannot 'start' smoked"
echo 'echo not an assignment' >> /etc/rc.conf.local
out=$(/etc/rc.d/smoked rcvar 2>&1)
check "a command in rc.conf is ignored with a warning" contains "$out" "rc.conf.local:4: not an assignment"
rm -f /etc/rc.d/smoked /etc/rc.conf.local

# --- shutdown -----------------------------------------------------------------------------
check "shutdown -C with nothing pending fails" not shutdown -C
check "shutdown rejects a bad time" not shutdown -r 25:00
check "shutdown -r +5 goes to the background" shutdown -r +5 "rc smoke test"
check "and records its pid" eventually [ -s /var/run/shutdown.pid ]
check "and blocks logins inside five minutes" eventually [ -e /etc/nologin ]
check "a second shutdown is refused" not shutdown -h +10
check "shutdown -C cancels it" shutdown -C
check "the pid file goes away" eventually [ ! -e /var/run/shutdown.pid ]
check "and so does nologin" eventually [ ! -e /etc/nologin ]
# The warning itself goes to /dev/console, which a script can't read back; nologin carries the
# same message.
check "shutdown -k now succeeds" shutdown -k now "just kidding"
check "and its message is in nologin" contains "$(cat /etc/nologin 2>/dev/null)" "just kidding"
check "shutdown -k leaves logins blocked" [ -e /etc/nologin ]
rm -f /etc/nologin

# --- reboot / halt / poweroff (argument handling only: success would end the test) ---------
check "reboot rejects an unknown flag" not reboot -x
check "halt rejects -n without -q" not halt -n
check "halt and poweroff are reboot" [ /sbin/halt -ef /sbin/reboot ]

echo "rc-smoke: $fail failure(s)"
[ "$fail" -eq 0 ]
