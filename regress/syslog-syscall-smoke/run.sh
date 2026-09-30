#!/sbin/init_sh
#
# On-target check for system logging (SYSLOG.md §12.2), seeded as /usr/tests/syslog/run.sh.
# Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "syslog-smoke: ok: $_desc"
	else
		echo "syslog-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
# Whether file $1 has a line matching basic regular expression $2.
has() { grep -q -- "$2" "$1" 2>/dev/null; }
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
running() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
mode_is() { ls -l "$2" | grep -q "^$1"; }
klog_busy() { ! (exec 3</dev/klog) 2>/dev/null; }
dmesg_has() { dmesg | grep -q -- "$1"; }

# --- The boot path: rc.d scripts and the default configuration -----------------------------
/etc/rc.d/newsyslog onestart > /dev/null
check "newsyslog -CN creates /var/log/messages" [ -f /var/log/messages ]
check "newsyslog -CN creates /var/log/auth.log, mode 600" mode_is -rw------- /var/log/auth.log
/etc/rc.d/syslogd onestart > /dev/null
pid=$(cat /var/run/syslog.pid 2>/dev/null)
check "rc.d/syslogd starts syslogd" running "$pid"
check "/dev/log is a socket" [ -S /dev/log ]
check "/dev/klog refuses a second open" klog_busy
logger -p auth.info -t smoke "auth message"
check "auth.info from logger lands in /var/log/auth.log" eventually has /var/log/auth.log "smoke\[[0-9]*\]: auth message"
check "kernel messages land in /var/log/messages" eventually has /var/log/messages " kernel: "
check "dmesg shows boot messages" dmesg_has "oxfs"
/etc/rc.d/syslogd onestop > /dev/null
check "rc.d/syslogd stops syslogd" not running "$pid"
check "syslogd removes /dev/log" [ ! -e /dev/log ]

# --- Routing, with a configuration of our own ----------------------------------------------
mkdir -p /tmp/sl
cat > /tmp/sl/syslog.conf << 'EOF'
*.info;local3.none;local4.none		/tmp/sl/all
kern.*					/tmp/sl/kern
syslog.info					/tmp/sl/self
local3.!info				/tmp/sl/neg
!blocked
*.*					/tmp/sl/prog
!*
local4.*				|cat >> /tmp/sl/pipe
local5.*				/tmp/sl/missing
:msg, contains, "needle"
*.*					/tmp/sl/prop
EOF
for f in all kern neg prog prop self; do
	: > /tmp/sl/$f
done
syslogd -s -m 0 -f /tmp/sl/syslog.conf -P /tmp/sl/pid
pid=$(cat /tmp/sl/pid 2>/dev/null)
check "syslogd -f starts" running "$pid"
check "syslogd logs its start as syslog.info" eventually has /tmp/sl/self "syslogd: restart"

logger -p local3.debug -t neg "debug here"
logger -p local3.err -t neg "err here"
logger -p user.info -t blocked "blocked message"
logger -p user.info -t other "other message"
logger -p local4.info -t piped "through the pipe"
logger -p local5.info -t nowhere "to a missing file"
logger "a needle in here"
logger "only hay"
logger -p kern.err -t fake "claims to be the kernel"
logger -t credtest "no pid given"
logger -i -t withpid "pid given"
printf 'same\nsame\nsame\ndifferent\n' | logger -t rep
logger -t barrier "last one"
check "messages arrive in order" eventually has /tmp/sl/all "barrier\[[0-9]*\]: last one"

check "local3.!info takes local3.debug" has /tmp/sl/neg "neg\[[0-9]*\]: debug here"
check "local3.!info refuses local3.err" not has /tmp/sl/neg "err here"
check "local3.none keeps local3 out of a *.info rule" not has /tmp/sl/all "neg\["
check "a !prog block takes its program" has /tmp/sl/prog "blocked\[[0-9]*\]: blocked message"
check "a !prog block refuses other programs" not has /tmp/sl/prog "other message"
check "a pipe action gets its lines" eventually has /tmp/sl/pipe "piped\[[0-9]*\]: through the pipe"
check "a missing log file is not created without -C" [ ! -e /tmp/sl/missing ]
check "a property filter takes a match" has /tmp/sl/prop "a needle in here"
check "a property filter refuses the rest" not has /tmp/sl/prop "only hay"
check "kern from user space becomes user" not has /tmp/sl/kern "claims to be the kernel"
check "it is still logged, as user" has /tmp/sl/all "fake\[[0-9]*\]: claims to be the kernel"
check "a message without a pid gets the sender's" has /tmp/sl/all "credtest\[[0-9][0-9]*\]: no pid given"
check "logger -i gives its pid" has /tmp/sl/all "withpid\[[0-9][0-9]*\]: pid given"
check "repeats are counted" has /tmp/sl/all "last message repeated 2 times"
check "and the next message is written" has /tmp/sl/all "rep\[[0-9]*\]: different"

# SIGHUP reopens the files: a file moved away stops growing.
mv /tmp/sl/all /tmp/sl/all.moved
: > /tmp/sl/all
kill -HUP "$pid"
sleep 1
logger -t hup "after the reload"
check "SIGHUP reopens a moved file" eventually has /tmp/sl/all "hup\[[0-9]*\]: after the reload"
check "the moved file stops growing" not has /tmp/sl/all.moved "after the reload"

# newsyslog rotates, and tells syslogd through its pid file.
echo "/tmp/sl/all	600	3	*	*	-	/tmp/sl/pid" > /tmp/sl/newsyslog.conf
newsyslog -F -f /tmp/sl/newsyslog.conf
check "newsyslog -F rotates to all.0" has /tmp/sl/all.0 "after the reload"
check "newsyslog writes the turn-over message" has /tmp/sl/all "logfile turned over"
logger -t rotated "into the new file"
check "syslogd writes to the new file after rotation" eventually has /tmp/sl/all "rotated\[[0-9]*\]: into the new file"
check "the new file is mode 600" mode_is -rw------- /tmp/sl/all

kill "$pid"
check "SIGTERM stops syslogd" eventually not running "$pid"
check "syslogd removes its pid file" [ ! -e /tmp/sl/pid ]

echo "syslog-smoke: $fail failed"
[ $fail -eq 0 ]
