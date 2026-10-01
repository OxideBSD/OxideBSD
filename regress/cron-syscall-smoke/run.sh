#!/sbin/init_sh
#
# On-target check for cron and crontab (CRON.md §9.2), seeded as /usr/tests/cron/run.sh.
# Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "cron-smoke: ok: $_desc"
	else
		echo "cron-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
# Whether file $1 has a line matching basic regular expression $2.
has() { grep -q -- "$2" "$1" 2>/dev/null; }
# Waits up to $1 seconds for a command to succeed.
within() {
	_n=$1
	shift
	_i=0
	while [ $_i -lt $_n ]; do
		"$@" && return 0
		sleep 1
		_i=$((_i + 1))
	done
	return 1
}
eventually() { within 10 "$@"; }
running() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
owner_is() { ls -l "$2" | grep -q "^[^ ]* *[0-9]* $1 "; }

# --- syslogd, which cron logs through -------------------------------------------------------
/etc/rc.d/newsyslog onestart > /dev/null
/etc/rc.d/syslogd onestart > /dev/null

# --- cron: @reboot and @every_second jobs from a cron.d table --------------------------------
mkdir -p /tmp/cron
chmod 1777 /tmp/cron
rm -f /var/run/cron.reboot
cat > /etc/cron.d/smoke <<'EOF'
@reboot		root	touch /tmp/cron/reboot; echo reboot-ran
@every_second	root	touch /tmp/cron/tick; echo tick
* * * * *	root	cat > /tmp/cron/input%first line%second line
EOF
cron -n &
cronpid=$!
check "cron runs" eventually running "$cronpid"
check "the @reboot job runs" eventually [ -f /tmp/cron/reboot ]
check "and is recorded in /var/run/cron.reboot" [ -f /var/run/cron.reboot ]
check "the @every_second job runs" eventually [ -f /tmp/cron/tick ]
check "a job's start is logged" eventually has /var/log/cron "(root) CMD (touch /tmp/cron/tick; echo tick)"
check "its output is logged" eventually has /var/log/cron "(root) CMDOUT (reboot-ran)"
check "a second cron refuses to start" not cron -n

# --- crontab ---------------------------------------------------------------------------------
cat > /tmp/cron/user.tab <<'EOF'
# a user's table
GREETING = hello from cron
@every_second	touch /tmp/cron/user-ran; echo "$GREETING as $USER"
EOF
check "crontab installs a user's table" crontab -u user /tmp/cron/user.tab
check "as /var/cron/tabs/user, mode 0600" eventually [ "$(ls -l /var/cron/tabs/user | cut -c1-10)" = "-rw-------" ]
crontab -u user -l > /tmp/cron/listed
check "crontab -l gives the table back" cmp -s /tmp/cron/user.tab /tmp/cron/listed
check "cron rereads the tables and runs the user's job" eventually [ -f /tmp/cron/user-ran ]
check "as the user" owner_is user /tmp/cron/user-ran
check "with the table's environment" eventually has /var/log/cron "(user) CMDOUT (hello from cron as user)"

printf '* * * * *\n61 * * * * true\n' > /tmp/cron/bad.tab
crontab -u user /tmp/cron/bad.tab 2> /tmp/cron/bad.err
check "an invalid table is refused" [ $? -ne 0 ]
check "naming the bad line" has /tmp/cron/bad.err "line 2: minute 61 is out of range"
crontab -u user -l > /tmp/cron/listed
check "and the installed one is left alone" cmp -s /tmp/cron/user.tab /tmp/cron/listed
check "a table for an unknown user is refused" not crontab -u nosuchuser /tmp/cron/user.tab
check "crontab -r -f removes it" crontab -u user -r -f
check "after which -l says there is none" not crontab -u user -l

# --- the % input -----------------------------------------------------------------------------
# A minute's job: runs at the next minute boundary.
check "a job's % text is its input" within 70 has /tmp/cron/input "second line"

# --- periodic --------------------------------------------------------------------------------
periodic daily
check "periodic daily writes /var/log/daily.log" has /var/log/daily.log "daily run output"
check "with the disk status" has /var/log/daily.log "Disk status:"
check "and the uptime" has /var/log/daily.log "Uptime:"
check "and the end of the run" has /var/log/daily.log "End of daily output"
check "the account files are backed up" [ -f /var/backups/master.passwd.bak ]
check "readable only by root" [ "$(ls -l /var/backups/master.passwd.bak | cut -c1-10)" = "-rw-------" ]
check "a first run reports no change" not has /var/log/daily.log "has changed"
echo "smoke:*:2000:" >> /etc/group
periodic daily
check "a change to /etc/group is reported" has /var/log/daily.log "/etc/group has changed"
check "with the line that changed" has /var/log/daily.log "smoke:\*:2000:"

# Exit statuses and the show_* settings, in a directory of its own (named by its path).
mkdir -p /tmp/cron/p
for s in "a 0 quiet-ok" "b 1 notable-out" "c 2 badconfig-out" "d 3 error-out"; do
	set -- $s
	printf '#!/bin/sh\necho %s\nexit %s\n' "$3" "$2" > /tmp/cron/p/$1
	chmod 755 /tmp/cron/p/$1
done
printf '#!/bin/sh\necho not-executable\n' > /tmp/cron/p/e
printf 'p_output=/tmp/cron/p.log\np_show_success=NO\n' > /etc/periodic.conf
periodic /tmp/cron/p
rm -f /etc/periodic.conf
check "a script that found nothing is hidden by show_success=NO" not has /tmp/cron/p.log quiet-ok
check "one with notable output is kept" has /tmp/cron/p.log notable-out
check "a misconfigured one is hidden by default" not has /tmp/cron/p.log badconfig-out
check "an error is always kept" has /tmp/cron/p.log error-out
check "a file that isn't executable isn't run" not has /tmp/cron/p.log not-executable

kill "$cronpid"
check "cron stops" eventually not running "$cronpid"

echo "cron-smoke: $fail failed"
[ $fail -eq 0 ]
