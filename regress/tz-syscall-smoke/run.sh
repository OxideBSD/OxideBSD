#!/sbin/init_sh
#
# On-target check for time zones (TIMEZONE.md §6.1), seeded as /usr/tests/tz/run.sh with the
# tz-smoke fixture next to it. Runs as root; prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
T=/usr/tests/tz/tz-smoke

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "tz-smoke: ok: $_desc"
	else
		echo "tz-smoke: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
# Runs the fixture with TZ set to $1 ("" leaves TZ unset).
in_tz() {
	_tz=$1
	shift
	if [ -n "$_tz" ]; then TZ=$_tz $T "$@"; else (unset TZ; $T "$@"); fi
}
has() { grep -q -- "$2" "$1" 2>/dev/null; }
eventually() {
	_i=0
	while [ $_i -lt 10 ]; do
		"$@" && return 0
		sleep 1
		_i=$((_i + 1))
	done
	return 1
}
links_to() { [ "$(readlink /etc/localtime)" = "$1" ]; }
zdump_has() { zdump -v -c 2026,2027 "$1" | grep -q -- "$2"; }
link_count() { [ "$(ls -l "$1" | awk '{print $2}')" = "$2" ]; }

# 2026-03-29T01:00:00Z: Berlin springs forward. 2026-10-25T01:00:00Z: it falls back.
SPRING=1774746000
FALL=1792890000

# --- The database ----------------------------------------------------------------------------
check "zoneinfo has Europe/Berlin" [ -f /usr/share/zoneinfo/Europe/Berlin ]
check "zoneinfo has zone1970.tab" [ -f /usr/share/zoneinfo/zone1970.tab ]
check "zoneinfo has tzdata.zi" [ -f /usr/share/zoneinfo/tzdata.zi ]
check "an alias is a hard link to its zone" link_count /usr/share/zoneinfo/US/Eastern 2
check "there are no leap-second zones" [ ! -e /usr/share/zoneinfo/right ]

# --- No /etc/localtime: UTC ------------------------------------------------------------------
rm -f /etc/localtime
check "without /etc/localtime, local time is UTC" in_tz "" 0 1970-01-01T00:00:00 0 0
check "... at a Berlin transition too" in_tz "" $SPRING 2026-03-29T01:00:00 0 0

# --- A zone with daylight saving time, by TZ -------------------------------------------------
check "Berlin, last second of winter time" in_tz Europe/Berlin $((SPRING - 1)) 2026-03-29T01:59:59 3600 0
check "Berlin, first second of summer time" in_tz Europe/Berlin $SPRING 2026-03-29T03:00:00 7200 1
check "Berlin, last second of summer time" in_tz Europe/Berlin $((FALL - 1)) 2026-10-25T02:59:59 7200 1
check "Berlin, 02:00 the second time round" in_tz Europe/Berlin $FALL 2026-10-25T02:00:00 3600 0
check "New York, by its alias" in_tz US/Eastern $SPRING 2026-03-28T21:00:00 -14400 1
check "a POSIX TZ string" in_tz EST5EDT,M3.2.0,M11.1.0 $SPRING 2026-03-28T21:00:00 -14400 1

# --- A zone without, through /etc/localtime; TZ wins over it ---------------------------------
ln -s /usr/share/zoneinfo/Asia/Tokyo /etc/localtime
check "Tokyo through /etc/localtime" in_tz "" $SPRING 2026-03-29T10:00:00 32400 0
check "Tokyo has no summer time" in_tz "" $FALL 2026-10-25T10:00:00 32400 0
check "TZ overrides /etc/localtime" in_tz Europe/Berlin $SPRING 2026-03-29T03:00:00 7200 1
rm -f /etc/localtime

# --- zdump and zic ---------------------------------------------------------------------------
check "zdump -v lists Berlin's spring transition" zdump_has Europe/Berlin "Sun Mar 29 01:00:00 2026 UT = Sun Mar 29 03:00:00 2026 CEST isdst=1 gmtoff=7200"
check "zdump -v lists Berlin's autumn transition" zdump_has Europe/Berlin "Sun Oct 25 01:00:00 2026 UT = Sun Oct 25 02:00:00 2026 CET isdst=0 gmtoff=3600"
mkdir -p /tmp/tz
printf 'Zone\tTest/Fixed\t5:30\t-\tIST\n' > /tmp/tz/fixed.zi
check "zic compiles a zone" zic -d /tmp/tz/zi /tmp/tz/fixed.zi
check "... which localtime reads" in_tz /tmp/tz/zi/Test/Fixed 0 1970-01-01T05:30:00 19800 0

# --- tzsetup ---------------------------------------------------------------------------------
check "tzsetup sets a zone" tzsetup Europe/Berlin
check "... as a link into the database" links_to /usr/share/zoneinfo/Europe/Berlin
check "... which localtime follows" in_tz "" $SPRING 2026-03-29T03:00:00 7200 1
check "tzsetup refuses an unknown zone" not tzsetup Nowhere/Atlantis
check "... and leaves the link alone" links_to /usr/share/zoneinfo/Europe/Berlin
check "tzsetup refuses a path out of the database" not tzsetup ../../etc/passwd
check "tzsetup refuses a file that isn't a zone" not tzsetup zone1970.tab
check "... still leaving the link alone" links_to /usr/share/zoneinfo/Europe/Berlin
check "tzsetup -n changes nothing" tzsetup -n Asia/Tokyo
check "... really nothing" links_to /usr/share/zoneinfo/Europe/Berlin
check "tzsetup -r refreshes the link" tzsetup -r
check "... to the same zone" links_to /usr/share/zoneinfo/Europe/Berlin
printf 'q\n' | tzsetup > /dev/null
check "quitting the menu changes nothing" links_to /usr/share/zoneinfo/Europe/Berlin

# --- syslogd re-reads the zone on SIGHUP (TIMEZONE.md §5.4) ----------------------------------
tzsetup UTC
mkdir -p /tmp/tzsl
: > /tmp/tzsl/all
printf '*.*\t/tmp/tzsl/all\n' > /tmp/tzsl/syslog.conf
syslogd -s -m 0 -f /tmp/tzsl/syslog.conf -P /tmp/tzsl/pid
pid=$(cat /tmp/tzsl/pid)
logger -t before "in UTC"
tzsetup Asia/Tokyo
kill -HUP "$pid"
sleep 1
logger -t after "in Tokyo"
eventually has /tmp/tzsl/all "after: in Tokyo"
# The hour of each line: Tokyo is 9 hours ahead (10 if an hour boundary fell in between).
h1=$(grep "before: in UTC" /tmp/tzsl/all | cut -c8-9)
h2=$(grep "after: in Tokyo" /tmp/tzsl/all | cut -c8-9)
h1=${h1#0}
h2=${h2#0}
d=$(( (h2 - h1 + 24) % 24 ))
check "syslogd stamps in the new zone after SIGHUP" [ "$d" = 9 -o "$d" = 10 ]
kill "$pid"
rm -f /etc/localtime

echo "tz-smoke: $fail failed"
[ $fail -eq 0 ]
