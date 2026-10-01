#!/bin/sh
#
# periodic(8): runs the maintenance scripts of each directory named (CRON.md §7). For a name such
# as "daily", every executable file in /etc/periodic/daily and then /usr/local/etc/periodic/daily,
# in name order; an absolute path names a directory itself. Which scripts' output is kept, and
# where it goes, is periodic.conf(5)'s <name>_show_* and <name>_output.

usage()
{
	echo "usage: periodic directory ..." >&2
	exit 1
}

[ $# -ge 1 ] || usage

if [ -r /etc/defaults/periodic.conf ]; then
	. /etc/defaults/periodic.conf
	source_periodic_confs
fi

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
host=$(hostname)

# The value of variable $1, or $2 if it is unset or empty.
setting()
{
	eval "_v=\${$1}"
	echo "${_v:-$2}"
}

# Whether a script's output is kept, given its exit status: 0 nothing notable, 1 notable
# output, 2 invalid configuration, anything else an error, which is always kept.
keep()
{
	case $1 in
	0) [ "$show_success" = YES ] ;;
	1) [ "$show_info" = YES ] ;;
	2) [ "$show_badconfig" = YES ] ;;
	*) true ;;
	esac
}

# Runs every script of the directories in $dirs, printing the output it keeps.
run_scripts()
{
	local _dir _script _out _rc
	for _dir in $dirs; do
		[ -d "$_dir" ] || continue
		for _script in "$_dir"/*; do
			[ -f "$_script" ] && [ -x "$_script" ] || continue
			_out=$("$_script" 2>&1)
			_rc=$?
			if [ -n "$_out" ] && keep $_rc; then
				echo
				echo "$_out"
			fi
		done
	done
}

for arg; do
	case $arg in
	/*)
		dirs=$arg
		name=${arg##*/}
		;;
	*)
		dirs="/etc/periodic/$arg /usr/local/etc/periodic/$arg"
		name=$arg
		;;
	esac
	output=$(setting "${name}_output" "")
	show_success=$(setting "${name}_show_success" YES)
	show_info=$(setting "${name}_show_info" YES)
	show_badconfig=$(setting "${name}_show_badconfig" NO)

	report=$(run_scripts)
	text="$host $name run output, $(date)
$report

-- End of $name output --"

	case $output in
	"")
		echo "$text"
		;;
	/*)
		echo "$text" >> "$output"
		;;
	*)
		# A user to send the output to: no mail system yet (CRON.md §4.3), so it is logged.
		echo "$text" | logger -p daemon.notice -t "periodic $name for $output"
		;;
	esac
done
exit 0
