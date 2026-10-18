#!/bin/sh
#
# rmuser(8): removes users through pw(8), after showing each account (its passwd(5) line, no
# hash) and asking. The shape is FreeBSD's rmuser, simplified: the user's processes are killed,
# then `pw userdel` removes the account, its crontab and, if asked, its home directory and mail.

PW=/usr/sbin/pw

usage()
{
	echo "usage: rmuser [-y] [-f file] [user ...]" >&2
	exit 64
}

err()
{
	echo "rmuser: $*" >&2
}

# yes_no prompt default: succeeds for yes; -y answers every question with yes.
yes_no()
{
	[ "$assume_yes" = yes ] && return 0
	while :; do
		printf '%s [%s]: ' "$1" "$2"
		if ! read -r answer; then
			echo
			exit 1
		fi
		case ${answer:-$2} in
		[Yy] | [Yy][Ee][Ss]) return 0 ;;
		[Nn] | [Nn][Oo]) return 1 ;;
		esac
		echo "Please answer yes or no."
	done
}

rm_one()
{
	name=$1
	if [ "$name" = root ]; then
		err "root may not be removed"
		return 1
	fi
	entry=$($PW usershow -7 -q -n "$name") || {
		err "user ($name) does not exist"
		return 1
	}
	uid=$(echo "$entry" | cut -d: -f3)
	home=$(echo "$entry" | cut -d: -f6)
	echo "$entry"
	yes_no "Is this the entry you wish to remove?" no || return 0
	set -- userdel -n "$name"
	if [ -n "$home" ] && [ "$home" != / ] && [ -d "$home" ]; then
		yes_no "Remove user's home directory ($home)?" yes && set -- "$@" -r
	fi
	# A process left running would keep the uid in use with no account behind it. Never for
	# uid 0: a second superuser account (toor) shares it with everything root runs.
	[ "$uid" != 0 ] && pkill -KILL -U "$uid" 2>/dev/null
	if $PW "$@"; then
		echo "Removed user ($name)."
	else
		err "there was an error removing user ($name)"
		return 1
	fi
}

assume_yes= file=
while getopts f:y opt; do
	case $opt in
	f) file=$OPTARG ;;
	y) assume_yes=yes ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

if [ "$(id -u)" != 0 ]; then
	err "you must be the superuser to remove users"
	exit 77
fi

users="$*"
if [ -n "$file" ]; then
	[ -r "$file" ] || { err "$file: cannot read"; exit 66; }
	users="$users $(sed -e 's/#.*//' "$file" | tr '\n' ' ')"
fi
if [ -z "$(echo $users)" ]; then
	printf 'Please enter one or more usernames: '
	read -r users || exit 1
fi

status=0
for u in $users; do
	rm_one "$u" || status=1
done
exit $status
