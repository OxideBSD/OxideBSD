#!/bin/sh
#
# adduser(8): adds users through pw(8), asking for each account's details, or reading them from
# a file with -f. The shape is FreeBSD's adduser, simplified: no configuration file of its own
# (pw's defaults come from usermgmt.conf(5)), one user per round, a summary to confirm.

PW=/usr/sbin/pw
SHELLS=/etc/shells
CONF=/etc/usermgmt.conf

usage()
{
	echo "usage: adduser [-f file] [-G groups] [-g group] [-k skel] [-L class] [-s shell]" >&2
	echo "               [-w no|none|random|yes]" >&2
	exit 64
}

err()
{
	echo "adduser: $*" >&2
}

info()
{
	echo "adduser: INFO: $*"
}

# ask prompt [default]: reads an answer into $answer, the default if it is empty. End of input
# ends the program, as nothing more can be asked.
ask()
{
	if [ -n "$2" ]; then
		printf '%s [%s]: ' "$1" "$2"
	else
		printf '%s: ' "$1"
	fi
	if ! read -r answer; then
		echo
		exit 1
	fi
	[ -n "$answer" ] || answer=$2
}

# yes_no prompt default: succeeds for yes.
yes_no()
{
	while :; do
		ask "$1" "$2"
		case $answer in
		[Yy] | [Yy][Ee][Ss]) return 0 ;;
		[Nn] | [Nn][Oo]) return 1 ;;
		esac
		echo "Please answer yes or no."
	done
}

# get_password prompt: reads $password with echo off.
get_password()
{
	trap 'stty echo 2>/dev/null; echo; exit 1' INT TERM
	stty -echo 2>/dev/null
	printf '%s: ' "$1"
	read -r password || password=
	stty echo 2>/dev/null
	trap - INT TERM
	echo
}

# The login shells offered: /etc/shells' names, and nologin.
shell_names()
{
	if [ -r "$SHELLS" ]; then
		sed -n 's,^\(/[^#[:space:]]*\).*,\1,p' "$SHELLS" | sed 's,.*/,,' | awk '!seen[$0]++' | tr '\n' ' '
	else
		printf 'sh '
	fi
	echo nologin
}

# shell_path name: the path for a shell named by the user, or nothing if it isn't one.
shell_path()
{
	case $1 in
	nologin) echo /sbin/nologin; return ;;
	/*) [ -x "$1" ] && echo "$1"; return ;;
	esac
	if [ -r "$SHELLS" ]; then
		sed -n 's,^\(/[^#[:space:]]*\).*,\1,p' "$SHELLS" | while read -r p; do
			[ "${p##*/}" = "$1" ] && { echo "$p"; break; }
		done
	elif [ -x "/bin/$1" ]; then
		echo "/bin/$1"
	fi
}

base_dir()
{
	b=
	[ -r "$CONF" ] && b=$(sed -n 's/^base_dir[[:space:]]*//p' "$CONF" | sed 's/[[:space:]]*#.*//')
	echo "${b:-/home}"
}

user_exists()
{
	# -n: a name, not a uid, even if it is all digits.
	$PW usershow -q -n "$1" >/dev/null 2>&1
}

group_exists()
{
	$PW groupshow -q -n "$1" >/dev/null 2>&1
}

# Asks for one account and adds it.
add_one()
{
	while :; do
		ask "Username"
		name=$answer
		[ -n "$name" ] || continue
		if user_exists "$name"; then
			err "user $name already exists"
			continue
		fi
		# A dry run checks the name the way pw will.
		$PW useradd -N -n "$name" >/dev/null && break
	done

	while :; do
		ask "Full name"
		gecos=$answer
		case $gecos in
		*:*) err "the full name may not contain a colon" ;;
		*) break ;;
		esac
	done

	nextuid=$($PW usernext | cut -d: -f1)
	while :; do
		ask "Uid (Leave empty for default)" "$nextuid"
		uid=$answer
		case $uid in
		'' | *[!0-9]*) err "a uid is a number" ;;
		*) break ;;
		esac
	done

	while :; do
		ask "Login group" "${defgroup:-$name}"
		group=$answer
		# The user's own name is a new group of its own unless it exists already.
		[ "$group" = "$name" ] && ! group_exists "$group" && break
		group_exists "$group" && break
		err "group $group does not exist"
	done

	while :; do
		ask "Login group is $group. Invite $name into other groups?" "$defgroups"
		groups=$answer
		missing=
		for g in $(echo "$groups" | tr ',' ' '); do
			group_exists "$g" || missing="$missing $g"
		done
		[ -z "$missing" ] && break
		err "no such group:$missing"
	done

	ask "Login class" "${defclass:-default}"
	class=$answer
	[ "$class" = default ] && class=

	while :; do
		ask "Shell ($(shell_names))" "$defshell"
		shell=$(shell_path "$answer")
		[ -n "$shell" ] && break
		err "$answer is not a login shell"
	done

	ask "Home directory" "$(base_dir)/$name"
	home=$answer

	pwmode=$passwdtype
	if [ "$pwmode" = yes ]; then
		if ! yes_no "Use password-based authentication?" yes; then
			pwmode=no
		elif yes_no "Use an empty password? (yes/no)" no; then
			pwmode=none
		elif yes_no "Use a random password? (yes/no)" no; then
			pwmode=random
		else
			while :; do
				get_password "Enter password"
				first=$password
				get_password "Enter password again"
				[ "$first" = "$password" ] && [ -n "$password" ] && break
				if [ -z "$password" ]; then
					err "the password is empty; answer yes to an empty password instead"
				else
					err "the passwords didn't match"
				fi
			done
		fi
	fi
	lock=no
	yes_no "Lock out the account after creation?" no && lock=yes

	case $pwmode in
	yes) shown='*****' ;;
	none) shown='<blank>' ;;
	random) shown='<random>' ;;
	no) shown='<disabled>' ;;
	esac
	echo
	echo "Username   : $name"
	echo "Password   : $shown"
	echo "Full Name  : $gecos"
	echo "Uid        : $uid"
	echo "Class      : $class"
	echo "Groups     : $group $groups"
	echo "Home       : $home"
	echo "Shell      : $shell"
	echo "Locked     : $lock"
	yes_no "OK? (yes/no)" yes || return 1

	set -- useradd -n "$name" -u "$uid" -c "$gecos" -d "$home" -s "$shell" -m
	group_exists "$group" && set -- "$@" -g "$group"
	[ -n "$groups" ] && set -- "$@" -G "$groups"
	[ -n "$class" ] && set -- "$@" -L "$class"
	[ -n "$skel" ] && set -- "$@" -k "$skel"
	case $pwmode in
	yes) printf '%s\n' "$password" | $PW "$@" -h 0 ;;
	none) $PW "$@" -w none ;;
	random)
		pw=$($PW "$@" -w random) && echo "Password for $name is: $pw"
		[ -n "$pw" ]
		;;
	no) $PW "$@" -h - ;;
	esac || { err "there was an error adding user ($name)"; return 1; }
	password= first=
	[ "$lock" = yes ] && $PW lock -n "$name"
	info "Successfully added ($name) to the user database."
}

# Adds the accounts in a file, one per line:
#	name:uid:gid:class:change:expire:gecos:home:shell:password
# Empty fields take the defaults; an empty password follows -w (a disabled one for "yes").
add_file()
{
	status=0
	while IFS=: read -r name uid gid class change expire gecos home shell password; do
		case $name in
		'' | '#'*) continue ;;
		esac
		set -- useradd -n "$name" -m
		[ -n "$uid" ] && set -- "$@" -u "$uid"
		gid=${gid:-$defgroup}
		[ -n "$gid" ] && set -- "$@" -g "$gid"
		class=${class:-$defclass}
		[ -n "$class" ] && set -- "$@" -L "$class"
		[ -n "$change" ] && set -- "$@" -p "$change"
		[ -n "$expire" ] && set -- "$@" -e "$expire"
		[ -n "$gecos" ] && set -- "$@" -c "$gecos"
		[ -n "$home" ] && set -- "$@" -d "$home"
		shell=$(shell_path "${shell:-$defshell}")
		[ -n "$shell" ] && set -- "$@" -s "$shell"
		[ -n "$defgroups" ] && set -- "$@" -G "$defgroups"
		[ -n "$skel" ] && set -- "$@" -k "$skel"
		if [ -n "$password" ]; then
			printf '%s\n' "$password" | $PW "$@" -h 0
		else
			case $passwdtype in
			none) $PW "$@" -w none ;;
			random) pw=$($PW "$@" -w random) && echo "Password for $name is: $pw" ;;
			*) $PW "$@" -h - ;;
			esac
		fi
		if [ $? -eq 0 ]; then
			info "Successfully added ($name) to the user database."
		else
			err "there was an error adding user ($name)"
			status=1
		fi
	done <"$file"
	return $status
}

file= defgroups= defgroup= skel= defclass= defshell=sh passwdtype=yes
while getopts f:G:g:k:L:s:w: opt; do
	case $opt in
	f) file=$OPTARG ;;
	G) defgroups=$OPTARG ;;
	g) defgroup=$OPTARG ;;
	k) skel=$OPTARG ;;
	L) defclass=$OPTARG ;;
	s) defshell=$OPTARG ;;
	w)
		case $OPTARG in
		no | none | random | yes) passwdtype=$OPTARG ;;
		*) usage ;;
		esac
		;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage

if [ "$(id -u)" != 0 ]; then
	err "you must be the superuser to add users"
	exit 77
fi

if [ -n "$file" ]; then
	[ -r "$file" ] || { err "$file: cannot read"; exit 66; }
	add_file
	exit
fi

while :; do
	add_one
	yes_no "Add another user? (yes/no)" no || break
done
echo "Goodbye!"
