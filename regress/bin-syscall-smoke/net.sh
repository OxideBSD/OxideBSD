#!/bin/sh
#
# On-target check for the network configuration tools: ifconfig(8), route(8), dhclient(8).
# Runs as root under QEMU's user networking (slirp: 10.0.2.15/24, router 10.0.2.2, DNS
# 10.0.2.3, a DHCP server built in). Prints one line per check and exits 0 if all pass.
# It leaves rl0 configured by DHCP and /etc/resolv.conf as it found it.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 022

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "net: ok: $_desc"
	else
		echo "net: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
not() { ! "$@"; }
status_is() { _want=$1; shift; "$@" > /dev/null 2>&1; [ $? -eq "$_want" ]; }
contains() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
# file_has file text: the file (read now) contains the text.
file_has() { contains "$(cat "$1" 2> /dev/null)" "$2"; }
gateway_is() { [ "$(sysctl -n net.inet.ip.default_gateway)" = "$1" ]; }
# Waits up to $1 half-seconds for the command to succeed (it is run again each time, so it
# must read what it checks itself: no $(...) in the arguments).
wait_for() {
	_n=$1
	shift
	while [ "$_n" -gt 0 ]; do
		"$@" && return 0
		sleep 0.5
		_n=$((_n - 1))
	done
	return 1
}
TAB=$(printf '\t')
T=/tmp/net-test
rm -rf $T
mkdir -p $T
LEASES=/var/db/dhclient.leases.rl0
PIDFILE=/var/run/dhclient/dhclient.rl0.pid
cp /etc/resolv.conf $T/resolv.conf.saved 2> /dev/null

# Whatever rc started on rl0 goes first.
if [ -f $PIDFILE ]; then
	kill "$(cat $PIDFILE)" 2> /dev/null
	wait_for 10 not test -f $PIDFILE
fi

# --- ifconfig: listing --------------------------------------------------------------------
names=$(ifconfig -l)
check "ifconfig -l names lo0" contains " $names " " lo0 "
check "ifconfig -l names rl0" contains " $names " " rl0 "
lo=$(ifconfig lo0)
check "lo0 is up and a loopback" contains "$lo" "<UP,LOOPBACK,RUNNING"
check "lo0 has 127.0.0.1/8" contains "$lo" "${TAB}inet 127.0.0.1 netmask 0xff000000"
rl=$(ifconfig rl0)
check "rl0's flags line" contains "$rl" "rl0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500"
check "rl0 has an Ethernet address" contains "$rl" "${TAB}ether 52:54:00:"
all=$(ifconfig -a)
check "ifconfig -a describes both" contains "$all" "lo0: flags="
check "ifconfig with no arguments is -a" [ "$(ifconfig)" = "$all" ]
check "an unknown interface" status_is 1 ifconfig nope0
check "the message for it" [ "$(ifconfig nope0 2>&1)" = "ifconfig: interface nope0 does not exist" ]

# --- ifconfig: by hand ----------------------------------------------------------------------
ifconfig rl0 delete > /dev/null 2>&1
check "rl0 without an address has no inet line" [ -z "$(ifconfig rl0 inet)" ]
check "delete refuses when there's none" status_is 1 ifconfig rl0 delete
check "set an address/prefixlen" ifconfig rl0 inet 10.0.2.15/24
check "and see it" [ "$(ifconfig rl0 inet)" = "${TAB}inet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255" ]
check "replace it, netmask form" ifconfig rl0 inet 10.0.2.16 netmask 255.255.0.0
check "and see that" [ "$(ifconfig rl0 inet)" = "${TAB}inet 10.0.2.16 netmask 0xffff0000 broadcast 10.0.255.255" ]
check "a mask alone" ifconfig rl0 netmask 0xffffff00
check "changes the mask" contains "$(ifconfig rl0 inet)" "netmask 0xffffff00 broadcast 10.0.2.255"
check "a second address is refused" status_is 1 ifconfig rl0 inet 10.0.2.17 alias
check "a non-contiguous mask is refused" status_is 1 ifconfig rl0 inet 10.0.2.15 netmask 255.0.255.0
check "a wrong broadcast address is refused" status_is 1 ifconfig rl0 inet 10.0.2.15/24 broadcast 10.0.0.255
check "ifconfig down" ifconfig rl0 down
check "takes it down" not contains "$(ifconfig rl0)" "<UP,"
check "ifconfig -l -d lists it" contains " $(ifconfig -l -d) " " rl0 "
check "ifconfig -l -u doesn't" not contains " $(ifconfig -l -u) " " rl0 "
check "ifconfig up" ifconfig rl0 up
check "brings it up" contains "$(ifconfig rl0)" "<UP,"
check "-alias with the wrong address is refused" status_is 1 ifconfig rl0 inet 10.0.2.99 -alias
check "-alias with its address" ifconfig rl0 inet 10.0.2.16 -alias
check "removes it" [ -z "$(ifconfig rl0 inet)" ]
check "alias on a bare interface sets it" ifconfig rl0 inet 10.0.2.15/24 alias
check "to that" contains "$(ifconfig rl0 inet)" "inet 10.0.2.15 netmask 0xffffff00"
if id user > /dev/null 2>&1; then
	out=$(su -m user -c "ifconfig rl0 inet 10.0.2.99/24" 2>&1)
	check "a user may not set an address" contains "$out" "Operation not permitted"
	check "and nothing changed" contains "$(ifconfig rl0 inet)" "inet 10.0.2.15 "
fi

# --- route ----------------------------------------------------------------------------------
route -q delete default > /dev/null 2>&1
check "no default route to begin with" status_is 1 route -n get default
check "the sysctl is empty" [ -z "$(sysctl -n net.inet.ip.default_gateway)" ]
check "route add default" [ "$(route add default 10.0.2.2)" = "add net default: gateway 10.0.2.2" ]
check "the sysctl has it" [ "$(sysctl -n net.inet.ip.default_gateway)" = 10.0.2.2 ]
got=$(route -n get default)
check "route get default: gateway" contains "$got" "    gateway: 10.0.2.2"
check "route get default: interface" contains "$got" "  interface: rl0"
check "route get: a local address" contains "$(route -n get 10.0.2.77)" "destination: 10.0.2.0"
shown=$(route -n show)
check "route show: the default" contains "$shown" "default            10.0.2.2           UGS"
check "route show: the subnet" contains "$shown" "10.0.2.0/24        link#"
check "a second default is refused" status_is 1 route add default 10.0.2.3
check "route change" [ "$(route change default 10.0.2.3)" = "change net default: gateway 10.0.2.3" ]
check "changed" [ "$(sysctl -n net.inet.ip.default_gateway)" = 10.0.2.3 ]
check "other routes are refused (EX_UNAVAILABLE)" status_is 69 route add -net 192.168.0.0/24 10.0.2.2
check "with a message" contains "$(route add -host 10.1.2.3 10.0.2.2 2>&1)" "only the default route can be set"
check "a gateway that isn't an address" status_is 68 route add default gw.example
check "delete with the wrong gateway is refused" status_is 1 route delete default 10.0.2.2
check "route delete default" [ "$(route delete default)" = "delete net default: gateway 10.0.2.3" ]
check "gone" status_is 1 route -n get default
check "and from the sysctl" [ -z "$(sysctl -n net.inet.ip.default_gateway)" ]
check "delete again: not in table" status_is 1 route delete default
if id user > /dev/null 2>&1; then
	check "a user may not add a route" status_is 77 su -m user -c "route add default 10.0.2.2"
fi

# --- dhclient -------------------------------------------------------------------------------
check "dhclient refuses the loopback" status_is 1 dhclient -d lo0
check "dhclient refuses an unknown interface" status_is 1 dhclient -d nope0
ifconfig rl0 delete > /dev/null 2>&1
rm -f $LEASES
echo "nameserver 192.0.2.1" > /etc/resolv.conf
dhclient -d rl0 > $T/dhclient.log 2>&1 &
dpid=$!
bound() { contains "$(ifconfig rl0 inet)" "inet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255"; }
check "dhclient gets 10.0.2.15/24 within 10 s" wait_for 20 bound
check "and the default route 10.0.2.2" wait_for 4 gateway_is 10.0.2.2
check "route agrees" contains "$(route -n get default)" "    gateway: 10.0.2.2"
check "resolv.conf names 10.0.2.3" wait_for 4 file_has /etc/resolv.conf "nameserver 10.0.2.3"
IFS= read -r first < /etc/resolv.conf
check "resolv.conf's first line names dhclient" contains "$first" "dhclient"
check "the old name server is gone" not contains "$(cat /etc/resolv.conf)" "192.0.2.1"
check "the lease is saved" contains "$(cat $LEASES 2> /dev/null)" "fixed-address 10.0.2.15;"
check "for rl0" contains "$(cat $LEASES 2> /dev/null)" 'interface "rl0";'
check "the pid file names it" [ "$(cat $PIDFILE 2> /dev/null)" = "$dpid" ]
check "a second dhclient on rl0 is refused" status_is 1 dhclient -d rl0
log=$(cat $T/dhclient.log)
check "the log shows the exchange" contains "$log" "DHCPOFFER from 10.0.2.2"
check "and the binding" contains "$log" "bound to 10.0.2.15 -- renewal in"
kill $dpid
wait $dpid
st=$?
check "dhclient exits 0 on SIGTERM" [ $st -eq 0 ]
check "keeping the address" bound
check "removing its pid file" not test -f $PIDFILE

# INIT-REBOOT: the saved lease is asked for again, with no DISCOVER.
dhclient -d rl0 > $T/dhclient2.log 2>&1 &
dpid=$!
check "a restarted dhclient confirms the saved lease" wait_for 20 file_has $T/dhclient2.log "bound to 10.0.2.15"
check "without a DISCOVER" not contains "$(cat $T/dhclient2.log)" "DHCPDISCOVER"
kill $dpid
wait $dpid

# -r: DHCPRELEASE and the address removed on exit.
dhclient -d -r rl0 > $T/dhclient3.log 2>&1 &
dpid=$!
wait_for 20 file_has $T/dhclient3.log "bound to 10.0.2.15"
kill $dpid
wait $dpid
check "dhclient -r releases the lease" contains "$(cat $T/dhclient3.log)" "DHCPRELEASE on rl0 to 10.0.2.2"
check "and removes the address" [ -z "$(ifconfig rl0 inet)" ]

# Leave rl0 as rc would: through rc.d/dhclient (in the background, as at boot).
/etc/rc.d/dhclient forcestart rl0 > /dev/null 2>&1
check "rc.d/dhclient starts it again" wait_for 20 bound
check "rc.d/dhclient status" status_is 0 /etc/rc.d/dhclient status rl0
if [ -f $T/resolv.conf.saved ]; then
	cp $T/resolv.conf.saved /etc/resolv.conf
fi

echo "net: $fail failed"
[ $fail -eq 0 ]
