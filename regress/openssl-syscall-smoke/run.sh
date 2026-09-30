#!/sbin/init_sh
#
# On-target check for OpenSSL, seeded as /usr/tests/openssl/run.sh with the openssl-smoke fixture
# next to it. Prints one line per check and exits 0 if all pass.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

fail=0
check() {
	_desc=$1
	shift
	if "$@"; then
		echo "openssl-run: ok: $_desc"
	else
		echo "openssl-run: FAIL: $_desc"
		fail=$((fail + 1))
	fi
}
has() { printf '%s\n' "$1" | grep -q -- "$2"; }

# Libraries, the legacy provider module and TLS, from C.
check "openssl-smoke" /usr/tests/openssl/openssl-smoke

# The openssl program: a dynamically linked PIE on libssl.so.3 and libcrypto.so.3.
out=$(openssl version -d)
echo "$out"
check "openssl version -d names /etc/ssl" has "$out" 'OPENSSLDIR: "/etc/ssl"'
out=$(printf abc | openssl dgst -sha256)
check "openssl dgst -sha256" has "$out" ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
out=$(openssl list -providers -provider legacy -provider default)
check "openssl loads the legacy provider" has "$out" legacy
check "/etc/ssl/openssl.cnf is installed" [ -r /etc/ssl/openssl.cnf ]

echo "openssl-run: $fail failed"
[ $fail -eq 0 ]
