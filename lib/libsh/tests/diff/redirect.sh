# Redirections, here-documents, descriptors.
t=${TMPDIR:-/tmp}/libsh-diff-$$
mkdir -p "$t" && cd "$t" || exit 1
echo one > f; echo two >> f; cat f
exec 3>g; echo via3 >&3; exec 3>&-; cat g
cat < f | wc -l
{ echo stdout; echo stderr >&2; } 2>/dev/null
{ echo a; echo b >&2; } >both 2>&1; cat both
cat <<'EOF2'
literal $HOME `x`
EOF2
v=world
cat <<EOF2
hello $v $(echo cmd) \$v \\
EOF2
cat <<-EOF2
	tab stripped
	EOF2
set -C; echo x > f 2>/dev/null || echo noclobber-refused; echo y >| f; cat f; set +C
read line < f; echo "read: $line"
exec 4<f; read l4 <&4; echo "fd4: $l4"; exec 4<&-
echo err 2>&1 >/dev/null
cmd_that_does_not_exist_xyz 2>/dev/null; echo nf=$?
: > empty; [ -s empty ] || echo empty-file
cd /; rm -rf "$t"
