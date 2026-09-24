# The dot command, return from a dot script, positional parameters.
t=${TMPDIR:-/tmp}/libsh-dot-$$
printf 'echo "dot: $#"\nsourced=yes\nreturn 5\necho unreachable\n' > "$t"
. "$t"; echo "status=$? sourced=$sourced"
rm -f "$t"
