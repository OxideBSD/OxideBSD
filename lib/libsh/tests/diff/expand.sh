# Parameter expansion, field splitting, "$@" and "$*".
set -- "a b" "" c
printf '<%s>' "$@"; echo
printf '<%s>' $@; echo
printf '<%s>' "$*"; echo
printf '<%s>' ${1+"$@"}; echo
IFS=:; printf '<%s>' "$*"; echo; unset IFS
x=' lead  trail '; printf '<%s>' $x; echo
IFS=': '; y='a: b::c :'; printf '<%s>' $y; echo; IFS=' 	
'
v=hello.tar.gz
echo ${v%.*} ${v%%.*} ${v#*.} ${v##*.} ${#v}
echo ${unset-def} ${unset:-def2} "${empty=}" ${empty:-was-empty} ${v:+alt}
echo ${nope:=assigned} $nope
e=""; echo "[${e-x}] [${e:-x}]"
echo "${v%"*.gz"}" ${v%'.gz'}
pat='*.gz'; echo ${v%$pat} "${v%"$pat"}"
set --; printf '<%s>' "$@" x; echo
echo ~root/x ~nosuchuserxyz
a=1 b=2; echo $a$b "$a"'$b' \$a
echo "$(printf 'x\n\n\n')|"
echo $((1+2*3)) $((10/3)) $((10%3)) $((1<<4)) $(( 7 > 3 && 2 )) $((0x10 + 010))
i=5; : $((i+=2)); echo $i $((i++)) $i $((--i))
