/* Milestone-1 fixture for PT_INTERP/dynamic-linking support (see CLAUDE.md's "Dynamic linking"
 * section once it exists, and the plan this was built from). Deliberately trivial: one write()
 * call is enough to prove real, on-target dynamic linking worked end to end -- the kernel loaded
 * both this binary (ET_EXEC, fixed base) and its PT_INTERP interpreter (musl's own
 * ld-musl-x86_64.so.1, which doubles as libc.so, ET_DYN, its own fixed base), the interpreter
 * self-relocated and jumped to this program's real entry via AT_ENTRY, and the resulting call
 * into libc's own write() wrapper reached a real SYSCALL. Not built with the existing static
 * musl sysroot (`build_musl_sysroot`/`regress/musl-smoke`) -- see `build_dynlink_smoke` in
 * build.rs for the separate, real -fPIC/-shared sysroot this links against instead. */
#include <unistd.h>

int main(void) {
    write(1, "dynlink-smoke: hello via real PT_INTERP dynamic linking\n", 58);
    return 0;
}
