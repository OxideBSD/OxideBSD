OxideBSD

AI GENERATED CONTENT DISCLOSURE!

AI assistance was used in the making of this project. If you do not like this, you can look at a different repository.

Overview:
The kernel is a hybrid of monolithic and modular, to allow isolating attack surface even if it is wide, such that exploits can be isolated and fixed quickly.
This technique also speeds up development as it allows critical system components to be developed seperately from the kernel.
It also removes one of the key disadvantages of modularity, as it allows components to run at the same level as the kernel.

Dependencies:
A C compiler (clang or gcc) with musl support
GNU make (for BusyBox)
Cargo nightly
QEMU (for testing in a VM), plus OVMF firmware for the default UEFI boot path

Building:
To build it, use `cargo build`.

Documentation:
Design docs, the project roadmap, and POSIX compliance tracking live in a separate repo,
matching how other BSDs split base/doc/ports: https://github.com/Pomsky2011/OxideBSD-doc

Versions:
Each major release will have extended support for a year after the release of its successor - i.e. if v1.x comes out in 2027, and v2.x comes out in 2029, v1.x will be discontinued in 2030.
There is one exception: The LTS releases of vX.0 will have support for 3 years after the release of its successor (every major version's first minor edition).
Each minor release will be supported for 2 months after the release of its successor, of course excluding LTS releases.
The format is a typical semantic release, where the minor versions have minor feature additions between them, the major versions have major overhauls or feature additions between them, and the bugfix versions merely carry bugfixes between them.
v0.x.y releases WILL BE UNSTABLE. Therefore they will not have extended support past a week.
