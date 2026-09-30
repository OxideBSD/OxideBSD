# OxideBSD vendoring notes

The IANA time zone database, `tzcode` and `tzdata` release 2026d, unpacked together as IANA
distributes them (`tzcode2026d.tar.gz` and `tzdata2026d.tar.gz` from
<https://data.iana.org/time-zones/releases/>, both signed by Paul Eggert, key
`7E3792A9D8ACF7D633BC1588ED97E90E62AA7E34`). A plain tree, not a fork: IANA publishes versioned
tarballs, and there are no OxideBSD patches (OxideBSD-doc `TIMEZONE.md` §3).

What uses it (`build.rs`, `build_tz`):

- a host build of this `zic` compiles the zones (`-b slim`) into `/usr/share/zoneinfo`, aliases
  from `backward` as hard links, with `zone1970.tab`, `zone.tab`, `iso3166.tab` and `tzdata.zi`;
- `zic` and `zdump` are built for OxideBSD against musl (`/usr/sbin/zic`, `/usr/bin/zdump`);
- the manual pages `tzfile.5`, `zic.8` and `zdump.8`.

The leap-second (`right/`) zones are not installed. Everything else here (tzcode's own `date`,
`localtime.c`, `tzselect`) is unused: musl provides `localtime(3)`, and `tzsetup(8)` replaces
`tzselect`.

To update: verify the new tarballs' signatures, delete everything here except this file, unpack
both, and change the release above. `version` names the release the build stamps its output with.
