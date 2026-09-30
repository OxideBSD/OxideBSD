# OxideBSD vendoring notes

Mozilla's root certificate list, `lib/ckfw/builtins/certdata.txt` from NSS release `NSS_3_130_RTM`
(<https://github.com/nss-dev/nss>, the official mirror of `hg.mozilla.org/projects/nss`). Just that
one file, unmodified; MPL 2.0 (its header).

What uses it (`build.rs`, `build_trust_store`, through `lib/libcertstore`): each root whose
`CKA_TRUST_SERVER_AUTH` is `CKT_NSS_TRUSTED_DELEGATOR` becomes a PEM file in
`/usr/share/certs/trusted`, each whose value is `CKT_NSS_NOT_TRUSTED` one in
`/usr/share/certs/untrusted`, and the rest (e-mail-only roots and such) are left out, as in
FreeBSD's `secure/caroot`. `CKA_NSS_SERVER_DISTRUST_AFTER` is not enforced (OpenSSL can't express
it): such a root is trusted, as FreeBSD and curl's bundle do. `certctl rehash` then builds
`/etc/ssl/certs` and `/etc/ssl/cert.pem`.

To update: replace `certdata.txt` with the one from a newer `NSS_*_RTM` tag and change the release
above. `lib/libcertstore`'s host tests (`cargo test` there) check every root's subject hash against
the host's `openssl`.
