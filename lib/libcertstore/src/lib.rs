//! The system trust store's shared logic: used by `build.rs` on the host, to seed
//! `/usr/share/certs` and `/etc/ssl` from Mozilla's root list, and by `certctl(8)` on OxideBSD, to
//! maintain them. No dependencies, so the same code runs in both places.
//!
//! - [`certdata`]: parse NSS's `certdata.txt` into roots and their TLS server trust.
//! - [`pem`]: PEM encoding and decoding of certificates.
//! - [`name`]: OpenSSL's subject name hash (`openssl x509 -subject_hash`), which names the
//!   `<hash>.<n>` links OpenSSL looks certificates up by in a `-CApath` directory.
//! - [`store`]: the link names for a set of certificates, as `certctl rehash` makes them.
//! - [`ctl`]: `certctl`'s operations (rehash, list, untrust, trust) on a trust store.

pub mod certdata;
pub mod ctl;
mod der;
pub mod name;
pub mod pem;
pub mod sha1;
pub mod store;
