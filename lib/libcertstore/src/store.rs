//! Names in a `-CApath` directory: `<hash>.<n>`, the subject name hash as eight lowercase hex
//! digits and a count from 0 among certificates whose subjects hash the same.

use std::collections::{HashMap, HashSet};

use crate::name::subject_hash;

/// The link names for `certs`, in order: `None` for a certificate that doesn't parse, or that is
/// the same certificate (DER) as an earlier one.
pub fn link_names(certs: &[&[u8]]) -> Vec<Option<String>> {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut counts: HashMap<u32, u32> = HashMap::new();
    certs
        .iter()
        .map(|&der| {
            let hash = subject_hash(der)?;
            if !seen.insert(der) {
                return None;
            }
            let n = counts.entry(hash).or_insert(0);
            let name = format!("{hash:08x}.{n}");
            *n += 1;
            Some(name)
        })
        .collect()
}

/// The first `<hash>.<n>` for `der` not in `taken`; `None` if it doesn't parse.
pub fn free_name(der: &[u8], taken: &HashSet<String>) -> Option<String> {
    let hash = subject_hash(der)?;
    (0..).map(|n| format!("{hash:08x}.{n}")).find(|name| !taken.contains(name))
}

/// Whether `name` has the `<hash>.<n>` form.
pub fn is_link_name(name: &str) -> bool {
    let Some((hash, n)) = name.split_once('.') else { return false };
    hash.len() == 8
        && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
}
