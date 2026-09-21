//! A fixed-capacity path buffer (no `alloc` in a freestanding binary) plus `basename`.

pub const MAX_PATH: usize = 1024;

pub struct PathBuf {
    buf: [u8; MAX_PATH],
    len: usize,
}

impl PathBuf {
    /// `None` if `s` doesn't fit.
    pub fn from(s: &[u8]) -> Option<PathBuf> {
        if s.len() > MAX_PATH {
            return None;
        }
        let mut p = PathBuf {
            buf: [0; MAX_PATH],
            len: 0,
        };
        p.buf[..s.len()].copy_from_slice(s);
        p.len = s.len();
        Some(p)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Appends `/component` (no doubled slash if the buffer already ends in one). `false` (and
    /// no change) if it wouldn't fit.
    pub fn push(&mut self, component: &[u8]) -> bool {
        let need_slash = self.len > 0 && self.buf[self.len - 1] != b'/';
        let total = self.len + need_slash as usize + component.len();
        if total > MAX_PATH {
            return false;
        }
        if need_slash {
            self.buf[self.len] = b'/';
            self.len += 1;
        }
        self.buf[self.len..self.len + component.len()].copy_from_slice(component);
        self.len += component.len();
        true
    }

    /// Restores the buffer to an earlier `len()` (undoing a `push`).
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }
}

/// The final path component, ignoring trailing slashes (`"a/b/"` -> `"b"`); `"/"` stays `"/"`.
pub fn basename(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(i) if trimmed.len() > 1 => &trimmed[i + 1..],
        _ => trimmed,
    }
}

/// `dir/basename(src)` -- where `cp`/`mv`/`ln` put a source that's being moved *into* an existing
/// directory. `None` if it doesn't fit.
pub fn join_basename(dir: &[u8], src: &[u8]) -> Option<PathBuf> {
    let mut p = PathBuf::from(dir)?;
    if p.push(basename(src)) { Some(p) } else { None }
}
