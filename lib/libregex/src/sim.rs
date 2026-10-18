//! NFA simulations over the text: state sets, never backtracking, so linear in the window times
//! the NFA size.

use crate::nfa::{Nfa, St, StateId};

/// The text being matched and what the anchors see at each position.
#[derive(Clone, Copy)]
pub struct Text<'t> {
    pub t: &'t [u8],
    pub notbol: bool,
    pub noteol: bool,
    /// `REG_NEWLINE`: `^`/`$` also match after/before a newline.
    pub nl: bool,
}

impl Text<'_> {
    #[inline]
    pub fn bol(&self, p: usize) -> bool {
        if p == 0 { !self.notbol } else { self.nl && self.t[p - 1] == b'\n' }
    }

    #[inline]
    pub fn eol(&self, p: usize) -> bool {
        if p == self.t.len() { !self.noteol } else { self.nl && self.t[p] == b'\n' }
    }
}

/// Sparse set of states (Briggs-Torczon): O(1) clear, insertion order kept.
pub struct SparseSet {
    dense: Vec<StateId>,
    sparse: Vec<u32>,
}

impl SparseSet {
    pub fn new(n: usize) -> SparseSet {
        SparseSet { dense: Vec::with_capacity(n), sparse: vec![0; n] }
    }

    #[inline]
    pub fn contains(&self, s: StateId) -> bool {
        let i = self.sparse[s as usize] as usize;
        i < self.dense.len() && self.dense[i] == s
    }

    /// Inserts `s`; false if it was there.
    #[inline]
    pub fn insert(&mut self, s: StateId) -> bool {
        if self.contains(s) {
            return false;
        }
        self.sparse[s as usize] = self.dense.len() as u32;
        self.dense.push(s);
        true
    }

    pub fn clear(&mut self) {
        self.dense.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.dense.is_empty()
    }

    pub fn as_slice(&self) -> &[StateId] {
        &self.dense
    }
}

/// Positions `base..=base+n` as a bit set.
pub struct Bits {
    base: usize,
    w: Vec<u64>,
}

impl Bits {
    fn new(base: usize, last: usize) -> Bits {
        Bits { base, w: vec![0; (last - base) / 64 + 1] }
    }

    fn set(&mut self, p: usize) {
        let i = p - self.base;
        self.w[i / 64] |= 1 << (i % 64);
    }

    pub fn get(&self, p: usize) -> bool {
        let Some(i) = p.checked_sub(self.base) else { return false };
        self.w.get(i / 64).is_some_and(|w| w >> (i % 64) & 1 != 0)
    }
}

/// Epsilon closure of `s`, forward. `stop` is entered but not left.
pub fn fclosure(nfa: &Nfa, set: &mut SparseSet, stack: &mut Vec<StateId>, s: StateId, bol: bool, eol: bool, stop: StateId) {
    stack.push(s);
    while let Some(s) = stack.pop() {
        if !set.insert(s) || s == stop {
            continue;
        }
        match nfa.st[s as usize] {
            St::Split(a, b) => {
                stack.push(b);
                stack.push(a);
            }
            St::Eps(n) => stack.push(n),
            St::Bol(n) if bol => stack.push(n),
            St::Eol(n) if eol => stack.push(n),
            _ => {}
        }
    }
}

/// Epsilon closure of `s` against the edges. `barrier` is entered but not left.
fn rclosure(nfa: &Nfa, set: &mut SparseSet, stack: &mut Vec<StateId>, s: StateId, bol: bool, eol: bool, barrier: StateId) {
    stack.push(s);
    while let Some(s) = stack.pop() {
        if !set.insert(s) || s == barrier {
            continue;
        }
        for &q in &nfa.eps_rev[s as usize] {
            match nfa.st[q as usize] {
                St::Bol(_) if !bol => {}
                St::Eol(_) if !eol => {}
                _ => stack.push(q),
            }
        }
    }
}

/// Reusable simulation state, sized to one NFA.
pub struct Sim {
    a: SparseSet,
    b: SparseSet,
    stack: Vec<StateId>,
    /// Pike search: each thread's start, parallel to the dense sets.
    sa: Vec<usize>,
    sb: Vec<usize>,
}

impl Sim {
    pub fn new(nfa: &Nfa) -> Sim {
        let n = nfa.st.len();
        Sim { a: SparseSet::new(n), b: SparseSet::new(n), stack: Vec::new(), sa: Vec::new(), sb: Vec::new() }
    }

    /// Every `p` in `i..=kmax` such that the fragment from `from` reaches `stop` having
    /// consumed exactly `text[i..p]`, ascending.
    pub fn ends(&mut self, nfa: &Nfa, tx: &Text, from: StateId, stop: StateId, i: usize, kmax: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let (a, b, stack) = (&mut self.a, &mut self.b, &mut self.stack);
        a.clear();
        fclosure(nfa, a, stack, from, tx.bol(i), tx.eol(i), stop);
        let mut p = i;
        loop {
            if a.contains(stop) {
                out.push(p);
            }
            if p >= kmax || a.is_empty() {
                break;
            }
            let c = tx.t[p];
            b.clear();
            let (bol, eol) = (tx.bol(p + 1), tx.eol(p + 1));
            for &s in a.as_slice() {
                if let St::Byte(set, n) = nfa.st[s as usize]
                    && set.contains(c)
                {
                    fclosure(nfa, b, stack, n, bol, eol, stop);
                }
            }
            std::mem::swap(a, b);
            p += 1;
        }
        out
    }

    /// Every `p` in `imin..=k` such that state `at`, reached at `p`, leads to `from` having
    /// consumed exactly `text[p..k]`: run backwards from `from`, never past `barrier` (the
    /// enclosing fragment's entry, which may be `at` itself).
    #[allow(clippy::too_many_arguments)]
    pub fn starts(&mut self, nfa: &Nfa, tx: &Text, from: StateId, k: usize, at: StateId, barrier: StateId, imin: usize) -> Bits {
        let mut out = Bits::new(imin, k);
        let (a, b, stack) = (&mut self.a, &mut self.b, &mut self.stack);
        a.clear();
        rclosure(nfa, a, stack, from, tx.bol(k), tx.eol(k), barrier);
        let mut p = k;
        loop {
            if a.contains(at) {
                out.set(p);
            }
            if p <= imin || a.is_empty() {
                break;
            }
            let c = tx.t[p - 1];
            b.clear();
            let (bol, eol) = (tx.bol(p - 1), tx.eol(p - 1));
            for &s in a.as_slice() {
                if s == barrier {
                    continue;
                }
                for &q in &nfa.byte_rev[s as usize] {
                    if let St::Byte(set, _) = nfa.st[q as usize]
                        && set.contains(c)
                    {
                        rclosure(nfa, b, stack, q, bol, eol, barrier);
                    }
                }
            }
            std::mem::swap(a, b);
            p -= 1;
        }
        out
    }

    /// The leftmost-longest match of the whole NFA starting in `q..=last_start`: a Pike VM
    /// whose threads carry their start, kept in ascending start order so the first thread to
    /// reach a state is the leftmost one.
    pub fn extent(&mut self, nfa: &Nfa, tx: &Text, q: usize, last_start: usize) -> Option<(usize, usize)> {
        let (a, b, stack) = (&mut self.a, &mut self.b, &mut self.stack);
        let (sa, sb) = (&mut self.sa, &mut self.sb);
        a.clear();
        sa.clear();
        let mut best: Option<(usize, usize)> = None;
        let mut p = q;
        let len = tx.t.len();
        loop {
            let (bol, eol) = (tx.bol(p), tx.eol(p));
            if best.is_none() && p <= last_start {
                closure_from(nfa, a, sa, stack, nfa.start, p, bol, eol);
            }
            if a.contains(nfa.accept) {
                let idx = a.as_slice().iter().position(|&s| s == nfa.accept).unwrap();
                let s = sa[idx];
                best = match best {
                    Some((bs, be)) if bs < s || (bs == s && be >= p) => Some((bs, be)),
                    _ => Some((s, p)),
                };
            }
            if p >= len || (a.is_empty() && (best.is_some() || p >= last_start)) {
                break;
            }
            let c = tx.t[p];
            b.clear();
            sb.clear();
            let (nbol, neol) = (tx.bol(p + 1), tx.eol(p + 1));
            for (idx, &s) in a.as_slice().iter().enumerate() {
                let st = sa[idx];
                if best.is_some_and(|(bs, _)| st > bs) {
                    break; // ascending starts: the rest are all later
                }
                if let St::Byte(set, n) = nfa.st[s as usize]
                    && set.contains(c)
                {
                    closure_from(nfa, b, sb, stack, n, st, nbol, neol);
                }
            }
            std::mem::swap(a, b);
            std::mem::swap(sa, sb);
            p += 1;
        }
        best
    }
}

#[allow(clippy::too_many_arguments)]
fn closure_from(
    nfa: &Nfa,
    set: &mut SparseSet,
    starts: &mut Vec<usize>,
    stack: &mut Vec<StateId>,
    s: StateId,
    start: usize,
    bol: bool,
    eol: bool,
) {
    stack.push(s);
    while let Some(s) = stack.pop() {
        if !set.insert(s) {
            continue;
        }
        starts.push(start);
        match nfa.st[s as usize] {
            St::Split(x, y) => {
                stack.push(y);
                stack.push(x);
            }
            St::Eps(n) => stack.push(n),
            St::Bol(n) if bol => stack.push(n),
            St::Eol(n) if eol => stack.push(n),
            _ => {}
        }
    }
}
