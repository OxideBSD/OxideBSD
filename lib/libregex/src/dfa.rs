//! Lazy DFAs over the NFA, built a transition at a time and flushed when they grow too big.
//! Three are used: forward unanchored (is there a match, and where does the earliest one end:
//! the hot path for `grep`), reverse unanchored (where does the leftmost match start) and
//! forward anchored (where does the longest match from a given start end).
//!
//! A DFA state is the set of NFA states entered by the last byte, *before* epsilon closure,
//! plus whether the position it stands at is a line boundary on the side already read (`^`
//! going forward, `$` going backward). The closure waits for the next byte, because the
//! other anchor needs it: a transition on byte `b` takes the closure with one anchor decided
//! by the state and the other by `b`, notes whether that closure holds the target (a match
//! ends, or starts, *before* `b`), then steps over `b`.

use std::collections::HashMap;

use crate::nfa::{Nfa, St, StateId};
use crate::sim::{SparseSet, fclosure};

const UNKNOWN: u32 = u32::MAX;
/// Flush past this many states (each costs 4 bytes per byte class).
const MAX_STATES: usize = 4096;
const NONE: StateId = u32::MAX;

type Key = (Box<[StateId]>, bool);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Fwd,
    Rev,
}

pub struct Dfa {
    dir: Dir,
    anchored: bool,
    class: [u8; 256],
    nclass: usize,
    rep: Vec<u8>,
    nl: bool,
    keys: Vec<Key>,
    map: HashMap<Key, u32>,
    /// `trans[s * nclass + c]`: next state `<< 1`, low bit = the target is reached before
    /// this byte.
    trans: Vec<u32>,
    /// Per state, the target at the end of the text: bit 0/1 known/value with the anchor
    /// allowed there, bit 2/3 the same under `REG_NOTEOL` (forward) or `REG_NOTBOL` (reverse).
    eot: Vec<u8>,
    /// Start state for each value of the boundary flag, until the next flush.
    start: [u32; 2],
    set: SparseSet,
    stack: Vec<StateId>,
    /// Bumped by every flush.
    generation: u64,
}

impl Dfa {
    pub fn new(nfa: &Nfa, nl: bool, dir: Dir, anchored: bool) -> Dfa {
        // Byte classes: bytes no NFA set (nor, under REG_NEWLINE, the anchors) tells apart.
        let mut class = [0u8; 256];
        let mut nclass = 1;
        let mut seen = std::collections::HashSet::new();
        let refine = |class: &mut [u8; 256], nclass: &mut usize, f: &dyn Fn(u8) -> bool| {
            let mut m: HashMap<(u8, bool), u8> = HashMap::new();
            let mut n = 0usize;
            for b in 0..=255u8 {
                let k = (class[b as usize], f(b));
                let id = *m.entry(k).or_insert_with(|| {
                    n += 1;
                    (n - 1) as u8
                });
                class[b as usize] = id;
            }
            *nclass = n;
        };
        for s in &nfa.st {
            if let St::Byte(set, _) = s
                && seen.insert(*set)
                && nclass < 256
            {
                refine(&mut class, &mut nclass, &|b| set.contains(b));
            }
        }
        if nl {
            refine(&mut class, &mut nclass, &|b| b == b'\n');
        }
        let mut rep = vec![0u8; nclass];
        for b in (0..=255u8).rev() {
            rep[class[b as usize] as usize] = b;
        }
        Dfa {
            dir,
            anchored,
            class,
            nclass,
            rep,
            nl,
            keys: Vec::new(),
            map: HashMap::new(),
            trans: Vec::new(),
            eot: Vec::new(),
            start: [UNKNOWN; 2],
            set: SparseSet::new(nfa.st.len()),
            stack: Vec::new(),
            generation: 0,
        }
    }

    /// The NFA state added at every position (unanchored) or only at the start, and the one
    /// being looked for.
    fn ends(&self, nfa: &Nfa) -> (StateId, StateId) {
        match self.dir {
            Dir::Fwd => (nfa.start, nfa.accept),
            Dir::Rev => (nfa.accept, nfa.start),
        }
    }

    fn intern(&mut self, k: Key) -> u32 {
        if let Some(&id) = self.map.get(&k) {
            return id;
        }
        if self.keys.len() >= MAX_STATES {
            self.keys.clear();
            self.map.clear();
            self.trans.clear();
            self.eot.clear();
            self.start = [UNKNOWN; 2];
            self.generation += 1;
        }
        let id = self.keys.len() as u32;
        self.keys.push(k.clone());
        self.map.insert(k, id);
        self.trans.extend(std::iter::repeat_n(UNKNOWN, self.nclass));
        self.eot.push(0);
        id
    }

    fn start_state(&mut self, nfa: &Nfa, flag: bool) -> u32 {
        let s = self.start[flag as usize];
        if s != UNKNOWN {
            return s;
        }
        let pending: Box<[StateId]> = if self.anchored { Box::new([self.ends(nfa).0]) } else { Box::new([]) };
        let id = self.intern((pending, flag));
        self.start[flag as usize] = id;
        id
    }

    fn dead(&self, sid: u32) -> bool {
        self.anchored && self.keys[sid as usize].0.is_empty()
    }

    fn closure(&mut self, nfa: &Nfa, sid: u32, bol: bool, eol: bool) {
        self.set.clear();
        let inject = (!self.anchored).then(|| self.ends(nfa).0);
        let (set, stack) = (&mut self.set, &mut self.stack);
        let keys = &self.keys[sid as usize].0;
        for s in inject.into_iter().chain(keys.iter().copied()) {
            match self.dir {
                Dir::Fwd => fclosure(nfa, set, stack, s, bol, eol, NONE),
                Dir::Rev => rclosure(nfa, set, stack, s, bol, eol),
            }
        }
    }

    /// Computes (and, unless the cache was flushed, stores) the transition on class `c`.
    #[inline(never)]
    fn step(&mut self, nfa: &Nfa, sid: u32, c: usize) -> u32 {
        let b = self.rep[c];
        let flag = self.keys[sid as usize].1;
        let nlb = self.nl && b == b'\n';
        let (bol, eol) = if self.dir == Dir::Fwd { (flag, nlb) } else { (nlb, flag) };
        self.closure(nfa, sid, bol, eol);
        let accept = self.set.contains(self.ends(nfa).1);
        let mut next: Vec<StateId> = Vec::new();
        for &s in self.set.as_slice() {
            match self.dir {
                Dir::Fwd => {
                    if let St::Byte(set, n) = nfa.st[s as usize]
                        && set.contains(b)
                    {
                        next.push(n);
                    }
                }
                Dir::Rev => {
                    for &q in &nfa.byte_rev[s as usize] {
                        if let St::Byte(set, _) = nfa.st[q as usize]
                            && set.contains(b)
                        {
                            next.push(q);
                        }
                    }
                }
            }
        }
        next.sort_unstable();
        next.dedup();
        let generation = self.generation;
        let nid = self.intern((next.into_boxed_slice(), nlb));
        let v = nid << 1 | accept as u32;
        if self.generation != generation {
            return v; // flushed: `sid` is gone
        }
        self.trans[sid as usize * self.nclass + c] = v;
        v
    }

    #[inline(always)]
    fn next(&mut self, nfa: &Nfa, sid: u32, b: u8) -> u32 {
        let c = self.class[b as usize] as usize;
        let v = self.trans[sid as usize * self.nclass + c];
        if v != UNKNOWN { v } else { self.step(nfa, sid, c) }
    }

    /// The target at the end of the text; `not` is `REG_NOTEOL` forward, `REG_NOTBOL` back.
    fn at_end(&mut self, nfa: &Nfa, sid: u32, not: bool) -> bool {
        let sh = if not { 2 } else { 0 };
        let e = self.eot[sid as usize] >> sh;
        if e & 1 != 0 {
            return e & 2 != 0;
        }
        let flag = self.keys[sid as usize].1;
        let (bol, eol) = if self.dir == Dir::Fwd { (flag, !not) } else { (!not, flag) };
        self.closure(nfa, sid, bol, eol);
        let acc = self.set.contains(self.ends(nfa).1);
        self.eot[sid as usize] |= (1 | (acc as u8) << 1) << sh;
        acc
    }

    /// Forward, unanchored: the end of the earliest-ending match. `bol`: whether `^` matches
    /// at the start of `t`.
    pub fn earliest(&mut self, nfa: &Nfa, t: &[u8], bol: bool, noteol: bool) -> Option<usize> {
        let mut sid = self.start_state(nfa, bol);
        for (p, &b) in t.iter().enumerate() {
            let v = self.next(nfa, sid, b);
            if v & 1 != 0 {
                return Some(p);
            }
            sid = v >> 1;
        }
        self.at_end(nfa, sid, noteol).then_some(t.len())
    }

    /// Forward, anchored at `from`: the end of the longest match starting there. `bol`:
    /// whether `^` matches at `from`.
    pub fn longest(&mut self, nfa: &Nfa, t: &[u8], from: usize, bol: bool, noteol: bool) -> Option<usize> {
        let mut sid = self.start_state(nfa, bol);
        let mut last = None;
        for (p, &b) in t.iter().enumerate().skip(from) {
            let v = self.next(nfa, sid, b);
            if v & 1 != 0 {
                last = Some(p);
            }
            sid = v >> 1;
            if self.dead(sid) {
                return last;
            }
        }
        if self.at_end(nfa, sid, noteol) {
            last = Some(t.len());
        }
        last
    }

    /// Reverse, unanchored, over all of `t`: the start of the leftmost match.
    pub fn leftmost_start(&mut self, nfa: &Nfa, t: &[u8], notbol: bool, noteol: bool) -> Option<usize> {
        let mut sid = self.start_state(nfa, !noteol);
        let mut first = None;
        for p in (0..t.len()).rev() {
            let v = self.next(nfa, sid, t[p]);
            if v & 1 != 0 {
                first = Some(p + 1);
            }
            sid = v >> 1;
        }
        if self.at_end(nfa, sid, notbol) {
            first = Some(0);
        }
        first
    }
}

/// Epsilon closure against the edges, without barrier (the reverse DFA's).
fn rclosure(nfa: &Nfa, set: &mut SparseSet, stack: &mut Vec<StateId>, s: StateId, bol: bool, eol: bool) {
    stack.push(s);
    while let Some(s) = stack.pop() {
        if !set.insert(s) {
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
