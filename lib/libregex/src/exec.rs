//! Submatch assignment once the overall match is known, and the back-reference search.
//!
//! Both engines answer "how does node `n` match exactly `text[i..k]`" by the rule of XBD 9.1:
//! subpatterns, left to right, each match the longest string that still lets the whole match
//! succeed. Concretely:
//!
//! - concatenation: the first item takes the longest prefix after which the rest still
//!   matches, then the next item, and so on;
//! - alternation: the first alternative that matches the span;
//! - repetition: the first iteration is the longest after which the remaining iterations still
//!   match, then the next. Iterations are non-empty unless the count demands more; a repetition
//!   over an empty span takes one empty iteration if its body can match empty (a null match is
//!   longer than no match). Groups inside report the last iteration only, cleared at the start
//!   of each iteration (XBD 9.1 rule 3: an inner group is reported within its outer one).
//!   With back-references, a final empty iteration is also tried, last, since it can make a
//!   back-reference match.
//!
//! "Still matches" is decided by NFA simulations over windows (`sim.rs`), so for a pattern
//! without back-references every choice is right the first time: `assign` never backtracks.
//! It also skips any subtree with no groups, and walks a repetition's iterations only to find
//! where the last one starts.
//!
//! With back-references the simulations are supersets, so `exact` enumerates choices in that
//! same preference order (continuation-passing, backtracking on failure) and the first success
//! is the preferred one. Subtrees that neither hold a back-reference nor contain a group one
//! names are handed to `assign`. The search is bounded by `STEP_LIMIT` calls and
//! `DEPTH_LIMIT` nesting, past which it fails with `REG_ESPACE` instead of hanging.

use crate::error::{Error, ErrorKind};
use crate::nfa::Nfa;
use crate::parse::{Ast, Kind, Node, NodeId};
use crate::sim::{Bits, Sim, Text};

pub type Span = (usize, usize);
type Res = Result<bool, Error>;
type Cont<'c, 'a> = &'c mut dyn FnMut(&mut Exec<'a>) -> Res;

/// Work bound for the back-reference search: calls plus bytes simulated.
const STEP_LIMIT: u64 = 5_000_000;
/// Continuation nesting (each level is a few stack frames; this fits a 2 MiB thread stack).
const DEPTH_LIMIT: u32 = 2_000;

pub struct Exec<'a> {
    ast: &'a Ast,
    nfa: &'a Nfa,
    tx: Text<'a>,
    icase: bool,
    pub caps: Vec<Option<Span>>,
    pub sim: Sim,
    steps: u64,
    depth: u32,
    /// Tests only: enumerate everything instead of handing independent subtrees to `assign`,
    /// to check the two engines against each other.
    #[cfg(test)]
    pub no_indep: bool,
}

fn space() -> Error {
    Error::new(ErrorKind::Space, 0)
}

impl<'a> Exec<'a> {
    pub fn new(ast: &'a Ast, nfa: &'a Nfa, tx: Text<'a>, icase: bool) -> Exec<'a> {
        Exec {
            ast,
            nfa,
            tx,
            icase,
            caps: vec![None; ast.nsub as usize + 1],
            sim: Sim::new(nfa),
            steps: 0,
            depth: 0,
            #[cfg(test)]
            no_indep: false,
        }
    }

    fn node(&self, n: NodeId) -> &'a Node {
        &self.ast.nodes[n as usize]
    }

    fn same(&self, a: usize, i: usize, len: usize) -> bool {
        let (x, y) = (&self.tx.t[a..a + len], &self.tx.t[i..i + len]);
        if self.icase { x.eq_ignore_ascii_case(y) } else { x == y }
    }

    /// Where node `n` can end when started at `i`, up to `k`, ascending. Exact for nodes
    /// without back-references, a superset otherwise.
    fn ends(&mut self, n: NodeId, i: usize, k: usize) -> Vec<usize> {
        let node = self.node(n);
        let one = |ok: bool, p: usize| if ok { vec![p] } else { Vec::new() };
        match node.kind {
            Kind::Empty => vec![i],
            Kind::Set(s) => one(i < k && s.contains(self.tx.t[i]), i + 1),
            Kind::Bol => one(self.tx.bol(i), i),
            Kind::Eol => one(self.tx.eol(i), i),
            Kind::Backref(g) => match self.caps[g as usize] {
                Some((a, b)) => one(i + (b - a) <= k && self.same(a, i, b - a), i + (b - a)),
                None => Vec::new(),
            },
            _ => {
                self.steps += (k - i) as u64 + 1;
                self.sim.ends(self.nfa, &self.tx, node.entry, node.exit, i, k)
            }
        }
    }

    fn matches(&mut self, n: NodeId, i: usize, k: usize) -> bool {
        self.ends(n, i, k).last() == Some(&k)
    }

    /// Where `items[m..]` of concatenation `cn` can start and end exactly at `k`.
    fn rest<'c>(&mut self, cn: NodeId, items: &[NodeId], m: usize, k: usize, i0: usize, cache: &'c mut [Option<Bits>]) -> &'c Bits {
        if cache[m].is_none() {
            self.steps += (k - i0) as u64 + 1;
            let at = self.node(items[m]).entry;
            cache[m] = Some(self.sim.starts(self.nfa, &self.tx, self.node(cn).exit, k, at, at, i0));
        }
        cache[m].as_ref().unwrap()
    }

    /// Where repetition `rn` can stand having done `c` iterations and still end at `k`.
    fn remaining<'c>(&mut self, rn: NodeId, c: u32, k: usize, i0: usize, cache: &'c mut [Option<Bits>]) -> &'c Bits {
        let node = self.node(rn);
        let idx = (c as usize).min(node.iters.len() - 1);
        if cache[idx].is_none() {
            self.steps += (k - i0) as u64 + 1;
            cache[idx] = Some(self.sim.starts(self.nfa, &self.tx, node.exit, k, node.iters[idx], node.entry, i0));
        }
        cache[idx].as_ref().unwrap()
    }

    fn take_groups(&mut self, (lo, hi): (u32, u32)) -> Vec<Option<Span>> {
        let r = &mut self.caps[lo as usize..hi as usize];
        let saved = r.to_vec();
        r.fill(None);
        saved
    }

    fn put_groups(&mut self, (lo, _): (u32, u32), saved: Vec<Option<Span>>) {
        self.caps[lo as usize..lo as usize + saved.len()].copy_from_slice(&saved);
    }

    // ---- without back-references ----

    /// Records the groups of node `n`, which is known to match `text[i..k]` and holds no
    /// back-reference.
    pub fn assign(&mut self, n: NodeId, i: usize, k: usize) {
        let node = self.node(n);
        if node.groups.0 == node.groups.1 {
            return;
        }
        match &node.kind {
            &Kind::Group(g, b) => {
                self.caps[g as usize] = Some((i, k));
                self.assign(b, i, k);
            }
            Kind::Concat(items) => {
                let Some(last) = items.iter().rposition(|&it| {
                    let g = self.node(it).groups;
                    g.0 < g.1
                }) else {
                    return;
                };
                let mut cache: Vec<Option<Bits>> = (0..items.len()).map(|_| None).collect();
                let mut pos = i;
                for (m, &it) in items.iter().enumerate().take(last + 1) {
                    let end = if m + 1 == items.len() {
                        k
                    } else {
                        let mut c = self.ends(it, pos, k);
                        if c.len() > 1 {
                            let r = self.rest(n, items, m + 1, k, i, &mut cache);
                            c.retain(|&x| r.get(x));
                        }
                        let Some(&e) = c.last() else {
                            debug_assert!(false, "concatenation lost its match");
                            return;
                        };
                        e
                    };
                    self.assign(it, pos, end);
                    pos = end;
                }
            }
            Kind::Alt(alts) => {
                for &a in alts {
                    if self.matches(a, i, k) {
                        self.assign(a, i, k);
                        return;
                    }
                }
            }
            &Kind::Repeat { body, min, max } => {
                let mut cache: Vec<Option<Bits>> = (0..node.iters.len()).map(|_| None).collect();
                let (mut count, mut pos) = (0u32, i);
                let mut last = None;
                while max.is_none_or(|x| count < x) {
                    if pos == k {
                        if count < min {
                            last = Some((pos, pos));
                            count += 1;
                            continue;
                        }
                        if count == 0 && self.matches(body, pos, pos) {
                            last = Some((pos, pos));
                        }
                        break;
                    }
                    let mut c = self.ends(body, pos, k);
                    c.retain(|&x| x > pos || count < min);
                    if c.len() > 1 {
                        let r = self.remaining(n, count + 1, k, i, &mut cache);
                        c.retain(|&x| r.get(x));
                    }
                    let Some(&e) = c.last() else {
                        debug_assert!(false, "repetition lost its match");
                        break;
                    };
                    last = Some((pos, e));
                    pos = e;
                    count += 1;
                }
                if let Some((a, b)) = last {
                    self.assign(body, a, b);
                }
            }
            _ => {}
        }
    }

    // ---- with back-references ----

    /// The leftmost-longest match at or after `q`, with its groups in `caps`.
    pub fn search(&mut self, q: usize) -> Result<Option<Span>, Error> {
        let len = self.tx.t.len();
        let root = self.ast.root;
        for s in q..=len {
            let ends = self.sim.ends(self.nfa, &self.tx, self.nfa.start, self.nfa.accept, s, len);
            for &e in ends.iter().rev() {
                self.caps.fill(None);
                if self.exact(root, s, e, &mut |_| Ok(true))? {
                    self.caps[0] = Some((s, e));
                    return Ok(Some((s, e)));
                }
            }
        }
        Ok(None)
    }

    /// Calls `cont` for each way node `n` can match exactly `text[i..k]`, preferred first,
    /// until it returns true.
    fn exact(&mut self, n: NodeId, i: usize, k: usize, cont: Cont<'_, 'a>) -> Res {
        self.steps += 1;
        if self.steps > STEP_LIMIT || self.depth > DEPTH_LIMIT {
            return Err(space());
        }
        let node = self.node(n);
        #[cfg(test)]
        let indep = node.indep && !self.no_indep;
        #[cfg(not(test))]
        let indep = node.indep;
        if indep {
            if !self.matches(n, i, k) {
                return Ok(false);
            }
            let saved = self.take_groups(node.groups);
            self.assign(n, i, k);
            if cont(self)? {
                return Ok(true);
            }
            self.put_groups(node.groups, saved);
            return Ok(false);
        }
        self.depth += 1;
        let r = match &node.kind {
            &Kind::Backref(g) => match self.caps[g as usize] {
                Some((a, b)) if k - i == b - a && self.same(a, i, b - a) => cont(self),
                _ => Ok(false),
            },
            &Kind::Group(g, b) => self.exact(b, i, k, &mut |ex| {
                let old = ex.caps[g as usize];
                ex.caps[g as usize] = Some((i, k));
                if cont(ex)? {
                    return Ok(true);
                }
                ex.caps[g as usize] = old;
                Ok(false)
            }),
            Kind::Concat(items) => {
                let mut cache: Vec<Option<Bits>> = (0..items.len()).map(|_| None).collect();
                self.concat(n, items, 0, i, k, i, &mut cache, cont)
            }
            Kind::Alt(alts) => {
                let mut r = Ok(false);
                for &a in alts {
                    r = self.exact(a, i, k, cont);
                    if !matches!(r, Ok(false)) {
                        break;
                    }
                }
                r
            }
            Kind::Repeat { .. } => {
                let mut cache: Vec<Option<Bits>> = (0..node.iters.len()).map(|_| None).collect();
                self.walk(n, 0, i, k, i, &mut cache, cont)
            }
            // Leaves only get here with `no_indep`.
            _ => {
                if self.matches(n, i, k) {
                    cont(self)
                } else {
                    Ok(false)
                }
            }
        };
        self.depth -= 1;
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn concat(
        &mut self,
        cn: NodeId,
        items: &'a [NodeId],
        m: usize,
        pos: usize,
        k: usize,
        i0: usize,
        cache: &mut [Option<Bits>],
        cont: Cont<'_, 'a>,
    ) -> Res {
        if m + 1 == items.len() {
            return self.exact(items[m], pos, k, cont);
        }
        let mut c = self.ends(items[m], pos, k);
        if c.len() > 1 {
            let r = self.rest(cn, items, m + 1, k, i0, cache);
            c.retain(|&x| r.get(x));
        }
        for &e in c.iter().rev() {
            if self.exact(items[m], pos, e, &mut |ex| ex.concat(cn, items, m + 1, e, k, i0, cache, cont))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Iterations of repetition `rn` from `count` done at `i`, to end at `k`.
    #[allow(clippy::too_many_arguments)]
    fn walk(&mut self, rn: NodeId, count: u32, i: usize, k: usize, i0: usize, cache: &mut [Option<Bits>], cont: Cont<'_, 'a>) -> Res {
        let node = self.node(rn);
        let Kind::Repeat { body, min, max } = node.kind else { unreachable!() };
        if max.is_some_and(|x| count >= x) {
            return if i == k { cont(self) } else { Ok(false) };
        }
        if i == k {
            if count < min {
                return self.iteration(body, i, i, &mut |ex| ex.walk(rn, count + 1, i, k, i0, cache, cont));
            }
            let can_empty = self.ends(body, i, i).contains(&i);
            if count == 0 && can_empty && self.iteration(body, i, i, cont)? {
                return Ok(true);
            }
            if cont(self)? {
                return Ok(true);
            }
            // Least preferred: a last, empty iteration. It changes nothing but the groups, and
            // a back-reference may need that (`a(a|b*)*\1` matches all of `aab`).
            return Ok(count > 0 && can_empty && self.iteration(body, i, i, cont)?);
        }
        let mut c = self.ends(body, i, k);
        c.retain(|&x| x > i || count < min);
        if c.len() > 1 {
            let r = self.remaining(rn, count + 1, k, i0, cache);
            c.retain(|&x| r.get(x));
        }
        for &e in c.iter().rev() {
            if self.iteration(body, i, e, &mut |ex| ex.walk(rn, count + 1, e, k, i0, cache, cont))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// One iteration of a repetition: its groups start out unset.
    fn iteration(&mut self, body: NodeId, i: usize, k: usize, cont: Cont<'_, 'a>) -> Res {
        let g = self.node(body).groups;
        let saved = self.take_groups(g);
        let r = self.exact(body, i, k, cont)?;
        if !r {
            self.put_groups(g, saved);
        }
        Ok(r)
    }
}
