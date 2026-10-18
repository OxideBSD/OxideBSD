//! Thompson NFA for the syntax tree, plus its reverse edges.
//!
//! Every tree node compiles to a fragment with a dedicated entry and exit state: nothing outside
//! the fragment leads into its entry except from before it, and nothing leaves through its exit
//! except to after it. That lets `sim.rs` run any one node, or any suffix of a concatenation,
//! over a window of the text by starting at one state and stopping at another.
//!
//! Counted repetition is expanded into copies of its body. A node records the states of its
//! first copy only (all copies are identical, and the submatch engine needs just one).
//!
//! A back-reference compiles to a copy of its group's body with anchors made empty: a
//! superset of what the back-reference can match (it can only repeat a string the group
//! matched). The automata are then exact for patterns without back-references, and a sound
//! prefilter for those with them.

use crate::byteset::ByteSet;
use crate::error::{Error, ErrorKind};
use crate::parse::{Ast, Kind, NodeId};

pub type StateId = u32;
const PATCH: StateId = u32::MAX;
/// Bound on NFA size (counted repetition multiplies), then `REG_ESPACE`.
const MAX_STATES: usize = 1 << 18;

#[derive(Clone, Copy, Debug)]
pub enum St {
    Byte(ByteSet, StateId),
    Split(StateId, StateId),
    Eps(StateId),
    Bol(StateId),
    Eol(StateId),
    Match,
}

pub struct Nfa {
    pub st: Vec<St>,
    pub start: StateId,
    pub accept: StateId,
    /// `eps_rev[s]`: states with an epsilon edge (Split/Eps/Bol/Eol) to `s`.
    pub eps_rev: Vec<Vec<StateId>>,
    /// `byte_rev[s]`: `Byte` states whose successor is `s`.
    pub byte_rev: Vec<Vec<StateId>>,
}

pub fn compile(ast: &mut Ast) -> Result<Nfa, Error> {
    let mut b = B { ast, st: Vec::new(), record: true, superset: 0 };
    let root = b.ast.root;
    let (e, x) = b.frag(root)?;
    let accept = b.add(St::Match)?;
    b.link(x, accept);
    let st = b.st;
    let mut eps_rev = vec![Vec::new(); st.len()];
    let mut byte_rev = vec![Vec::new(); st.len()];
    for (q, s) in st.iter().enumerate() {
        let q = q as StateId;
        match *s {
            St::Byte(_, n) => byte_rev[n as usize].push(q),
            St::Split(a, c) => {
                eps_rev[a as usize].push(q);
                eps_rev[c as usize].push(q);
            }
            St::Eps(n) | St::Bol(n) | St::Eol(n) => eps_rev[n as usize].push(q),
            St::Match => {}
        }
    }
    Ok(Nfa { st, start: e, accept, eps_rev, byte_rev })
}

struct B<'a> {
    ast: &'a mut Ast,
    st: Vec<St>,
    /// Record fragment states on the tree (off while copying a group for a back-reference).
    record: bool,
    /// Inside a back-reference's copy of its group: anchors are empty, nested back-references
    /// match anything.
    superset: u32,
}

impl B<'_> {
    fn add(&mut self, s: St) -> Result<StateId, Error> {
        if self.st.len() >= MAX_STATES {
            return Err(Error::new(ErrorKind::Space, 0));
        }
        self.st.push(s);
        Ok((self.st.len() - 1) as StateId)
    }

    fn eps(&mut self) -> Result<StateId, Error> {
        self.add(St::Eps(PATCH))
    }

    /// Points `from` (an `Eps`, or an iteration `Split`'s first arm) at `to`.
    fn link(&mut self, from: StateId, to: StateId) {
        match &mut self.st[from as usize] {
            St::Eps(n) | St::Split(n, _) => *n = to,
            s => unreachable!("link from {s:?}"),
        }
    }

    fn leaf(&mut self, s: St) -> Result<(StateId, StateId), Error> {
        let e = self.eps()?;
        let x = self.eps()?;
        let m = self.add(s)?;
        match &mut self.st[m as usize] {
            St::Byte(_, n) | St::Bol(n) | St::Eol(n) => *n = x,
            _ => unreachable!(),
        }
        self.link(e, m);
        Ok((e, x))
    }

    /// `(any byte)*`
    fn any_loop(&mut self) -> Result<(StateId, StateId), Error> {
        let e = self.eps()?;
        let x = self.eps()?;
        let l = self.add(St::Split(PATCH, x))?;
        let by = self.add(St::Byte(ByteSet::full(), l))?;
        self.link(l, by);
        self.link(e, l);
        Ok((e, x))
    }

    fn frag(&mut self, id: NodeId) -> Result<(StateId, StateId), Error> {
        let (e, x, iters) = match &self.ast.nodes[id as usize].kind {
            Kind::Empty => {
                let e = self.eps()?;
                let x = self.eps()?;
                self.link(e, x);
                (e, x, Vec::new())
            }
            &Kind::Set(s) => {
                let (e, x) = self.leaf(St::Byte(s, PATCH))?;
                (e, x, Vec::new())
            }
            Kind::Bol | Kind::Eol if self.superset > 0 => {
                let e = self.eps()?;
                let x = self.eps()?;
                self.link(e, x);
                (e, x, Vec::new())
            }
            Kind::Bol => {
                let (e, x) = self.leaf(St::Bol(PATCH))?;
                (e, x, Vec::new())
            }
            Kind::Eol => {
                let (e, x) = self.leaf(St::Eol(PATCH))?;
                (e, x, Vec::new())
            }
            &Kind::Group(_, body) => {
                let (e, x) = self.frag(body)?;
                (e, x, Vec::new())
            }
            &Kind::Backref(g) => {
                let (e, x) = if self.superset > 0 {
                    self.any_loop()?
                } else {
                    let gn = self.ast.group_node[g as usize];
                    let Kind::Group(_, body) = self.ast.nodes[gn as usize].kind else { unreachable!() };
                    let rec = std::mem::replace(&mut self.record, false);
                    self.superset += 1;
                    let r = self.frag(body);
                    self.superset -= 1;
                    self.record = rec;
                    r?
                };
                (e, x, Vec::new())
            }
            Kind::Concat(items) => {
                let items = items.clone();
                let e = self.eps()?;
                let mut prev = e;
                for it in items {
                    let (ie, ix) = self.frag(it)?;
                    self.link(prev, ie);
                    prev = ix;
                }
                let x = self.eps()?;
                self.link(prev, x);
                (e, x, Vec::new())
            }
            Kind::Alt(alts) => {
                let alts = alts.clone();
                let e = self.eps()?;
                let x = self.eps()?;
                let mut entries = Vec::with_capacity(alts.len());
                for a in alts {
                    let (ae, ax) = self.frag(a)?;
                    self.link(ax, x);
                    entries.push(ae);
                }
                // A right-leaning chain of splits.
                let mut tail = *entries.last().unwrap();
                for &ae in entries[..entries.len() - 1].iter().rev() {
                    tail = self.add(St::Split(ae, tail))?;
                }
                self.link(e, tail);
                (e, x, Vec::new())
            }
            &Kind::Repeat { body, min, max } => {
                let e = self.eps()?;
                let x = self.eps()?;
                // iters[t]: t iterations done. Mandatory ones lead straight into the next copy;
                // optional ones may leave; an unbounded repeat loops on iters[min].
                let last = max.unwrap_or(min);
                let mut iters = Vec::with_capacity(last as usize + 1);
                for t in 0..=last {
                    let s = if max == Some(t) {
                        St::Eps(x)
                    } else if t < min {
                        St::Eps(PATCH)
                    } else {
                        St::Split(PATCH, x)
                    };
                    iters.push(self.add(s)?);
                }
                let copies = if max.is_some() { last } else { last + 1 };
                for t in 0..copies {
                    let (ce, cx) = self.frag(body)?;
                    self.link(iters[t as usize], ce);
                    let next = (t + 1).min(last);
                    self.link(cx, iters[next as usize]);
                }
                self.link(e, iters[0]);
                (e, x, iters)
            }
        };
        let node = &mut self.ast.nodes[id as usize];
        if self.record && !node.compiled {
            node.compiled = true;
            node.entry = e;
            node.exit = x;
            node.iters = iters;
        }
        Ok((e, x))
    }
}
