//! Pattern syntax (XBD 9.3 BREs, 9.4 EREs) to a syntax tree held in an arena. Children are always
//! pushed before their parent, so a forward walk over the arena is a post-order walk.

use crate::byteset::{self, ByteSet};
use crate::error::{Error, ErrorKind as K};

pub type NodeId = u32;

/// `RE_DUP_MAX`, as on the BSDs (and POSIX's minimum).
pub const DUP_MAX: u32 = 255;
/// Deepest nesting of groups and repetitions accepted; the parser, the compiler and the submatch
/// engine recurse on it.
const MAX_DEPTH: u32 = 500;

#[derive(Debug)]
pub enum Kind {
    Empty,
    Set(ByteSet),
    Bol,
    Eol,
    Group(u32, NodeId),
    Concat(Vec<NodeId>),
    Alt(Vec<NodeId>),
    Repeat { body: NodeId, min: u32, max: Option<u32> },
    Backref(u32),
}

pub struct Node {
    pub kind: Kind,
    /// Group numbers inside this subtree, a contiguous range (groups number in the order their
    /// open parentheses appear). Empty when `lo == hi`.
    pub groups: (u32, u32),
    /// The subtree holds a back-reference.
    pub backref: bool,
    /// Neither holds a back-reference nor a group some back-reference names: how it matches
    /// inside its span cannot change whether the rest of the pattern matches.
    pub indep: bool,
    /// Nesting depth of the subtree.
    pub depth: u32,
    // Filled in by the compiler (`nfa.rs`) from the first copy it makes of this node.
    pub compiled: bool,
    pub entry: u32,
    pub exit: u32,
    /// For `Repeat`: the NFA state reached after `t` iterations, `t = 0..=` the last distinct one.
    pub iters: Vec<u32>,
}

pub struct Ast {
    pub nodes: Vec<Node>,
    pub root: NodeId,
    pub nsub: u32,
    /// `group_node[g]`: the `Group` node of group `g` (index 0 unused).
    pub group_node: Vec<NodeId>,
    pub has_backref: bool,
}

pub struct Opts {
    pub ere: bool,
    pub icase: bool,
    pub newline: bool,
}

pub fn parse(pat: &[u8], o: &Opts) -> Result<Ast, Error> {
    let mut p =
        P { p: pat, i: 0, o, nodes: Vec::new(), ngroups: 0, closed: vec![false], referenced: vec![false], group_node: vec![0], depth: 0 };
    let root = if o.ere { p.ere_alt()? } else { p.bre_branch()? };
    if p.i != pat.len() {
        // Only an unmatched closing parenthesis stops the top-level parse early.
        return Err(p.err(K::Paren));
    }
    let referenced = std::mem::take(&mut p.referenced);
    let mut nodes = p.nodes;
    annotate(&mut nodes, &referenced)?;
    let has_backref = nodes[root as usize].backref;
    Ok(Ast { nodes, root, nsub: p.ngroups, group_node: p.group_node, has_backref })
}

/// Fills `groups`, `backref`, `indep` and `depth` bottom-up.
fn annotate(nodes: &mut [Node], referenced: &[bool]) -> Result<(), Error> {
    for n in 0..nodes.len() {
        let kids: Vec<NodeId> = match &nodes[n].kind {
            Kind::Group(_, b) => vec![*b],
            Kind::Concat(v) | Kind::Alt(v) => v.clone(),
            Kind::Repeat { body, .. } => vec![*body],
            _ => vec![],
        };
        let (mut lo, mut hi) = (u32::MAX, 0);
        let mut backref = matches!(nodes[n].kind, Kind::Backref(_));
        let mut depth = 0;
        let mut refd = false;
        for &k in &kids {
            let c = &nodes[k as usize];
            if c.groups.0 < c.groups.1 {
                lo = lo.min(c.groups.0);
                hi = hi.max(c.groups.1);
            }
            backref |= c.backref;
            refd |= !c.indep && !c.backref;
            depth = depth.max(c.depth);
        }
        if let Kind::Group(g, _) = nodes[n].kind {
            lo = lo.min(g);
            hi = hi.max(g + 1);
            refd |= referenced[g as usize];
        }
        if lo >= hi {
            (lo, hi) = (0, 0);
        }
        let node = &mut nodes[n];
        node.groups = (lo, hi);
        node.backref = backref;
        node.indep = !backref && !refd;
        node.depth = depth + 1;
        if node.depth > MAX_DEPTH {
            return Err(Error::new(K::Space, 0));
        }
    }
    Ok(())
}

struct P<'a> {
    p: &'a [u8],
    i: usize,
    o: &'a Opts,
    nodes: Vec<Node>,
    ngroups: u32,
    closed: Vec<bool>,
    referenced: Vec<bool>,
    group_node: Vec<NodeId>,
    depth: u32,
}

/// One bracket-expression element.
enum Elem {
    Char(u8),
    Class(ByteSet),
}

type R<T> = Result<T, Error>;

impl P<'_> {
    fn err(&self, k: K) -> Error {
        Error::new(k, self.i)
    }

    fn peek(&self) -> Option<u8> {
        self.p.get(self.i).copied()
    }

    fn peek_at(&self, off: usize) -> Option<u8> {
        self.p.get(self.i + off).copied()
    }

    fn push(&mut self, kind: Kind) -> NodeId {
        self.nodes.push(Node {
            kind,
            groups: (0, 0),
            backref: false,
            indep: true,
            depth: 0,
            compiled: false,
            entry: 0,
            exit: 0,
            iters: Vec::new(),
        });
        (self.nodes.len() - 1) as NodeId
    }

    fn set(&mut self, mut s: ByteSet) -> NodeId {
        if self.o.icase {
            s.fold_case();
        }
        self.push(Kind::Set(s))
    }

    fn lit(&mut self, b: u8) -> NodeId {
        self.set(ByteSet::single(b))
    }

    fn dot(&mut self) -> NodeId {
        let mut s = ByteSet::full();
        if self.o.newline {
            s.remove(b'\n');
        }
        self.push(Kind::Set(s))
    }

    fn concat(&mut self, mut items: Vec<NodeId>) -> NodeId {
        match items.len() {
            0 => self.push(Kind::Empty),
            1 => items.pop().unwrap(),
            _ => self.push(Kind::Concat(items)),
        }
    }

    fn open_group(&mut self) -> R<u32> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err(K::Space));
        }
        self.ngroups += 1;
        self.closed.push(false);
        self.referenced.push(false);
        self.group_node.push(0);
        Ok(self.ngroups)
    }

    fn close_group(&mut self, g: u32, inner: NodeId) -> NodeId {
        self.depth -= 1;
        self.closed[g as usize] = true;
        let n = self.push(Kind::Group(g, inner));
        self.group_node[g as usize] = n;
        n
    }

    fn repeat(&mut self, body: NodeId, min: u32, max: Option<u32>) -> NodeId {
        self.push(Kind::Repeat { body, min, max })
    }

    /// After a backslash: a back-reference or a quoted character. Undefined escapes (`\n`,
    /// `\w`, ...) are the character itself, as on the BSDs without `REG_ENHANCED`.
    fn escape(&mut self) -> R<NodeId> {
        self.i += 1;
        let Some(c) = self.peek() else { return Err(self.err(K::Escape)) };
        if (b'1'..=b'9').contains(&c) {
            let n = (c - b'0') as u32;
            if n > self.ngroups || !self.closed[n as usize] {
                return Err(self.err(K::Subreg));
            }
            self.i += 1;
            self.referenced[n as usize] = true;
            return Ok(self.push(Kind::Backref(n)));
        }
        self.i += 1;
        Ok(self.lit(c))
    }

    // ---- EREs ----

    fn ere_alt(&mut self) -> R<NodeId> {
        let mut br = vec![self.ere_branch()?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            br.push(self.ere_branch()?);
        }
        Ok(if br.len() == 1 { br[0] } else { self.push(Kind::Alt(br)) })
    }

    fn ere_branch(&mut self) -> R<NodeId> {
        let mut items = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'|') => break,
                Some(b')') if self.depth > 0 => break,
                _ => {}
            }
            let mut atom = self.ere_atom()?;
            loop {
                let (min, max) = match self.peek() {
                    Some(b'*') => (0, None),
                    Some(b'+') => (1, None),
                    Some(b'?') => (0, Some(1)),
                    Some(b'{') => {
                        self.i += 1;
                        let (m, n) = self.interval(false)?;
                        self.i -= 1;
                        (m, n)
                    }
                    _ => break,
                };
                if matches!(self.nodes[atom as usize].kind, Kind::Bol | Kind::Eol) {
                    return Err(self.err(K::BadRpt));
                }
                self.i += 1;
                atom = self.repeat(atom, min, max);
            }
            items.push(atom);
        }
        Ok(self.concat(items))
    }

    fn ere_atom(&mut self) -> R<NodeId> {
        let c = self.p[self.i];
        match c {
            b'(' => {
                self.i += 1;
                let g = self.open_group()?;
                let inner = self.ere_alt()?;
                if self.peek() != Some(b')') {
                    return Err(self.err(K::Paren));
                }
                self.i += 1;
                Ok(self.close_group(g, inner))
            }
            b'*' | b'+' | b'?' | b'{' => Err(self.err(K::BadRpt)),
            b'^' => {
                self.i += 1;
                Ok(self.push(Kind::Bol))
            }
            b'$' => {
                self.i += 1;
                Ok(self.push(Kind::Eol))
            }
            b'.' => {
                self.i += 1;
                Ok(self.dot())
            }
            b'[' => self.bracket(),
            b'\\' => self.escape(),
            // Including an unmatched `)`: XBD 9.4.3 makes it special only when matched.
            _ => {
                self.i += 1;
                Ok(self.lit(c))
            }
        }
    }

    // ---- BREs ----

    fn at_close_paren(&self) -> bool {
        self.peek() == Some(b'\\') && self.peek_at(1) == Some(b')')
    }

    fn bre_branch(&mut self) -> R<NodeId> {
        let mut items: Vec<NodeId> = Vec::new();
        let mut lead_anchor = false;
        while let Some(c) = self.peek() {
            if self.at_close_paren() {
                if self.depth > 0 {
                    break;
                }
                return Err(self.err(K::Paren));
            }
            // `*` is literal at the start of the RE or a subexpression, or after a leading `^`.
            let start = items.is_empty() || (lead_anchor && items.len() == 1);
            let mut atom = match c {
                b'^' if items.is_empty() => {
                    self.i += 1;
                    lead_anchor = true;
                    let a = self.push(Kind::Bol);
                    items.push(a);
                    continue;
                }
                b'$' if {
                    let rest = &self.p[self.i + 1..];
                    rest.is_empty() || rest.starts_with(b"\\)")
                } =>
                {
                    self.i += 1;
                    let a = self.push(Kind::Eol);
                    items.push(a);
                    continue;
                }
                b'*' if start => {
                    self.i += 1;
                    self.lit(b'*')
                }
                b'.' => {
                    self.i += 1;
                    self.dot()
                }
                b'[' => self.bracket()?,
                b'\\' => match self.peek_at(1) {
                    Some(b'(') => {
                        self.i += 2;
                        let g = self.open_group()?;
                        let inner = self.bre_branch()?;
                        if !self.at_close_paren() {
                            return Err(self.err(K::Paren));
                        }
                        self.i += 2;
                        self.close_group(g, inner)
                    }
                    Some(b'{') => return Err(self.err(K::BadRpt)),
                    _ => self.escape()?,
                },
                _ => {
                    self.i += 1;
                    self.lit(c)
                }
            };
            loop {
                if self.peek() == Some(b'*') {
                    self.i += 1;
                    atom = self.repeat(atom, 0, None);
                } else if self.peek() == Some(b'\\') && self.peek_at(1) == Some(b'{') {
                    self.i += 2;
                    let (m, n) = self.interval(true)?;
                    atom = self.repeat(atom, m, n);
                } else {
                    break;
                }
            }
            items.push(atom);
        }
        Ok(self.concat(items))
    }

    // ---- shared ----

    /// After `{` (or `\{`): `m`, `m,` or `m,n`, then the closing brace, which is consumed.
    fn interval(&mut self, bre: bool) -> R<(u32, Option<u32>)> {
        let num = |s: &mut Self| -> R<Option<u32>> {
            let mut v: Option<u32> = None;
            while let Some(d @ b'0'..=b'9') = s.peek() {
                let n = v.unwrap_or(0) * 10 + (d - b'0') as u32;
                if n > DUP_MAX {
                    return Err(s.err(K::BadBr));
                }
                v = Some(n);
                s.i += 1;
            }
            Ok(v)
        };
        let Some(min) = num(self)? else {
            return Err(self.err(if self.peek().is_none() { K::Brace } else { K::BadBr }));
        };
        let max = if self.peek() == Some(b',') {
            self.i += 1;
            num(self)?
        } else {
            Some(min)
        };
        let closed = if bre { self.peek() == Some(b'\\') && self.peek_at(1) == Some(b'}') } else { self.peek() == Some(b'}') };
        if !closed {
            let at_end = self.peek().is_none() || (bre && self.peek() == Some(b'\\') && self.peek_at(1).is_none());
            return Err(self.err(if at_end { K::Brace } else { K::BadBr }));
        }
        self.i += if bre { 2 } else { 1 };
        if max.is_some_and(|n| n < min) {
            return Err(self.err(K::BadBr));
        }
        Ok((min, max))
    }

    /// At `[`. Backslash is literal inside; `]` first (after an optional `^`) is literal; `-`
    /// is literal first or last.
    fn bracket(&mut self) -> R<NodeId> {
        self.i += 1;
        let neg = self.peek() == Some(b'^');
        if neg {
            self.i += 1;
        }
        let mut set = ByteSet::new();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else { return Err(self.err(K::Brack)) };
            if c == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            let start = self.bracket_elem()?;
            let is_range = self.peek() == Some(b'-') && self.peek_at(1).is_some_and(|c| c != b']');
            if !is_range {
                match start {
                    Elem::Char(c) => set.insert(c),
                    Elem::Class(s) => set.union(&s),
                }
                continue;
            }
            let Elem::Char(lo) = start else { return Err(self.err(K::Range)) };
            self.i += 1;
            let Elem::Char(hi) = self.bracket_elem()? else { return Err(self.err(K::Range)) };
            if lo > hi {
                return Err(self.err(K::Range));
            }
            set.insert_range(lo, hi);
            // A range end can't start another range: `[a-c-e]`.
            if self.peek() == Some(b'-') && self.peek_at(1).is_some_and(|c| c != b']') {
                return Err(self.err(K::Range));
            }
        }
        if self.o.icase {
            set.fold_case();
        }
        if neg {
            set.negate();
            if self.o.newline {
                set.remove(b'\n');
            }
        }
        Ok(self.push(Kind::Set(set)))
    }

    fn bracket_elem(&mut self) -> R<Elem> {
        let c = self.p[self.i];
        if c == b'['
            && let Some(d @ (b'.' | b'=' | b':')) = self.peek_at(1)
        {
            let body = self.i + 2;
            let close = [d, b']'];
            let Some(len) = self.p[body..].windows(2).position(|w| w == close) else {
                return Err(self.err(K::Brack));
            };
            let name = &self.p[body..body + len];
            self.i = body + len + 2;
            return match d {
                b':' => match byteset::class(name) {
                    Some(s) => Ok(Elem::Class(s)),
                    None => Err(self.err(K::Ctype)),
                },
                // The POSIX locale's collating elements and equivalence classes are single
                // characters.
                _ if name.len() != 1 => Err(self.err(K::Collate)),
                b'.' => Ok(Elem::Char(name[0])),
                _ => Ok(Elem::Class(ByteSet::single(name[0]))),
            };
        }
        self.i += 1;
        Ok(Elem::Char(c))
    }
}
