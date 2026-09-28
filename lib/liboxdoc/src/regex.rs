//! POSIX extended regular expressions (`regex(7)`), for `apropos`'s `~` searches (MAN.md §7):
//! alternation, grouping, `* + ? {m,n}`, `.`, bracket expressions with ranges and character
//! classes, `^` and `$`, and the BSD word boundaries `[[:<:]]` and `[[:>:]]`. No back-references
//! (ERE has none), so a pattern compiles to an NFA simulated in lock step: matching time is
//! linear in the text, whatever the pattern.

/// A compiled pattern.
#[derive(Clone, Debug)]
pub struct Regex {
    prog: Vec<Inst>,
    icase: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Inst {
    Char(char),
    Any,
    /// A bracket expression: its items, and whether it is negated.
    Set(Vec<Item>, bool),
    Split(usize, usize),
    Jmp(usize),
    Bol,
    Eol,
    WordStart,
    WordEnd,
    Match,
}

#[derive(Clone, Debug, PartialEq)]
enum Item {
    Char(char),
    Range(char, char),
    Class(Class),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Class {
    Alnum,
    Alpha,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Xdigit,
}

impl Class {
    fn named(name: &str) -> Option<Class> {
        Some(match name {
            "alnum" => Class::Alnum,
            "alpha" => Class::Alpha,
            "blank" => Class::Blank,
            "cntrl" => Class::Cntrl,
            "digit" => Class::Digit,
            "graph" => Class::Graph,
            "lower" => Class::Lower,
            "print" => Class::Print,
            "punct" => Class::Punct,
            "space" => Class::Space,
            "upper" => Class::Upper,
            "xdigit" => Class::Xdigit,
            _ => return None,
        })
    }

    fn has(self, c: char) -> bool {
        match self {
            Class::Alnum => c.is_alphanumeric(),
            Class::Alpha => c.is_alphabetic(),
            Class::Blank => c == ' ' || c == '\t',
            Class::Cntrl => c.is_control(),
            Class::Digit => c.is_ascii_digit(),
            Class::Graph => !c.is_control() && !c.is_whitespace(),
            Class::Lower => c.is_lowercase(),
            Class::Print => !c.is_control(),
            Class::Punct => c.is_ascii_punctuation(),
            Class::Space => c.is_whitespace(),
            Class::Upper => c.is_uppercase(),
            Class::Xdigit => c.is_ascii_hexdigit(),
        }
    }
}

/// A parsed pattern, before compiling.
#[derive(Clone, Debug)]
enum Ast {
    Empty,
    Char(char),
    Any,
    Set(Vec<Item>, bool),
    Bol,
    Eol,
    WordStart,
    WordEnd,
    Concat(Vec<Ast>),
    Alt(Vec<Ast>),
    /// A repetition: at least `min`, at most `max` (unbounded when `None`).
    Repeat(Box<Ast>, usize, Option<usize>),
}

/// Why a pattern didn't compile, in words like regerror(3)'s.
#[derive(Clone, Debug, PartialEq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A repetition count above this is refused: the NFA copies the repeated part that many times.
const MAX_REPEAT: usize = 255;

impl Regex {
    /// Compiles `pattern`; `icase` ignores case in matching.
    pub fn new(pattern: &str, icase: bool) -> Result<Regex, Error> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut p = Parser { s: &chars, i: 0 };
        let ast = p.alt()?;
        if p.i < chars.len() {
            // Only an unmatched `)` stops the parse early.
            return Err(Error("parentheses not balanced"));
        }
        let mut prog = Vec::new();
        compile(&ast, &mut prog);
        prog.push(Inst::Match);
        Ok(Regex { prog, icase })
    }

    /// Whether the pattern matches anywhere in `text`.
    pub fn is_match(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().collect();
        let n = self.prog.len();
        let mut clist: Vec<usize> = Vec::new();
        let mut nlist: Vec<usize> = Vec::new();
        let mut on = vec![usize::MAX; n];
        for pos in 0..=text.len() {
            // A match may start at any position: add the start state each step.
            self.add(&mut clist, &mut on, 0, pos, &text);
            if clist.iter().any(|&pc| self.prog[pc] == Inst::Match) {
                return true;
            }
            let Some(&c) = text.get(pos) else { break };
            nlist.clear();
            for &pc in &clist {
                let ok = match &self.prog[pc] {
                    Inst::Char(x) => self.eq(*x, c),
                    Inst::Any => true,
                    Inst::Set(items, neg) => self.in_set(items, c) != *neg,
                    _ => false,
                };
                if ok {
                    self.add(&mut nlist, &mut on, pc + 1, pos + 1, &text);
                }
            }
            std::mem::swap(&mut clist, &mut nlist);
        }
        false
    }

    /// Adds `pc` and everything reachable from it without reading a character, at `pos`.
    fn add(&self, list: &mut Vec<usize>, on: &mut [usize], pc: usize, pos: usize, text: &[char]) {
        if on[pc] == pos {
            return;
        }
        on[pc] = pos;
        match self.prog[pc] {
            Inst::Split(a, b) => {
                self.add(list, on, a, pos, text);
                self.add(list, on, b, pos, text);
            }
            Inst::Jmp(a) => self.add(list, on, a, pos, text),
            Inst::Bol => {
                if pos == 0 {
                    self.add(list, on, pc + 1, pos, text);
                }
            }
            Inst::Eol => {
                if pos == text.len() {
                    self.add(list, on, pc + 1, pos, text);
                }
            }
            Inst::WordStart => {
                let before = pos > 0 && is_word(text[pos - 1]);
                let after = text.get(pos).is_some_and(|c| is_word(*c));
                if !before && after {
                    self.add(list, on, pc + 1, pos, text);
                }
            }
            Inst::WordEnd => {
                let before = pos > 0 && is_word(text[pos - 1]);
                let after = text.get(pos).is_some_and(|c| is_word(*c));
                if before && !after {
                    self.add(list, on, pc + 1, pos, text);
                }
            }
            _ => list.push(pc),
        }
    }

    fn eq(&self, a: char, b: char) -> bool {
        a == b || self.icase && fold(a) == fold(b)
    }

    fn in_set(&self, items: &[Item], c: char) -> bool {
        let test = |c: char| {
            items.iter().any(|it| match it {
                Item::Char(x) => *x == c,
                Item::Range(lo, hi) => *lo <= c && c <= *hi,
                Item::Class(k) => k.has(c),
            })
        };
        test(c) || self.icase && (test(fold(c)) || test(c.to_uppercase().next().unwrap_or(c)))
    }
}

fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

/// A character of a word, for `[[:<:]]` and `[[:>:]]`: alphanumeric or underscore.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    /// `branch | branch ...`
    fn alt(&mut self) -> Result<Ast, Error> {
        let mut branches = vec![self.concat()?];
        while self.peek() == Some('|') {
            self.i += 1;
            branches.push(self.concat()?);
        }
        Ok(if branches.len() == 1 { branches.pop().unwrap() } else { Ast::Alt(branches) })
    }

    /// Pieces up to `|`, `)` or the end.
    fn concat(&mut self) -> Result<Ast, Error> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.repeats(atom)?);
        }
        Ok(match items.len() {
            0 => Ast::Empty,
            1 => items.pop().unwrap(),
            _ => Ast::Concat(items),
        })
    }

    fn atom(&mut self) -> Result<Ast, Error> {
        let c = self.peek().unwrap();
        self.i += 1;
        Ok(match c {
            '(' => {
                let inner = self.alt()?;
                if self.peek() != Some(')') {
                    return Err(Error("parentheses not balanced"));
                }
                self.i += 1;
                inner
            }
            '.' => Ast::Any,
            '^' => Ast::Bol,
            '$' => Ast::Eol,
            '[' => self.bracket()?,
            '\\' => match self.peek() {
                Some(e) => {
                    self.i += 1;
                    Ast::Char(e)
                }
                None => return Err(Error("trailing backslash (\\)")),
            },
            '*' | '+' | '?' => return Err(Error("repetition-operator operand invalid")),
            '{' if self.i == 1 => return Err(Error("repetition-operator operand invalid")),
            c => Ast::Char(c),
        })
    }

    /// Repetition operators after an atom.
    fn repeats(&mut self, mut atom: Ast) -> Result<Ast, Error> {
        loop {
            let (min, max) = match self.peek() {
                Some('*') => (0, None),
                Some('+') => (1, None),
                Some('?') => (0, Some(1)),
                Some('{') if self.s.get(self.i + 1).is_some_and(|c| c.is_ascii_digit()) => {
                    self.i += 1;
                    let min = self.number()?;
                    let max = if self.peek() == Some(',') {
                        self.i += 1;
                        if self.peek() == Some('}') { None } else { Some(self.number()?) }
                    } else {
                        Some(min)
                    };
                    if self.peek() != Some('}') {
                        return Err(Error("braces not balanced"));
                    }
                    if max.is_some_and(|m| m < min) || min > MAX_REPEAT || max.is_some_and(|m| m > MAX_REPEAT) {
                        return Err(Error("invalid repetition count(s)"));
                    }
                    (min, max)
                }
                _ => return Ok(atom),
            };
            self.i += 1;
            atom = Ast::Repeat(Box::new(atom), min, max);
        }
    }

    fn number(&mut self) -> Result<usize, Error> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let s: String = self.s[start..self.i].iter().collect();
        s.parse().map_err(|_| Error("invalid repetition count(s)"))
    }

    /// After `[`: a bracket expression up to its `]`, or a word boundary.
    fn bracket(&mut self) -> Result<Ast, Error> {
        let rest: String = self.s[self.i..].iter().take(7).collect();
        if rest.starts_with("[:<:]]") {
            self.i += 6;
            return Ok(Ast::WordStart);
        }
        if rest.starts_with("[:>:]]") {
            self.i += 6;
            return Ok(Ast::WordEnd);
        }
        let mut neg = false;
        if self.peek() == Some('^') {
            neg = true;
            self.i += 1;
        }
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else { return Err(Error("brackets ([ ]) not balanced")) };
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            // `[:class:]`, `[=c=]`, `[.c.]`.
            if c == '[' && matches!(self.s.get(self.i + 1), Some(':' | '=' | '.')) {
                let kind = self.s[self.i + 1];
                let start = self.i + 2;
                let mut j = start;
                while j + 1 < self.s.len() && !(self.s[j] == kind && self.s[j + 1] == ']') {
                    j += 1;
                }
                if j + 1 >= self.s.len() {
                    return Err(Error("brackets ([ ]) not balanced"));
                }
                let name: String = self.s[start..j].iter().collect();
                self.i = j + 2;
                match kind {
                    ':' => items.push(Item::Class(Class::named(&name).ok_or(Error("invalid character class"))?)),
                    _ => {
                        let mut it = name.chars();
                        match (it.next(), it.next()) {
                            (Some(ch), None) => items.push(Item::Char(ch)),
                            _ => return Err(Error("invalid collating element")),
                        }
                    }
                }
                continue;
            }
            self.i += 1;
            // A range, unless the `-` is last.
            if self.peek() == Some('-') && self.s.get(self.i + 1).is_some_and(|n| *n != ']') {
                let hi = self.s[self.i + 1];
                self.i += 2;
                if hi < c {
                    return Err(Error("invalid character range"));
                }
                items.push(Item::Range(c, hi));
            } else {
                items.push(Item::Char(c));
            }
        }
        Ok(Ast::Set(items, neg))
    }
}

fn compile(ast: &Ast, prog: &mut Vec<Inst>) {
    match ast {
        Ast::Empty => {}
        Ast::Char(c) => prog.push(Inst::Char(*c)),
        Ast::Any => prog.push(Inst::Any),
        Ast::Set(items, neg) => prog.push(Inst::Set(items.clone(), *neg)),
        Ast::Bol => prog.push(Inst::Bol),
        Ast::Eol => prog.push(Inst::Eol),
        Ast::WordStart => prog.push(Inst::WordStart),
        Ast::WordEnd => prog.push(Inst::WordEnd),
        Ast::Concat(items) => {
            for a in items {
                compile(a, prog);
            }
        }
        Ast::Alt(branches) => {
            // split L1, next; L1: branch; jmp end; next: split ... ; last branch
            let mut jumps = Vec::new();
            for (k, b) in branches.iter().enumerate() {
                if k + 1 < branches.len() {
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, 0));
                    compile(b, prog);
                    jumps.push(prog.len());
                    prog.push(Inst::Jmp(0));
                    let next = prog.len();
                    prog[split] = Inst::Split(split + 1, next);
                } else {
                    compile(b, prog);
                }
            }
            let end = prog.len();
            for j in jumps {
                prog[j] = Inst::Jmp(end);
            }
        }
        Ast::Repeat(a, min, max) => {
            for _ in 0..*min {
                compile(a, prog);
            }
            match max {
                None => {
                    // L: split body, out; body; jmp L
                    let l = prog.len();
                    prog.push(Inst::Split(l + 1, 0));
                    compile(a, prog);
                    prog.push(Inst::Jmp(l));
                    let out = prog.len();
                    prog[l] = Inst::Split(l + 1, out);
                }
                Some(max) => {
                    // Each optional copy: split body, out.
                    let mut splits = Vec::new();
                    for _ in *min..*max {
                        splits.push(prog.len());
                        prog.push(Inst::Split(0, 0));
                        compile(a, prog);
                    }
                    let out = prog.len();
                    for s in splits {
                        prog[s] = Inst::Split(s + 1, out);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Regex;

    fn m(p: &str, t: &str) -> bool {
        Regex::new(p, false).unwrap().is_match(t)
    }

    #[test]
    fn basics() {
        assert!(m("abc", "xxabcxx"));
        assert!(!m("^abc", "xabc"));
        assert!(m("^abc$", "abc"));
        assert!(m("a|b", "b"));
        assert!(m("^(ab|cd)+$", "abcdab"));
        assert!(!m("^(ab|cd)+$", "abc"));
        assert!(m("^a{2,3}$", "aaa"));
        assert!(!m("^a{2,3}$", "aaaa"));
        assert!(m("^a{2,}$", "aaaaa"));
        assert!(m("colou?r", "color"));
        assert!(m("^[[:digit:]]+$", "123"));
        assert!(m("^[^a-c]$", "d"));
        assert!(!m("^[^a-c]$", "b"));
        assert!(m("[]x]", "]"));
        assert!(m("^[a-]$", "-"));
        assert!(m("set.?[ug]id", "setuid"));
        assert!(m("a.c", "abc"));
        assert!(m("\\.cf", "x.cf"));
        assert!(!m("\\.cf", "xacf"));
        assert!(m("", "anything"));
    }

    #[test]
    fn words_and_case() {
        assert!(m("[[:<:]]ssh[[:>:]]", "an ssh client"));
        assert!(!m("[[:<:]]ssh[[:>:]]", "sshd"));
        assert!(Regex::new("LS", true).unwrap().is_match("ls"));
        assert!(!Regex::new("LS", false).unwrap().is_match("ls"));
        assert!(Regex::new("[A-C]", true).unwrap().is_match("b"));
    }

    #[test]
    fn errors() {
        assert!(Regex::new("(a", false).is_err());
        assert!(Regex::new("a)", false).is_err());
        assert!(Regex::new("[a", false).is_err());
        assert!(Regex::new("*a", false).is_err());
        assert!(Regex::new("a{3,2}", false).is_err());
    }

    #[test]
    fn no_blowup() {
        let p = "^(a|aa)*(a|aa)*(a|aa)*b$";
        let t = "a".repeat(5000);
        assert!(!m(p, &t));
    }
}
