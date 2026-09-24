//! Parser for the POSIX Shell Command Language (XCU 2.3 token recognition, 2.10 grammar).
//!
//! Scanning and parsing are one pass over one character stream, because the language doesn't
//! allow them to be separated: `$( … )` contains a complete command list (whose `case` patterns
//! may contain a bare `)`), and a here-document's body begins on the line *after* the `<<` that
//! introduced it. The scanner reads one token at a time on demand; a here-document registered by
//! the parser is filled in when the scanner next consumes a newline.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use crate::ast::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

/// Parses a complete script.
pub fn parse(source: &str) -> Result<List> {
    let mut p = Parser::new(source);
    let list = p.list(Terminator::Eof)?;
    p.expect_eof()?;
    Ok(list)
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Word(Word, String),
    IoNumber(u32),
    Op(Op),
    Newline,
    Eof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    AndIf,
    OrIf,
    DSemi,
    Semi,
    Amp,
    Pipe,
    LParen,
    RParen,
    Less,
    Great,
    DLess,
    DLessDash,
    DGreat,
    LessAnd,
    GreatAnd,
    LessGreat,
    Clobber,
}

/// What ends the list currently being parsed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Terminator {
    Eof,
    /// Inside `$( … )`: stop at the matching `)`.
    CloseParen,
    /// Inside a compound command: stop at any of these reserved words / operators.
    Words(&'static [&'static str]),
}

struct PendingHereDoc {
    delimiter: String,
    strip_tabs: bool,
    quoted: bool,
    body: Rc<RefCell<Word>>,
}

struct Parser {
    src: Vec<char>,
    pos: usize,
    peeked: Option<(Token, usize)>,
    pending: Vec<PendingHereDoc>,
}

const METACHARS: &[char] = &['|', '&', ';', '<', '>', '(', ')', ' ', '\t', '\n'];

fn is_name_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_name_char(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

pub(crate) fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(is_name_start) && chars.all(is_name_char)
}

impl Parser {
    fn new(source: &str) -> Self {
        Parser { src: source.chars().collect(), pos: 0, peeked: None, pending: Vec::new() }
    }

    // --- errors -------------------------------------------------------------------------------

    fn error_at(&self, pos: usize, message: impl Into<String>) -> ParseError {
        let before = &self.src[..pos.min(self.src.len())];
        let line = before.iter().filter(|&&c| c == '\n').count() + 1;
        let column = pos - before.iter().rposition(|&c| c == '\n').map_or(0, |i| i + 1) + 1;
        ParseError { line, column, message: message.into() }
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        let pos = self.peeked.as_ref().map_or(self.pos, |(_, start)| *start);
        self.error_at(pos, message)
    }

    // --- characters ---------------------------------------------------------------------------

    fn ch(&self) -> Option<char> {
        self.src.get(self.pos).copied()
    }

    fn ch_at(&self, offset: usize) -> Option<char> {
        self.src.get(self.pos + offset).copied()
    }

    fn eat_char(&mut self, c: char) -> bool {
        if self.ch() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    // --- tokens -------------------------------------------------------------------------------

    fn peek(&mut self) -> Result<&Token> {
        if self.peeked.is_none() {
            let start_and_token = self.scan()?;
            self.peeked = Some(start_and_token);
        }
        Ok(&self.peeked.as_ref().unwrap().0)
    }

    fn next(&mut self) -> Result<Token> {
        self.peek()?;
        Ok(self.peeked.take().unwrap().0)
    }

    /// The current token is this unquoted reserved word (only meaningful in command position).
    fn peek_reserved(&mut self, word: &str) -> Result<bool> {
        Ok(matches!(self.peek()?, Token::Word(_, raw) if raw == word))
    }

    fn peek_op(&mut self, op: Op) -> Result<bool> {
        Ok(*self.peek()? == Token::Op(op))
    }

    fn skip_newlines(&mut self) -> Result<()> {
        while *self.peek()? == Token::Newline {
            self.next()?;
        }
        Ok(())
    }

    fn expect_reserved(&mut self, word: &str) -> Result<()> {
        if self.peek_reserved(word)? {
            self.next()?;
            Ok(())
        } else {
            Err(self.error(format!("expected `{word}`")))
        }
    }

    fn expect_op(&mut self, op: Op, what: &str) -> Result<()> {
        if self.peek_op(op)? {
            self.next()?;
            Ok(())
        } else {
            Err(self.error(format!("expected `{what}`")))
        }
    }

    fn expect_eof(&mut self) -> Result<()> {
        match self.peek()?.clone() {
            Token::Eof => Ok(()),
            Token::Op(Op::RParen) => Err(self.error("unexpected `)`")),
            Token::Op(Op::DSemi) => Err(self.error("unexpected `;;`")),
            Token::Word(_, raw) => Err(self.error(format!("unexpected `{raw}`"))),
            _ => Err(self.error("unexpected token")),
        }
    }

    // --- scanner ------------------------------------------------------------------------------

    /// Reads the next token, returning it with its starting offset.
    fn scan(&mut self) -> Result<(Token, usize)> {
        loop {
            match self.ch() {
                Some(' ' | '\t') => self.pos += 1,
                Some('\\') if self.ch_at(1) == Some('\n') => self.pos += 2,
                Some('#') => {
                    while self.ch().is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let start = self.pos;
        let Some(c) = self.ch() else {
            if let Some(h) = self.pending.first() {
                let d = h.delimiter.clone();
                return Err(self.error_at(start, format!("here-document delimited by `{d}` never ends")));
            }
            return Ok((Token::Eof, start));
        };
        if c == '\n' {
            self.pos += 1;
            self.read_pending_heredocs()?;
            return Ok((Token::Newline, start));
        }
        if let Some(op) = self.scan_operator() {
            return Ok((Token::Op(op), start));
        }
        // An all-digit word immediately followed by `<` or `>` is an IO_NUMBER.
        let digits = self.src[self.pos..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && matches!(self.ch_at(digits), Some('<' | '>')) {
            let n: String = self.src[self.pos..self.pos + digits].iter().collect();
            self.pos += digits;
            let n = n.parse().map_err(|_| self.error_at(start, "file descriptor number too large"))?;
            return Ok((Token::IoNumber(n), start));
        }
        let word = self.scan_word(start)?;
        let raw: String = self.src[start..self.pos].iter().collect();
        Ok((Token::Word(word, raw), start))
    }

    fn scan_operator(&mut self) -> Option<Op> {
        let c0 = self.ch()?;
        let c1 = self.ch_at(1);
        let c2 = self.ch_at(2);
        let (op, len) = match (c0, c1, c2) {
            ('&', Some('&'), _) => (Op::AndIf, 2),
            ('|', Some('|'), _) => (Op::OrIf, 2),
            (';', Some(';'), _) => (Op::DSemi, 2),
            ('<', Some('<'), Some('-')) => (Op::DLessDash, 3),
            ('<', Some('<'), _) => (Op::DLess, 2),
            ('>', Some('>'), _) => (Op::DGreat, 2),
            ('<', Some('&'), _) => (Op::LessAnd, 2),
            ('>', Some('&'), _) => (Op::GreatAnd, 2),
            ('<', Some('>'), _) => (Op::LessGreat, 2),
            ('>', Some('|'), _) => (Op::Clobber, 2),
            (';', _, _) => (Op::Semi, 1),
            ('&', _, _) => (Op::Amp, 1),
            ('|', _, _) => (Op::Pipe, 1),
            ('(', _, _) => (Op::LParen, 1),
            (')', _, _) => (Op::RParen, 1),
            ('<', _, _) => (Op::Less, 1),
            ('>', _, _) => (Op::Great, 1),
            _ => return None,
        };
        self.pos += len;
        Some(op)
    }

    /// Scans one word up to the next unquoted metacharacter.
    fn scan_word(&mut self, start: usize) -> Result<Word> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        while let Some(c) = self.ch() {
            if METACHARS.contains(&c) {
                break;
            }
            match c {
                '\\' => {
                    self.pos += 1;
                    match self.ch() {
                        Some('\n') => self.pos += 1,
                        Some(e) => {
                            flush(&mut lit, &mut parts);
                            parts.push(WordPart::Quoted(e.to_string()));
                            self.pos += 1;
                        }
                        None => lit.push('\\'),
                    }
                }
                '\'' => {
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::Quoted(self.scan_single_quoted()?));
                }
                '"' => {
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::DoubleQuoted(self.scan_double_quoted()?));
                }
                '$' => {
                    if let Some(part) = self.scan_dollar()? {
                        flush(&mut lit, &mut parts);
                        parts.push(part);
                    } else {
                        lit.push('$');
                    }
                }
                '`' => {
                    flush(&mut lit, &mut parts);
                    parts.push(self.scan_backquote(false)?);
                }
                _ => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        flush(&mut lit, &mut parts);
        if parts.is_empty() && self.pos == start {
            return Err(self.error_at(start, "expected a word"));
        }
        Ok(parts)
    }

    fn scan_single_quoted(&mut self) -> Result<String> {
        let open = self.pos;
        self.pos += 1;
        let mut s = String::new();
        loop {
            match self.ch() {
                None => return Err(self.error_at(open, "unterminated single quote")),
                Some('\'') => {
                    self.pos += 1;
                    return Ok(s);
                }
                Some(c) => {
                    s.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    /// Scans `"…"`. Inside, backslash only escapes `$ \` " \\` and newline (XCU 2.2.3).
    fn scan_double_quoted(&mut self) -> Result<Vec<WordPart>> {
        let open = self.pos;
        self.pos += 1;
        let mut parts = Vec::new();
        let mut lit = String::new();
        loop {
            match self.ch() {
                None => return Err(self.error_at(open, "unterminated double quote")),
                Some('"') => {
                    self.pos += 1;
                    break;
                }
                Some('\\') => {
                    self.pos += 1;
                    match self.ch() {
                        Some('\n') => self.pos += 1,
                        Some(e @ ('$' | '`' | '"' | '\\')) => {
                            lit.push(e);
                            self.pos += 1;
                        }
                        _ => lit.push('\\'),
                    }
                }
                Some('$') => {
                    if let Some(part) = self.scan_dollar()? {
                        flush_quoted(&mut lit, &mut parts);
                        parts.push(part);
                    } else {
                        lit.push('$');
                    }
                }
                Some('`') => {
                    flush_quoted(&mut lit, &mut parts);
                    parts.push(self.scan_backquote(true)?);
                }
                Some(c) => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        flush_quoted(&mut lit, &mut parts);
        Ok(parts)
    }

    /// At a `$`. Returns `None` (consuming only the `$`) when it doesn't start an expansion.
    fn scan_dollar(&mut self) -> Result<Option<WordPart>> {
        let start = self.pos;
        self.pos += 1;
        match self.ch() {
            Some('(') if self.ch_at(1) == Some('(') => {
                self.pos += 2;
                Ok(Some(WordPart::Arith(self.scan_arith(start)?)))
            }
            Some('(') => {
                self.pos += 1;
                let list = self.sub_list(start)?;
                Ok(Some(WordPart::CommandSubst(Rc::new(list))))
            }
            Some('{') => {
                self.pos += 1;
                Ok(Some(WordPart::Param(self.scan_braced_param(start)?)))
            }
            Some(c) if is_name_start(c) => {
                let mut name = String::new();
                while let Some(c) = self.ch().filter(|&c| is_name_char(c)) {
                    name.push(c);
                    self.pos += 1;
                }
                Ok(Some(plain(Param::Named(name))))
            }
            Some(c) if c.is_ascii_digit() => {
                self.pos += 1;
                Ok(Some(plain(digit_param(c))))
            }
            Some(c @ ('@' | '*' | '#' | '?' | '-' | '$' | '!')) => {
                self.pos += 1;
                Ok(Some(plain(Param::Special(c))))
            }
            _ => Ok(None),
        }
    }

    /// Parses the list inside `$( … )`, consuming the closing `)`.
    fn sub_list(&mut self, open: usize) -> Result<List> {
        debug_assert!(self.peeked.is_none());
        let list = self.list(Terminator::CloseParen)?;
        if !self.peek_op(Op::RParen)? {
            return Err(self.error_at(open, "unterminated `$(`"));
        }
        self.peeked = None;
        Ok(list)
    }

    /// Scans a `$(( … ))` expression up to the matching `))`. The text is kept as a word (so its
    /// own `$x` and `$(…)` expand before evaluation); nested parentheses are balanced.
    fn scan_arith(&mut self, start: usize) -> Result<Vec<WordPart>> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut depth = 0usize;
        loop {
            match self.ch() {
                None => return Err(self.error_at(start, "unterminated `$((`")),
                Some(')') if depth == 0 && self.ch_at(1) == Some(')') => {
                    self.pos += 2;
                    break;
                }
                Some(c @ ('(' | ')')) => {
                    depth = if c == '(' { depth + 1 } else { depth.saturating_sub(1) };
                    lit.push(c);
                    self.pos += 1;
                }
                Some('$') => match self.scan_dollar()? {
                    Some(part) => {
                        flush(&mut lit, &mut parts);
                        parts.push(part);
                    }
                    None => lit.push('$'),
                },
                Some('`') => {
                    flush(&mut lit, &mut parts);
                    parts.push(self.scan_backquote(false)?);
                }
                Some(c) => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        flush(&mut lit, &mut parts);
        Ok(parts)
    }

    fn scan_braced_param(&mut self, start: usize) -> Result<ParamExpansion> {
        // `${#}` is the parameter `#`; `${#x}` is the length of x.
        let length = self.ch() == Some('#') && !matches!(self.ch_at(1), Some('}') | None);
        if length {
            self.pos += 1;
        }
        let param = match self.ch() {
            Some(c) if is_name_start(c) => {
                let mut name = String::new();
                while let Some(c) = self.ch().filter(|&c| is_name_char(c)) {
                    name.push(c);
                    self.pos += 1;
                }
                Param::Named(name)
            }
            Some(c) if c.is_ascii_digit() => {
                let mut n = String::new();
                while let Some(c) = self.ch().filter(char::is_ascii_digit) {
                    n.push(c);
                    self.pos += 1;
                }
                Param::Positional(n.parse().map_err(|_| self.error_at(start, "bad parameter"))?)
            }
            Some(c @ ('@' | '*' | '#' | '?' | '-' | '$' | '!')) => {
                self.pos += 1;
                Param::Special(c)
            }
            _ => return Err(self.error_at(start, "bad substitution")),
        };
        if length {
            if !self.eat_char('}') {
                return Err(self.error_at(start, "bad substitution"));
            }
            return Ok(ParamExpansion { param, op: ParamOp::Length });
        }
        if self.eat_char('}') {
            return Ok(ParamExpansion { param, op: ParamOp::Plain });
        }
        let colon = self.eat_char(':');
        let op_char = self.ch().ok_or_else(|| self.error_at(start, "unterminated `${`"))?;
        self.pos += 1;
        let doubled = |p: &mut Self, c: char| p.eat_char(c);
        let op = match op_char {
            '-' => ParamOp::Default { colon, word: self.scan_param_word(start)? },
            '=' => ParamOp::Assign { colon, word: self.scan_param_word(start)? },
            '?' => ParamOp::Error { colon, word: self.scan_param_word(start)? },
            '+' => ParamOp::Alternative { colon, word: self.scan_param_word(start)? },
            '%' if !colon => {
                let longest = doubled(self, '%');
                ParamOp::RemoveSuffix { longest, pattern: self.scan_param_word(start)? }
            }
            '#' if !colon => {
                let longest = doubled(self, '#');
                ParamOp::RemovePrefix { longest, pattern: self.scan_param_word(start)? }
            }
            _ => return Err(self.error_at(start, "bad substitution")),
        };
        Ok(ParamExpansion { param, op })
    }

    /// The word inside `${x-word}` up to the closing `}`. Quotes and expansions nest; `}` inside
    /// quotes doesn't close it.
    fn scan_param_word(&mut self, start: usize) -> Result<Word> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        loop {
            match self.ch() {
                None => return Err(self.error_at(start, "unterminated `${`")),
                Some('}') => {
                    self.pos += 1;
                    break;
                }
                Some('\\') => {
                    self.pos += 1;
                    if let Some(e) = self.ch() {
                        flush(&mut lit, &mut parts);
                        parts.push(WordPart::Quoted(e.to_string()));
                        self.pos += 1;
                    }
                }
                Some('\'') => {
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::Quoted(self.scan_single_quoted()?));
                }
                Some('"') => {
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::DoubleQuoted(self.scan_double_quoted()?));
                }
                Some('$') => match self.scan_dollar()? {
                    Some(part) => {
                        flush(&mut lit, &mut parts);
                        parts.push(part);
                    }
                    None => lit.push('$'),
                },
                Some('`') => {
                    flush(&mut lit, &mut parts);
                    parts.push(self.scan_backquote(false)?);
                }
                Some(c) => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        flush(&mut lit, &mut parts);
        Ok(parts)
    }

    /// `` `…` ``: backslash escapes only `$`, `` ` ``, `\` (and `"` inside double quotes); the
    /// unescaped text is parsed as a command list.
    fn scan_backquote(&mut self, in_double_quotes: bool) -> Result<WordPart> {
        let open = self.pos;
        self.pos += 1;
        let mut text = String::new();
        loop {
            match self.ch() {
                None => return Err(self.error_at(open, "unterminated backquote")),
                Some('`') => {
                    self.pos += 1;
                    break;
                }
                Some('\\') => {
                    let next = self.ch_at(1);
                    let escapes = matches!(next, Some('$' | '`' | '\\'))
                        || (in_double_quotes && next == Some('"'));
                    if escapes {
                        text.push(next.unwrap());
                        self.pos += 2;
                    } else {
                        text.push('\\');
                        self.pos += 1;
                    }
                }
                Some(c) => {
                    text.push(c);
                    self.pos += 1;
                }
            }
        }
        let list = parse(&text).map_err(|e| self.error_at(open, format!("in backquotes: {e}")))?;
        Ok(WordPart::CommandSubst(Rc::new(list)))
    }

    fn read_pending_heredocs(&mut self) -> Result<()> {
        for h in std::mem::take(&mut self.pending) {
            let start = self.pos;
            let mut lines = String::new();
            loop {
                if self.ch().is_none() {
                    return Err(self.error_at(start, format!("here-document delimited by `{}` never ends", h.delimiter)));
                }
                let line_start = self.pos;
                while self.ch().is_some_and(|c| c != '\n') {
                    self.pos += 1;
                }
                let mut line: String = self.src[line_start..self.pos].iter().collect();
                self.eat_char('\n');
                if h.strip_tabs {
                    line = line.trim_start_matches('\t').to_string();
                }
                if line == h.delimiter {
                    break;
                }
                lines.push_str(&line);
                lines.push('\n');
            }
            *h.body.borrow_mut() =
                if h.quoted { vec![WordPart::Quoted(lines)] } else { parse_heredoc_body(&lines)? };
        }
        Ok(())
    }

    // --- grammar ------------------------------------------------------------------------------

    fn at_terminator(&mut self, term: Terminator) -> Result<bool> {
        Ok(match term {
            Terminator::Eof => *self.peek()? == Token::Eof,
            Terminator::CloseParen => self.peek_op(Op::RParen)?,
            Terminator::Words(words) => {
                let t = self.peek()?.clone();
                match t {
                    Token::Word(_, raw) => words.contains(&raw.as_str()),
                    Token::Op(Op::RParen) => words.contains(&")"),
                    Token::Op(Op::DSemi) => words.contains(&";;"),
                    Token::Eof => true,
                    _ => false,
                }
            }
        })
    }

    /// A (possibly empty) list, up to `term` (not consumed).
    fn list(&mut self, term: Terminator) -> Result<List> {
        let mut items = Vec::new();
        loop {
            self.skip_newlines()?;
            if self.at_terminator(term)? {
                return Ok(items);
            }
            let and_or = self.and_or()?;
            let background = self.peek_op(Op::Amp)?;
            items.push(ListItem { and_or, background });
            match self.peek()? {
                Token::Op(Op::Semi | Op::Amp) | Token::Newline => {
                    self.next()?;
                }
                _ => {
                    if self.at_terminator(term)? {
                        return Ok(items);
                    }
                    return Err(match self.peek()?.clone() {
                        Token::Word(_, raw) => self.error(format!("unexpected `{raw}`")),
                        Token::Op(Op::RParen) => self.error("unexpected `)`"),
                        Token::Op(Op::DSemi) => self.error("unexpected `;;`"),
                        _ => self.error("syntax error"),
                    });
                }
            }
        }
    }

    fn and_or(&mut self) -> Result<AndOr> {
        let first = self.pipeline()?;
        let mut rest = Vec::new();
        loop {
            let op = match self.peek()? {
                Token::Op(Op::AndIf) => AndOrOp::And,
                Token::Op(Op::OrIf) => AndOrOp::Or,
                _ => return Ok(AndOr { first, rest }),
            };
            self.next()?;
            self.skip_newlines()?;
            rest.push((op, self.pipeline()?));
        }
    }

    fn pipeline(&mut self) -> Result<Pipeline> {
        let bang = self.peek_reserved("!")?;
        if bang {
            self.next()?;
        }
        let mut commands = vec![self.command()?];
        while self.peek_op(Op::Pipe)? {
            self.next()?;
            self.skip_newlines()?;
            commands.push(self.command()?);
        }
        Ok(Pipeline { bang, commands })
    }

    fn command(&mut self) -> Result<Command> {
        let token = self.peek()?.clone();
        let compound = match &token {
            Token::Op(Op::LParen) => {
                self.next()?;
                let body = self.list(Terminator::Words(&[")"]))?;
                self.expect_op(Op::RParen, ")")?;
                Some(CompoundCommand::Subshell(body))
            }
            Token::Word(_, raw) => match raw.as_str() {
                "{" => {
                    self.next()?;
                    let body = self.list(Terminator::Words(&["}"]))?;
                    self.expect_reserved("}")?;
                    Some(CompoundCommand::Brace(body))
                }
                "if" => Some(self.if_clause()?),
                "while" | "until" => Some(self.loop_clause(raw == "while")?),
                "for" => Some(self.for_clause()?),
                "case" => Some(self.case_clause()?),
                "then" | "else" | "elif" | "fi" | "do" | "done" | "esac" | "}" | "in" => {
                    return Err(self.error(format!("unexpected `{raw}`")));
                }
                _ => None,
            },
            Token::Eof | Token::Newline => return Err(self.error("expected a command")),
            Token::Op(Op::Semi | Op::Amp | Op::AndIf | Op::OrIf | Op::Pipe | Op::DSemi | Op::RParen) => {
                return Err(self.error("expected a command"));
            }
            _ => None,
        };
        if let Some(compound) = compound {
            let redirects = self.redirects()?;
            return Ok(Command::Compound(compound, redirects));
        }
        self.simple_command_or_function()
    }

    fn simple_command_or_function(&mut self) -> Result<Command> {
        let mut cmd = SimpleCommand::default();
        loop {
            match self.peek()?.clone() {
                Token::Word(word, raw) => {
                    // `name ( )` in command position is a function definition.
                    if cmd.words.is_empty() && cmd.assignments.is_empty() && cmd.redirects.is_empty() && is_name(&raw) {
                        self.next()?;
                        if self.peek_op(Op::LParen)? {
                            self.next()?;
                            self.expect_op(Op::RParen, ")")?;
                            self.skip_newlines()?;
                            let body = self.command()?;
                            if !matches!(body, Command::Compound(..)) {
                                return Err(self.error("function body must be a compound command"));
                            }
                            return Ok(Command::FunctionDef { name: raw, body: Rc::new(body) });
                        }
                        cmd.words.push(word);
                        continue;
                    }
                    self.next()?;
                    if cmd.words.is_empty()
                        && let Some(assignment) = as_assignment(&word)
                    {
                        cmd.assignments.push(assignment);
                    } else {
                        cmd.words.push(word);
                    }
                }
                Token::IoNumber(_)
                | Token::Op(Op::Less | Op::Great | Op::DLess | Op::DLessDash | Op::DGreat | Op::LessAnd | Op::GreatAnd | Op::LessGreat | Op::Clobber) => {
                    let r = self.redirect()?;
                    cmd.redirects.push(r);
                }
                _ => break,
            }
        }
        if cmd.words.is_empty() && cmd.assignments.is_empty() && cmd.redirects.is_empty() {
            return Err(self.error("expected a command"));
        }
        Ok(Command::Simple(cmd))
    }

    fn redirects(&mut self) -> Result<Vec<Redirect>> {
        let mut out = Vec::new();
        while matches!(
            self.peek()?,
            Token::IoNumber(_)
                | Token::Op(Op::Less | Op::Great | Op::DLess | Op::DLessDash | Op::DGreat | Op::LessAnd | Op::GreatAnd | Op::LessGreat | Op::Clobber)
        ) {
            out.push(self.redirect()?);
        }
        Ok(out)
    }

    fn redirect(&mut self) -> Result<Redirect> {
        let fd = match self.peek()? {
            Token::IoNumber(n) => {
                let n = *n;
                self.next()?;
                Some(n)
            }
            _ => None,
        };
        let op = match self.next()? {
            Token::Op(Op::Less) => RedirOp::Input,
            Token::Op(Op::Great) => RedirOp::Output,
            Token::Op(Op::Clobber) => RedirOp::Clobber,
            Token::Op(Op::DGreat) => RedirOp::Append,
            Token::Op(Op::LessGreat) => RedirOp::ReadWrite,
            Token::Op(Op::LessAnd) => RedirOp::DupInput,
            Token::Op(Op::GreatAnd) => RedirOp::DupOutput,
            Token::Op(op @ (Op::DLess | Op::DLessDash)) => {
                let (word, raw) = match self.next()? {
                    Token::Word(w, raw) => (w, raw),
                    _ => return Err(self.error("expected a here-document delimiter")),
                };
                let quoted = word.iter().any(|p| !matches!(p, WordPart::Literal(_)))
                    || raw.contains(['\'', '"', '\\']);
                let body = Rc::new(RefCell::new(Vec::new()));
                self.pending.push(PendingHereDoc {
                    delimiter: unquote_delimiter(&word),
                    strip_tabs: op == Op::DLessDash,
                    quoted,
                    body: body.clone(),
                });
                let target = RedirTarget::HereDoc(HereDoc { quoted, strip_tabs: op == Op::DLessDash, body });
                return Ok(Redirect { fd, op: RedirOp::HereDoc, target });
            }
            _ => return Err(self.error("expected a redirection operator")),
        };
        match self.next()? {
            Token::Word(w, _) => Ok(Redirect { fd, op, target: RedirTarget::Word(w) }),
            _ => Err(self.error("expected a file name after the redirection")),
        }
    }

    /// `do_group` / `brace_group` body for loops.
    fn do_group(&mut self) -> Result<List> {
        self.skip_newlines()?;
        self.expect_reserved("do")?;
        let body = self.list(Terminator::Words(&["done"]))?;
        self.expect_reserved("done")?;
        Ok(body)
    }

    fn if_clause(&mut self) -> Result<CompoundCommand> {
        self.expect_reserved("if")?;
        let mut branches = Vec::new();
        let mut else_body = None;
        loop {
            let cond = self.list(Terminator::Words(&["then"]))?;
            self.expect_reserved("then")?;
            let body = self.list(Terminator::Words(&["elif", "else", "fi"]))?;
            branches.push((cond, body));
            if self.peek_reserved("elif")? {
                self.next()?;
                continue;
            }
            if self.peek_reserved("else")? {
                self.next()?;
                else_body = Some(self.list(Terminator::Words(&["fi"]))?);
            }
            self.expect_reserved("fi")?;
            return Ok(CompoundCommand::If { branches, else_body });
        }
    }

    fn loop_clause(&mut self, is_while: bool) -> Result<CompoundCommand> {
        self.next()?;
        let cond = self.list(Terminator::Words(&["do"]))?;
        let body = self.do_group()?;
        Ok(if is_while { CompoundCommand::While { cond, body } } else { CompoundCommand::Until { cond, body } })
    }

    fn for_clause(&mut self) -> Result<CompoundCommand> {
        self.expect_reserved("for")?;
        let var = match self.next()? {
            Token::Word(_, raw) if is_name(&raw) => raw,
            _ => return Err(self.error("expected a variable name after `for`")),
        };
        // `for x; do`, `for x do`, `for x in words; do`
        let mut words = None;
        self.skip_newlines()?;
        if self.peek_reserved("in")? {
            self.next()?;
            let mut list = Vec::new();
            while let Token::Word(w, _) = self.peek()?.clone() {
                self.next()?;
                list.push(w);
            }
            words = Some(list);
            if !matches!(self.peek()?, Token::Op(Op::Semi) | Token::Newline) {
                return Err(self.error("expected `;` or a newline after the `for` word list"));
            }
            self.next()?;
        } else if self.peek_op(Op::Semi)? {
            self.next()?;
        }
        let body = self.do_group()?;
        Ok(CompoundCommand::For { var, words, body })
    }

    fn case_clause(&mut self) -> Result<CompoundCommand> {
        self.expect_reserved("case")?;
        let word = match self.next()? {
            Token::Word(w, _) => w,
            _ => return Err(self.error("expected a word after `case`")),
        };
        self.skip_newlines()?;
        self.expect_reserved("in")?;
        let mut arms = Vec::new();
        loop {
            self.skip_newlines()?;
            if self.peek_reserved("esac")? {
                self.next()?;
                return Ok(CompoundCommand::Case { word, arms });
            }
            if self.peek_op(Op::LParen)? {
                self.next()?;
            }
            let mut patterns = Vec::new();
            loop {
                match self.next()? {
                    Token::Word(w, _) => patterns.push(w),
                    _ => return Err(self.error("expected a `case` pattern")),
                }
                if self.peek_op(Op::Pipe)? {
                    self.next()?;
                    continue;
                }
                break;
            }
            self.expect_op(Op::RParen, ")")?;
            let body = self.list(Terminator::Words(&[";;", "esac"]))?;
            arms.push(CaseArm { patterns, body });
            if self.peek_op(Op::DSemi)? {
                self.next()?;
                continue;
            }
            self.skip_newlines()?;
            self.expect_reserved("esac")?;
            return Ok(CompoundCommand::Case { word, arms });
        }
    }
}

fn plain(param: Param) -> WordPart {
    WordPart::Param(ParamExpansion { param, op: ParamOp::Plain })
}

fn digit_param(c: char) -> Param {
    if c == '0' { Param::Special('0') } else { Param::Positional(c.to_digit(10).unwrap() as usize) }
}

fn flush(lit: &mut String, parts: &mut Vec<WordPart>) {
    if !lit.is_empty() {
        parts.push(WordPart::Literal(std::mem::take(lit)));
    }
}

fn flush_quoted(lit: &mut String, parts: &mut Vec<WordPart>) {
    if !lit.is_empty() {
        parts.push(WordPart::Quoted(std::mem::take(lit)));
    }
}

/// `NAME=value` at the start of an unquoted word is an assignment (XCU 2.10.2 rule 7).
fn as_assignment(word: &Word) -> Option<Assignment> {
    let WordPart::Literal(first) = word.first()? else { return None };
    let eq = first.find('=')?;
    let name = &first[..eq];
    if !is_name(name) {
        return None;
    }
    let mut value = Vec::new();
    if eq + 1 < first.len() {
        value.push(WordPart::Literal(first[eq + 1..].to_string()));
    }
    value.extend(word[1..].iter().cloned());
    Some(Assignment { name: name.to_string(), value })
}

/// The delimiter text with quoting removed (`'EOF'`, `"EOF"`, `\EOF` all mean `EOF`).
fn unquote_delimiter(word: &Word) -> String {
    let mut s = String::new();
    for part in word {
        match part {
            WordPart::Literal(t) | WordPart::Quoted(t) => s.push_str(t),
            WordPart::DoubleQuoted(inner) => s.push_str(&unquote_delimiter(inner)),
            WordPart::Param(_) | WordPart::CommandSubst(_) | WordPart::Arith(_) => {}
        }
    }
    s
}

/// An unquoted here-document body: `$` expansions, `` ` `` and backslash (before `$ \` \\` and
/// newline) are active, as inside double quotes, but `"` is an ordinary character.
fn parse_heredoc_body(text: &str) -> Result<Word> {
    let mut p = Parser::new(text);
    let mut parts = Vec::new();
    let mut lit = String::new();
    while let Some(c) = p.ch() {
        match c {
            '\\' => {
                p.pos += 1;
                match p.ch() {
                    Some('\n') => p.pos += 1,
                    Some(e @ ('$' | '`' | '\\')) => {
                        lit.push(e);
                        p.pos += 1;
                    }
                    _ => lit.push('\\'),
                }
            }
            '$' => match p.scan_dollar()? {
                Some(part) => {
                    flush_quoted(&mut lit, &mut parts);
                    parts.push(part);
                }
                None => lit.push('$'),
            },
            '`' => {
                flush_quoted(&mut lit, &mut parts);
                parts.push(p.scan_backquote(false)?);
            }
            _ => {
                lit.push(c);
                p.pos += 1;
            }
        }
    }
    flush_quoted(&mut lit, &mut parts);
    Ok(parts)
}
