//! Arithmetic expansion (XCU 2.6.4): the C integer expression subset, over `i64`.
//!
//! Operators, lowest precedence first: `= *= /= %= += -= <<= >>= &= ^= |=`, `?:`, `||`, `&&`,
//! `|`, `^`, `&`, `== !=`, `< <= > >=`, `<< >>`, `+ -`, `* / %`, unary `+ - ~ !`. Constants are
//! decimal, octal (`0` prefix) or hexadecimal (`0x`). A variable's value is itself evaluated as an
//! expression; an unset or empty variable is 0.

pub trait Vars {
    fn get(&self, name: &str) -> Option<String>;
    fn set(&mut self, name: &str, value: i64) -> Result<(), String>;
}

pub fn eval(expr: &str, vars: &mut dyn Vars) -> Result<i64, String> {
    eval_depth(expr, vars, 0)
}

fn eval_depth(expr: &str, vars: &mut dyn Vars, depth: usize) -> Result<i64, String> {
    if depth > 64 {
        return Err("expression recursion too deep".into());
    }
    let tokens = tokenize(expr)?;
    if tokens.is_empty() {
        return Ok(0);
    }
    let mut p = P { t: tokens, i: 0, vars, depth, skip: 0 };
    let v = p.assign()?;
    if p.i != p.t.len() {
        return Err(format!("syntax error in expression: `{expr}`"));
    }
    Ok(v)
}

#[derive(Clone, Debug, PartialEq)]
enum T {
    Num(i64),
    Name(String),
    Op(&'static str),
}

const OPS: &[&str] = &[
    "<<=", ">>=", "&&", "||", "==", "!=", "<=", ">=", "<<", ">>", "*=", "/=", "%=", "+=", "-=", "&=", "^=",
    "|=", "+", "-", "*", "/", "%", "<", ">", "&", "^", "|", "!", "~", "?", ":", "=", "(", ")",
];

fn tokenize(s: &str) -> Result<Vec<T>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < c.len() {
        if c[i].is_whitespace() {
            i += 1;
            continue;
        }
        if c[i].is_ascii_digit() {
            let start = i;
            while i < c.len() && c[i].is_ascii_alphanumeric() {
                i += 1;
            }
            let text: String = c[start..i].iter().collect();
            out.push(T::Num(parse_number(&text)?));
            continue;
        }
        if c[i] == '_' || c[i].is_ascii_alphabetic() {
            let start = i;
            while i < c.len() && (c[i] == '_' || c[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push(T::Name(c[start..i].iter().collect()));
            continue;
        }
        let rest: String = c[i..].iter().take(3).collect();
        let op = OPS.iter().find(|op| rest.starts_with(*op)).ok_or_else(|| format!("unexpected `{}` in expression", c[i]))?;
        out.push(T::Op(op));
        i += op.len();
    }
    Ok(out)
}

fn parse_number(text: &str) -> Result<i64, String> {
    let bad = || format!("bad number `{text}`");
    let (digits, radix) = if let Some(h) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        (h, 16)
    } else if text.len() > 1 && text.starts_with('0') {
        (&text[1..], 8)
    } else {
        (text, 10)
    };
    u64::from_str_radix(digits, radix).map(|v| v as i64).map_err(|_| bad())
}

struct P<'a> {
    t: Vec<T>,
    i: usize,
    vars: &'a mut dyn Vars,
    depth: usize,
    /// >0 while evaluating a branch whose value is discarded (`0 && x=1` must not assign).
    skip: usize,
}

impl P<'_> {
    fn peek_op(&self) -> Option<&'static str> {
        match self.t.get(self.i) {
            Some(T::Op(o)) => Some(o),
            _ => None,
        }
    }

    fn eat(&mut self, op: &str) -> bool {
        if self.peek_op() == Some(op) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn var_value(&mut self, name: &str) -> Result<i64, String> {
        match self.vars.get(name) {
            None => Ok(0),
            Some(v) if v.trim().is_empty() => Ok(0),
            Some(v) => eval_depth(&v, self.vars, self.depth + 1),
        }
    }

    fn assign(&mut self) -> Result<i64, String> {
        if let (Some(T::Name(name)), Some(T::Op(op))) = (self.t.get(self.i).cloned(), self.t.get(self.i + 1).cloned())
            && matches!(op, "=" | "*=" | "/=" | "%=" | "+=" | "-=" | "<<=" | ">>=" | "&=" | "^=" | "|=")
        {
            self.i += 2;
            let rhs = self.assign()?;
            let value = if op == "=" {
                rhs
            } else {
                let lhs = self.var_value(&name)?;
                binary(&op[..op.len() - 1], lhs, rhs)?
            };
            if self.skip == 0 {
                self.vars.set(&name, value)?;
            }
            return Ok(value);
        }
        self.ternary()
    }

    fn ternary(&mut self) -> Result<i64, String> {
        let cond = self.logical_or()?;
        if !self.eat("?") {
            return Ok(cond);
        }
        if cond == 0 {
            self.skip += 1;
        }
        let a = self.assign()?;
        if cond == 0 {
            self.skip -= 1;
        }
        if !self.eat(":") {
            return Err("expected `:` in conditional expression".into());
        }
        if cond != 0 {
            self.skip += 1;
        }
        let b = self.ternary()?;
        if cond != 0 {
            self.skip -= 1;
        }
        Ok(if cond != 0 { a } else { b })
    }

    fn logical_or(&mut self) -> Result<i64, String> {
        let mut v = self.logical_and()?;
        while self.eat("||") {
            if v != 0 {
                self.skip += 1;
            }
            let r = self.logical_and()?;
            if v != 0 {
                self.skip -= 1;
            }
            v = (v != 0 || r != 0) as i64;
        }
        Ok(v)
    }

    fn logical_and(&mut self) -> Result<i64, String> {
        let mut v = self.binary_level(0)?;
        while self.eat("&&") {
            if v == 0 {
                self.skip += 1;
            }
            let r = self.binary_level(0)?;
            if v == 0 {
                self.skip -= 1;
            }
            v = (v != 0 && r != 0) as i64;
        }
        Ok(v)
    }

    fn binary_level(&mut self, level: usize) -> Result<i64, String> {
        const LEVELS: &[&[&str]] =
            &[&["|"], &["^"], &["&"], &["==", "!="], &["<", "<=", ">", ">="], &["<<", ">>"], &["+", "-"], &["*", "/", "%"]];
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut v = self.binary_level(level + 1)?;
        while let Some(op) = self.peek_op().filter(|op| LEVELS[level].contains(op)) {
            self.i += 1;
            let r = self.binary_level(level + 1)?;
            v = if self.skip > 0 && matches!(op, "/" | "%") && r == 0 { 0 } else { binary(op, v, r)? };
        }
        Ok(v)
    }

    fn unary(&mut self) -> Result<i64, String> {
        for (op, f) in [("-", (|v: i64| v.wrapping_neg()) as fn(i64) -> i64), ("+", |v| v), ("~", |v| !v), ("!", |v| (v == 0) as i64)] {
            if self.eat(op) {
                return Ok(f(self.unary()?));
            }
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<i64, String> {
        match self.t.get(self.i).cloned() {
            Some(T::Num(n)) => {
                self.i += 1;
                Ok(n)
            }
            Some(T::Name(name)) => {
                self.i += 1;
                self.var_value(&name)
            }
            Some(T::Op("(")) => {
                self.i += 1;
                let v = self.assign()?;
                if !self.eat(")") {
                    return Err("expected `)` in expression".into());
                }
                Ok(v)
            }
            _ => Err("syntax error in expression".into()),
        }
    }
}

fn binary(op: &str, a: i64, b: i64) -> Result<i64, String> {
    Ok(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" | "%" if b == 0 => return Err("division by zero".into()),
        "/" => a.wrapping_div(b),
        "%" => a.wrapping_rem(b),
        "<<" => a.wrapping_shl(b as u32),
        ">>" => a.wrapping_shr(b as u32),
        "<" => (a < b) as i64,
        "<=" => (a <= b) as i64,
        ">" => (a > b) as i64,
        ">=" => (a >= b) as i64,
        "==" => (a == b) as i64,
        "!=" => (a != b) as i64,
        "&" => a & b,
        "^" => a ^ b,
        "|" => a | b,
        _ => return Err(format!("unknown operator `{op}`")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct M(HashMap<String, String>);
    impl Vars for M {
        fn get(&self, n: &str) -> Option<String> {
            self.0.get(n).cloned()
        }
        fn set(&mut self, n: &str, v: i64) -> Result<(), String> {
            self.0.insert(n.into(), v.to_string());
            Ok(())
        }
    }

    fn e(s: &str) -> i64 {
        eval(s, &mut M(HashMap::new())).unwrap()
    }

    #[test]
    fn arithmetic() {
        assert_eq!(e("1 + 2 * 3"), 7);
        assert_eq!(e("(1 + 2) * 3"), 9);
        assert_eq!(e("-3 / 2"), -1);
        assert_eq!(e("7 % 3"), 1);
        assert_eq!(e("1 << 4 | 1"), 17);
        assert_eq!(e("010 + 0x10"), 24);
        assert_eq!(e("!0 && ~0 == -1"), 1);
        assert_eq!(e("1 ? 2 : 3"), 2);
        assert_eq!(e("0 ? 2 : 0 ? 3 : 4"), 4);
        assert_eq!(e(""), 0);
    }

    #[test]
    fn variables_and_assignment() {
        let mut m = M(HashMap::from([("x".into(), "5".into()), ("y".into(), "x + 1".into())]));
        assert_eq!(eval("y * 2", &mut m).unwrap(), 12);
        assert_eq!(eval("x += 3", &mut m).unwrap(), 8);
        assert_eq!(m.0["x"], "8");
        assert_eq!(eval("unset_var + 1", &mut m).unwrap(), 1);
        assert_eq!(eval("0 && (x = 99)", &mut m).unwrap(), 0);
        assert_eq!(m.0["x"], "8", "short-circuited assignment must not happen");
    }

    #[test]
    fn errors() {
        let mut m = M(HashMap::new());
        assert!(eval("1 / 0", &mut m).is_err());
        assert!(eval("1 +", &mut m).is_err());
        assert!(eval("09", &mut m).is_err());
    }
}
