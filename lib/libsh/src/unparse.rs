//! Syntax tree back to shell text: how `jobs` shows a job. Faithful enough to recognise the
//! command, not byte-for-byte the original.

use crate::ast::*;

pub fn list(l: &List) -> String {
    let mut out = String::new();
    for (i, item) in l.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_str(&and_or(&item.and_or));
        if item.background {
            out.push_str(" &");
        }
    }
    out
}

pub fn and_or(a: &AndOr) -> String {
    let mut out = pipeline(&a.first);
    for (op, p) in &a.rest {
        out.push_str(if *op == AndOrOp::And { " && " } else { " || " });
        out.push_str(&pipeline(p));
    }
    out
}

pub fn pipeline(p: &Pipeline) -> String {
    let cmds: Vec<String> = p.commands.iter().map(command).collect();
    format!("{}{}", if p.bang { "! " } else { "" }, cmds.join(" | "))
}

pub fn command(c: &Command) -> String {
    match c {
        Command::Simple(s) => {
            let mut parts: Vec<String> = s.assignments.iter().map(|a| format!("{}={}", a.name, word(&a.value))).collect();
            parts.extend(s.words.iter().map(|w| word(w)));
            parts.extend(s.redirects.iter().map(redirect));
            parts.join(" ")
        }
        Command::Compound(cc, redirs) => {
            let mut s = compound(cc);
            for r in redirs {
                s.push(' ');
                s.push_str(&redirect(r));
            }
            s
        }
        Command::FunctionDef { name, body } => format!("{name}() {}", command(body)),
    }
}

fn compound(cc: &CompoundCommand) -> String {
    match cc {
        CompoundCommand::Brace(l) => format!("{{ {}; }}", list(l)),
        CompoundCommand::Subshell(l) => format!("({})", list(l)),
        CompoundCommand::For { var, words, body } => match words {
            Some(w) => format!("for {var} in {}; do {}; done", w.iter().map(|x| word(x)).collect::<Vec<_>>().join(" "), list(body)),
            None => format!("for {var}; do {}; done", list(body)),
        },
        CompoundCommand::Case { word: w, arms } => {
            let arms: Vec<String> = arms
                .iter()
                .map(|a| format!("{}) {};;", a.patterns.iter().map(|p| word(p)).collect::<Vec<_>>().join("|"), list(&a.body)))
                .collect();
            format!("case {} in {} esac", word(w), arms.join(" "))
        }
        CompoundCommand::If { branches, else_body } => {
            let mut s = String::new();
            for (i, (c, b)) in branches.iter().enumerate() {
                s.push_str(if i == 0 { "if " } else { "; elif " });
                s.push_str(&format!("{}; then {}", list(c), list(b)));
            }
            if let Some(e) = else_body {
                s.push_str(&format!("; else {}", list(e)));
            }
            s.push_str("; fi");
            s
        }
        CompoundCommand::While { cond, body } => format!("while {}; do {}; done", list(cond), list(body)),
        CompoundCommand::Until { cond, body } => format!("until {}; do {}; done", list(cond), list(body)),
    }
}

fn redirect(r: &Redirect) -> String {
    let op = match r.op {
        RedirOp::Input => "<",
        RedirOp::Output => ">",
        RedirOp::Clobber => ">|",
        RedirOp::Append => ">>",
        RedirOp::ReadWrite => "<>",
        RedirOp::DupInput => "<&",
        RedirOp::DupOutput => ">&",
        RedirOp::HereDoc => "<<",
    };
    let fd = r.fd.map(|f| f.to_string()).unwrap_or_default();
    match &r.target {
        RedirTarget::Word(w) => format!("{fd}{op}{}", word(w)),
        RedirTarget::HereDoc(_) => format!("{fd}{op}EOF"),
    }
}

pub fn word(w: &Word) -> String {
    w.iter().map(|p| part(p, false)).collect()
}

fn part(p: &WordPart, in_dq: bool) -> String {
    match p {
        WordPart::Literal(s) => s.clone(),
        WordPart::Quoted(s) if in_dq => s.chars().fold(String::new(), |mut o, c| {
            if matches!(c, '"' | '\\' | '$' | '`') {
                o.push('\\');
            }
            o.push(c);
            o
        }),
        WordPart::Quoted(s) => {
            if s.chars().all(|c| !" \t\n'\"\\$`|&;<>()*?[#~=%".contains(c)) && !s.is_empty() {
                // A single escaped character or a plain run: backslash form reads best.
                if s.chars().count() == 1 { format!("\\{s}") } else { format!("'{s}'") }
            } else {
                format!("'{}'", s.replace('\'', "'\\''"))
            }
        }
        WordPart::DoubleQuoted(inner) => format!("\"{}\"", inner.iter().map(|x| part(x, true)).collect::<String>()),
        WordPart::Param(pe) => param(pe),
        WordPart::CommandSubst(l) => format!("$({})", list(l)),
        WordPart::Arith(e) => format!("$(({}))", e.iter().map(|x| part(x, true)).collect::<String>()),
    }
}

fn param(pe: &ParamExpansion) -> String {
    let name = match &pe.param {
        Param::Named(n) => n.clone(),
        Param::Positional(n) => n.to_string(),
        Param::Special(c) => c.to_string(),
    };
    let w = |x: &Word| x.iter().map(|p| part(p, false)).collect::<String>();
    match &pe.op {
        ParamOp::Plain => format!("${name}"),
        ParamOp::Length => format!("${{#{name}}}"),
        ParamOp::Default { colon, word } => format!("${{{name}{}-{}}}", if *colon { ":" } else { "" }, w(word)),
        ParamOp::Assign { colon, word } => format!("${{{name}{}={}}}", if *colon { ":" } else { "" }, w(word)),
        ParamOp::Error { colon, word } => format!("${{{name}{}?{}}}", if *colon { ":" } else { "" }, w(word)),
        ParamOp::Alternative { colon, word } => format!("${{{name}{}+{}}}", if *colon { ":" } else { "" }, w(word)),
        ParamOp::RemoveSuffix { longest, pattern } => format!("${{{name}{}{}}}", if *longest { "%%" } else { "%" }, w(pattern)),
        ParamOp::RemovePrefix { longest, pattern } => format!("${{{name}{}{}}}", if *longest { "##" } else { "#" }, w(pattern)),
    }
}
