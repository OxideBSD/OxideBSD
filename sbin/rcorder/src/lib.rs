//! `rcorder(8)`: orders `rc.d` scripts by their dependency declarations (INIT.md §4.7,
//! INIT_SH.md §6).
//!
//! A script declares its ordering either with classic FreeBSD comment headers
//! (`# PROVIDE:`, `# REQUIRE:`, `# BEFORE:`, `# KEYWORD:`) or with the `provide`, `require`,
//! `before` and `keyword` fields of an init_sh service block; a mixed set orders together.
//! Errors follow FreeBSD: a requirement nobody provides is a warning, and a dependency cycle is
//! broken where it is found, reported, and makes the exit status 1 -- the order is still printed
//! so the boot can go on.

use std::collections::HashMap;
use std::fmt::Write;

/// One script's ordering declarations.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Script {
    pub path: String,
    pub provides: Vec<String>,
    pub requires: Vec<String>,
    pub befores: Vec<String>,
    pub keywords: Vec<String>,
}

impl Script {
    /// Reads the declarations from a script's text. `Err` is a service-block syntax error; the
    /// caller reports it and orders the script as declaring nothing.
    pub fn from_text(path: &str, text: &str) -> Result<Script, String> {
        if let Some(script) = classic_headers(path, text) {
            return Ok(script);
        }
        // Only a script that looks like it has a service block is parsed: a classic script with
        // no headers may use syntax this shell rejects, and that's not rcorder's business.
        if !text.lines().any(|l| l.trim_start().starts_with("service ")) {
            return Ok(Script { path: path.into(), ..Script::default() });
        }
        let list = libsh::parse(text).map_err(|e| format!("{path}:{e}"))?;
        let block = list.iter().find_map(|item| match item.and_or.first.commands.first() {
            Some(libsh::ast::Command::Compound(libsh::ast::CompoundCommand::Service(b), _)) => Some(b.clone()),
            _ => None,
        });
        Ok(match block {
            Some(b) => Script {
                path: path.into(),
                provides: b.provides(),
                requires: b.literal_field("require"),
                befores: b.literal_field("before"),
                keywords: b.literal_field("keyword"),
            },
            None => Script { path: path.into(), ..Script::default() },
        })
    }

    fn has_keyword(&self, set: &[String]) -> bool {
        self.keywords.iter().any(|k| set.contains(k))
    }
}

/// The contiguous block of `# KEY: words` lines, if the script has one. Lines before it (the
/// `#!` line, a licence) are skipped; the first other line after it ends it.
fn classic_headers(path: &str, text: &str) -> Option<Script> {
    let mut script = Script { path: path.into(), ..Script::default() };
    let mut seen = false;
    for line in text.lines() {
        let header = line.strip_prefix('#').and_then(|rest| {
            let (key, words) = rest.trim_start().split_once(':')?;
            let list = match key {
                "PROVIDE" | "PROVIDES" => &mut script.provides,
                "REQUIRE" | "REQUIRES" => &mut script.requires,
                "BEFORE" => &mut script.befores,
                "KEYWORD" | "KEYWORDS" => &mut script.keywords,
                _ => return None,
            };
            list.extend(words.split_whitespace().map(String::from));
            Some(())
        });
        match header {
            Some(()) => seen = true,
            None if seen => break,
            None => {}
        }
    }
    seen.then_some(script)
}

/// Which scripts to print: `-k` keeps only scripts with one of these keywords, `-s` drops
/// scripts with any of these. Filtering happens at output; filtered scripts still order the rest.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub keep: Vec<String>,
    pub skip: Vec<String>,
}

impl Filter {
    pub fn shows(&self, s: &Script) -> bool {
        (self.keep.is_empty() || s.has_keyword(&self.keep)) && !s.has_keyword(&self.skip)
    }
}

/// An edge `from` → `to`: script `from` must run before script `to`, because of `name`.
#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub name: String,
    /// Dropped to break a cycle.
    pub broken: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Ordering {
    /// Script indices, dependencies first.
    pub order: Vec<usize>,
    /// Each script's depth: 0 if it depends on nothing, else one more than its deepest
    /// dependency. Scripts at the same depth can run concurrently (`-p`).
    pub level: Vec<usize>,
    pub edges: Vec<Edge>,
    /// `(script, name)`: a `REQUIRE` nobody provides.
    pub missing: Vec<(usize, String)>,
    pub warnings: Vec<String>,
    pub cycle: bool,
}

/// Orders scripts: a depth-first walk in argument order, printing each script after everything
/// it depends on -- FreeBSD's traversal, so the same inputs give the same order.
pub fn order(scripts: &[Script]) -> Ordering {
    let mut providers: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, s) in scripts.iter().enumerate() {
        for p in &s.provides {
            providers.entry(p).or_default().push(i);
        }
    }
    let mut o = Ordering { level: vec![0; scripts.len()], ..Ordering::default() };
    // deps[i]: indices into o.edges of the edges ending at i, in declaration order.
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); scripts.len()];
    for (i, s) in scripts.iter().enumerate() {
        for r in &s.requires {
            match providers.get(r.as_str()) {
                Some(ps) => {
                    for &p in ps.iter().filter(|&&p| p != i) {
                        deps[i].push(o.edges.len());
                        o.edges.push(Edge { from: p, to: i, name: r.clone(), broken: false });
                    }
                }
                None => {
                    o.warnings.push(format!("requirement `{r}' in file `{}' has no providers.", s.path));
                    o.missing.push((i, r.clone()));
                }
            }
        }
        // A BEFORE naming nothing is not an error: it only constrains scripts that exist.
        for b in &s.befores {
            for &p in providers.get(b.as_str()).into_iter().flatten().filter(|&&p| p != i) {
                deps[p].push(o.edges.len());
                o.edges.push(Edge { from: i, to: p, name: b.clone(), broken: false });
            }
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum State {
        New,
        Active,
        Done,
    }
    let mut state = vec![State::New; scripts.len()];
    // An explicit stack, so a long dependency chain can't overflow the real one:
    // (script, next dependency to look at).
    for root in 0..scripts.len() {
        if state[root] != State::New {
            continue;
        }
        state[root] = State::Active;
        let mut stack = vec![(root, 0)];
        while let Some(&mut (i, ref mut next)) = stack.last_mut() {
            if let Some(&e) = deps[i].get(*next) {
                *next += 1;
                let from = o.edges[e].from;
                match state[from] {
                    State::New => {
                        state[from] = State::Active;
                        stack.push((from, 0));
                    }
                    State::Active => {
                        o.edges[e].broken = true;
                        o.cycle = true;
                        let name = &o.edges[e].name;
                        o.warnings.push(format!("Circular dependency on provision `{name}' in file `{}'.", scripts[i].path));
                    }
                    State::Done => {}
                }
                continue;
            }
            stack.pop();
            state[i] = State::Done;
            o.level[i] = deps[i]
                .iter()
                .filter(|&&e| !o.edges[e].broken)
                .map(|&e| o.level[o.edges[e].from] + 1)
                .max()
                .unwrap_or(0);
            o.order.push(i);
        }
    }
    o
}

/// One path per line.
pub fn render_list(scripts: &[Script], o: &Ordering, f: &Filter) -> String {
    let mut out = String::new();
    for &i in o.order.iter().filter(|&&i| f.shows(&scripts[i])) {
        writeln!(out, "{}", scripts[i].path).unwrap();
    }
    out
}

/// `-p`: one line per depth; the scripts on a line don't depend on each other.
pub fn render_parallel(scripts: &[Script], o: &Ordering, f: &Filter) -> String {
    let depth = o.level.iter().copied().max().map_or(0, |m| m + 1);
    let mut out = String::new();
    for d in 0..depth {
        let line: Vec<&str> = o
            .order
            .iter()
            .filter(|&&i| o.level[i] == d && f.shows(&scripts[i]))
            .map(|&i| scripts[i].path.as_str())
            .collect();
        if !line.is_empty() {
            writeln!(out, "{}", line.join(" ")).unwrap();
        }
    }
    out
}

/// `-g`: the dependency graph in graphviz's dot language. Edges point the way the boot runs;
/// cycle-breaking edges and missing providers are drawn in red.
pub fn render_graph(scripts: &[Script], o: &Ordering, f: &Filter) -> String {
    fn quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
    let shown = |i: usize| f.shows(&scripts[i]);
    let mut out = String::from("digraph rcorder {\n\trankdir=TB;\n\tnode [shape=box];\n");
    for &i in o.order.iter().filter(|&&i| shown(i)) {
        let path = &scripts[i].path;
        let label = path.rsplit('/').next().unwrap_or(path);
        writeln!(out, "\t{} [label={}];", quote(path), quote(label)).unwrap();
    }
    for e in o.edges.iter().filter(|e| shown(e.from) && shown(e.to)) {
        let style = if e.broken { ", color=red, fontcolor=red" } else { "" };
        let (from, to) = (&scripts[e.from].path, &scripts[e.to].path);
        writeln!(out, "\t{} -> {} [label={}{style}];", quote(from), quote(to), quote(&e.name)).unwrap();
    }
    for (i, name) in o.missing.iter().filter(|(i, _)| shown(*i)) {
        let node = quote(&format!("missing:{name}"));
        writeln!(out, "\t{node} [label={}, shape=ellipse, style=dashed, color=red];", quote(name)).unwrap();
        writeln!(out, "\t{node} -> {} [style=dashed, color=red];", quote(&scripts[*i].path)).unwrap();
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(path: &str, provides: &[&str], requires: &[&str], befores: &[&str], keywords: &[&str]) -> Script {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect();
        Script { path: path.into(), provides: v(provides), requires: v(requires), befores: v(befores), keywords: v(keywords) }
    }

    fn paths(scripts: &[Script], o: &Ordering) -> Vec<String> {
        o.order.iter().map(|&i| scripts[i].path.clone()).collect()
    }

    #[test]
    fn classic_headers_are_read_up_to_the_first_other_line() {
        let text = "#!/bin/sh\n#\n# $FreeBSD$\n\n# PROVIDE: cron\n# REQUIRE: LOGIN FILESYSTEMS\n#REQUIRE: a\n# BEFORE:  securelevel\n# KEYWORD: shutdown\n\n# REQUIRE: late\n";
        let got = Script::from_text("/etc/rc.d/cron", text).unwrap();
        assert_eq!(got, s("/etc/rc.d/cron", &["cron"], &["LOGIN", "FILESYSTEMS", "a"], &["securelevel"], &["shutdown"]));
    }

    #[test]
    fn service_blocks_are_read_without_running_them() {
        let text = "#!/sbin/init_sh\nservice cron {\n  require LOGIN\n  keyword shutdown\n  start_pre { exit 1; }\n}\n";
        let got = Script::from_text("cron", text).unwrap();
        assert_eq!(got, s("cron", &["cron"], &["LOGIN"], &[], &["shutdown"]));
    }

    #[test]
    fn scripts_without_declarations_declare_nothing() {
        assert_eq!(Script::from_text("x", "#!/bin/sh\n[[ bash ]] && echo\n").unwrap(), s("x", &[], &[], &[], &[]));
        assert!(Script::from_text("x", "service x { require $Y }\n").unwrap_err().starts_with("x:1:"));
    }

    #[test]
    fn dependencies_first_otherwise_argument_order() {
        let scripts = [
            s("c", &["C"], &["B"], &[], &[]),
            s("free", &[], &[], &[], &[]),
            s("b", &["B"], &["A"], &[], &[]),
            s("a", &["A"], &[], &[], &[]),
        ];
        let o = order(&scripts);
        assert_eq!(paths(&scripts, &o), ["a", "b", "c", "free"]);
        assert!(!o.cycle && o.warnings.is_empty());
        assert_eq!(render_parallel(&scripts, &o, &Filter::default()), "a free\nb\nc\n");
    }

    #[test]
    fn before_is_a_reverse_require_and_every_provider_counts() {
        let scripts = [
            s("net1", &["NETWORK"], &[], &[], &[]),
            s("net2", &["NETWORK"], &[], &[], &[]),
            s("late", &[], &["NETWORK"], &[], &[]),
            s("early", &[], &[], &["NETWORK", "nobody"], &[]),
        ];
        let o = order(&scripts);
        assert_eq!(paths(&scripts, &o), ["early", "net1", "net2", "late"]);
        assert!(o.warnings.is_empty(), "{:?}", o.warnings);
    }

    #[test]
    fn missing_providers_warn_but_order_the_rest() {
        let scripts = [s("x", &["X"], &["NOPE"], &[], &[])];
        let o = order(&scripts);
        assert_eq!(paths(&scripts, &o), ["x"]);
        assert_eq!(o.warnings, ["requirement `NOPE' in file `x' has no providers."]);
        assert!(!o.cycle);
    }

    #[test]
    fn cycles_are_broken_reported_and_still_ordered() {
        let scripts = [s("a", &["A"], &["B"], &[], &[]), s("b", &["B"], &["A"], &[], &[]), s("c", &[], &["A"], &[], &[])];
        let o = order(&scripts);
        assert!(o.cycle);
        assert_eq!(o.warnings, ["Circular dependency on provision `A' in file `b'."]);
        assert_eq!(paths(&scripts, &o), ["b", "a", "c"]);
        assert!(render_graph(&scripts, &o, &Filter::default()).contains("\"a\" -> \"b\" [label=\"A\", color=red"));
    }

    #[test]
    fn keywords_filter_output_but_not_ordering() {
        let scripts = [
            s("a", &["A"], &[], &[], &["nojail"]),
            s("b", &["B"], &["A"], &[], &["shutdown"]),
            s("c", &[], &["B"], &[], &["shutdown", "nojail"]),
        ];
        let o = order(&scripts);
        let keep = Filter { keep: vec!["shutdown".into()], skip: vec![] };
        assert_eq!(render_list(&scripts, &o, &keep), "b\nc\n");
        let both = Filter { keep: vec!["shutdown".into()], skip: vec!["nojail".into()] };
        assert_eq!(render_list(&scripts, &o, &both), "b\n");
        assert_eq!(render_parallel(&scripts, &o, &both), "b\n");
    }

    #[test]
    fn long_chains_do_not_recurse() {
        let scripts: Vec<Script> = (0..20_000)
            .map(|i| Script { path: i.to_string(), provides: vec![format!("p{i}")], requires: vec![format!("p{}", i + 1)], ..Script::default() })
            .collect();
        let o = order(&scripts);
        assert_eq!(o.order[0], 19_999);
        assert_eq!(o.warnings.len(), 1); // p100000
    }
}
