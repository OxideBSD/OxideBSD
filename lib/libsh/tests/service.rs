//! Service blocks (INIT_SH.md §4.1): parsed only with the init dialect.
#![cfg(feature = "init-dialect")]

use libsh::ast::*;
use libsh::parse;

fn service(src: &str) -> ServiceBlock {
    let list = parse(src).unwrap_or_else(|e| panic!("{e}"));
    let blocks: Vec<_> = list
        .iter()
        .filter_map(|item| match &item.and_or.first.commands[0] {
            Command::Compound(CompoundCommand::Service(b), _) => Some((**b).clone()),
            _ => None,
        })
        .collect();
    assert_eq!(blocks.len(), 1, "{src}");
    blocks.into_iter().next().unwrap()
}

fn error(src: &str) -> String {
    parse(src).expect_err(src).message
}

const CRON: &str = r#"#!/sbin/init_sh
service cron {
    desc     "Daemon to execute scheduled commands"
    provide  cron
    require  LOGIN FILESYSTEMS
    before   securelevel
    keyword  shutdown
    command  /usr/sbin/cron
    pidfile  /var/run/cron.pid

    start_pre {
        mkdir -p /var/cron/tabs
    }
    command reload { kill -HUP $pid; }
}
"#;

#[test]
fn the_spec_example() {
    let b = service(CRON);
    assert_eq!(b.name, "cron");
    assert_eq!(b.provides(), ["cron"]);
    assert_eq!(b.literal_field("require"), ["LOGIN", "FILESYSTEMS"]);
    assert_eq!(b.literal_field("before"), ["securelevel"]);
    assert_eq!(b.literal_field("keyword"), ["shutdown"]);
    assert_eq!(b.literal_field("desc"), ["Daemon to execute scheduled commands"]);
    let command = b.fields.iter().find(|f| f.name == "command").unwrap();
    assert_eq!(command.line, 8);
    assert_eq!(b.hooks.len(), 2);
    assert_eq!((b.hooks[0].name.as_str(), b.hooks[0].action.as_deref()), ("start_pre", None));
    assert_eq!((b.hooks[1].name.as_str(), b.hooks[1].action.as_deref()), ("command", Some("reload")));
}

#[test]
fn provide_defaults_to_the_name_and_ordering_fields_accumulate() {
    let b = service("service tmp { require a\nrequire 'b' \"c\"; }");
    assert_eq!(b.provides(), ["tmp"]);
    assert_eq!(b.literal_field("require"), ["a", "b", "c"]);
}

#[test]
fn brace_may_start_the_next_line() {
    assert_eq!(service("service x\n{\n}\n").name, "x");
}

#[test]
fn rejects_bad_declarations() {
    assert!(error("service x { requrie a }").contains("unknown service field `requrie`"));
    assert!(error("service x { require $A }").contains("literal"));
    assert!(error("service x { require $(echo a) }").contains("literal"));
    assert!(error("service x { pidfile a\npidfile b }").contains("duplicate"));
    assert!(error("service x { desc }").contains("needs a value"));
    assert!(error("service x { status }").contains("expected `{` after `status`"));
    assert!(error("service x { start_pre now { :; } }").contains("takes no arguments"));
    assert!(error("service x { start_pre { :; }\nstart_pre { :; } }").contains("duplicate hook"));
    assert!(error("service x { command { :; } }").contains("command NAME"));
    assert!(error("service 9x { }").contains("service name"));
    assert!(error("service x { desc a > b }").contains("operator"));
    let e = parse("service x {\n desc a\n").unwrap_err();
    assert!(e.incomplete, "{e:?}");
}

#[test]
fn fields_may_expand_and_hooks_are_ordinary_shell() {
    let b = service("service x { pidfile ${x_pidfile:-/var/run/x.pid}; status { case $1 in *) : ;; esac; } }");
    assert_eq!(b.hooks[0].body.len(), 1);
}
