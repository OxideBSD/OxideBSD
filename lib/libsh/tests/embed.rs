//! Embedding the shell (devd's configuration, OxideBSD-doc `DEVD.md` §5.2): built-ins a program
//! adds (`Shell::add_builtin`) and sourcing text into a shell it keeps (`Shell::source`).

use std::cell::RefCell;
use std::rc::Rc;

use libsh::{Flow, Shell};

/// A shell with an `on` built-in that records its arguments, and the record.
fn with_on() -> (Shell, Rc<RefCell<Vec<Vec<String>>>>) {
    let mut sh = Shell::new("embed".into(), Vec::new());
    let rules = Rc::new(RefCell::new(Vec::new()));
    let r = rules.clone();
    sh.add_builtin("on", move |sh: &mut Shell, args: &[String]| {
        if args.len() < 4 {
            sh.error("on: usage: on verb class handler [name=pattern ...]");
            return Ok(2);
        }
        r.borrow_mut().push(args[1..].to_vec());
        Ok(0)
    })
    .unwrap();
    (sh, rules)
}

fn run(sh: &mut Shell, src: &str) -> i32 {
    match sh.source(src) {
        Ok(Ok(s)) => s,
        Ok(Err(Flow::Exit(s) | Flow::Fatal(s))) => s,
        Ok(Err(f)) => panic!("{src}: {f:?}"),
        Err(e) => panic!("{src}: {e}"),
    }
}

#[test]
fn an_added_builtin_runs_with_its_fields() {
    let (mut sh, rules) = with_on();
    let status = run(&mut sh, "plugged() { :; }\nkind=ahci\non attach disk plugged \"bus=$kind\" 'name=sata*'\n");
    assert_eq!(status, 0);
    assert_eq!(*rules.borrow(), vec![vec!["attach", "disk", "plugged", "bus=ahci", "name=sata*"]]);
    assert!(sh.functions.contains_key("plugged"), "the function stays defined");
    assert_eq!(sh.get("kind").as_deref(), Some("ahci"), "and the variable set");
}

#[test]
fn its_status_is_the_commands() {
    let (mut sh, rules) = with_on();
    assert_eq!(run(&mut sh, "on attach disk\n"), 2);
    assert!(rules.borrow().is_empty());
    assert_eq!(run(&mut sh, "on a b c || exit 7; on a b\n"), 2);
    assert_eq!(rules.borrow().len(), 1);
}

#[test]
fn it_is_a_regular_builtin() {
    let (mut sh, rules) = with_on();
    // XCU 2.14: an assignment before a regular built-in isn't kept.
    run(&mut sh, "X=1 on a b c\n");
    assert_eq!(sh.get("X"), None);
    // A function of the same name comes first; `command` skips it.
    run(&mut sh, "on() { :; }\non d e f\ncommand on g h i\n");
    let names: Vec<String> = rules.borrow().iter().map(|r| r[0].clone()).collect();
    assert_eq!(names, vec!["a", "g"]);
    assert_eq!(run(&mut sh, "unset -f on; type on >/dev/null\n"), 0, "`type` knows it");
}

#[test]
fn special_builtins_cant_be_replaced() {
    let mut sh = Shell::new("embed".into(), Vec::new());
    assert!(sh.add_builtin("set", |_: &mut Shell, _: &[String]| Ok(0)).is_err());
    assert!(sh.add_builtin("a b", |_: &mut Shell, _: &[String]| Ok(0)).is_err());
    assert!(sh.add_builtin("", |_: &mut Shell, _: &[String]| Ok(0)).is_err());
    // A regular one can.
    sh.add_builtin("true", |_: &mut Shell, _: &[String]| Ok(3)).unwrap();
    assert_eq!(run(&mut sh, "true\n"), 3);
}

#[test]
fn a_syntax_error_runs_nothing_and_says_where() {
    let (mut sh, rules) = with_on();
    let e = sh.source("on a b c\nfoo )\n").expect_err("a syntax error");
    assert_eq!(e.line, 2);
    assert!(rules.borrow().is_empty(), "nothing before it ran");
}

#[test]
fn sourcing_keeps_the_shell() {
    let (mut sh, _) = with_on();
    run(&mut sh, "trap 'echo bye' EXIT\nreturn 4\necho not reached\n");
    assert!(sh.traps.contains_key(&0), "the EXIT trap waits for the shell's end");
    assert_eq!(run(&mut sh, "f() { return 5; }; f\n"), 5);
    // Later text sees what earlier text defined (DEVD.md §5.3: one shell, every file).
    let (mut sh, rules) = with_on();
    run(&mut sh, "helper() { on h c \"$1\"; }\n");
    run(&mut sh, "helper one\n");
    assert_eq!(*rules.borrow(), vec![vec!["h", "c", "one"]]);
}
