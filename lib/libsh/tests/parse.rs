use libsh::ast::*;
use libsh::parse;

fn only_simple(src: &str) -> SimpleCommand {
    let list = parse(src).unwrap();
    assert_eq!(list.len(), 1, "{src}");
    let p = &list[0].and_or.first;
    assert_eq!(p.commands.len(), 1);
    match &p.commands[0] {
        Command::Simple(s) => s.clone(),
        other => panic!("not simple: {other:?}"),
    }
}

fn lit(s: &str) -> WordPart {
    WordPart::Literal(s.into())
}

#[test]
fn words_keep_quoting_structure() {
    let s = only_simple(r#"echo a'b c'"d $x" \e"#);
    assert_eq!(s.words[0], vec![lit("echo")]);
    assert_eq!(
        s.words[1],
        vec![
            lit("a"),
            WordPart::Quoted("b c".into()),
            WordPart::DoubleQuoted(vec![
                WordPart::Quoted("d ".into()),
                WordPart::Param(ParamExpansion { param: Param::Named("x".into()), op: ParamOp::Plain }),
            ]),
        ]
    );
    assert_eq!(s.words[2], vec![WordPart::Quoted("e".into())]);
}

#[test]
fn assignments_only_before_the_command_name() {
    let s = only_simple("A=1 B= cmd C=2");
    assert_eq!(s.assignments.len(), 2);
    assert_eq!(s.assignments[0].name, "A");
    assert_eq!(s.assignments[1].value, Vec::<WordPart>::new());
    assert_eq!(s.words.len(), 2, "C=2 after the command name is an argument");
}

#[test]
fn param_expansion_forms() {
    let s = only_simple("echo ${x:-d} ${#y} ${z%%.*} ${#} ${10} $?$$");
    let op = |i: usize| match &s.words[i][0] {
        WordPart::Param(p) => p.clone(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(op(1).op, ParamOp::Default { colon: true, .. }));
    assert_eq!(op(2).op, ParamOp::Length);
    assert!(matches!(op(3).op, ParamOp::RemoveSuffix { longest: true, .. }));
    assert_eq!(op(4).param, Param::Special('#'));
    assert_eq!(op(5).param, Param::Positional(10));
    assert_eq!(s.words[6].len(), 2);
}

#[test]
fn and_or_pipelines_and_background() {
    let list = parse("a | b && ! c || d &\ne").unwrap();
    assert_eq!(list.len(), 2);
    assert!(list[0].background);
    assert_eq!(list[0].and_or.first.commands.len(), 2);
    assert_eq!(list[0].and_or.rest.len(), 2);
    assert!(list[0].and_or.rest[0].1.bang);
}

#[test]
fn compound_commands() {
    for src in [
        "if a; then b; elif c; then d; else e; fi",
        "while a; do b; done",
        "until a\ndo\nb\ndone",
        "for x in 1 2 3; do echo $x; done",
        "for x; do :; done",
        "for x\ndo :; done",
        "case $x in a|b) echo ab;; (c) echo c;; *) ;; esac",
        "case x in esac",
        "{ a; b; }",
        "(a; b) > out",
        "f() { echo hi; }",
        "f()\n{\n  echo hi\n}",
    ] {
        parse(src).unwrap_or_else(|e| panic!("{src}: {e}"));
    }
}

#[test]
fn function_definition() {
    let list = parse("greet() { echo hi; }").unwrap();
    match &list[0].and_or.first.commands[0] {
        Command::FunctionDef { name, body } => {
            assert_eq!(name, "greet");
            assert!(matches!(**body, Command::Compound(CompoundCommand::Brace(_), _)));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn redirections_and_io_numbers() {
    let s = only_simple("cmd 2>&1 >out <in 3<>rw >>app >|clob");
    let ops: Vec<_> = s.redirects.iter().map(|r| (r.fd, r.op)).collect();
    assert_eq!(
        ops,
        vec![
            (Some(2), RedirOp::DupOutput),
            (None, RedirOp::Output),
            (None, RedirOp::Input),
            (Some(3), RedirOp::ReadWrite),
            (None, RedirOp::Append),
            (None, RedirOp::Clobber),
        ]
    );
    let s = only_simple("echo 2 >x");
    assert_eq!(s.words.len(), 2, "`2 >` has a space: 2 is an argument, not an IO_NUMBER");
}

#[test]
fn heredocs() {
    let list = parse("cat <<EOF; cat <<'Q'\nhello $name\nEOF\nlit $x\nQ\necho after\n").unwrap();
    assert_eq!(list.len(), 3);
    let body = |i: usize| match &list[i].and_or.first.commands[0] {
        Command::Simple(s) => match &s.redirects[0].target {
            RedirTarget::HereDoc(h) => (h.quoted, h.body.borrow().clone()),
            _ => panic!(),
        },
        _ => panic!(),
    };
    let (quoted, b) = body(0);
    assert!(!quoted);
    assert_eq!(b.len(), 3, "text, $name, newline: {b:?}");
    let (quoted, b) = body(1);
    assert!(quoted);
    assert_eq!(b, vec![WordPart::Quoted("lit $x\n".into())]);
}

#[test]
fn heredoc_strip_tabs() {
    let list = parse("cat <<-EOF\n\t\tindented\n\tEOF\n").unwrap();
    let Command::Simple(s) = &list[0].and_or.first.commands[0] else { panic!() };
    let RedirTarget::HereDoc(h) = &s.redirects[0].target else { panic!() };
    assert_eq!(*h.body.borrow(), vec![WordPart::Quoted("indented\n".into())]);
}

#[test]
fn command_substitution_with_case_paren() {
    // The `)` after the case pattern must not close the `$(`.
    let s = only_simple("echo $(case x in x) echo y;; esac) done");
    assert!(matches!(s.words[1][0], WordPart::CommandSubst(_)));
    assert_eq!(s.words[2], vec![lit("done")]);
}

#[test]
fn backquotes_and_arith() {
    let s = only_simple("echo `echo \\`date\\`` $((1 + (2 * $n)))");
    assert!(matches!(s.words[1][0], WordPart::CommandSubst(_)));
    assert!(matches!(s.words[2][0], WordPart::Arith(_)));
}

#[test]
fn reserved_words_only_in_command_position() {
    let s = only_simple("echo if then fi done");
    assert_eq!(s.words.len(), 5);
}

#[test]
fn comments_and_line_continuation() {
    let s = only_simple("echo a \\\n b # comment here");
    assert_eq!(s.words.len(), 3);
}

#[test]
fn syntax_errors_have_positions() {
    for (src, line) in [("if true; then", 1), ("echo 'open", 1), ("a &&", 1), ("\n\nfi", 3), ("cat <<EOF\nno end", 2)] {
        let err = parse(src).unwrap_err();
        assert_eq!(err.line, line, "{src}: {err}");
    }
}
