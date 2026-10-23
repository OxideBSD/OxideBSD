//! gpart on image files (INSTALLER.md §11 step 8): each verb, its output, and its refusals.

use std::process::{Command, Output};

fn image(name: &str, bytes: u64) -> String {
    let dir = std::env::temp_dir().join(format!("gpart-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(bytes).unwrap();
    p.to_str().unwrap().to_string()
}

fn gpart(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gpart")).args(args).output().unwrap()
}

fn ok(args: &[&str]) -> String {
    let out = gpart(args);
    assert!(out.status.success(), "gpart {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn refused(args: &[&str]) -> String {
    let out = gpart(args);
    assert!(!out.status.success(), "gpart {args:?} should fail");
    String::from_utf8(out.stderr).unwrap()
}

const MIB: u64 = 1 << 20;

#[test]
fn a_gpt_disk_by_hand() {
    let d = image("gpt.img", 256 * MIB);
    assert_eq!(ok(&["create", "-s", "gpt", &d]), "gpt.img created\n");
    assert_eq!(ok(&["add", "-t", "efi", "-s", "64m", "-l", "esp", &d]), "gpt.imgp1 added\n");
    ok(&["add", "-t", "oxfs", "-s", "100m", "-l", "rootfs", &d]);
    ok(&["add", "-t", "swap", &d]);
    let shown = ok(&["show", &d]);
    let rows: Vec<Vec<&str>> = shown.lines().map(|l| l.split_whitespace().collect()).collect();
    assert_eq!(rows[0][..5], ["=>", "34", "524221", "gpt.img", "GPT"]);
    assert_eq!(rows[2][..4], ["2048", "131072", "1", "efi"]);
    assert_eq!(rows[3][..4], ["133120", "204800", "2", "oxfs"]);
    assert_eq!(rows[4][2..4], ["3", "swap"]);
    // Deleting the swap lets the root grow to the end.
    ok(&["delete", "-i", "3", &d]);
    ok(&["resize", "-i", "2", &d]);
    let labels = ok(&["show", "-l", &d]);
    assert!(labels.contains(" 2  rootfs  (191M)"), "{labels}");
    ok(&["modify", "-i", "1", "-t", "ms-basic-data", "-l", "data", &d]);
    assert!(ok(&["show", &d]).contains(" 1  ms-basic-data  (64M)"));
}

#[test]
fn refusals() {
    let d = image("refuse.img", 64 * MIB);
    assert!(refused(&["add", "-t", "oxfs", &d]).contains("no partition table"));
    ok(&["create", "-s", "mbr", &d]);
    // An MBR with no partitions may be replaced.
    ok(&["create", "-s", "gpt", &d]);
    let d = image("refuse2.img", 64 * MIB);
    ok(&["create", "-s", "gpt", &d]);
    assert!(refused(&["create", "-s", "mbr", &d]).contains("has a partition table already"));
    assert!(refused(&["add", "-t", "nonesuch", &d]).contains("no such type"));
    ok(&["add", "-t", "oxfs", "-s", "32m", &d]);
    assert!(refused(&["add", "-t", "oxfs", "-s", "64m", &d]).contains("not enough free space"));
    assert!(refused(&["resize", "-i", "7", &d]).contains("no such partition"));
    assert!(refused(&["set", "-a", "active", "-i", "1", &d]).contains("can't be stored in this scheme"));
    assert!(refused(&["destroy", &d]).contains("has partitions"));
    ok(&["destroy", "-F", &d]);
    assert!(refused(&["show", &d]).contains("no partition table"));
    assert!(!gpart(&["frobnicate", &d]).status.success());
}

#[test]
fn an_mbr_disk() {
    let d = image("mbr.img", 128 * MIB);
    ok(&["create", "-s", "mbr", &d]);
    ok(&["add", "-t", "ms-basic-data", "-s", "32m", &d]);
    ok(&["set", "-a", "active", "-i", "1", &d]);
    assert_eq!(ok(&["add", "-t", "oxfs", &d]), "mbr.imgs2 added\n");
    let shown = ok(&["show", &d]);
    assert!(shown.contains("1  ms-basic-data  [active]"), "{shown}");
    assert!(refused(&["add", "-t", "bios-boot", &d]).contains("not a type an MBR table has"));
    assert!(refused(&["modify", "-i", "1", "-l", "x", &d]).contains("labels are GPT's"));
}
