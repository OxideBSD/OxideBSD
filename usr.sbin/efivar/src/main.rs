//! `efivar(8)`: shows and changes UEFI variables (OxideBSD-doc `EFIRT.md` §6.1), through
//! `/dev/efi` (`efi(4)`), with FreeBSD's options.
//!
//! ```text
//! efivar [-abdDHlLNpqRuw] [-n name] [-f file] [-t attributes] [--load-option] [name]
//! ```
//!
//! A variable is named `GUID-name` (`8be4df61-93ca-11d2-aa0d-00e098032b8c-BootOrder`), or with a
//! well-known GUID's name in its place (`global-BootOrder`, `-L` lists them). `-l` lists every
//! variable (`-p` with each one's value too); `-p` or a name alone prints one; `-w` writes one
//! from the standard input or `-f file`, `-a` appends to it, `-D` deletes it. Values print as a
//! hex dump (`-H`, the default), as text with unprintable bytes as `%xx` (`-A`), as UCS-2
//! converted to UTF-8 (`-u`), or raw (`-b`); `-d` prints one as a device path, `--load-option`
//! as a boot entry (`lib/libefivar`, shared with efibootmgr(8)).

use std::io::{Read, Write};
use std::process::ExitCode;

use efivar::dev::{self, Efi};
use efivar::{Guid, LoadOption, devpath, guid};

const DEFAULT_ATTRIBUTES: u32 = dev::NV_BS_RT;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Hex,
    Ascii,
    Utf8,
    Binary,
    DevicePath,
    LoadOption,
}

struct Opts {
    list: bool,
    print: bool,
    write: bool,
    append: bool,
    delete: bool,
    no_name: bool,
    quiet: bool,
    symbolic: bool,
    raw: bool,
    format: Format,
    attributes: Option<u32>,
    name: Option<String>,
    file: Option<String>,
}

fn usage() -> ExitCode {
    eprintln!("usage: efivar [-abdDHlLNpqRuw] [-n name] [-f file] [-t attributes] [--ascii] [--utf8] [--load-option] [name]");
    ExitCode::from(1)
}

/// `-A`'s text: printable ASCII as it is, every other byte as `%xx`.
fn ascii(data: &[u8]) -> String {
    data.iter().map(|&b| if (0x20..0x7f).contains(&b) && b != b'%' { (b as char).to_string() } else { format!("%{b:02x}") }).collect()
}

/// `-H`'s hex dump: an offset, 16 bytes, and their printable ASCII.
fn hexdump(data: &[u8]) -> String {
    let mut s = String::new();
    for (i, line) in data.chunks(16).enumerate() {
        let hex: Vec<String> = line.iter().map(|b| format!("{b:02x}")).collect();
        let text: String = line.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
        s.push_str(&format!("{:04x}: {:<47}  |{}|\n", i * 16, hex.join(" "), text));
    }
    s
}

/// `-u`'s text: the value as UCS-2, up to a NUL.
fn utf8(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    String::from_utf16_lossy(&units)
}

fn show_name(o: &Opts, g: &Guid, name: &str) -> String {
    format!("{}-{name}", if o.symbolic && !o.raw { g.symbolic() } else { g.to_string() })
}

fn print_value(o: &Opts, out: &mut impl Write, g: &Guid, name: &str, data: &[u8]) -> std::io::Result<()> {
    if o.format == Format::Binary {
        return out.write_all(data);
    }
    if !o.no_name {
        writeln!(out, "{}", show_name(o, g, name))?;
    }
    match o.format {
        Format::Ascii => writeln!(out, "{}", ascii(data)),
        Format::Utf8 => writeln!(out, "{}", utf8(data)),
        Format::DevicePath => match devpath::to_text(data) {
            Some(t) => writeln!(out, "{t}"),
            None => writeln!(out, "(not a device path)"),
        },
        Format::LoadOption => match LoadOption::parse(data) {
            Some(lo) => writeln!(
                out,
                "{}{} {}\n    {}",
                if lo.attributes & efivar::LOAD_OPTION_ACTIVE != 0 { "*" } else { " " },
                if lo.attributes & efivar::LOAD_OPTION_HIDDEN != 0 { " (hidden)" } else { "" },
                lo.description,
                devpath::to_text(&lo.path).unwrap_or_default()
            ),
            None => writeln!(out, "(not a load option)"),
        },
        _ => write!(out, "{}", hexdump(data)),
    }
}

fn run(o: &Opts) -> Result<(), String> {
    let writing = o.write || o.append || o.delete;
    let dev = Efi::open(writing).map_err(|e| format!("{}: {e}", dev::DEVICE))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if o.list {
        for (g, name) in dev.list().map_err(|e| format!("listing the variables: {e}"))? {
            if o.print {
                let (data, _) = dev.get(&g, &name).map_err(|e| format!("{}: {e}", show_name(o, &g, &name)))?;
                print_value(o, &mut out, &g, &name, &data).map_err(|e| e.to_string())?;
            } else {
                writeln!(out, "{}", show_name(o, &g, &name)).map_err(|e| e.to_string())?;
            }
        }
        return Ok(());
    }
    let full = o.name.as_deref().ok_or("no variable named (-n name)")?;
    let (g, name) = guid::split_name(full).ok_or(format!("{full}: not GUID-name"))?;
    if o.delete {
        return dev.set(&g, &name, o.attributes.unwrap_or(DEFAULT_ATTRIBUTES), &[]).map_err(|e| format!("{full}: {e}"));
    }
    if o.write || o.append {
        let mut data = Vec::new();
        match &o.file {
            Some(f) => data = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?,
            None => {
                std::io::stdin().read_to_end(&mut data).map_err(|e| e.to_string())?;
            }
        }
        let mut attrib = o.attributes.unwrap_or(DEFAULT_ATTRIBUTES);
        if o.append {
            attrib |= dev::APPEND_WRITE;
        }
        return dev.set(&g, &name, attrib, &data).map_err(|e| format!("{full}: {e}"));
    }
    let (data, _) = dev.get(&g, &name).map_err(|e| format!("{full}: {e}"))?;
    print_value(o, &mut out, &g, &name, &data).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let mut o = Opts {
        list: false,
        print: false,
        write: false,
        append: false,
        delete: false,
        no_name: false,
        quiet: false,
        symbolic: false,
        raw: false,
        format: Format::Hex,
        attributes: None,
        name: None,
        file: None,
    };
    let mut list_guids = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut operands = Vec::new();
    while i < args.len() {
        let a = args[i].as_str();
        let value = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        let long = |s: &str| match s {
            "--append" => Some('a'),
            "--ascii" => Some('A'),
            "--binary" => Some('b'),
            "--delete" => Some('D'),
            "--fromfile" => Some('f'),
            "--guid" => Some('g'),
            "--hex" => Some('H'),
            "--list-guids" => Some('L'),
            "--list" => Some('l'),
            "--name" => Some('n'),
            "--no-name" => Some('N'),
            "--print" => Some('p'),
            "--quiet" => Some('q'),
            "--raw-guid" => Some('R'),
            "--attributes" => Some('t'),
            "--utf8" => Some('u'),
            "--write" => Some('w'),
            _ => None,
        };
        let flags: Vec<char> = if a.starts_with("--") {
            match long(a) {
                Some(c) => vec![c],
                None if a == "--device-path" || a == "--device" => vec!['d'],
                None if a == "--load-option" => vec!['O'],
                None => return usage(),
            }
        } else if a.len() > 1 && a.starts_with('-') {
            a[1..].chars().collect()
        } else {
            operands.push(a.to_string());
            i += 1;
            continue;
        };
        for c in flags {
            match c {
                'a' => o.append = true,
                'A' => o.format = Format::Ascii,
                'b' => o.format = Format::Binary,
                'D' => o.delete = true,
                'g' => o.symbolic = true,
                'H' => o.format = Format::Hex,
                'L' => list_guids = true,
                'l' => o.list = true,
                'N' => o.no_name = true,
                'p' => o.print = true,
                'q' => o.quiet = true,
                'R' => o.raw = true,
                'u' => o.format = Format::Utf8,
                'w' => o.write = true,
                'n' => match value(&mut i) {
                    Some(v) => o.name = Some(v),
                    None => return usage(),
                },
                'f' => match value(&mut i) {
                    Some(v) => o.file = Some(v),
                    None => return usage(),
                },
                't' => match value(&mut i).and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok()) {
                    Some(v) => o.attributes = Some(v),
                    None => return usage(),
                },
                'd' => o.format = Format::DevicePath,
                'O' if a.starts_with("--") => o.format = Format::LoadOption,
                _ => return usage(),
            }
        }
        i += 1;
    }
    if list_guids {
        for (name, g) in guid::KNOWN {
            if o.raw {
                println!("{}", Guid(*g));
            } else {
                println!("{:<12} {}", name, Guid(*g));
            }
        }
        return ExitCode::SUCCESS;
    }
    if let Some(n) = operands.pop() {
        if o.name.is_some() || !operands.is_empty() {
            return usage();
        }
        o.name = Some(n);
    }
    if [o.write || o.append, o.delete, o.list].iter().filter(|&&b| b).count() > 1 {
        return usage();
    }
    match run(&o) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !o.quiet {
                eprintln!("efivar: {e}");
            }
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(ascii(b"Boot%1\x00"), "Boot%251%00");
        assert_eq!(utf8(&[b'O', 0, b'x', 0, 0, 0, b'z', 0]), "Ox");
        let d = hexdump(b"0123456789abcdefXY");
        assert_eq!(d.lines().next().unwrap(), "0000: 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66  |0123456789abcdef|");
        assert!(d.lines().nth(1).unwrap().starts_with("0010: 58 59 "));
    }
}
