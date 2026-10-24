//! The firmware's variables through `/dev/efi` (`efi(4)`, OxideBSD-doc `EFIRT.md` §5.1), for the
//! tools (feature `dev`).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;

use crate::Guid;

pub const DEVICE: &str = "/dev/efi";
const EFIIOC_VAR_GET: u64 = 0x6f78_4504;
const EFIIOC_VAR_NEXT: u64 = 0x6f78_4505;
const EFIIOC_VAR_SET: u64 = 0x6f78_4506;

/// `EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS`: what boot entries and
/// most variables are written with.
pub const NV_BS_RT: u32 = 0x7;
/// `EFI_VARIABLE_APPEND_WRITE`.
pub const APPEND_WRITE: u32 = 0x40;

/// The device's request: the name in UTF-16 with its NUL (`namesize` in bytes), the vendor GUID,
/// the attributes, and the data (`datasize` bytes).
#[repr(C)]
#[derive(Default)]
struct VarIoc {
    name: u64,
    namesize: u64,
    vendor: [u8; 16],
    attrib: u32,
    pad: u32,
    data: u64,
    datasize: u64,
}

/// `/dev/efi`, open for reading, and writing if `write`.
pub struct Efi(File);

fn ucs2(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(core::iter::once(0)).collect()
}

impl Efi {
    pub fn open(write: bool) -> io::Result<Efi> {
        OpenOptions::new().read(true).write(write).open(DEVICE).map(Efi)
    }

    fn ioctl(&self, request: u64, v: &mut VarIoc) -> io::Result<()> {
        // SAFETY: the request reads and writes one `VarIoc`, whose pointers name live buffers.
        if unsafe { libc::ioctl(self.0.as_raw_fd(), request as _, v as *mut VarIoc) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Variable `name` of `vendor`: its value and attributes (`ENOENT`'s error if there's none).
    pub fn get(&self, vendor: &Guid, name: &str) -> io::Result<(Vec<u8>, u32)> {
        let wide = ucs2(name);
        let mut data = vec![0u8; 1024];
        loop {
            let mut v = VarIoc {
                name: wide.as_ptr() as u64,
                namesize: (wide.len() * 2) as u64,
                vendor: vendor.0,
                data: data.as_mut_ptr() as u64,
                datasize: data.len() as u64,
                ..Default::default()
            };
            match self.ioctl(EFIIOC_VAR_GET, &mut v) {
                Ok(()) => {
                    data.truncate(v.datasize as usize);
                    return Ok((data, v.attrib));
                }
                Err(e) if e.raw_os_error() == Some(libc::EOVERFLOW) && v.datasize as usize > data.len() => {
                    data.resize(v.datasize as usize, 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Like `get`, but `None` for a variable that isn't there.
    pub fn get_opt(&self, vendor: &Guid, name: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
        match self.get(vendor, name) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Sets variable `name` of `vendor` to `data` with `attrib`; an empty `data` deletes it.
    pub fn set(&self, vendor: &Guid, name: &str, attrib: u32, data: &[u8]) -> io::Result<()> {
        let wide = ucs2(name);
        let mut v = VarIoc {
            name: wide.as_ptr() as u64,
            namesize: (wide.len() * 2) as u64,
            vendor: vendor.0,
            attrib,
            data: data.as_ptr() as u64,
            datasize: data.len() as u64,
            ..Default::default()
        };
        self.ioctl(EFIIOC_VAR_SET, &mut v)
    }

    /// Deletes variable `name` of `vendor`; one that isn't there is no error.
    pub fn delete(&self, vendor: &Guid, name: &str) -> io::Result<()> {
        match self.set(vendor, name, NV_BS_RT, &[]) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            r => r,
        }
    }

    /// Every variable, in the firmware's order.
    pub fn list(&self) -> io::Result<Vec<(Guid, String)>> {
        let mut out = Vec::new();
        let mut name: Vec<u16> = vec![0; 256];
        let mut vendor = Guid([0; 16]);
        loop {
            let mut v = VarIoc {
                name: name.as_mut_ptr() as u64,
                namesize: (name.len() * 2) as u64,
                vendor: vendor.0,
                ..Default::default()
            };
            match self.ioctl(EFIIOC_VAR_NEXT, &mut v) {
                Ok(()) => {
                    vendor = Guid(v.vendor);
                    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                    out.push((vendor, String::from_utf16_lossy(&name[..end])));
                }
                Err(e) if e.raw_os_error() == Some(libc::EOVERFLOW) && v.namesize as usize > name.len() * 2 => {
                    name.resize(v.namesize as usize / 2 + 1, 0);
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(out),
                Err(e) => return Err(e),
            }
        }
    }
}
