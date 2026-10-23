//! `/var/run/devd.pipe` (OxideBSD-doc `DEVD.md` §5.5): every event line devd reads, written to
//! every client connected when it came. A client that can't take a line at once is dropped, and
//! what clients send is thrown away.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

pub const PATH: &str = "/var/run/devd.pipe";

pub struct Pipe {
    listener: UnixListener,
    clients: Vec<UnixStream>,
}

impl Pipe {
    /// Binds `path` (a stale socket of an earlier devd removed first), mode `0666`.
    pub fn bind(path: &Path) -> std::io::Result<Pipe> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        Ok(Pipe { listener, clients: Vec::new() })
    }

    pub fn listener_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    pub fn client_fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.clients.iter().map(|c| c.as_raw_fd())
    }

    /// Takes every waiting connection.
    pub fn accept(&mut self) {
        while let Ok((client, _)) = self.listener.accept() {
            if client.set_nonblocking(true).is_ok() {
                self.clients.push(client);
            }
        }
    }

    /// Reads what client `fd` sent, dropping it at its end of file or an error.
    pub fn service(&mut self, fd: RawFd) {
        let Some(i) = self.clients.iter().position(|c| c.as_raw_fd() == fd) else { return };
        let mut junk = [0u8; 512];
        loop {
            match self.clients[i].read(&mut junk) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        self.clients.swap_remove(i);
    }

    /// Writes `line` to every client; one that can't take all of it now is dropped.
    pub fn broadcast(&mut self, line: &[u8]) {
        self.clients.retain_mut(|c| matches!(c.write(line), Ok(n) if n == line.len()));
    }
}
