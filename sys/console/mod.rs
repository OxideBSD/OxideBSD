//! Console/terminal I/O: the hand-rolled 16550 UART (`serial`), a real ANSI/VT100 text engine
//! (`vga` -- the name predates Limine; it now drives an in-memory buffer, not real VGA hardware,
//! see its own `SHADOW_BUFFER` doc comment) that `framebuffer` rasterizes onto Limine's real
//! linear framebuffer using a VGA-proportioned bitmap font and the real 16-color CGA/VGA palette.
//! The terminal built on them, `ttyv0`, is `crate::tty::console`.

pub mod framebuffer;
pub mod keyevents;
pub mod serial;
pub mod vga;
