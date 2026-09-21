//! Console/terminal I/O: the hand-rolled 16550 UART (`serial`), a real ANSI/VT100 text engine
//! (`vga` -- the name predates Limine; it now drives an in-memory buffer, not real VGA hardware,
//! see its own `SHADOW_BUFFER` doc comment) that `framebuffer` rasterizes onto Limine's real
//! linear framebuffer using a VGA-proportioned bitmap font and the real 16-color CGA/VGA palette,
//! and the keyboard-IRQ-fed stdin ring buffer plus real termios state (`stdin`) -- see CLAUDE.md's
//! interactive-shell section for the full design.

pub mod framebuffer;
pub mod keyevents;
pub mod serial;
pub mod stdin;
pub mod vga;
