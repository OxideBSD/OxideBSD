//! Real hardware drivers not already grouped elsewhere (the network driver, `rtl8139`, lives under
//! `net/` alongside the protocol stack it exists for): `ata` is the hand-rolled legacy IDE PIO disk
//! driver backing oxfs's real disk persistence, `pci` is legacy I/O-port PCI config-space
//! enumeration (today only used to find the NIC and the xHCI controller, kept generic for any
//! future PCI device), `usb` is the xHCI host-controller driver + HID boot-keyboard input path
//! (this kernel's only input source on hardware with no PS/2 controller, e.g. a Surface Pro).

pub mod ata;
pub mod fbdev;
pub mod pci;
pub mod usb;
