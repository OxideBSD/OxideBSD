//! Real hardware drivers not already grouped elsewhere (the network driver, `rtl8139`, lives under
//! `net/` alongside the protocol stack it exists for): `disk` picks the data disk backing oxfs's
//! persistence -- `virtio_blk` (over the `virtio` transport) or `ata`, legacy IDE by bus-master
//! DMA (`dma`) or PIO -- `pci` is legacy I/O-port PCI config-space
//! enumeration (today only used to find the NIC and the xHCI controller, kept generic for any
//! future PCI device), `usb` is the xHCI host-controller driver + HID boot-keyboard input path
//! (this kernel's only input source on hardware with no PS/2 controller, e.g. a Surface Pro).

pub mod ata;
pub mod disk;
pub mod dma;
pub mod fbdev;
pub mod pci;
pub mod rtl8139;
pub mod usb;
pub mod virtio;
pub mod virtio_blk;
