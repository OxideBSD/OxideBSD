//! Minimal PCI configuration-space access via the legacy I/O-port mechanism (port `0xCF8`
//! address, `0xCFC` data). See <https://wiki.osdev.org/PCI>.
//!
//! No PCI-to-PCI bridge traversal -- QEMU puts every device directly on bus 0, and nothing in
//! this kernel needs to walk a deeper topology yet. A flat scan of all 256 buses is simpler and,
//! at PCI's own fixed 256*32*8 upper bound, cheap enough not to need one.

use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

const VENDOR_ID_NONE: u16 = 0xFFFF;
const HEADER_TYPE_MULTIFUNCTION_BIT: u8 = 0x80;

/// One PCI function discovered during a bus scan.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    bars: [u32; 6],
    pub interrupt_line: u8,
}

impl PciDevice {
    /// The I/O port base for BAR `n`, if it's an I/O-space BAR (bit 0 set).
    pub fn io_bar(&self, n: usize) -> Option<u16> {
        let raw = self.bars[n];
        (raw & 0x1 == 1).then_some((raw & 0xFFFC) as u16)
    }

    /// The physical base address for BAR `n`, if it's a memory-space BAR (bit 0 clear). Handles
    /// both the 32-bit form (bits `2:1 == 0b00`) and the 64-bit form (bits `2:1 == 0b10`, where
    /// BAR `n+1` holds the address's upper 32 bits, per the PCI spec) -- `drivers::usb::xhci`
    /// needs the latter, since xHCI controllers commonly expose a 64-bit BAR0. `0b01` (the
    /// obsolete "below 1 MiB" encoding) is treated as absent, same as an I/O-space BAR.
    pub fn mem_bar(&self, n: usize) -> Option<u64> {
        let raw = self.bars[n];
        if raw & 0x1 != 0 {
            return None;
        }
        let low = (raw & 0xFFFF_FFF0) as u64;
        match (raw >> 1) & 0x3 {
            0b00 => Some(low),
            0b10 => {
                let high = *self.bars.get(n + 1)? as u64;
                Some((high << 32) | low)
            }
            _ => None,
        }
    }

    /// Sets the bus-mastering bit (command register bit 2), letting this device initiate DMA.
    pub fn enable_bus_mastering(&self) {
        let command = config_read_u32(self.bus, self.device, self.function, 0x04);
        config_write_u32(
            self.bus,
            self.device,
            self.function,
            0x04,
            command | (1 << 2),
        );
    }
}

fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | (offset as u32 & 0xFC)
}

fn config_read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let mut address_port: Port<u32> = Port::new(CONFIG_ADDRESS);
    let mut data_port: Port<u32> = Port::new(CONFIG_DATA);
    unsafe {
        address_port.write(config_address(bus, device, function, offset));
        data_port.read()
    }
}

fn config_write_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let mut address_port: Port<u32> = Port::new(CONFIG_ADDRESS);
    let mut data_port: Port<u32> = Port::new(CONFIG_DATA);
    unsafe {
        address_port.write(config_address(bus, device, function, offset));
        data_port.write(value);
    }
}

fn header_type(bus: u8, device: u8, function: u8) -> u8 {
    ((config_read_u32(bus, device, function, 0x0C) >> 16) & 0xFF) as u8
}

fn probe_function(bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    let id = config_read_u32(bus, device, function, 0x00);
    let vendor_id = (id & 0xFFFF) as u16;
    if vendor_id == VENDOR_ID_NONE {
        return None;
    }
    let device_id = (id >> 16) as u16;

    let class_reg = config_read_u32(bus, device, function, 0x08);
    let class = (class_reg >> 24) as u8;
    let subclass = (class_reg >> 16) as u8;
    let prog_if = (class_reg >> 8) as u8;

    let mut bars = [0u32; 6];
    for (n, bar) in bars.iter_mut().enumerate() {
        *bar = config_read_u32(bus, device, function, 0x10 + (n as u8) * 4);
    }

    // Interrupt Line register: offset 0x3C, low byte of that dword.
    let interrupt_line = (config_read_u32(bus, device, function, 0x3C) & 0xFF) as u8;

    Some(PciDevice {
        bus,
        device,
        function,
        vendor_id,
        device_id,
        class,
        subclass,
        prog_if,
        bars,
        interrupt_line,
    })
}

/// Calls `f` for every PCI function present on bus `0..256`. Flat scan -- see module doc comment.
fn for_each_device(mut f: impl FnMut(PciDevice)) {
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let Some(function0) = probe_function(bus, device, 0) else {
                continue;
            };
            let multifunction = header_type(bus, device, 0) & HEADER_TYPE_MULTIFUNCTION_BIT != 0;
            f(function0);
            if multifunction {
                for function in 1..8u8 {
                    if let Some(dev) = probe_function(bus, device, function) {
                        f(dev);
                    }
                }
            }
        }
    }
}

/// Finds the first device matching a PCI class/subclass pair (e.g. `(0x02, 0x00)` for an
/// Ethernet controller) -- the generic discovery path any future driver can use, not just
/// `rtl8139`.
pub fn find_by_class(class: u8, subclass: u8) -> Option<PciDevice> {
    let mut found = None;
    for_each_device(|dev| {
        if found.is_none() && dev.class == class && dev.subclass == subclass {
            found = Some(dev);
        }
    });
    found
}

/// Finds the first device matching an exact vendor/device ID pair.
pub fn find_by_id(vendor: u16, device_id: u16) -> Option<PciDevice> {
    let mut found = None;
    for_each_device(|dev| {
        if found.is_none() && dev.vendor_id == vendor && dev.device_id == device_id {
            found = Some(dev);
        }
    });
    found
}
