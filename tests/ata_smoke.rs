//! Smoke test for `sys/drivers/ata.rs`'s raw sector-level driver, by PIO and then by bus-master DMA -- `read_sector`/`write_sector`
//! called directly as plain Rust functions (no real `SYSCALL` involved; there's no syscall surface
//! for raw block I/O in this phase -- oxfs consumes `src/ata.rs` internally via
//! `oxidebsd_block_read`/`_write`, not through anything a userland ELF could reach). Runs against
//! `target/oxfs_test_disk.img` (`Cargo.toml`'s `test-args`, always freshly zeroed by `build.rs`),
//! not the real persistent `target/oxfs_disk.img` `cargo run` uses -- this test writes raw,
//! filesystem-format-agnostic patterns directly to low LBAs, which would corrupt a real oxfs
//! superblock/inode table if it ever ran against the dev disk instead.
//!
//! Covers: the disk is actually detected at boot (`oxidebsd_block_device_present`), a written
//! sector reads back byte-for-byte identical at a few different LBAs (catching address-computation
//! bugs, not just "it round-trips at LBA 0"), and a full 0..256 byte-value sweep round-trips
//! correctly (catching a word-order/byte-order bug in the 16-bit PIO word transfer that a
//! same-valued pattern like all-zero or all-`0xAA` could never catch).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::drivers::ata::{self, Channel, Drive};
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

fn round_trip(lba: u32, pattern: &[u8; 512]) {
    ata::write_sector(Channel::Secondary, Drive::Master, lba, pattern)
        .unwrap_or_else(|e| panic!("write_sector(lba={lba}) failed: {e:?}"));

    let mut readback = [0u8; 512];
    ata::read_sector(Channel::Secondary, Drive::Master, lba, &mut readback)
        .unwrap_or_else(|e| panic!("read_sector(lba={lba}) failed: {e:?}"));

    assert_eq!(
        &readback, pattern,
        "sector {lba} didn't read back what was written"
    );
}

/// The same checks through whichever path `ata` currently uses for the data disk.
fn sector_checks(mode: &str) {
    // A few different LBAs, not just 0 -- catches an address-computation bug that only a
    // non-first sector would expose (e.g. the drive/head or LBA-high registers never actually
    // being written).
    for &lba in &[0u32, 1, 7, 100] {
        let mut pattern = [0u8; 512];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = ((lba as usize + i) % 256) as u8;
        }
        round_trip(lba, &pattern);
    }
    serial_println!("ata_smoke: {}: round trip verified at several LBAs", mode);

    // A full 0..256 byte-value sweep, twice over to fill 512 bytes -- would catch a byte-order
    // bug in the 16-bit word transfer that an all-same-value pattern could never expose (a
    // swapped high/low byte within a word is invisible if both bytes happen to be equal).
    let mut sweep = [0u8; 512];
    for (i, b) in sweep.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    round_trip(200, &sweep);
    serial_println!("ata_smoke: {}: byte-order sweep verified", mode);
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (_mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    ata::init();
    assert!(ata::present(), "ata_smoke's own test-args should have attached a data disk at secondary/master");
    serial_println!("ata_smoke: data disk detected");

    sector_checks("PIO");
    let mut marker = [0u8; 512];
    marker[..16].copy_from_slice(b"written with PIO");
    round_trip(300, &marker);

    ata::init_dma(&mut frame_allocator, physical_memory_offset);
    sector_checks("DMA");
    let (transfers, _) = ata::dma_stats();
    assert!(transfers > 0, "the data disk's transfers should have gone by DMA");

    // PIO and DMA see the same disk.
    let mut readback = [0u8; 512];
    ata::read_sector(Channel::Secondary, Drive::Master, 300, &mut readback).expect("DMA read");
    assert_eq!(readback, marker, "a sector written by PIO should read back by DMA");

    // 100 sectors in one command, crossing a 64 KiB Physical Region Descriptor boundary.
    static mut BIG: [u8; 100 * 512] = [0; 100 * 512];
    static mut BIG_BACK: [u8; 100 * 512] = [0; 100 * 512];
    let (big, big_back) = unsafe { (&mut *core::ptr::addr_of_mut!(BIG), &mut *core::ptr::addr_of_mut!(BIG_BACK)) };
    for (i, b) in big.iter_mut().enumerate() {
        *b = (i / 512 + i) as u8;
    }
    ata::write_sectors(Channel::Secondary, Drive::Master, 1000, 100, big).expect("100-sector DMA write");
    ata::read_sectors(Channel::Secondary, Drive::Master, 1000, 100, big_back).expect("100-sector DMA read");
    assert!(big == big_back, "a 100-sector DMA transfer should round-trip");
    let (transfers, irqs) = ata::dma_stats();
    serial_println!("ata_smoke: DMA: multi-sector transfer verified ({} transfers, {} completion interrupts)", transfers, irqs);

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
