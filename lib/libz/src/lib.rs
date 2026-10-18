//! DEFLATE (RFC 1951) and its two wrappers, gzip (RFC 1952) and zlib (RFC 1950), written from
//! scratch for OxideBSD's gzip(1), gunzip(1), zcat(1) and tar -z. It is a library with a Rust
//! API, not a zlib-compatible C ABI.
//!
//! What matters, in order: never accept a stream wrongly or reject one zlib accepts, never
//! panic, hang or allocate without bound on hostile input; then compression ratio; then speed.
//!
//! # Design
//!
//! - [`inflate`]: a resumable decoder. Input is decoded in *units* (a block header with its
//!   whole dynamic code description, one literal or length/distance pair, a stored block's
//!   length, a run of stored bytes); a unit is committed only once every bit of it has arrived,
//!   so running out of input mid-unit just rolls back to the unit's start and waits. Huffman
//!   codes decode through a two-level table (zlib's validation rules: over-subscribed codes are
//!   rejected, incomplete ones only allowed for a single one-bit code). Output goes through a
//!   96 KiB window holding the 32 KiB of history back-references may reach.
//! - [`deflate`]: zlib's algorithm and level table: LZ77 over a 64 KiB sliding window with
//!   hash chains, greedy matching at levels 1-3 and lazy matching at 4-9, blocks of up to 16K
//!   symbols, each sent as whichever of stored, fixed or dynamic Huffman is smallest. Dynamic
//!   codes are length-limited by package-merge, which is optimal (zlib uses a heuristic).
//! - [`gzip`] and [`zlib`]: the framings, with `std::io` adapters (encoders over `Write`,
//!   decoders over `BufRead`, so a decoder consumes exactly the stream's bytes) and whole-buffer
//!   helpers. [`crc32`] is slicing-by-8; [`adler32`] the usual deferred-modulo loop.

pub mod adler32;
pub mod crc32;
pub mod deflate;
pub mod gzip;
mod huffman;
pub mod inflate;
mod tables;
pub mod zlib;

use std::fmt;
use std::io;

pub use deflate::{Deflater, Flush};
pub use inflate::{Inflater, Progress, Status};

/// Everything that can go wrong decoding (or, for a few variants, encoding) a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Block type 3.
    InvalidBlockType,
    /// A stored block's LEN is not the complement of its NLEN.
    StoredLength,
    /// HLIT above 286 or HDIST above 30.
    TooManyCodes,
    /// The code length code is over-subscribed, incomplete or empty.
    BadCodeLengths,
    /// A repeat code with nothing to repeat, or running past the end of the lengths.
    BadRepeat,
    /// The literal/length code has no end-of-block symbol.
    MissingEndOfBlock,
    /// The literal/length code lengths are over-subscribed or incomplete.
    BadLitLenCode,
    /// The distance code lengths are over-subscribed or incomplete.
    BadDistCode,
    /// A bit sequence no code assigns, or symbol 286/287 or distance symbol 30/31.
    InvalidCode,
    /// A distance reaching back before the start of the output.
    DistanceTooFar,
    /// The input ended inside the stream.
    Truncated,
    /// The output would exceed the caller's limit.
    OutputLimit,
    /// Not a gzip member (bad magic).
    BadMagic,
    /// A compression method other than 8 (deflate).
    BadMethod,
    /// Reserved gzip flag bits set.
    ReservedFlags,
    /// The gzip header CRC (FHCRC) does not match.
    HeaderCrc,
    /// A gzip file name, comment or header longer than this library accepts.
    HeaderTooLong,
    /// A gzip header field that cannot be written (NUL in a name or comment, extra field
    /// longer than 65535 bytes).
    BadHeaderField,
    /// The CRC-32 in a gzip trailer does not match the data.
    Crc,
    /// The ISIZE in a gzip trailer does not match the data's length.
    Length,
    /// A malformed zlib header (bad FCHECK, method or window size).
    BadZlibHeader,
    /// A zlib stream needing a preset dictionary, which is not supported.
    PresetDictionary,
    /// The Adler-32 in a zlib trailer does not match the data.
    Adler,
    /// Data after the last gzip member that is not another member. The data before it is
    /// intact, so gunzip treats this as a warning.
    TrailingGarbage,
    /// Input given to a compressor after `Flush::Finish`.
    Finished,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidBlockType => "invalid block type",
            Error::StoredLength => "invalid stored block lengths",
            Error::TooManyCodes => "too many length or distance symbols",
            Error::BadCodeLengths => "invalid code lengths set",
            Error::BadRepeat => "invalid bit length repeat",
            Error::MissingEndOfBlock => "invalid code -- missing end-of-block",
            Error::BadLitLenCode => "invalid literal/lengths set",
            Error::BadDistCode => "invalid distances set",
            Error::InvalidCode => "invalid literal/length or distance code",
            Error::DistanceTooFar => "invalid distance too far back",
            Error::Truncated => "unexpected end of compressed data",
            Error::OutputLimit => "decompressed data exceeds the size limit",
            Error::BadMagic => "not in gzip format",
            Error::BadMethod => "unknown compression method",
            Error::ReservedFlags => "reserved header flags set",
            Error::HeaderCrc => "header CRC mismatch",
            Error::HeaderTooLong => "header field too long",
            Error::BadHeaderField => "header field cannot be encoded",
            Error::Crc => "CRC error",
            Error::Length => "length error",
            Error::BadZlibHeader => "incorrect zlib header",
            Error::PresetDictionary => "preset dictionary not supported",
            Error::Adler => "incorrect data check",
            Error::TrailingGarbage => "trailing garbage ignored",
            Error::Finished => "stream already finished",
        })
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = if e == Error::Truncated { io::ErrorKind::UnexpectedEof } else { io::ErrorKind::InvalidData };
        io::Error::new(kind, e)
    }
}

impl Error {
    /// The library error inside an `io::Error` from one of the adapters, if it is one.
    pub fn from_io(e: &io::Error) -> Option<Error> {
        e.get_ref().and_then(|x| x.downcast_ref::<Error>()).copied()
    }
}

/// Maps an adapter's `io::Error` back to [`Error`] for the whole-buffer helpers, which read
/// from memory and so can fail no other way.
pub(crate) fn unwrap_io(e: io::Error) -> Error {
    Error::from_io(&e).unwrap_or(Error::Truncated)
}
