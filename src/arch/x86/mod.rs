//! Arch x86 runtime and analysis.

use iced_x86::{Decoder, DecoderOptions, Instruction};

mod block;
pub use block::BasicBlockAnalysis;

mod idr;
pub use idr::IdrDecoder;


/// The x86 runtime for analyzer.
pub struct Runtime<'data> {
    /// The underlying bytes of data.
    pub data: &'data [u8],
    /// Bitness of the instruction's decoder (16, 32, 64).
    pub bitness: u32,
    /// The x86 instruction decoder.
    pub decoder: RangeDecoder<'data>,
    /// Sections and their metadata.
    pub sections: Sections,
}

impl<'data> Runtime<'data> {

    pub fn new(data: &'data [u8], bitness: u32) -> Self {
        Self {
            data,
            bitness,
            decoder: RangeDecoder::new(data, bitness),
            sections: Sections::default(),
        }
    }

}


/// Listing important sections for runtime.
#[derive(Debug, Default)]
pub struct Sections {
    /// Code sections.
    code: Vec<Section>,
}

impl Sections {

    #[inline]
    pub fn add_code_section(&mut self, pos: usize, first_addr: u64, last_addr: u64) {
        self.code.push(Section { pos, begin_addr: first_addr, end_addr: last_addr });
    }

    /// Returns true if the given address is in code range.
    pub fn in_code_range(&self, addr: u64) -> bool {
        self.code.iter().any(|s| addr >= s.begin_addr && addr < s.end_addr)
    }

    /// Returns the maximum code address, 0 if no code sections is set.
    pub fn max_code_addr(&self) -> u64 {
        self.code.iter().map(|s| s.end_addr).max().unwrap_or(0)
    }

}


/// Represent a section in a section-based object format.
/// 
/// **NOTE**: Later, this might be generalized in a common 
/// structure for all runtimes. 
#[derive(Debug)]
pub struct Section {
    /// Offset of the code in the file.
    pos: usize,
    /// First virtual address of the section.
    begin_addr: u64,
    /// Last virtual address of the section (exclusive).
    end_addr: u64,
}


/// A wrapper for the x86 [`Decoder`] that provides a way to restrict
/// the decoding to a given range.
pub struct RangeDecoder<'data> {
    /// The original decoder.
    decoder: Decoder<'data>,
    /// The current end IP for the decoder.
    end_ip: u64,
    /// Cached instruction used void copying instruction when decoding.
    inst: Instruction,
}

impl<'data> RangeDecoder<'data> {

    pub fn new(data: &'data [u8], bitness: u32) -> Self {
        Self {
            decoder: Decoder::new(bitness, data, DecoderOptions::NO_PAUSE),
            end_ip: u64::MAX,
            inst: Instruction::new(),
        }
    }

    /// Set the decoder to start to a new data position and IP 
    /// and ends at a end IP.
    pub fn goto_range(&mut self, pos: usize, begin_ip: u64, end_ip: u64) {
        self.decoder.set_position(pos).unwrap();
        self.decoder.set_ip(begin_ip);
        self.end_ip = end_ip;
    }

    /// Decode the next instruction.
    pub fn decode(&mut self) -> Option<&Instruction> {
        if self.decoder.can_decode() && self.decoder.ip() < self.end_ip {
            self.decoder.decode_out(&mut self.inst);
            Some(&self.inst)
        } else {
            None
        }
    }

}
