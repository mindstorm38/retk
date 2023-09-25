//! Arch x86 runtime and analysis.

use iced_x86::{Decoder, DecoderOptions, Instruction};

mod early;
mod idr;


/// The x86 backend for analyzer.
pub struct Backend<'data> {
    /// The underlying bytes of data.
    pub data: &'data [u8],
    /// Pointer width of the instruction's decoder (16, 32, 64).
    pub pointer_size: u32,
    /// The x86 instruction decoder.
    pub decoder: RangeDecoder<'data>,
    /// Sections and their metadata.
    pub sections: Sections,
}

impl<'data> Backend<'data> {

    pub fn new(data: &'data [u8], pointer_size: u32) -> Self {
        Self {
            data,
            pointer_size,
            decoder: RangeDecoder::new(data, pointer_size),
            sections: Sections::default(),
        }
    }

    pub fn analyse(&mut self) {

        println!("== Analyzing early functions...");
        let early_functions = early::analyze_early_functions(&mut *self);
        println!(" = Basic blocks count: {}", early_functions.basic_blocks_count());
        println!(" = Functions count: {}", early_functions.functions_count());

        println!("== Analyzing intermediate decompilation representation...");
        idr::analyze_idr(&mut *self, &early_functions);
        println!(" = Done.");

        // println!();
        
        // for function in early_functions.iter_functions().take(10) {

        //     let section = self.sections.get_code_section_at(function.begin()).unwrap();
        //     let offset = function.begin() - section.begin_addr;
        //     self.decoder.goto_range_at(section.pos + offset as usize, function.begin(), function.end());

        //     while let Some(inst) = self.decoder.decode() {
        //         if function.contains_block(inst.ip()) {
        //             println!("================");
        //         }
        //         println!("[{:08X}] {inst}", inst.ip());
        //     }

        //     println!();

        // }

    }

    // pub fn goto(&mut self, begin_ip: u64, end_ip: u64) {

    //     let section = self.sections.get_code_section_at(begin_ip)
    //         .expect("the given ip is not in a code section");

    //     let offset = begin_ip - section.begin_addr;
    //     self.decoder.goto_range_at(section.pos + offset as usize, begin_ip, end_ip);

    // }

}


/// Listing important sections for runtime.
#[derive(Debug, Default)]
pub struct Sections {
    /// Code sections.
    code: Vec<Section>,
}

impl Sections {

    #[inline]
    pub fn add_code_section(&mut self, pos: usize, begin_addr: u64, end_addr: u64) {
        self.code.push(Section { pos, begin_addr, end_addr });
    }

    /// Returns the maximum code address, 0 if no code sections is set.
    pub fn max_code_addr(&self) -> u64 {
        self.code.iter().map(|s| s.end_addr).max().unwrap_or(0)
    }

    /// Returns the section that contains the given address, if existing.
    pub fn get_code_section_at(&self, addr: u64) -> Option<&Section> {
        self.code.iter()
            .filter(|s| addr >= s.begin_addr && addr < s.end_addr)
            .next()
    }

    /// Returns true if the given address is in code range.
    pub fn in_code_range(&self, addr: u64) -> bool {
        self.get_code_section_at(addr).is_some()
    }

}


/// Represent a section in a section-based object format.
/// 
/// **NOTE**: Later, this might be generalized in a common 
/// structure for all runtimes. 
#[derive(Debug, Clone)]
pub struct Section {
    /// Offset of the code in the file.
    pub pos: usize,
    /// First virtual address of the section.
    pub begin_addr: u64,
    /// Last virtual address of the section (exclusive).
    pub end_addr: u64,
}


/// A wrapper for the x86 [`Decoder`] that provides a way to restrict the decoding to a 
/// given range and easily set read position and instruction pointer.
pub struct RangeDecoder<'data> {
    /// The original decoder.
    decoder: Decoder<'data>,
    /// The current end IP for the decoder.
    end_ip: u64,
    /// Cached instruction used void copying instruction when decoding.
    inst: Instruction,
}

impl<'data> RangeDecoder<'data> {

    pub fn new(data: &'data [u8], pointer_size: u32) -> Self {
        Self {
            decoder: Decoder::new(pointer_size, data, DecoderOptions::NO_PAUSE),
            end_ip: u64::MAX,
            inst: Instruction::new(),
        }
    }

    /// Set the decoder to start to a new data position and IP 
    /// and ends at a end IP.
    pub fn goto_range_at(&mut self, pos: usize, begin_ip: u64, end_ip: u64) {
        self.decoder.set_position(pos).unwrap();
        self.goto_range(begin_ip, end_ip);
    }

    pub fn goto_range(&mut self, begin_ip: u64, end_ip: u64) {
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
