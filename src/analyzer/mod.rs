//! This module provides functions to analyze instructions
//! and automatically detect various symbols.

use std::collections::HashMap;
use std::fmt::Write;

use iced_x86::{
    Instruction, Decoder, DecoderOptions, 
    Formatter, IntelFormatter, FormatterOutput, FormatterTextKind,
};

use colored::{Color, Colorize};

use crate::symbol::{BasicBlock, Function};

pub mod abi;

mod block;
pub use block::BasicBlockPass;

mod func;
pub use func::{FunctionFindPass, FunctionAbiPass};


/// A trait usable to run a pass on an [`Analyzer`].
pub trait AnalyzerPass {

    /// Do a pass on the given analyzer.
    fn analyze(&mut self, analyzer: &mut Analyzer);

}

/// A utility to analyze instructions and auto detect various symbols.
/// This structure doesn't do anything alone, but needs custom [`CodePass`].
pub struct Analyzer<'data> {
    /// Runtime's data of the analyzer.
    pub runtime: AnalyzerRuntime<'data>,
    /// Database of the analyzer, filled during analysis.
    pub database: AnalyzerDatabase,
}

pub struct AnalyzerRuntime<'data> {
    /// The first instruction pointer for the first byte of data.
    first_ip: u64,
    /// The data decoder.
    pub decoder: Decoder<'data>,
}

#[derive(Default)]
pub struct AnalyzerDatabase {
    pub basic_blocks: HashMap<u64, BasicBlock>,
    pub functions: HashMap<u64, Function>,
}

impl<'data> Analyzer<'data> {

    pub fn new(data: &'data [u8], first_ip: u64) -> Self {
        Self {
            runtime: AnalyzerRuntime {
                first_ip,
                decoder: Decoder::with_ip(64, data, first_ip, DecoderOptions::NONE),
            },
            database: AnalyzerDatabase::default()
        }
    }

    /// Analyze with the given pass on the given decoder.
    #[inline]
    pub fn analyze<P>(&mut self, mut pass: P)
    where
        P: AnalyzerPass
    {
        pass.analyze(self);
    }

    /// A debug method to print a range.
    pub fn print(&mut self, from_ip: u64, to_ip: u64, debug: bool) {

        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_first_operand_char_index(10);
        formatter.options_mut().set_space_after_operand_separator(true);

        let mut line = TermFormatter::new();
        let mut inst = Instruction::default();

        let rt = &mut self.runtime;
        rt.goto_ip(from_ip);
        
        while rt.decoder.can_decode() && rt.decoder.ip() < to_ip {

            rt.decoder.decode_out(&mut inst);

            line.init();
            formatter.format(&inst, &mut line);
            println!("{:016X} {}", inst.ip(), line.buffer);

            if debug {
                println!("  {:?}, base={:?}, off={}, off_scale={:?}, registers=[{:?}, {:?}, {:?}, {:?}]", 
                    inst.code(), 
                    inst.memory_base(), 
                    inst.memory_displacement64() as i64, 
                    inst.memory_index_scale(), 
                    inst.op0_register(),
                    inst.op1_register(),
                    inst.op2_register(),
                    inst.op3_register(),
                );
            }

        }

    }

}

impl<'data> AnalyzerRuntime<'data> {

    #[inline]
    pub fn first_ip(&self) -> u64 {
        self.first_ip
    }

    #[inline]
    pub fn last_ip(&self) -> u64 {
        self.first_ip + self.decoder.max_position() as u64
    }

    /// Reset the decoder to a given instruction pointer.
    #[track_caller]
    pub fn goto_ip(&mut self, ip: u64) {
        debug_assert!(ip >= self.first_ip(), "min ip reached: {ip}");
        debug_assert!(ip < self.last_ip(), "max ip reached: {ip}");
        self.decoder.set_position((ip - self.first_ip) as usize).unwrap();
        self.decoder.set_ip(ip);
    }

}


/// An advanced [`AnalyzerPass`] that will get instructions step by step.
/// You can also define a function to run before and after analysis.
pub trait AnalyzerStepPass {

    /// Feed the pass with an instruction.
    fn feed(&mut self, analyzer: &mut Analyzer, inst: &Instruction);

    /// Called before analysis.
    #[allow(unused)]
    fn before(&mut self, analyzer: &mut Analyzer) { }

    /// Called after analysis.
    #[allow(unused)]
    fn after(&mut self, analyzer: &mut Analyzer) { }

}

impl<P: AnalyzerStepPass> AnalyzerPass for P {

    fn analyze(&mut self, analyzer: &mut Analyzer) {
        
        self.before(&mut *analyzer);

        let mut inst = Instruction::default();
        analyzer.runtime.goto_ip(analyzer.runtime.first_ip);

        while analyzer.runtime.decoder.can_decode() {
            analyzer.runtime.decoder.decode_out(&mut inst);
            self.feed(&mut *analyzer, &inst);
        }

        self.after(&mut *analyzer);

    }

}


struct TermFormatter {
    buffer: String
}

impl TermFormatter {

    fn new() -> Self {
        Self { buffer: String::new() }
    }

    fn init(&mut self) {
        self.buffer.clear();
    }

}

impl FormatterOutput for TermFormatter {

    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        
        #[inline(always)]
        fn color_from_kind(kind: FormatterTextKind) -> Option<Color> {
            Some(match kind {
                FormatterTextKind::Text => Color::Yellow,
                FormatterTextKind::Number => Color::Yellow,
                FormatterTextKind::Mnemonic => Color::Blue,
                FormatterTextKind::LabelAddress => Color::Green,
                FormatterTextKind::FunctionAddress => Color::Green,
                FormatterTextKind::Label => Color::Green,
                FormatterTextKind::Function => Color::Green,
                FormatterTextKind::Keyword => Color::BrightBlack,
                _ => return None
            })
        }

        if let Some(color) = color_from_kind(kind) {
            write!(self.buffer, "{}", text.color(color)).unwrap();
        } else {
            self.buffer.push_str(text);
        }

    }

}