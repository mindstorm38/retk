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

mod block;
pub use block::BasicBlockPass;


/// A trait usable to run a pass on an [`Analyzer`].
pub trait AnalyzerPass {

    /// Do a pass on the given analyzer.
    fn analyze(&mut self, analyzer: &mut Analyzer);

}

/// A utility to analyze instructions and auto detect various symbols.
/// This structure doesn't do anything alone, but it needs custom 
/// [`CodePass`]
pub struct Analyzer<'data> {
    pub runtime: AnalyzerRuntime<'data>,
    pub database: AnalyzerDatabase<'data>,
}

pub struct AnalyzerRuntime<'data> {
    data: &'data [u8],
    ip: u64,
    decoder: Decoder<'data>,
}

#[derive(Debug, Default)]
pub struct AnalyzerDatabase<'data> {
    pub basic_blocks: HashMap<u64, BasicBlock>,
    pub functions: HashMap<u64, Function<'data>>,
}

impl<'data> Analyzer<'data> {

    pub fn new(data: &'data [u8], ip: u64) -> Self {
        Self {
            runtime: AnalyzerRuntime {
                data,
                ip,
                decoder: Decoder::with_ip(64, data, ip, DecoderOptions::NONE),
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
    pub fn print(&mut self, from: u64, to: u64) {

        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_first_operand_char_index(10);
        formatter.options_mut().set_space_after_operand_separator(true);

        let mut line = TermFormatter::new();
        let mut inst = Instruction::default();

        let rt = &mut self.runtime;
        rt.reset(from);
        
        while rt.decoder.can_decode() && (rt.decoder.position() as u64) < to {

            rt.decoder.decode_out(&mut inst);

            line.init();
            formatter.format(&inst, &mut line);
            println!("{:016X} {}", inst.ip(), line.buffer);
            println!("  {:?}, base={:?}, off={}, off-scale={:?}", inst.code(), inst.memory_base(), inst.memory_displacement64(), inst.memory_index_scale());

        }

    }

}

impl<'data> AnalyzerRuntime<'data> {

    /// Reset the decoder to an absolute data position.
    pub fn reset(&mut self, pos: u64) {
        self.decoder.set_position(pos as usize).unwrap();
        self.decoder.set_ip(pos + self.ip);
    }

    #[inline]
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    #[inline]
    pub fn data_ip_range(&self, ip: u64, len: u64) -> &'data [u8] {
        let offset = (ip - self.ip) as usize;
        &self.data[offset..][..len as usize]
    }

}


/// An advanced [`AnalyzerPass`] that will get instructions step by step.
/// You can also define a function to run before and after analysis.
pub trait AnalyzerStepPass {

    /// Analyze an instruction and update the internal pass' state machine.
    fn accept(&mut self, analyzer: &mut Analyzer, inst: &Instruction);

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
        analyzer.runtime.reset(0);

        while analyzer.runtime.decoder.can_decode() {
            analyzer.runtime.decoder.decode_out(&mut inst);
            self.accept(&mut *analyzer, &inst);
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