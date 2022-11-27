//! Basic blocks related utilities.

use std::fmt;


mod graph;
pub use graph::ContiguousGraphResolver;

mod list;
pub use list::ListResolver;


/// A "basic block" of code. In the analyzer code, a basic block is 
/// a block of code that has a single entry point and a single output 
/// that can be one of: unconditionnal jump, conditionnal jump or 
/// return.
/// 
/// ***Procedure calls are not considered as basic block outputs,
/// because these are expected to return in the basic block. Some
/// function might never return, but this can't be known statically.***
/// 
/// *Note that this is statically analyzed, so relative addressed 
/// jumps' destination can't be known.*
#[derive(Clone)]
pub struct BasicBlock {
    /// Beging instruction pointer for the basic block.
    pub begin_ip: u64,
    /// End instruction pointer (exclusive) for the basic block.
    /// 
    /// *This should be the pointer of another block contiguous to it.*
    pub end_ip: u64,
    /// IP of bblocks that are known to lead to this bblock.
    pub entries_from: Vec<u64>,
    /// Number of goto to this block.
    pub entries_count: u32,
    /// True if this basic block is called, i.e. is a function.
    pub function: bool,
    /// The kind of exit for this basic block.
    pub exit: BasicBlockExit,
}

/// Type of exit statement for a basic block.
#[derive(Clone)]
pub enum BasicBlockExit {
    /// Unconditionnaly jumps to the absolute address.
    Unconditionnal { 
        /// Instruction pointer of the next basic block.
        goto_ip: u64 
    },
    /// Conditionnal jump to the absolute address.
    Conditionnal { 
        /// The instruction pointer of the basic block to goto if 
        /// the condition is true.
        goto_ip: u64,
        /// The instruction pointer of the next contiguous basic block
        /// to goto if the condition is false.
        /// 
        /// *Note that **the next block should be directly following the 
        /// current block**, because conditionnal jump instructions only
        /// provides a single "goto address", if the condition is not met,
        /// the flow continue after the instruction.*
        continue_ip: u64,
    },
    /// For relative addressed jumps.
    Unknown,
}

impl fmt::Debug for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicBlock")
            .field("begin_ip", &format_args!("0x{:08X}", self.begin_ip))
            .field("end_ip", &format_args!("0x{:08X}", self.end_ip))
            // .field("entries_from", &self.entries_from)
            // .field("entries_count", &self.entries_count)
            // .field("calls_count", &self.calls_count)
            .field("exit", &self.exit)
            .finish()
    }
}

impl fmt::Debug for BasicBlockExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unconditionnal { goto_ip } => f.debug_struct("Unconditionnal")
                .field("goto_ip", &format_args!("0x{:08X}", goto_ip))
                .finish(),
            Self::Conditionnal { goto_ip: then_ip, continue_ip: else_ip } => f.debug_struct("Conditionnal")
                .field("then_ip", &format_args!("0x{:08X}", then_ip))
                .field("else_ip", &format_args!("0x{:08X}", else_ip))
                .finish(),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
