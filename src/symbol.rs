//! A module providing high-level symbols that helps understanding
//! the code. They are produce by analyzer passes.

use std::collections::HashSet;
use std::fmt;


// /// Enumeration of all type
// #[derive(Debug, Clone)]
// pub enum Symbol<'data> {
//     /// An raw block of code, that can be called or jumped
//     /// to. Certain blocks might be upgraded into functions, but
//     /// most of them will remains basic labels jumped to in 
//     /// functions.
//     /// 
//     /// *This type of block should not be called a basic block,
//     /// because it might contains unresolved relative jumps.*
//     /// 
//     /// *This type is temporary during analysis.*
//     Block(BasicBlock),
//     /// Basically a label that is called, instead of jumped to.
//     /// This symbol is derived from labels by certain passes
//     /// and contains, in addition to labels fields, a calling
//     /// convention and a signature.
//     Function(Function<'data>),
// }

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
    pub end_ip: u64,
    /// All unique locations (xrefs) that can goto this block.
    pub entries_from: HashSet<u64>,
    /// Number of goto to this block.
    pub entries_count: usize,
    /// From the total number of entries, how many are calls.
    /// This is used to know if a block is a function.
    pub entries_calls_count: usize,
    /// The kind of exit for this basic block.
    pub exit: BasicBlockExit,
}

/// Type of exit statement for a basic block.
#[derive(Clone)]
pub enum BasicBlockExit {
    /// Unconditionnaly jumps to the absolute address.
    Unconditionnal { goto_ip: u64 },
    /// Conditionnal jump to the absolute address.
    Conditionnal { then_ip: u64, else_ip: u64 },
    /// For relative addressed jumps.
    Unknown,
}

impl BasicBlock {

    pub fn new(begin_ip: u64) -> Self {
        Self { 
            begin_ip,
            end_ip: begin_ip,
            entries_from: Default::default(), 
            entries_count: Default::default(), 
            entries_calls_count: Default::default(), 
            exit: BasicBlockExit::Unknown,
        }
    }

}

impl fmt::Debug for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicBlock")
            .field("begin_ip", &format_args!("0x{:08X}", self.begin_ip))
            .field("end_ip", &format_args!("0x{:08X}", self.end_ip))
            // .field("entries_from", &self.entries_from)
            // .field("entries_count", &self.entries_count)
            // .field("entries_calls_count", &self.entries_calls_count)
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
            Self::Conditionnal { then_ip, else_ip } => f.debug_struct("Conditionnal")
                .field("then_ip", &format_args!("0x{:08X}", then_ip))
                .field("else_ip", &format_args!("0x{:08X}", else_ip))
                .finish(),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// /// Conditional for a basic block exit statement.
// #[derive(Debug, Clone)]
// pub enum BasicBlockExitCondition {
//     UnsignedGreater,
//     UnsignedGreaterOrEqual,
//     UnsignedLower,
//     UnsignedLowerOrEqual,
//     /// Jump if carry flag = 1
//     Carry,
//     /// Jump if CX = 0
//     CxZero,
//     /// Jump if ECX = 0
//     EcxZero,
//     /// Jump if RCX = 0
//     RcxZero,

// }

/// Function symbol details, signature and return types.
#[derive(Debug, Clone)]
pub struct Function<'data> {
    /// Slice of the function's data.
    pub data: &'data [u8],
    /// Custom name for the function.
    pub name: String,
    /// Calling convention.
    pub cc: CallingConvention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Unknown calling convention.
    Unknown,
    /// Unix C x86
    Cdecl,
    /// WINAPI
    Stdcall,
    /// Default on Windows x86
    Fastcall,
    /// # The x64 calling convention
    /// 
    /// ## Links
    /// - https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
    /// - https://learn.microsoft.com/en-us/cpp/build/stack-usage
    /// - https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog
    /// - https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
    /// 
    /// ## Stack overview
    /// Here is an overview of the stack of such calling convention.
    /// 
    /// ```txt
    ///  ╒═ func A ═══════════════╕
    ///  │ Local variables and    │
    ///  │ saved non-volatile     │
    ///  │ registers.             │
    ///  ├────────────────────────┤
    ///  │ Space for alloca,      │
    ///  │ if relevant.           │
    ///  ├───────┬────────────────┤
    ///  │ Stack │ Nth            │ (1)(2) 
    ///  │ args  ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    ///  │       │ 5th            │
    ///  ├───────┼────────────────┤
    ///  │ Reg   │ R9 home (4th)  │ (3)
    ///  │ args  ├────────────────┤
    ///  │ homes │ R8 home (3rd)  │ 
    ///  │       ├────────────────┤
    ///  │       │ RDX home (2nd) │
    ///  │       ├────────────────┤       
    ///  │       │ RCX home (1st) │
    ///  ├───────┴────────────────┤ ← 16-bytes align 
    ///  │ Caller return addr     │ ← call B
    ///  ╞═ func B ═══════════════╡ 
    ///  │                        │
    ///  │ ... same as above      │
    ///  │                        │
    ///  └────────────────────────┘
    /// 
    /// (1) Each slot is 8-bytes wide and aligned,
    ///     if an argument is smaller than 8 bytes,
    ///     it is right-aligned and if greater,
    ///     a pointer to it is used.
    /// (2) The number N of slots is the maximum
    ///     number of arguments needed for a call
    ///     in the function body.
    /// (3) Even if less than 4 arguments are needed,
    ///     the 4 "home" slots are guaranteed to be 
    ///     present. They are allocated in the caller 
    ///     but owned/used by the callee.
    /// ```
    /// 
    Win64,
    /// For leaf function calling convention, no 
    /// argument or framing.
    Leaf,
}
