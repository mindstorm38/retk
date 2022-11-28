//! # Windows x64 ABI and calling convention.
//! 
//! ## Links
//! - https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
//! - https://learn.microsoft.com/en-us/cpp/build/stack-usage
//! - https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog
//! - https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
//! 
//! ## Register volatility
//! Volatile registers: `RAX`, `RCX`, `RDX`, `R8-R11`, `XMM0-XMM5`.
//! 
//! Non-volatile registers: `RBX`, `RBP`, `RDI`, `RSI`, `RSP`, `R12-R15`, `XMM6-XMM15`.
//! 
//! Volatile registers should be considered destroyed when calling a function, and
//! must be saved by the caller if needed. Non-volatile registers should not and 
//! therefore should be saved/restored by callee.
//! 
//! ## Stack overview
//! Here is an overview of the stack of such calling convention.
//! 
//! ```txt
//!  ╒═ func A ═══════════════╕
//!  │ Local variables and    │
//!  │ saved non-volatile     │
//!  │ registers.             │
//!  ├────────────────────────┤
//!  │ Space for alloca,      │
//!  │ if relevant.           │
//!  ├───────┬────────────────┤
//!  │ Stack │ Nth            │ (1)(2) 
//!  │ args  ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
//!  │       │ 5th            │
//!  ├───────┼────────────────┤
//!  │ Reg   │ R9 home (4th)  │ (3)
//!  │ args  ├────────────────┤
//!  │ homes │ R8 home (3rd)  │ 
//!  │       ├────────────────┤
//!  │       │ RDX home (2nd) │
//!  │       ├────────────────┤       
//!  │       │ RCX home (1st) │
//!  ├───────┴────────────────┤ ← 16-bytes align 
//!  │ Caller return addr     │ ← call B
//!  ╞═ func B ═══════════════╡ 
//!  │                        │
//!  │ ... same as above      │
//!  │                        │
//!  └────────────────────────┘
//! 
//! (1) Each slot is 8-bytes wide and aligned,
//!     if an argument is smaller than 8 bytes,
//!     it is right-aligned and if greater,
//!     a pointer to it is used.
//! (2) The number N of slots is the maximum
//!     number of arguments needed for a call
//!     in the function body.
//! (3) Even if less than 4 arguments are needed,
//!     the 4 "home" slots are guaranteed to be 
//!     present. They are allocated in the caller 
//!     but owned/used by the callee.
//! ```

use iced_x86::{Instruction, Register, Code};


/// An internal state machine structure used to parse a function's 
/// signature and storage for parameters.
#[derive(Debug)]
pub struct Analyzer {
    state: AnalyzerState,
}

#[derive(Debug, Clone, Copy)]
enum AnalyzerState {
    /// Initial state.
    Initial,
    /// Can't analyze the function, its calling convention is not 
    /// windows x64.
    Invalid,
}

impl Analyzer {

    pub fn new() -> Self {
        Self {
            state: AnalyzerState::Initial,
        }
    }

    pub fn reset(&mut self) {
        self.state = AnalyzerState::Initial;
    }

    pub fn step(&mut self, analyzer: &mut Analyzer, inst: &Instruction) {

        if let AnalyzerState::Invalid = self.state {
            return;
        }

        loop {

            if let AnalyzerState::Initial = self.state {

                let code = inst.code();
                let base = inst.memory_base();
                let displ = inst.memory_displacement64();
                let reg1 = inst.op1_register();
    
                // Looking for mov [rsp+8+N], reg
                if base == Register::RSP || displ >= 8 {

                    match code {
                        Code::Mov_rm64_r64 => {

                            match reg1 {
                                Register::RCX => {
                                    // 1th arg

                                }
                                _ => {}
                            }

                        }
                        _ => {}
                    }

                }
    
            }

        }
        
    }

}
