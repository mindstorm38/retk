//! Module for initial functions analysis.

use iced_x86::{Instruction, Code, Register};

use super::{Analyzer, AnalyzerStepPass};
use crate::symbol::{CallingConvention, Function};


/// The goal of this pass is to define the maximum number of
/// functions while finding their ABI. This function also
/// define the function signature.
#[derive(Debug)]
pub struct DefineFunctionPass {
    state: DefineFunctionState,
    stack_addr: u64,
    func_addr: u64,
    func_cc: CallingConvention,
}

#[derive(Debug, Clone, Copy)]
pub enum DefineFunctionState {
    /// Initial state of the function definition.
    Initial,
    /// Error state when a pattern is not valid.
    Invalid,
    /// Values are moved to "home" stack location.
    /// At `RSP+N*8` where `N` starts at 1 and can
    /// go up to the arguments count.
    /// *This is used to detect the x64 ABI.*
    PrologHomeSave,
    /// Pushing (x64) non-volatile registers to stack.
    PrologRegSave,
    /// In the function body.
    Body,
}

impl Default for DefineFunctionPass {
    fn default() -> Self {
        Self { 
            state: DefineFunctionState::Initial,
            stack_addr: 0,
            func_addr: 0,
            func_cc: CallingConvention::Unknown,
        }
    }
}

impl AnalyzerStepPass for DefineFunctionPass {

    fn accept(&mut self, analyzer: &mut Analyzer, inst: &Instruction) {
        
        use DefineFunctionState::*;
        use Code::*;
        use Register::*;

        let code = inst.code();
        let state = self.state;
        let mem_base = inst.memory_base();
        let mem_off = inst.memory_displacement64();
        let mem_off_scale = inst.memory_index_scale();

        // println!("== Start state: {state:?}");
        // println!(" = Inst: {inst:?}");
        // println!(" = Stack: {}", self.stack_addr);
        // println!();

        match code {
            Mov_rm64_r64 => {

                if let Initial | PrologHomeSave = state {

                    // Pattern: mov [rsp+N], r64
                    if let (RSP, 1) = (mem_base, mem_off_scale) {
                        // Check: N>=8 && 8-bytes aligned
                        if mem_off >= 8 && mem_off % 8 == 0 {
                            if let Initial = state {
                                // Stack address start with an offset of 8 because
                                // of the caller return address.
                                self.stack_addr = 8;
                                self.func_addr = inst.ip();
                                self.func_cc = CallingConvention::Win64;
                            }
                            self.state = PrologHomeSave;
                            return;
                        }
                    }

                    self.state = Invalid;

                }

            }
            Push_r64 => {

                if let Initial | PrologHomeSave | PrologRegSave = state {

                    // Pattern: push rdi/rsi/rbx
                    if let RDI | RSI | RBX = inst.op0_register() {
                        if let Initial = state {
                            self.stack_addr = 8;
                            self.func_addr = inst.ip();
                            self.func_cc = CallingConvention::Win64;
                        }
                        self.state = PrologRegSave;
                        self.stack_addr += 8;
                    } else {
                        self.state = Invalid;
                    }

                }

            }
            Sub_rm64_imm8 | Sub_rm64_imm32 => {

                if let Initial | PrologHomeSave | PrologRegSave = state {
                    if let Initial = state {
                        self.stack_addr = 8;
                        self.func_addr = inst.ip();
                        self.func_cc = CallingConvention::Win64;
                    }
                    self.state = Body;
                    self.stack_addr = (self.stack_addr as i64 + inst.immediate32to64()) as u64;
                }

            }
            Int3 => {} // No effect
            Retnq => {

                // Return statements triggers funtion definition.

                if let Initial = state {
                    // The function only consist of a ret.
                    self.func_addr = inst.ip();
                    self.func_cc = CallingConvention::Leaf;
                } else if let Body = state {
                    // Nothing to do
                } else {
                    // Getting a ret from any other state cause an unknown calling convention.
                }

                // Total function length, in bytes.
                let func_len = inst.ip() - self.func_addr + inst.len() as u64;
                let func_data = analyzer.runtime.data_ip_range(self.func_addr, func_len);

                // analyzer.database.set_symbol(self.func_addr, Symbol::Function(Function { 
                //     data: func_data, 
                //     name: String::new(), 
                //     cc: self.func_cc,
                // }));

                self.state = Initial;

            }
            _ => {
                
                if let Initial = state {
                    // The function directly starts with a non-framing instruction.
                    self.func_addr = inst.ip();
                    self.func_cc = CallingConvention::Leaf;
                }

            }
        }

    }

}
