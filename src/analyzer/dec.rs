//! Decompilation of functions.

use std::collections::VecDeque;

use iced_x86::{Register, Instruction, Code};

use super::{AnalyzerPass, Analyzer};


#[derive(Default)]
pub struct FunctionDecompilerPass { }

impl AnalyzerPass for FunctionDecompilerPass {

    fn analyze(&mut self, analyzer: &mut Analyzer) {

        let function = &analyzer.database.functions[&0x1418AD320];

        let sim_stack = SimStack::default();
        let sim_registers = SimRegisters::default();

        let mut inst = Instruction::new();
        let rt = &mut analyzer.runtime;
        rt.goto_ip(function.begin_ip);
        while rt.decoder.can_decode() && rt.decoder.ip() < function.end_ip {

            rt.decoder.decode_out(&mut inst);

            match inst.code() {
                Code::Push_r16 => {
                    


                }
                _ => {}
            }

        }

    }

}


/// Represent a single byte of data present in the stack or a register.$
#[derive(Debug, Default, Clone, Copy)]
struct SimPlace {
    /// Index of the variable in the place.
    variable: u32,
    /// Offset of the byte stored in this place.
    offset: u16,
}

#[derive(Debug, Default)]
struct SimRegisters {
    /// RAX/RCX/RDX/RBX/RSI/RDI/R8-R15
    gp: [SimRegister<8>; 16],
    /// ZMM0-ZMM31
    zmm: [SimRegister<64>; 32],
}

#[derive(Debug)]
struct SimRegister<const LEN: usize>([SimPlace; LEN]);

impl<const LEN: usize> Default for SimRegister<LEN> {
    fn default() -> Self {
        Self([SimPlace { variable: 0, offset: 0 }; LEN])
    }
}

/// Simulation of the stack, used to track which place is used
/// for which variable.
#[derive(Debug, Default)]
struct SimStack {
    rsp: i32,
    stack: VecDeque<SimPlace>,
}

impl SimRegisters {

    fn place(&mut self, reg: Register) {

        let (idx, off, len) = match reg {
            // RAX
            Register::AL    => (0, 0, 1),
            Register::AH    => (0, 1, 1),
            Register::AX    => (0, 0, 2),
            Register::EAX   => (0, 0, 4),
            Register::RAX   => (0, 0, 8),
            // RCX
            Register::CL    => (1, 0, 1),
            Register::CH    => (1, 1, 1),
            Register::CX    => (1, 0, 2),
            Register::ECX   => (1, 0, 4),
            Register::RCX   => (1, 0, 8),
            // RDX
            Register::DL    => (2, 0, 1),
            Register::DH    => (2, 1, 1),
            Register::DX    => (2, 0, 2),
            Register::EDX   => (2, 0, 4),
            Register::RDX   => (2, 0, 8),
            // RBX
            Register::BL    => (3, 0, 1),
            Register::BH    => (3, 1, 1),
            Register::BX    => (3, 0, 2),
            Register::EBX   => (3, 0, 4),
            Register::RBX   => (3, 0, 8),
            // RSI
            Register::SIL   => (4, 0, 1),
            Register::SI    => (4, 0, 2),
            Register::ESI   => (4, 0, 4),
            Register::RSI   => (4, 0, 8),
            // RDI
            Register::DIL   => (5, 0, 1),
            Register::DI    => (5, 0, 2),
            Register::EDI   => (5, 0, 4),
            Register::RDI   => (5, 0, 8),
            // R8
            Register::R8L   => (6, 0, 1),
            Register::R8W   => (6, 0, 2),
            Register::R8D   => (6, 0, 4),
            Register::R8    => (6, 0, 8),
            _ => return
        };

    }

}

impl SimStack {



}


struct Assignment {
    /// Variable index.
    variable: u32,
    value: Expression,
}

enum Expression {
    /// When an expression is directory loaded from an external external
    /// that has not been 
    ExternalRegister(Register),
    ExternalStack(i32),
    Var(u32),
    Imm(i64),
    AddReg(u32, u32),
    AddImm(u32, i64),
    SubReg(u32, u32),
    SubImm(u32, i64),
}
