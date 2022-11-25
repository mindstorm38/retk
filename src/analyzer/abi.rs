//! ABI-specific analyzers.

use std::collections::HashMap;

use iced_x86::{Register, Instruction, Code, OpKind};

use super::{AnalyzerPass, Analyzer, AnalyzerRuntime};
use crate::symbol::Function;

pub mod x64;


#[derive(Default)]
pub struct FunctionAbiPass { }

impl AnalyzerPass for FunctionAbiPass {

    fn analyze(&mut self, analyzer: &mut Analyzer) {

        let mut frame_analyzer = FrameAnalyzer::new();

        for func in analyzer.database.functions.values() {
            
            frame_analyzer.clear();
            frame_analyzer.analyze_function(&mut analyzer.runtime, func);

            // if frame_analyzer.register.usage.contains_key(&Register::XMM0) {
            //     println!("Function with XMM0: {:08X}", func.begin_ip);
            // }

            if func.begin_ip == 0x1418AD320 {
                println!("Frame analysis:");
                println!("{:#?}", frame_analyzer.register);
                println!("{:#?}", frame_analyzer.stack);
            }

        }

    }

}


/// A primitive analyzer for stack and register that can help
/// defining the framing and calling convention of a function.
#[derive(Debug)]
pub struct FrameAnalyzer {
    /// Internal register analyzer.
    register: RegisterAnalyzer,
    /// Internal stack analyzer.
    stack: StackAnalyzer,
    /// Internal cache for decoding function.
    inst: Instruction,
}

#[derive(Debug)]
struct RegisterAnalyzer {
    /// Association of each used register and how it is used. 
    usage: HashMap<Register, RegisterUsage>,
}

#[derive(Debug)]
struct StackAnalyzer {
    /// Current stack pointer of the simulation.
    rsp: i32,
    /// Minimum stack pointer reached during simulation.
    min_rsp: i32,
}

impl FrameAnalyzer {

    pub fn new() -> Self {
        Self {
            register: RegisterAnalyzer {
                usage: HashMap::new(),
            },
            stack: StackAnalyzer {
                rsp: 0,
                min_rsp: 0,
            },
            inst: Instruction::new(),
        }
    }

    pub fn clear(&mut self) {
        self.register.usage.clear();
        self.stack.rsp = 0;
        self.stack.min_rsp = 0;
    }

    /// Analyze the given function using the given runtime.
    pub fn analyze_function(&mut self, rt: &mut AnalyzerRuntime, func: &Function) {

        let inst = &mut self.inst;
        let begin_ip = func.begin_ip;
        let end_ip = func.end_ip;

        rt.goto_ip(begin_ip);
        while rt.decoder.can_decode() && rt.decoder.ip() < end_ip {

            rt.decoder.decode_out(inst);
            
            // TODO: Handle all common instructions that moves to/from register/stack.

            let mem_base = inst.memory_base();
            let mem_off = inst.memory_displacement32() as i32;

            match inst.code() {
                Code::Jmp_rel8_64 |
                Code::Jmp_rel32_64 => {
                    let jmp_ip = inst.near_branch64();
                    if jmp_ip >= begin_ip && jmp_ip < end_ip {
                        // This is a function-internal jump.
                        // FIXME: Do not jump if already done.
                        if jmp_ip > rt.decoder.ip() {
                            rt.goto_ip(jmp_ip); 
                        } else {
                            break;
                        }
                    } else {
                        // This is a tail-call to another function.
                        // But calls stop the analysis.
                        break;
                    }
                }
                code if code.is_jcc_short_or_near() => {
                    // In case of conditionnal jump, we simulate a normal 
                    // executation flow.
                }
                Code::Call_rel16 |
                Code::Call_rel32_64 |
                Code::Retnq |
                Code::Retnq_imm16 => {
                    // Calls stop the analysis.
                    break;
                }
                Code::Mov_rm64_r64 | 
                Code::Mov_rm32_r32 | 
                Code::Mov_rm16_r16 |
                Code::Movss_xmmm32_xmm |
                Code::Movsd_xmmm64_xmm |
                Code::Movups_xmmm128_xmm |
                Code::Movaps_xmmm128_xmm |
                Code::Movupd_xmmm128_xmm |
                Code::Movapd_xmmm128_xmm => {
                    
                    let reg_len = match inst.code() {
                        Code::Movss_xmmm32_xmm => 4,
                        Code::Movsd_xmmm64_xmm => 8,
                        _ => inst.op1_register().size() as u8
                    };

                    if mem_base == Register::RSP {
                        // Stack saving a register.
                        self.register.read_to_stack(inst.op1_register(), self.stack.rsp + mem_off, reg_len);
                    } else {
                        self.register.read_value(inst.op1_register(), reg_len);
                        if mem_base == Register::None {
                            self.register.overriden(inst.op0_register());
                        } else {
                            self.register.read_addr(mem_base);
                        }
                    }

                }
                Code::Mov_r64_imm64 |
                Code::Mov_r64_rm64 |
                Code::Mov_r32_imm32 |
                Code::Mov_r32_rm32 |
                Code::Mov_r16_imm16 |
                Code::Mov_r16_rm16 |
                Code::Movss_xmm_xmmm32 |
                Code::Movsd_xmm_xmmm64 |
                Code::Movups_xmm_xmmm128 |
                Code::Movaps_xmm_xmmm128 |
                Code::Movupd_xmm_xmmm128 |
                Code::Movapd_xmm_xmmm128 => {

                    let reg_len = match inst.code() {
                        Code::Movss_xmmm32_xmm => 4,
                        Code::Movsd_xmmm64_xmm => 8,
                        _ => inst.op1_register().size() as u8
                    };

                    if mem_base == Register::None {
                        self.register.read_value(inst.op1_register(), reg_len);
                    } else if mem_base != Register::RSP {
                        self.register.read_addr(mem_base);
                    }

                    self.register.overriden(inst.op0_register());

                }
                Code::Lea_r64_m |
                Code::Lea_r32_m |
                Code::Lea_r16_m => {
                    self.register.read_addr(mem_base);
                    self.register.overriden(inst.op0_register());
                }
                Code::Push_r16 | 
                Code::Push_r32 | 
                Code::Push_r64 => {
                    let reg = inst.op0_register();
                    let rsp = self.stack.sub_rsp(reg.size() as u32);
                    self.register.read_to_stack_full(inst.op0_register(), rsp);
                }
                Code::Pop_r16 |
                Code::Pop_r32 |
                Code::Pop_r64 => {
                    let reg = inst.op0_register();
                    self.stack.add_rsp(reg.size() as u32);
                    self.register.overriden(reg);
                }
                Code::Add_rm64_imm8 |
                Code::Add_rm64_imm32 => {
                    if mem_base == Register::None {
                        if inst.op0_register() == Register::RSP {
                            self.stack.add_rsp(inst.immediate32());
                        } else {
                            self.register.read_value_full(inst.op0_register());
                        }
                    } else {
                        self.register.read_addr(mem_base);
                    }
                }
                Code::Sub_rm64_imm8 | 
                Code::Sub_rm64_imm32 => {
                    if mem_base == Register::None {
                        if inst.op0_register() == Register::RSP {
                            self.stack.sub_rsp(inst.immediate32());
                        } else {
                            self.register.read_value_full(inst.op0_register());
                        }
                    } else {
                        self.register.read_addr(mem_base);
                    }
                }
                Code::Xor_r64_rm64 |
                Code::Xor_r32_rm32 |
                Code::Xor_r16_rm16 |
                Code::Xor_rm64_r64 |
                Code::Xor_rm32_r32 |
                Code::Xor_rm16_r16 |
                Code::Xorps_xmm_xmmm128 |
                Code::Xorpd_xmm_xmmm128 if inst.op0_register() == inst.op1_register() => {
                    // XOR is a special because if the same register is used for both
                    // registers, it clears the register.
                    self.register.overriden(inst.op0_register());
                }
                _ if inst.op_count() == 2 => {

                    // These common cases should work for many simple,
                    // two-operand instructions.
                    
                    // Note that here we expect the first operand to be
                    // read and agregated with the second one before being
                    // written.
                    
                    match (inst.op0_kind(), inst.op1_kind()) {
                        (OpKind::Register, OpKind::Register) => {
                            self.register.read_value_full(inst.op1_register());
                            self.register.read_value_full(inst.op0_register());
                        }
                        (OpKind::Register, OpKind::Memory) => {
                            self.register.read_addr(mem_base);
                            self.register.overriden(inst.op0_register());
                        }
                        (OpKind::Memory, OpKind::Register) => {
                            self.register.read_addr(mem_base);
                            self.register.read_value_full(inst.op1_register());

                        }
                        _ => {}
                    }

                }
                _ => {}
            }
            
        }

    }

}

impl RegisterAnalyzer {

    #[inline]
    fn used(&mut self, register: Register, usage: RegisterUsage) {
        self.usage.entry(register).or_insert(usage);
    }

    fn overriden(&mut self, register: Register) {
        self.used(register, RegisterUsage::Overriden);
    }

    fn read_addr(&mut self, register: Register) {
        self.used(register, RegisterUsage::ReadAddr);
    }

    fn read_value(&mut self, register: Register, len: u8) {
        self.used(register, RegisterUsage::ReadValue { len });
    }

    #[inline]
    fn read_value_full(&mut self, register: Register) {
        self.read_value(register, register.size() as u8);
    }

    fn read_to_stack(&mut self, register: Register, rsp: i32, len: u8) {
        self.used(register, RegisterUsage::ReadToStack { rsp, len });
    }

    #[inline]
    fn read_to_stack_full(&mut self, register: Register, rsp: i32) {
        self.read_to_stack(register, rsp, register.size() as u8);
    }

}

impl StackAnalyzer {

    fn sub_rsp(&mut self, amount: u32) -> i32 {
        self.rsp -= amount as i32;
        self.min_rsp = self.min_rsp.min(self.rsp);
        self.rsp
    }

    fn add_rsp(&mut self, amount: u32) -> i32 {
        self.rsp += amount as i32;
        self.rsp
    }

}


/// Describe how register is handled by a block of code.
#[derive(Debug)]
pub enum RegisterUsage {
    /// The register is overriden without being saved.
    Overriden,
    /// The register is read as an address operand.
    ReadAddr,
    /// The first operation on this register is a read by an instruction.
    ReadValue {
        /// How many bytes were read from the register.
        len: u8,
    },
    /// The register is read and saved in the stack.
    ReadToStack {
        /// RSP where the register is saved.
        rsp: i32,
        /// How many bytes were saved at the stack offset.
        len: u8,
    },
}
