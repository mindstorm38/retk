//! x86 specific implementations.


use std::collections::VecDeque;

use iced_x86::{Instruction, Code, Register, ConditionCode};

use crate::idr::{
    IdrStatement, IdrExpression, 
    IdrVarFactory, IdrVar, IdrFunction, IdrCondition, IdrType,
};


#[inline]
fn new_ptr_type(pointed_type: IdrType) -> IdrType {
    IdrType::Pointer(Box::new(pointed_type), 8)
}


/// A x86 Intermediate Decompilation Representation decoder. 
/// It needs to be fed with raw x86 instructions and will
/// internally produce an [`IdrFunction`]. This function
/// can later be optimized and retyped before actually
/// producing a more human-readable pseudo-code.
#[derive(Default)]
pub struct IdrDecoder {
    /// Internal registers to track variables binding.
    registers: AnalyzerRegisters,
    /// Internal stack to track variables binding.
    stack: AnalyzerStack,
    /// Internal factory to create unique variables.
    var_factory: IdrVarFactory,
    /// Last comparison, used when a condition (jmp, mov, etc.) is decoded.
    cmp: Option<AnalyzerCmp>,
    /// Internal function being decoded.
    pub function: IdrFunction,
}

impl IdrDecoder {

    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, inst: &Instruction) {
        match inst.code() {
            Code::Nopw |
            Code::Nopd |
            Code::Nopq |
            Code::Nop_rm16 |
            Code::Nop_rm32 |
            Code::Nop_rm64 => {}
            Code::Push_r64 |
            Code::Push_r32 |
            Code::Push_r16 => self.decode_push_r(inst),
            Code::Pop_r64 |
            Code::Pop_r32 |
            Code::Pop_r16 => self.decode_pop_r(inst),
            Code::Add_rm64_imm8 |
            Code::Add_rm32_imm8 |
            Code::Add_rm16_imm8 |
            Code::Add_rm8_imm8 |
            Code::Add_rm64_imm32 |
            Code::Add_rm32_imm32 |
            Code::Add_rm16_imm16 => self.decode_arith_rm_imm(inst, AnalyzerArithOp::Add),
            Code::Sub_rm64_imm8 |
            Code::Sub_rm32_imm8 |
            Code::Sub_rm16_imm8 |
            Code::Sub_rm8_imm8 |
            Code::Sub_rm64_imm32 |
            Code::Sub_rm32_imm32 |
            Code::Sub_rm16_imm16 => self.decode_arith_rm_imm(inst, AnalyzerArithOp::Sub),
            Code::Mov_r64_rm64 |
            Code::Mov_r32_rm32 |
            Code::Mov_r16_rm16 => self.decode_mov_r_rm(inst),
            Code::Mov_r64_imm64 |
            Code::Mov_r32_imm32 |
            Code::Mov_r16_imm16 => self.decode_mov_r_imm(inst),
            Code::Call_rel16 |
            Code::Call_rel32_32 |
            Code::Call_rel32_64 => self.decode_call_rel(inst),
            Code::Call_rm64 |
            Code::Call_rm32 |
            Code::Call_rm16 => self.decode_call_rm(inst),
            Code::Cmp_rm64_imm8 |
            Code::Cmp_rm32_imm8 |
            Code::Cmp_rm16_imm8 |
            Code::Cmp_rm64_imm32 |
            Code::Cmp_rm32_imm32 |
            Code::Cmp_rm16_imm16 => self.decode_cmp_rm_imm(inst),
            Code::Test_rm64_r64 |
            Code::Test_rm32_r32 |
            Code::Test_rm16_r16 |
            Code::Test_rm8_r8 => self.decode_test_rm_r(inst),
            code if code.is_jcc_short_or_near() => self.decode_jcc(inst),
            _ => {
                self.function.statements.push(IdrStatement::Error);
            }
        }
    }

    #[inline]
    fn push_stmt(&mut self, stmt: IdrStatement) {
        self.function.statements.push(stmt);
    }

    /// Internal function to enqueue a statement
    fn push_assign(&mut self, var: IdrVar, ty: IdrType, expr: IdrExpression) {
        self.push_stmt(IdrStatement::Assign { var, ty, expr });
    }

    fn push_store(&mut self, pointer: IdrVar, var: IdrVar) {
        self.push_stmt(IdrStatement::Store { pointer, var });
    }

    fn push_branch(&mut self, pointer: u64, left_var: IdrVar, right_var: IdrVar, cond: IdrCondition) {
        self.function.statements.push(IdrStatement::Branch { 
            pointer, 
            left_var, 
            right_var, 
            cond,
        })
    }

    /// Ensure that a variable is bound to the given register.
    /// If the register is not yet bound, it is bound to a
    /// newly created variable. In such case the variable is
    /// "externally bound", it can be a non-volatile register
    /// being saved or a parameter being passed.
    fn decode_read_register(&mut self, register: Register) -> IdrVar {
        if let Some(var) = self.registers.get_var(register) {
            var
        } else {
            let var = self.var_factory.create();
            self.registers.set_var(register, var);
            var
        }
    }

    /// Create a new variable bound to the register.
    fn decode_write_register(&mut self, register: Register) -> IdrVar {
        let var = self.var_factory.create();
        self.registers.set_var(register, var);
        var
    }

    /// Decode an instruction's memory addressing operand and return
    /// the variable where the final address is stored. This variable
    /// can later be used for deref or store.
    fn decode_mem_addr(&mut self, inst: &Instruction) -> (IdrVar, u16) {

        let mem_base_reg = inst.memory_base();
        let mut var = self.decode_read_register(mem_base_reg);

        let mem_displ = inst.memory_displacement64() as i64;
        if mem_displ != 0 {
            let new_var = self.var_factory.create();
            self.push_assign(new_var, new_ptr_type(IdrType::VOID), IdrExpression::AddImm(var, mem_displ));
            var = new_var;
        }

        let mem_index_reg = inst.memory_index();
        if mem_index_reg != Register::None {

            let mut index_var = self.decode_read_register(mem_index_reg);

            let mem_scale = inst.memory_index_scale();
            if mem_scale != 1 {
                let new_var = self.var_factory.create();
                self.push_assign(new_var, new_ptr_type(IdrType::VOID), IdrExpression::MulImm(index_var, mem_scale as i64));
                index_var = new_var;
            }

            let new_var = self.var_factory.create();
            self.push_assign(new_var,  new_ptr_type(IdrType::VOID), IdrExpression::Add(var, index_var));
            var = new_var;

        }

        (var, inst.memory_size().size() as u16)

    }

    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_var = self.decode_read_register(reg);
        let reg_size = reg.size() as u16;

        // This is where the pointer to the stack slot is located.
        let stack_ptr = self.var_factory.create();

        self.stack.stack_pointer -= reg_size as i32;
        self.stack.store(self.stack.stack_pointer, reg_size, stack_ptr);
        
        self.push_assign(stack_ptr, new_ptr_type(IdrType::integer_aligned(reg_size)), IdrExpression::Alloca(reg_size));
        self.push_store(stack_ptr, reg_var);

    }

    fn decode_pop_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_var = self.decode_write_register(reg);
        let reg_size = reg.size() as u16;

        let stack_ptr = self.stack.get(self.stack.stack_pointer).unwrap();
        debug_assert!(stack_ptr.offset == 0, "todo");
        
        self.push_assign(reg_var, 
            IdrType::integer_aligned(reg_size), 
            IdrExpression::Deref { base: stack_ptr.var, offset: 0 });
        
        self.stack.stack_pointer += reg_size as i32;

    }

    fn decode_arith_rm_imm(&mut self, inst: &Instruction, op: AnalyzerArithOp) {
        let imm = inst.immediate64() as i64;
        match inst.op0_register() {
            Register::None => {
                let (mem_var, mem_size) = self.decode_mem_addr(inst);
                let val_var = self.var_factory.create();
                let val_ty = IdrType::integer_aligned(mem_size);
                self.push_assign(val_var, val_ty.clone(), IdrExpression::Deref { base: mem_var, offset: 0 });
                let tmp_var = self.var_factory.create();
                self.push_assign(tmp_var, val_ty, match op {
                    AnalyzerArithOp::Add => IdrExpression::AddImm(val_var, imm),
                    AnalyzerArithOp::Sub => IdrExpression::SubImm(val_var, imm),
                });
                self.push_store(mem_var, tmp_var)
            }
            Register::RSP => {
                // Special handling for RSP
                match op {
                    AnalyzerArithOp::Add => {
                        self.stack.stack_pointer += imm as i32;
                    }
                    AnalyzerArithOp::Sub => {
                        self.stack.stack_pointer -= imm as i32;
                    }
                }
            }
            reg => {
                let reg_var = self.decode_read_register(reg);
                let val_ty = IdrType::integer_aligned(reg.size() as u16);
                self.push_assign(reg_var, val_ty, match op {
                    AnalyzerArithOp::Add => IdrExpression::AddImm(reg_var, imm),
                    AnalyzerArithOp::Sub => IdrExpression::SubImm(reg_var, imm),
                });
            }
        }
    }

    /// Patterns:
    /// - `mov r0, r1` => `var0 = var1`
    /// - `mov r0, [r1]` => `var0 = *var1`
    /// - `mov r0, [r1+imm1]` => `tmp0 = var1 + imm1; var0 = *tmp0`
    fn decode_mov_r_rm(&mut self, inst: &Instruction) {
        let reg0 = inst.op0_register();
        let reg0_ty = IdrType::integer_aligned(reg0.size() as u16);
        match inst.op1_register() {
            Register::None => {
                let (mem_var, _) = self.decode_mem_addr(inst);
                let reg0_var = self.decode_write_register(reg0);
                self.push_assign(reg0_var, reg0_ty, IdrExpression::Deref { base: mem_var, offset: 0 });
            }
            Register::RSP => {
                panic!("dynamic mov to RSP is not currently supported")
            }
            reg1 => {
                let reg1_var = self.decode_read_register(reg1);
                let reg0_var = self.decode_write_register(reg0);
                self.push_assign(reg0_var, reg0_ty, IdrExpression::Copy(reg1_var));
            }
        }
    }

    /// Patterns:
    /// - `mov r0, imm0` => `var0 = imm0`
    fn decode_mov_r_imm(&mut self, inst: &Instruction) {
        let reg = inst.op0_register();
        let reg_var = self.decode_write_register(reg);
        let reg_ty = IdrType::integer_aligned(reg.size() as u16);
        let imm = inst.immediate64();
        self.push_assign(reg_var, reg_ty, IdrExpression::Constant(imm as i64));
    }

    /// Patterns:
    /// - `call imm0` => `var0 = imm0()`
    fn decode_call_rel(&mut self, inst: &Instruction) {
        let pointer = inst.near_branch64();
        let ret_var = self.var_factory.create();
        self.push_assign(ret_var, IdrType::VOID, IdrExpression::Call { 
            pointer, 
            args: vec![]
        });
    }

    fn decode_call_rm(&mut self, inst: &Instruction) {
        let ret_var = self.var_factory.create();
        let pointer_var = match inst.op0_register() {
            Register::None => self.decode_mem_addr(inst).0,
            reg => self.decode_read_register(reg),
        };
        self.push_assign(ret_var, IdrType::VOID, IdrExpression::CallIndirect { 
            pointer: pointer_var, 
            args: vec![],
        });
    }

    fn decode_cmp_rm_imm(&mut self, inst: &Instruction) {

        let (left_var, var_ty) = match inst.op0_register() {
            Register::None => {
                let (mem_var, mem_size) = self.decode_mem_addr(inst);
                let var = self.var_factory.create();
                let var_ty = IdrType::integer_aligned(mem_size);
                self.push_assign(var, var_ty.clone(), IdrExpression::Deref { base: mem_var, offset: 0 });
                (var, var_ty)
            }
            reg => {
                (self.decode_read_register(reg), IdrType::integer_aligned(reg.size() as u16))
            },
        };

        let right_var = self.var_factory.create();

        self.push_assign(right_var, var_ty.clone(), IdrExpression::Constant(inst.immediate64() as i64));

        self.cmp = Some(AnalyzerCmp { 
            left_var, 
            right_var, 
            ty: var_ty,
            kind: AnalyzerCmpKind::Cmp,
        });

    }

    fn decode_test_rm_r(&mut self, inst: &Instruction) {

        let right_reg = inst.op1_register();
        let right_reg_ty = IdrType::integer_aligned(right_reg.size() as u16);
        let right_var = self.decode_read_register(right_reg);

        let left_var = match inst.op0_register() {
            Register::None => {
                let (mem_var, _) = self.decode_mem_addr(inst);
                let var = self.var_factory.create();
                self.push_assign(var, right_reg_ty.clone(), IdrExpression::Deref { base: mem_var, offset: 0 });
                var
            }
            reg => self.decode_read_register(reg)
        };

        self.cmp = Some(AnalyzerCmp {
            left_var,
            right_var,
            ty: right_reg_ty,
            kind: AnalyzerCmpKind::Test,
        });

    }

    fn decode_jcc(&mut self, inst: &Instruction) {

        // Note that we take the comparison, so it is replaced 
        // with none. Even if jump instructions doesn't clear
        // the comparison flags, because of the switch of
        // basic blocks, we should clear it (at least for now). 
        if let Some(cmp) = self.cmp.take() {

            let pointer = inst.near_branch64();

            match cmp.kind {
                AnalyzerCmpKind::Cmp => {

                    let idr_cond = match inst.condition_code() {
                        ConditionCode::None => unreachable!(),
                        ConditionCode::o => todo!(),
                        ConditionCode::no => todo!(),
                        ConditionCode::b => IdrCondition::UnsignedLower,
                        ConditionCode::ae => IdrCondition::UnsignedGreaterOrEqual,
                        ConditionCode::e => IdrCondition::Equal,
                        ConditionCode::ne => IdrCondition::NotEqual,
                        ConditionCode::be => IdrCondition::UnsignedLowerOrEqual,
                        ConditionCode::a => IdrCondition::UnsignedGreater,
                        ConditionCode::s => todo!(),
                        ConditionCode::ns => todo!(),
                        ConditionCode::p => todo!(),
                        ConditionCode::np => todo!(),
                        ConditionCode::l => IdrCondition::SignedLower,
                        ConditionCode::ge => IdrCondition::SignedGeaterOrEqual,
                        ConditionCode::le => IdrCondition::SignedLowerOrEqual,
                        ConditionCode::g => IdrCondition::SignedGreater,
                    };
    
                    self.push_branch(pointer, cmp.left_var, cmp.right_var, idr_cond);

                }
                AnalyzerCmpKind::Test => {

                    let test_var;

                    // A common usage for test is to test if a variable 
                    // is equal to 0 or not, in this case the pattern is
                    // > test r0, r0
                    // > JE  => if r0 == 0
                    // > JNE => if r0 != 0
                    if cmp.left_var == cmp.right_var {
                        test_var = cmp.left_var;
                    } else {
                        test_var = self.var_factory.create();
                        self.push_assign(test_var, cmp.ty.clone(), IdrExpression::And(cmp.left_var, cmp.right_var));
                    }

                    let idr_cond = match inst.condition_code() {
                        ConditionCode::e => IdrCondition::Equal,
                        ConditionCode::ne => IdrCondition::NotEqual,
                        _ => todo!("unsupported condition code with 'test'"),
                    };

                    let zero_var = self.var_factory.create();
                    self.push_assign(zero_var, cmp.ty, IdrExpression::Constant(0));

                    self.push_branch(pointer, test_var, zero_var, idr_cond);

                }
            }

        } else {
            // No preceding comparison, error.
            self.function.statements.push(IdrStatement::Error);
        }

    }   

}


/// Used to keep track of registers.
#[derive(Debug, Default)]
struct AnalyzerRegisters {
    /// RAX/RCX/RDX/RBX/RSI/RDI/R8-R15
    gp: [AnalyzerRegister; 16],
}

#[derive(Debug)]
enum AnalyzerRegister {
    /// The register is currently unused.
    Uninit,
    /// The register is currently bound to a variable
    /// and a specific length is used.
    Init {
        var: IdrVar,
        len: u16,
    }
}

impl Default for AnalyzerRegister {
    fn default() -> Self {
        Self::Uninit
    }
}

impl AnalyzerRegister {

    fn var(&self) -> Option<IdrVar> {
        match *self {
            Self::Uninit => None,
            Self::Init { var, .. } => Some(var),
        }
    }

}

impl AnalyzerRegisters {

    fn get_var(&self, register: Register) -> Option<IdrVar> {
        if register.is_gpr() {
            self.gp[register.number()].var()
        } else {
            unimplemented!("this kind of register '{register:?}' is not yet supported");
        }
    }

    fn set_var(&mut self, register: Register, var: IdrVar) {
        if register.is_gpr() {
            self.gp[register.number()] = AnalyzerRegister::Init { 
                var, 
                len: register.size() as u16,
            };
        } else {
            unimplemented!("this kind of register '{register:?}' is not yet supported");
        }
    }

}


/// Simulation of the stack, used to track which slot is used
/// for which variable.
#[derive(Debug, Default)]
struct AnalyzerStack {
    /// Associate to each stack byte a place.
    stack: VecDeque<Option<AnalyzerStackSlot>>,
    /// Address of the first byte in the stack.
    stack_base: i32,
    /// Current stack pointer.
    stack_pointer: i32,
}

#[derive(Debug)]
struct AnalyzerStackSlot {
    /// The variable store here. Actually, the given variable is
    /// a pointer to the slot.
    var: IdrVar,
    /// The byte offset within the variable.
    offset: u16,
}

impl AnalyzerStack {

    fn store(&mut self, addr: i32, len: u16, var: IdrVar) {

        if addr < self.stack_base {
            for _ in addr..self.stack_base {
                self.stack.push_front(None);
                self.stack_base -= 1;
            }
        }

        let end_addr = addr + len as i32;
        let current_end_addr = self.stack_base + self.stack.len() as i32;

        if end_addr > current_end_addr {
            for _ in current_end_addr..end_addr {
                self.stack.push_back(None);
            }
        }

        for offset in 0..len {
            let idx = (addr + offset as i32 - self.stack_base) as usize;
            self.stack[idx] = Some(AnalyzerStackSlot {
                var,
                offset,
            });
        }

    }

    fn get(&self, addr: i32) -> Option<&AnalyzerStackSlot> {
        self.stack[(addr - self.stack_base) as usize].as_ref()
    }

}


/// Internal structure used to track possible comparisons.
#[derive(Debug, Clone)]
struct AnalyzerCmp {
    left_var: IdrVar,
    right_var: IdrVar,
    ty: IdrType,
    kind: AnalyzerCmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalyzerCmpKind {
    Cmp,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalyzerArithOp {
    Add,
    Sub,
}
