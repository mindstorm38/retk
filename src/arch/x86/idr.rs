//! x86 specific implementations.


use std::collections::{VecDeque, HashMap};

use iced_x86::{Instruction, Code, Register, ConditionCode};

use crate::idr::{
    IdrStatement, IdrExpression, 
    IdrVarFactory, IdrVar, IdrFunction, IdrCondition,
};

use crate::ty::Type;


// TODO LIST:
// - Support 16 and 32 bits instructions and registers (SP/ESP)
// - Elide copy expressions by just referencing variables


/// A x86 Intermediate Decompilation Representation decoder. 
/// It needs to be fed with raw x86 instructions and will
/// internally produce an [`IdrFunction`]. This function
/// can later be optimized and retyped before actually
/// producing a more human-readable pseudo-code.
/// 
/// Note that it's needed to traverse the function's basic
/// blocks in order of execution in order to produce an
/// execution simulation as accurate as possible. *However,
/// the same basic block should not be analyzed twice.*
/// 
/// This IDR decoder also analyse, while decoding a function,
/// its ABI, parameters and return types based on specific
/// patterns. The function howevers need to be fully parsed
/// before obtaining an accurate function signature, for
/// example if some stack parameters is accessed later than
/// all other ones or if the branch barrier is crossed.
#[derive(Default)]
pub struct IdrDecoder {
    /// Internal tracker for registers values.
    reg_tracker: RegisterTracker,
    /// Internal tracker for stack trace slots.
    stack_tracker: StackTracker,
    /// Internal tracker for constant values.
    const_tracker: ConstantTracker,
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
        println!("- {inst}");
        match inst.code() {
            Code::Nopw |
            Code::Nopd |
            Code::Nopq |
            Code::Nop_rm16 |
            Code::Nop_rm32 |
            Code::Nop_rm64 |
            Code::Int3 => {}
            Code::Push_r64 |
            Code::Push_r32 |
            Code::Push_r16 => self.decode_push_r(inst),
            Code::Pop_r64 |
            Code::Pop_r32 |
            Code::Pop_r16 => self.decode_pop_r(inst),
            Code::Lea_r64_m |
            Code::Lea_r32_m |
            Code::Lea_r16_m => self.decode_lea_r_m(inst),
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
            Code::Mov_r64_imm64 |
            Code::Mov_r32_imm32 |
            Code::Mov_r16_imm16 => self.decode_mov_r_imm(inst),
            Code::Mov_r64_rm64 |
            Code::Mov_r32_rm32 |
            Code::Mov_r16_rm16 => self.decode_mov_r_rm(inst),
            Code::Mov_rm64_r64 |
            Code::Mov_rm32_r32 |
            Code::Mov_rm16_r16 => self.decode_mov_rm_r(inst),
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
    fn push_assign(&mut self, var: IdrVar, ty: Type, expr: IdrExpression) {

        // Propagate constants if relevant.
        match expr {
            IdrExpression::Constant(val) => self.const_tracker.set(var, val),
            IdrExpression::Copy(from) => self.const_tracker.try_copy(from, var),
            IdrExpression::AddImm(from, val) => self.const_tracker.try_add(from, var, val),
            IdrExpression::SubImm(from, val) => self.const_tracker.try_sub(from, var, val),
            _ => {}
        }

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
        if let Some(var) = self.reg_tracker.get_var(register) {
            var
        } else {
            let var = self.var_factory.create();
            self.push_assign(var, Type::VOID, IdrExpression::Extern);
            self.reg_tracker.set_var(register, var);
            var
        }
    }

    /// Create a new variable bound to the register.
    fn decode_write_register(&mut self, register: Register) -> IdrVar {
        let var = self.var_factory.create();
        self.reg_tracker.set_var(register, var);
        var
    }

    /// Decode an instruction's memory addressing operand and return
    /// the variable where the final address is stored. This variable
    /// can later be used for deref or store.
    fn decode_mem_addr(&mut self, inst: &Instruction) -> (IdrVar, u16) {

        let mem_displ = inst.memory_displacement64() as i64;
        let mem_size = inst.memory_size().size() as u16;
        
        let mut var;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                // Special handling for RIP addressing, because displacement 
                // contains the final value.
                var = self.var_factory.create();
                self.push_assign(var, Type::VOID.to_pointer(1), IdrExpression::Constant(mem_displ));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                let addr = self.stack_tracker.sp() + mem_displ as i32;
                match self.stack_tracker.get(addr) {
                    Some(slot) => {
                        debug_assert!(slot.offset == 0, "todo");
                        var = slot.var;
                    }
                    None => {
                        var = self.var_factory.create();
                        if addr > 0 {
                            // If the stack address goes before the frame, it's
                            // an external parameter for sure.
                            // TMaybe use a "Parameter" expression in the future.
                            self.push_assign(var, Type::VOID.to_pointer(1), IdrExpression::Extern);
                        } else {
                            // Else, it's just a local stack allocation.
                            self.push_assign(var, Type::VOID.to_pointer(1), IdrExpression::Alloca(mem_size));
                        }
                        self.stack_tracker.store(addr, mem_size, var);
                        self.const_tracker.set(var, addr as i64);
                    }
                }
            }
            mem_base_reg => {
                var = self.decode_read_register(mem_base_reg);
                if mem_displ != 0 {
                    let new_var = self.var_factory.create();
                    self.push_assign(new_var, Type::VOID.to_pointer(1), IdrExpression::AddImm(var, mem_displ));
                    var = new_var;
                }
            }
        }
        
        let mem_index_reg = inst.memory_index();
        if mem_index_reg != Register::None {

            let mut index_var = self.decode_read_register(mem_index_reg);

            let mem_scale = inst.memory_index_scale();
            if mem_scale != 1 {
                let new_var = self.var_factory.create();
                self.push_assign(new_var, Type::VOID.to_pointer(1), IdrExpression::MulImm(index_var, mem_scale as i64));
                index_var = new_var;
            }

            let new_var = self.var_factory.create();
            self.push_assign(new_var, Type::VOID.to_pointer(1), IdrExpression::Add(var, index_var));
            var = new_var;

        }

        (var, mem_size)

    }

    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_var = self.decode_read_register(reg);
        let reg_size = reg.size() as u16;

        // This is where the pointer to the stack slot is located.
        let stack_ptr = self.var_factory.create();

        let sp = self.stack_tracker.sub_sp(reg_size);
        self.stack_tracker.store(sp, reg_size, stack_ptr);
        self.const_tracker.set(stack_ptr, sp as i64); // This pointer is statically known
        
        self.push_assign(stack_ptr, Type::from_integer_size(reg_size).to_pointer(1), IdrExpression::Alloca(reg_size));
        self.push_store(stack_ptr, reg_var);

    }

    fn decode_pop_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_var = self.decode_write_register(reg);
        let reg_size = reg.size() as u16;

        let stack_ptr = self.stack_tracker.get_at_sp().unwrap();
        debug_assert!(stack_ptr.offset == 0, "todo");
        
        self.push_assign(reg_var,
            Type::from_integer_size(reg_size),
            IdrExpression::Deref { base: stack_ptr.var, offset: 0 });
        
        self.stack_tracker.add_sp(reg_size);

    }

    fn decode_lea_r_m(&mut self, inst: &Instruction) {

        // mem_size with LEA would be null, so we use the size of the register
        let (mem_var, _) = self.decode_mem_addr(inst);

        let reg0 = inst.op0_register();
        self.reg_tracker.set_var(reg0, mem_var);

        // let reg0_var = self.decode_write_register(reg0);

        // self.push_assign(reg0_var,
        //     Type::from_integer_size(reg0.size() as u16),
        //     IdrExpression::Copy(mem_var));

    }

    fn decode_arith_rm_imm(&mut self, inst: &Instruction, op: AnalyzerArithOp) {
        let imm = inst.immediate64() as i64;
        match inst.op0_register() {
            Register::None => {
                let (mem_var, mem_size) = self.decode_mem_addr(inst);
                let val_var = self.var_factory.create();
                let val_ty = Type::from_integer_size(mem_size);
                self.push_assign(val_var, val_ty, IdrExpression::Deref { base: mem_var, offset: 0 });
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
                        self.stack_tracker.stack_pointer += imm as i32;
                    }
                    AnalyzerArithOp::Sub => {
                        self.stack_tracker.stack_pointer -= imm as i32;
                    }
                }
            }
            reg => {
                let reg_var = self.decode_read_register(reg);
                let val_ty = Type::from_integer_size(reg.size() as u16);
                self.push_assign(reg_var, val_ty, match op {
                    AnalyzerArithOp::Add => IdrExpression::AddImm(reg_var, imm),
                    AnalyzerArithOp::Sub => IdrExpression::SubImm(reg_var, imm),
                });
            }
        }
    }

    /// Patterns:
    /// - `mov r0, imm0` => `var0 = imm0`
    fn decode_mov_r_imm(&mut self, inst: &Instruction) {
        let reg = inst.op0_register();
        let reg_var = self.decode_write_register(reg);
        let reg_ty = Type::from_integer_size(reg.size() as u16);
        let imm = inst.immediate64();
        self.push_assign(reg_var, reg_ty, IdrExpression::Constant(imm as i64));
    }

    /// Patterns:
    /// - `mov r0, r1` => `var0 = var1`
    /// - `mov r0, [r1]` => `var0 = *var1`
    /// - `mov r0, [r1+imm1]` => `tmp0 = var1 + imm1; var0 = *tmp0`
    fn decode_mov_r_rm(&mut self, inst: &Instruction) {
        let reg0 = inst.op0_register();
        let reg0_ty = Type::from_integer_size(reg0.size() as u16);
        match inst.op1_register() {
            Register::None => {
                let (mem_var, _) = self.decode_mem_addr(inst);
                let reg0_var = self.decode_write_register(reg0);
                self.push_assign(reg0_var, reg0_ty, IdrExpression::Deref { base: mem_var, offset: 0 });
            }
            Register::RSP => {
                panic!("dynamic mov from RSP is unsupported")
            }
            reg1 => {

                if let Register::SP | Register::ESP | Register::RSP = reg0 {

                    let reg1_var = self.reg_tracker.get_var(reg1)
                        .expect("moving to sp requires the right register to be bound");
                    let reg1_val = self.const_tracker.get(reg1_var)
                        .expect("moving to sp requires the right register to be have constant value");

                    self.stack_tracker.stack_pointer = reg1_val as i32;

                } else {
                    // let reg0_var = self.decode_write_register(reg0);
                    let reg1_var = self.decode_read_register(reg1);
                    self.reg_tracker.set_var(reg0, reg1_var);
                    // self.push_assign(reg0_var, reg0_ty, IdrExpression::Copy(reg1_var));
                }

            }
        }
    }

    /// Patterns:
    /// - `mov r0, r1` => `var0 = var1`
    /// - `mov [r0], r1` => `*var0 = var1`
    fn decode_mov_rm_r(&mut self, inst: &Instruction) {
        let reg1 = inst.op1_register();
        match inst.op0_register() {
            Register::None => {
                let (mem_var, _) = self.decode_mem_addr(inst);
                let reg1_var = self.decode_read_register(reg1);
                self.push_store(mem_var, reg1_var);
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                let reg1_var = self.reg_tracker.get_var(reg1)
                    .expect("moving to sp requires the right register to be bound");
                let reg1_val = self.const_tracker.get(reg1_var)
                    .expect("moving to sp requires the right register to be have constant value");
                self.stack_tracker.stack_pointer = reg1_val as i32;
            }
            reg0 => {
                // let reg0_ty = Type::from_integer_size(reg0.size() as u16);
                // let reg0_var = self.decode_write_register(reg0);
                let reg1_var = self.decode_read_register(reg1);
                self.reg_tracker.set_var(reg0, reg1_var);
                // self.push_assign(reg0_var, reg0_ty, IdrExpression::Copy(reg1_var));
            }
        }
    }

    /// Patterns:
    /// - `call imm0` => `var0 = imm0()`
    fn decode_call_rel(&mut self, inst: &Instruction) {
        let pointer = inst.near_branch64();
        let ret_var = self.var_factory.create();
        self.push_assign(ret_var, Type::VOID, IdrExpression::Call { 
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
        self.push_assign(ret_var, Type::VOID, IdrExpression::CallIndirect { 
            pointer: pointer_var, 
            args: vec![],
        });
    }

    fn decode_cmp_rm_imm(&mut self, inst: &Instruction) {

        let (left_var, var_ty) = match inst.op0_register() {
            Register::None => {
                let (mem_var, mem_size) = self.decode_mem_addr(inst);
                let var = self.var_factory.create();
                let var_ty = Type::from_integer_size(mem_size);
                self.push_assign(var, var_ty.clone(), IdrExpression::Deref { base: mem_var, offset: 0 });
                (var, var_ty)
            }
            reg => {
                (self.decode_read_register(reg), Type::from_integer_size(reg.size() as u16))
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
        let right_reg_ty = Type::from_integer_size(right_reg.size() as u16);
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
struct RegisterTracker {
    /// RAX/RCX/RDX/RBX/RSI/RDI/R8-R15
    gp: [RegisterSlot; 16],
}

#[derive(Debug)]
enum RegisterSlot {
    /// The register is currently unused.
    Uninit,
    /// The register is currently bound to a variable
    /// and a specific length is used.
    Init {
        var: IdrVar,
        _len: u16,
    },
}

impl Default for RegisterSlot {
    fn default() -> Self {
        Self::Uninit
    }
}

impl RegisterSlot {

    fn var(&self) -> Option<IdrVar> {
        match *self {
            Self::Init { var, .. } => Some(var),
            _ => None,
        }
    }

}

impl RegisterTracker {

    fn get_var(&self, register: Register) -> Option<IdrVar> {
        if register.is_gpr() {
            self.gp[register.number()].var()
        } else {
            unimplemented!("this kind of register '{register:?}' is not yet supported");
        }
    }

    fn set_var(&mut self, register: Register, var: IdrVar) {
        if register.is_gpr() {
            self.gp[register.number()] = RegisterSlot::Init { 
                var, 
                _len: register.size() as u16 
            };
        } else {
            unimplemented!("this kind of register '{register:?}' is not yet supported");
        }
    }

}


/// Simulation of the stack, used to track which slot is used
/// for which variable.
#[derive(Debug, Default)]
struct StackTracker {
    /// Associate to each stack byte a place.
    stack: VecDeque<Option<StackSlot>>,
    /// Address of the first byte in the stack.
    stack_base: i32,
    /// Current stack pointer.
    stack_pointer: i32,
}

#[derive(Debug)]
struct StackSlot {
    /// The variable store here. Actually, the given variable is
    /// a pointer to the slot.
    var: IdrVar,
    /// The byte offset within the variable.
    offset: u16,
}

impl StackTracker {

    #[inline]
    fn sp(&self) -> i32 {
        self.stack_pointer
    }

    fn sub_sp(&mut self, n: u16) -> i32 {
        self.stack_pointer -= n as i32;
        self.stack_pointer
    }

    fn add_sp(&mut self, n: u16) -> i32 {
        self.stack_pointer += n as i32;
        self.stack_pointer
    }

    /// Store a value at an absolute address on stack.
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
            self.stack[idx] = Some(StackSlot {
                var,
                offset,
            });
        }

        self.debug();

    }

    fn store_from_sp(&mut self, offset: i32, len: u16, var: IdrVar) -> i32 {
        let offset = self.stack_pointer + offset;
        self.store(offset, len, var);
        offset
    }

    #[inline]
    fn store_at_sp(&mut self, len: u16, var: IdrVar) -> i32 {
        self.store_from_sp(0, len, var)
    }

    /// Get a value at an absolute address on the stack.
    fn get(&self, addr: i32) -> Option<&StackSlot> {
        println!("== Sim Stack GET {addr}");
        self.stack.get((addr - self.stack_base) as usize)?.as_ref()
    }

    fn get_from_sp(&self, offset: i32) -> Option<&StackSlot> {
        self.get(self.stack_pointer + offset)
    }

    #[inline]
    fn get_at_sp(&self) -> Option<&StackSlot> {
        self.get_from_sp(0)
    }

    /// FIXME: TEMPORARY
    /// 
    /// Debug print
    fn debug(&self) {

        println!("== Sim Stack");
        println!(" = SP: {}", self.stack_pointer);
        for (i, slot) in self.stack.iter().enumerate().rev() {
            let addr = self.stack_base + i as i32;
            print!(" = {addr}:");
            if let Some(slot) = slot {
                println!(" {slot:?}");
            } else {
                println!();
            }
        }

    }

}


/// A tracker for variables that have constant values known
/// at analysis. This is just a hint for most variables but
/// it's useful when used analysing optimisations around RSP.
#[derive(Debug, Default)]
struct ConstantTracker {
    constants: HashMap<IdrVar, i64>,
}

impl ConstantTracker {

    fn set(&mut self, var: IdrVar, val: i64) {
        self.constants.insert(var, val);
    }

    fn get(&mut self, var: IdrVar) -> Option<i64> {
        self.constants.get(&var).copied()
    }

    /// If the variable `from` has a constant value, map its 
    /// value using the given function to the `to` variable.
    #[inline]
    fn try_map<F>(&mut self, from: IdrVar, to: IdrVar, func: F)
    where
        F: FnOnce(i64) -> i64
    {
        if let Some(val) = self.get(from) {
            self.set(to, func(val));
        }
    }

    /// If the variable `from` has a constant value, copy
    /// it to the `to` variable.
    #[inline]
    fn try_copy(&mut self, from: IdrVar, to: IdrVar) {
        self.try_map(from, to, |v| v)
    }

    #[inline]
    fn try_add(&mut self, from: IdrVar, to: IdrVar, val: i64) {
        self.try_map(from, to, move |v| v + val)
    }

    #[inline]
    fn try_sub(&mut self, from: IdrVar, to: IdrVar, val: i64) {
        self.try_map(from, to, move |v| v - val)
    }

}


/// Internal structure used to track possible comparisons.
#[derive(Debug, Clone)]
struct AnalyzerCmp {
    left_var: IdrVar,
    right_var: IdrVar,
    ty: Type,
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
