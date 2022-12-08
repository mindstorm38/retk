//! IDR implementation for x86 instruction set.


use std::collections::hash_map::Entry;
use std::collections::{VecDeque, HashMap};

use iced_x86::{Instruction, Code, Register, ConditionCode};

use crate::idr::{
    // IdrFunction, IdrCondition,
    // IdrStatement, IdrExpression, 
    IdrVarFactory, IdrVar, 
};

use crate::idr::new::{
    Function, 
    Statement, Expression, Value, Assign, Store
};

use crate::ty::Type;


// TODO LIST:
// - Support 16 and 32 bits instructions and registers (SP/ESP)
// - Elide copy expressions by just referencing variables


/// ## IDR Decoder
/// A x86 Intermediate Decompilation Representation decoder. 
/// It needs to be fed with raw x86 instructions and will
/// internally produce an [`IdrFunction`]. This function
/// can later be optimized and retyped before actually
/// producing a more human-readable pseudo-code.
/// 
/// The three major steps are described in the following
/// sections.
/// 
/// ### Naive basic block decoding
/// This first step consists of analysing each basic block
/// individually and analysing their parameters. For each
/// basic block, parameters are the registers read in the 
/// block. Because each block will branch to another one
/// (except for ret/unknown branches), this decoding should
/// take branching arguments into account when possible.
/// For example when branching to an already analyzed block,
/// we already know which registers are expected.
/// 
/// **This first pass doesn't take function calls.**
/// 
/// ### Arguments propagation
/// In this second step, the decoder fixes 
/// 
pub struct IdrDecoder {
    /// The IDR function being decoded, which is architecture
    /// independent. For the decoding, we need to keep track
    /// of some architecture-specific informations, these
    /// are kept in this structure.
    function: Function,
    /// Current stack pointer. It is common through all of the
    /// function.
    stack_pointer: i32,
    /// Individual basic blocks trackers.
    basic_blocks: HashMap<usize, Box<BasicBlockTracker>>,
    /// The current basic block being built.
    basic_block: Option<Box<BasicBlockTracker>>,
    /// Tracker for constant value stored in variables.
    constants: ConstantTracker,
    /// Internal factory to create unique variables.
    var_factory: IdrVarFactory,
    /// Track the last comparison that might be used in a lated
    /// conditionnal jump.
    cmp: Option<Cmp>,
}

impl IdrDecoder {

    #[inline]
    pub fn new() -> Self {
        Self {
            function: Function::default(),
            stack_pointer: 0,
            basic_blocks: HashMap::new(),
            basic_block: None,
            constants: ConstantTracker::default(),
            var_factory: IdrVarFactory::new(),
            cmp: None,
        }
    }

    /// Initialize the IDR decoder to prepare for a new function.
    pub fn init(&mut self) {

        // Clear the function and add an initial line for the first
        // basic block.
        self.function.clear();
        self.function.add_line(); // At index 0 ofc
        self.function.set_basic_block(0);
        self.basic_block = Some(Box::new(BasicBlockTracker::new(0)));

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
            Code::Add_rm16_imm16 => self.decode_int_op_rm_imm(inst, IntOp::Add),
            Code::Sub_rm64_imm8 |
            Code::Sub_rm32_imm8 |
            Code::Sub_rm16_imm8 |
            Code::Sub_rm8_imm8 |
            Code::Sub_rm64_imm32 |
            Code::Sub_rm32_imm32 |
            Code::Sub_rm16_imm16 => self.decode_int_op_rm_imm(inst, IntOp::Sub),
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
            // Code::Cmp_rm64_imm8 |
            // Code::Cmp_rm32_imm8 |
            // Code::Cmp_rm16_imm8 |
            // Code::Cmp_rm64_imm32 |
            // Code::Cmp_rm32_imm32 |
            // Code::Cmp_rm16_imm16 => self.decode_cmp_rm_imm(inst),
            Code::Test_rm64_r64 |
            Code::Test_rm32_r32 |
            Code::Test_rm16_r16 |
            Code::Test_rm8_r8 => self.decode_test_rm_r(inst),
            // code if code.is_jcc_short_or_near() => self.decode_jcc(inst),
            _ => {
                self.push_stmt(Statement::Asm(inst.to_string()));
            }
        }

    }

    #[inline]
    pub fn function(&self) -> &Function {
        &self.function
    }

    fn sub_sp(&mut self, delta: i32) -> i32 {
        self.stack_pointer -= delta;
        self.stack_pointer
    }

    fn add_sp(&mut self, delta: i32) -> i32 {
        self.stack_pointer += delta;
        self.stack_pointer
    }

    fn create_dummy_var(&mut self) -> IdrVar {
        self.var_factory.create()
    }

    /// Read a stack pointer variable, ensuring that it already exists.
    fn read_stack_var(&mut self, addr: i32) -> IdrVar {
        let bb = self.basic_block.as_mut().unwrap();
        let param = FunctionParam::Stack(addr);
        match bb.vars.entry(param) {
            Entry::Occupied(o) => *o.into_mut(),
            Entry::Vacant(v) => {
                let var = self.var_factory.create();
                self.function.get_basic_block_mut(bb.index).unwrap()
                    .add_param(var, Type::VOIDP);
                bb.params.push(param);
                *v.insert(var)
            }
        }
    }

    fn read_reg_var(&mut self, reg: Register, ty: Type) -> IdrVar {
        let bb = self.basic_block.as_mut().unwrap();
        let param = FunctionParam::Reg(reg);
        match bb.vars.entry(param) {
            Entry::Occupied(o) => *o.into_mut(),
            Entry::Vacant(v) => {
                let var = self.var_factory.create();
                self.function.get_basic_block_mut(bb.index).unwrap()
                    .add_param(var, ty);
                bb.params.push(param);
                *v.insert(var)
            }
        }
    }

    fn write_reg_var(&mut self, reg: Register) -> IdrVar {
        let bb = self.basic_block.as_mut().unwrap();
        let param = FunctionParam::Reg(reg);
        let var = self.var_factory.create();
        bb.vars.insert(param, var);
        var
    }

    fn get_reg_var(&self, reg: Register) -> Option<IdrVar> {
        let bb = self.basic_block.as_ref().unwrap();
        bb.vars.get(&FunctionParam::Reg(reg)).copied()
    }

    fn set_reg_var(&mut self, reg: Register, var: IdrVar) {
        let bb = self.basic_block.as_mut().unwrap();
        let param = FunctionParam::Reg(reg);
        bb.vars.insert(param, var);
    }

    /// Utility method for fast query of constant value stored in
    /// a register.
    fn get_reg_const(&self, reg: Register) -> Option<i64> {
        let var = self.get_reg_var(reg)?;
        self.constants.get(var)
    }

    #[inline]
    fn push_stmt(&mut self, stmt: Statement) {
        self.function.add_statement(stmt);
    }

    /// Internal function to enqueue a statement
    fn push_assign(&mut self, var: IdrVar, ty: Type, val: Expression) {

        // Propagate constant values.
        match val {
            Expression::Constant(val) => self.constants.set(var, val),
            Expression::Add(from, Value::Val(val)) => 
                self.constants.try_add(from, var, val),
            Expression::Sub(from, Value::Val(val)) =>
                self.constants.try_sub(from, var, val),
            _ => {}
        }

        self.push_stmt(Statement::Assign(Assign { var, ty, val }));

    }

    fn push_store(&mut self, ptr: IdrVar, var: IdrVar) {
        self.push_stmt(Statement::Store(Store { ptr, var }));
    }

    /// Decode an instruction's memory addressing operand and return
    /// the variable where the final address is stored. This variable
    /// is a pointer type to a given type (ty) and can later be used 
    /// for load or store.
    fn decode_mem_addr(&mut self, inst: &Instruction, ty: Type) -> IdrVar {

        let mem_displ = inst.memory_displacement64() as i64;
        
        let mut var;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                // Special handling for RIP addressing, because displacement 
                // contains the final value.
                var = self.create_dummy_var();
                self.push_assign(var, ty.to_pointer(1), Expression::Constant(mem_displ));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // If we refer to RSP, we calculate the real address relative
                // to the function's base. And then we check if that slot 
                // already
                let addr = self.stack_pointer + mem_displ as i32;
                var = self.read_stack_var(addr);
                self.constants.set(var, addr as i64);
            }
            base_reg => {
                // Access relative to other registers.
                var = self.read_reg_var(base_reg, Type::VOIDP);
                if mem_displ != 0 {
                    let new_var = self.create_dummy_var();
                    let expr = Expression::Add(var, Value::Val(mem_displ));
                    self.push_assign(new_var, ty.to_pointer(1), expr);
                    var = new_var;
                }
            }
        }

        match inst.memory_index() {
            Register::None => {}
            index_reg => {
                // Indexed memory access converts to a GetElementPointer expression.
                var = self.create_dummy_var();
                let reg_var = self.read_reg_var(index_reg, Type::DWORD);
                let expr = Expression::GetElementPointer { 
                    pointer: var, 
                    index: reg_var, 
                    stride: inst.memory_index_scale() as u8
                };
                self.push_assign(var, ty.to_pointer(1), expr);
            }
        }

        var

    }

    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_size = reg.size() as u16;
        let reg_ty = Type::from_integer_size(reg_size);
        let reg_var = self.read_reg_var(reg, reg_ty);

        let sp = self.sub_sp(reg_size as i32);
        let stack_var = self.read_stack_var(sp);

        self.push_store(stack_var, reg_var);

    }

    fn decode_pop_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_size = reg.size() as u16;
        let reg_ty = Type::from_integer_size(reg_size);
        let reg_var = self.write_reg_var(reg);

        let sp = self.stack_pointer;
        let stack_var = self.read_stack_var(sp);
        self.add_sp(reg_size as i32);
        
        self.push_assign(reg_var, reg_ty, Expression::Load(stack_var));

    }

    fn decode_lea_r_m(&mut self, inst: &Instruction) {

        // mem_size with LEA would be null, so we use the size of the register
        let mem_var = self.decode_mem_addr(inst, Type::VOID);
        let reg = inst.op0_register();
        self.set_reg_var(reg, mem_var);

    }

    fn decode_int_op_rm_imm(&mut self, inst: &Instruction, op: IntOp) {
        let imm = inst.immediate64() as i64;
        match inst.op0_register() {
            Register::None => {
                // <op> [], imm
                let mem_size = inst.memory_size().size() as u16;
                let mem_ty = Type::from_integer_size(mem_size);
                let mem_var = self.decode_mem_addr(inst, mem_ty);
                // Temp variable to store loaded value.
                let val_var = self.create_dummy_var();
                self.push_assign(val_var, mem_ty, Expression::Load(mem_var));
                // Temp variable to store result of operation.
                let tmp_var = self.create_dummy_var();
                self.push_assign(tmp_var, mem_ty, match op {
                    IntOp::Add => Expression::Add(val_var, Value::Val(imm)),
                    IntOp::Sub => Expression::Sub(val_var, Value::Val(imm)),
                });
                // Store the final value back on mem pointer.
                self.push_store(mem_var, tmp_var)
            }
            Register::RSP => {
                // <op> rsp, imm
                match op {
                    IntOp::Add => self.add_sp(imm as i32),
                    IntOp::Sub => self.sub_sp(imm as i32),
                };
            }
            reg => {
                // <op> <reg>, imm
                let reg_size = reg.size() as u16;
                let reg_ty = Type::from_integer_size(reg_size);
                let reg_var = self.read_reg_var(reg, reg_ty);
                self.push_assign(reg_var, reg_ty, match op {
                    IntOp::Add => Expression::Add(reg_var, Value::Val(imm)),
                    IntOp::Sub => Expression::Sub(reg_var, Value::Val(imm)),
                });
            }
        }
    }

    fn decode_mov_r_imm(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let imm = inst.immediate64();

        if let Register::SP | Register::ESP | Register::RSP = reg {
            // mov rsp, imm
            panic!("move to sp cause undefined final address");
        } else {
            // mov <reg>, imm
            let reg_var = self.write_reg_var(reg);
            let reg_ty = Type::from_integer_size(reg.size() as u16);
            self.push_assign(reg_var, reg_ty, Expression::Constant(imm as i64));
        }

    }

    fn decode_mov_r_rm(&mut self, inst: &Instruction) {

        let reg0 = inst.op0_register();
        let reg0_ty = Type::from_integer_size(reg0.size() as u16);

        match inst.op1_register() {
            Register::None => {
                // mov <reg0>, []
                let mem_var = self.decode_mem_addr(inst, reg0_ty);
                let reg0_var = self.write_reg_var(reg0);
                self.push_assign(reg0_var, reg0_ty, Expression::Load(mem_var));
            }
            Register::RSP => {
                // mov <reg0>, rsp
                panic!("move from RSP is unsupported");
            }
            reg1 => {
                if let Register::SP | Register::ESP | Register::RSP = reg0 {
                    // mov sp, r
                    let reg1_val = self.get_reg_const(reg1)
                        .expect("move to sp requires constant value in right register");
                    self.stack_pointer = reg1_val as i32;
                } else {
                    // mov <reg0>, <reg1>
                    let reg1_var = self.read_reg_var(reg1, reg0_ty);
                    self.set_reg_var(reg0, reg1_var);
                }

            }
        }

    }

    fn decode_mov_rm_r(&mut self, inst: &Instruction) {

        let reg1 = inst.op1_register();
        let reg1_ty = Type::from_integer_size(reg1.size() as u16);

        match inst.op0_register() {
            Register::None => {
                // mov [], <reg1>
                let mem_var = self.decode_mem_addr(inst, reg1_ty);
                let reg1_var = self.read_reg_var(reg1, reg1_ty);
                self.push_store(mem_var, reg1_var);
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov rsp, <reg1>
                let reg1_val = self.get_reg_const(reg1)
                    .expect("move to sp requires constant value in right register");
                self.stack_pointer = reg1_val as i32;
            }
            reg0 => {
                // mov <reg0>, <reg1>
                let reg1_var = self.read_reg_var(reg1, reg1_ty);
                self.set_reg_var(reg0, reg1_var);
            }
        }

    }

    fn decode_call_rel(&mut self, inst: &Instruction) {
        let pointer = inst.near_branch64();
        let ret_var = self.create_dummy_var();
        self.push_assign(ret_var, Type::VOID, Expression::Call { 
            pointer: Value::Val(pointer as i64),
            arguments: Vec::new(),
        });
    }

    fn decode_call_rm(&mut self, inst: &Instruction) {
        let ret_var = self.var_factory.create();
        let pointer_var = match inst.op0_register() {
            Register::None => self.decode_mem_addr(inst, Type::VOID),
            reg => self.read_reg_var(reg, Type::VOIDP),
        };
        self.push_assign(ret_var, Type::VOID, Expression::Call { 
            pointer: Value::Var(pointer_var),
            arguments: Vec::new(),
        });
    }

    // fn decode_cmp_rm_imm(&mut self, inst: &Instruction) {

    //     let (left_var, var_ty) = match inst.op0_register() {
    //         Register::None => {
    //             let (mem_var, mem_size) = self.decode_mem_addr(inst);
    //             let var = self.var_factory.create();
    //             let var_ty = Type::from_integer_size(mem_size);
    //             self.push_assign(var, var_ty.clone(), IdrExpression::Deref { base: mem_var, offset: 0 });
    //             (var, var_ty)
    //         }
    //         reg => {
    //             (self.decode_read_register(reg), Type::from_integer_size(reg.size() as u16))
    //         },
    //     };

    //     let right_var = self.var_factory.create();

    //     self.push_assign(right_var, var_ty.clone(), IdrExpression::Constant(inst.immediate64() as i64));

    //     self.cmp = Some(AnalyzerCmp { 
    //         left_var, 
    //         right_var, 
    //         ty: var_ty,
    //         kind: AnalyzerCmpKind::Cmp,
    //     });

    // }

    fn decode_test_rm_r(&mut self, inst: &Instruction) {

        let right_reg = inst.op1_register();
        let reg_ty = Type::from_integer_size(right_reg.size() as u16);
        let right_var = self.read_reg_var(right_reg, reg_ty);

        let left_var = match inst.op0_register() {
            Register::None => {
                let mem_var = self.decode_mem_addr(inst, reg_ty);
                let var = self.var_factory.create();
                self.push_assign(var, reg_ty.clone(), Expression::Load(mem_var));
                var
            }
            reg => self.read_reg_var(reg, reg_ty)
        };

        self.cmp = Some(Cmp {
            left: Value::Var(left_var),
            right: Value::Var(right_var),
            ty: reg_ty,
            kind: CmpKind::Test,
        });

    }

    // fn decode_jcc(&mut self, inst: &Instruction) {

    //     // Note that we take the comparison, so it is replaced 
    //     // with none. Even if jump instructions doesn't clear
    //     // the comparison flags, because of the switch of
    //     // basic blocks, we should clear it (at least for now). 
    //     if let Some(cmp) = self.cmp.take() {

    //         let pointer = inst.near_branch64();

    //         match cmp.kind {
    //             AnalyzerCmpKind::Cmp => {

    //                 let idr_cond = match inst.condition_code() {
    //                     ConditionCode::None => unreachable!(),
    //                     ConditionCode::o => todo!(),
    //                     ConditionCode::no => todo!(),
    //                     ConditionCode::b => IdrCondition::UnsignedLower,
    //                     ConditionCode::ae => IdrCondition::UnsignedGreaterOrEqual,
    //                     ConditionCode::e => IdrCondition::Equal,
    //                     ConditionCode::ne => IdrCondition::NotEqual,
    //                     ConditionCode::be => IdrCondition::UnsignedLowerOrEqual,
    //                     ConditionCode::a => IdrCondition::UnsignedGreater,
    //                     ConditionCode::s => todo!(),
    //                     ConditionCode::ns => todo!(),
    //                     ConditionCode::p => todo!(),
    //                     ConditionCode::np => todo!(),
    //                     ConditionCode::l => IdrCondition::SignedLower,
    //                     ConditionCode::ge => IdrCondition::SignedGeaterOrEqual,
    //                     ConditionCode::le => IdrCondition::SignedLowerOrEqual,
    //                     ConditionCode::g => IdrCondition::SignedGreater,
    //                 };
    
    //                 self.push_branch(pointer, cmp.left_var, cmp.right_var, idr_cond);

    //             }
    //             AnalyzerCmpKind::Test => {

    //                 let test_var;

    //                 // A common usage for test is to test if a variable 
    //                 // is equal to 0 or not, in this case the pattern is
    //                 // > test r0, r0
    //                 // > JE  => if r0 == 0
    //                 // > JNE => if r0 != 0
    //                 if cmp.left_var == cmp.right_var {
    //                     test_var = cmp.left_var;
    //                 } else {
    //                     test_var = self.var_factory.create();
    //                     self.push_assign(test_var, cmp.ty.clone(), IdrExpression::And(cmp.left_var, cmp.right_var));
    //                 }

    //                 let idr_cond = match inst.condition_code() {
    //                     ConditionCode::e => IdrCondition::Equal,
    //                     ConditionCode::ne => IdrCondition::NotEqual,
    //                     _ => todo!("unsupported condition code with 'test'"),
    //                 };

    //                 let zero_var = self.var_factory.create();
    //                 self.push_assign(zero_var, cmp.ty, IdrExpression::Constant(0));

    //                 self.push_branch(pointer, test_var, zero_var, idr_cond);

    //             }
    //         }

    //     } else {
    //         // No preceding comparison, error.
    //         self.function.statements.push(IdrStatement::Error);
    //     }

    // }   

}


struct BasicBlockTracker {
    /// Index of this basic block within the function's lines.
    index: usize,
    /// Each parameter is mapped to a specific memory slot.
    params: Vec<FunctionParam>,
    /// Mapping of which variable is contained in specific
    /// memory slots.
    vars: HashMap<FunctionParam, IdrVar>,
}

/// Describe how a parameter is passed to a basic block when
/// branched to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FunctionParam {
    /// The parameter's value is passed in the given register.
    Reg(Register),
    /// The parameter isn't really passed but is guarenteed to
    /// exists in the stack, the type of this is a pointer.
    Stack(i32),
}

impl BasicBlockTracker {

    pub fn new(index: usize) -> Self {
        Self {
            index,
            params: Vec::new(),
            vars: HashMap::new(),
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

    fn get(&self, var: IdrVar) -> Option<i64> {
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


/// Internally used in a common function for all integer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntOp {
    Add,
    Sub,
}


/// Internal structure used to track possible comparisons.
#[derive(Debug, Clone)]
struct Cmp {
    left: Value,
    right: Value,
    ty: Type,
    kind: CmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpKind {
    Cmp,
    Test,
}


// /// Used to keep track of registers.
// #[derive(Debug, Default)]
// struct RegisterTracker {
//     /// RAX/RCX/RDX/RBX/RSI/RDI/R8-R15
//     gp: [RegisterSlot; 16],
// }

// #[derive(Debug)]
// enum RegisterSlot {
//     /// The register is currently unused.
//     Uninit,
//     /// The register is currently bound to a variable
//     /// and a specific length is used.
//     Init {
//         var: IdrVar,
//         _len: u16,
//     },
// }

// impl Default for RegisterSlot {
//     fn default() -> Self {
//         Self::Uninit
//     }
// }

// impl RegisterSlot {

//     fn var(&self) -> Option<IdrVar> {
//         match *self {
//             Self::Init { var, .. } => Some(var),
//             _ => None,
//         }
//     }

// }

// impl RegisterTracker {

//     fn get_var(&self, register: Register) -> Option<IdrVar> {
//         if register.is_gpr() {
//             self.gp[register.number()].var()
//         } else {
//             unimplemented!("this kind of register '{register:?}' is not yet supported");
//         }
//     }

//     fn set_var(&mut self, register: Register, var: IdrVar) {
//         if register.is_gpr() {
//             self.gp[register.number()] = RegisterSlot::Init { 
//                 var, 
//                 _len: register.size() as u16 
//             };
//         } else {
//             unimplemented!("this kind of register '{register:?}' is not yet supported");
//         }
//     }

// }


// /// Simulation of the stack, used to track which slot is used
// /// for which variable.
// #[derive(Debug, Default)]
// struct StackTracker {
//     /// Associate to each stack byte a place.
//     stack: VecDeque<Option<StackSlot>>,
//     /// Address of the first byte in the stack.
//     stack_base: i32,
//     /// Current stack pointer.
//     stack_pointer: i32,
// }

// #[derive(Debug)]
// struct StackSlot {
//     /// The variable store here. Actually, the given variable is
//     /// a pointer to the slot.
//     var: IdrVar,
//     /// The byte offset within the variable.
//     offset: u16,
// }

// impl StackTracker {

//     #[inline]
//     fn sp(&self) -> i32 {
//         self.stack_pointer
//     }

//     fn sub_sp(&mut self, n: u16) -> i32 {
//         self.stack_pointer -= n as i32;
//         self.stack_pointer
//     }

//     fn add_sp(&mut self, n: u16) -> i32 {
//         self.stack_pointer += n as i32;
//         self.stack_pointer
//     }

//     /// Store a value at an absolute address on stack.
//     fn store(&mut self, addr: i32, len: u16, var: IdrVar) {

//         if addr < self.stack_base {
//             for _ in addr..self.stack_base {
//                 self.stack.push_front(None);
//                 self.stack_base -= 1;
//             }
//         }

//         let end_addr = addr + len as i32;
//         let current_end_addr = self.stack_base + self.stack.len() as i32;

//         if end_addr > current_end_addr {
//             for _ in current_end_addr..end_addr {
//                 self.stack.push_back(None);
//             }
//         }

//         for offset in 0..len {
//             let idx = (addr + offset as i32 - self.stack_base) as usize;
//             self.stack[idx] = Some(StackSlot {
//                 var,
//                 offset,
//             });
//         }

//         self.debug();

//     }

//     fn store_from_sp(&mut self, offset: i32, len: u16, var: IdrVar) -> i32 {
//         let offset = self.stack_pointer + offset;
//         self.store(offset, len, var);
//         offset
//     }

//     #[inline]
//     fn store_at_sp(&mut self, len: u16, var: IdrVar) -> i32 {
//         self.store_from_sp(0, len, var)
//     }

//     /// Get a value at an absolute address on the stack.
//     fn get(&self, addr: i32) -> Option<&StackSlot> {
//         println!("== Sim Stack GET {addr}");
//         self.stack.get((addr - self.stack_base) as usize)?.as_ref()
//     }

//     fn get_from_sp(&self, offset: i32) -> Option<&StackSlot> {
//         self.get(self.stack_pointer + offset)
//     }

//     #[inline]
//     fn get_at_sp(&self) -> Option<&StackSlot> {
//         self.get_from_sp(0)
//     }

//     /// FIXME: TEMPORARY
//     /// 
//     /// Debug print
//     fn debug(&self) {

//         println!("== Sim Stack");
//         println!(" = SP: {}", self.stack_pointer);
//         for (i, slot) in self.stack.iter().enumerate().rev() {
//             let addr = self.stack_base + i as i32;
//             print!(" = {addr}:");
//             if let Some(slot) = slot {
//                 println!(" {slot:?}");
//             } else {
//                 println!();
//             }
//         }

//     }

// }


// /// # Windows x64 ABI and calling convention.
// /// 
// /// ## Links
// /// - https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
// /// - https://learn.microsoft.com/en-us/cpp/build/stack-usage
// /// - https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog
// /// - https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
// /// 
// /// ## Register volatility
// /// Volatile registers: `RAX`, `RCX`, `RDX`, `R8-R11`, `XMM0-XMM5`.
// /// 
// /// Non-volatile registers: `RBX`, `RBP`, `RDI`, `RSI`, `RSP`, `R12-R15`, `XMM6-XMM15`.
// /// 
// /// Volatile registers should be considered destroyed when calling a function, and
// /// must be saved by the caller if needed. Non-volatile registers should not and 
// /// therefore should be saved/restored by callee.
// /// 
// /// ## Stack overview
// /// Here is an overview of the stack of such calling convention.
// /// 
// /// ```txt
// ///  ╒═ func A ═══════════════╕
// ///  │ Local variables and    │
// ///  │ saved non-volatile     │
// ///  │ registers.             │
// ///  ├────────────────────────┤
// ///  │ Space for alloca,      │
// ///  │ if relevant.           │
// ///  ├───────┬────────────────┤
// ///  │ Stack │ Nth            │ (1)(2) 
// ///  │ args  ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
// ///  │       │ 5th            │
// ///  ├───────┼────────────────┤
// ///  │ Reg   │ R9 home (4th)  │ (3)
// ///  │ args  ├────────────────┤
// ///  │ homes │ R8 home (3rd)  │ 
// ///  │       ├────────────────┤
// ///  │       │ RDX home (2nd) │
// ///  │       ├────────────────┤       
// ///  │       │ RCX home (1st) │
// ///  ├───────┴────────────────┤ ← 16-bytes align 
// ///  │ Caller return addr     │ ← call B
// ///  ╞═ func B ═══════════════╡ 
// ///  │                        │
// ///  │ ... same as above      │
// ///  │                        │
// ///  └────────────────────────┘
// /// 
// /// (1) Each slot is 8-bytes wide and aligned,
// ///     if an argument is smaller than 8 bytes,
// ///     it is right-aligned and if greater,
// ///     a pointer to it is used.
// /// (2) The number N of slots is the maximum
// ///     number of arguments needed for a call
// ///     in the function body.
// /// (3) Even if less than 4 arguments are needed,
// ///     the 4 "home" slots are guaranteed to be 
// ///     present. They are allocated in the caller 
// ///     but owned/used by the callee.
// /// ```
// struct Win64 {
//     state: Win64State,
//     /// True if the parent "home" stack slots are used.
//     stack_home_used: bool,
//     /// Number of parameters likelly used by this function.
//     parameters_count: u16,
// }

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// enum Win64State {
//     Invalid,
//     StackSaving,
// }

// impl Win64 {

//     /// Pattersn:
//     /// - `mov [rsp+ADDR], reg`.
//     /// - `push reg`
//     fn stack_saved(&mut self, addr: i32, reg: Register) {

//         if self.state != Win64State::StackSaving {
//             return;
//         }

//         let mut new_parameters_count = 0;

//         match reg {
//             // Saved a non-volatile register.
//             Register::RBX |
//             Register::RBP |
//             Register::RDI |
//             Register::RSI |
//             Register::R12 |
//             Register::R13 |
//             Register::R14 |
//             Register::R15 => {
                
//             }
//             // Saved a parameter register. 
//             // This implies that these registers are used for arguments.
//             Register::RCX => new_parameters_count = 1,
//             Register::RDX => new_parameters_count = 2,
//             Register::R8 => new_parameters_count = 3,
//             Register::R9 => new_parameters_count = 4,
//             // When unexpected registers are saved, the state is invalid.
//             _ => {
//                 self.state = Win64State::Invalid;
//                 return;
//             }
//         }

//         if addr >= 8 {
//             self.stack_home_used = true;
//             if addr > 40 {
//                 // Out of range home stack access.
//                 self.state = Win64State::Invalid;
//                 return;
//             }
//         }

//         self.parameters_count = self.parameters_count.max(new_parameters_count);

//     }

//     fn reg_read(&mut self) {

//     }

// }
