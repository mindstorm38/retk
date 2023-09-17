//! Primitive IDR analysis, constructing an non-optimized IDR.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use iced_x86::{Instruction, Code, Register};

use crate::analyzer::{Analysis, Analyzer};

use crate::idr::{Statement, Name, NameFactory, Expression, Create, Store};
use crate::idr::types::{TypeSystem, Type, PrimitiveType};

use super::Backend;


/// This analysis fetch every instruction and construct a first primitive IDR.
#[derive(Default)]
pub struct IdrAnalysis { }

impl<'data> Analysis<Backend<'data>> for IdrAnalysis {

    fn analyze(&mut self, analyzer: &mut Analyzer<Backend<'data>>) {
        
        let decoder = &mut analyzer.backend.decoder;

        for section in &analyzer.backend.sections.code {

            decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);
            while let Some(inst) = decoder.decode() {

            }

        }

    }

}


const TY_VOID: Type = PrimitiveType::Int(0).plain();
const TY_BYTE: Type = PrimitiveType::Int(8).plain();
const TY_WORD: Type = PrimitiveType::Int(16).plain();
const TY_DWORD: Type = PrimitiveType::Int(32).plain();
const TY_QWORD: Type = PrimitiveType::Int(64).plain();


struct Decoder {
    /// Internal basic blocks resolver.
    blocks: BasicBlockResolver,
    /// Internal type system.
    type_system: TypeSystem,
    /// The name factory for the current basic block.
    name_factory: NameFactory,

    inputs: HashMap<>,
    /// Mapping of registers to the variable they hold.
    variables: HashMap<Register, Name>,
    /// Tracker for constant value stored in variables.
    constants: Constants,
    /// Current stack pointer. It is common through all of the function.
    stack_pointer: i32,
    /// Track the last comparison that might be used in a lated
    /// conditional jump.
    cmp: Option<Cmp>,
}

impl Decoder {

    pub fn new() -> Self {
        Self {
            blocks: BasicBlockResolver::default(),
            type_system: TypeSystem::new(64, 8),
            name_factory: NameFactory::default(),
            variables: HashMap::new(),
            constants: Constants::default(),
            stack_pointer: 0,
            cmp: None,
        }
    }

    pub fn feed(&mut self, inst: &Instruction) {

        println!("- {inst}");

        let ip = inst.ip();
        
        match inst.code() {
            // NOP
            Code::Nopw |
            Code::Nopd |
            Code::Nopq |
            Code::Nop_rm16 |
            Code::Nop_rm32 |
            Code::Nop_rm64 |
            Code::Int3 => {}
            // PUSH
            Code::Push_r64 |
            Code::Push_r32 |
            Code::Push_r16 => self.decode_push_r(inst),
            // POP
            Code::Pop_r64 |
            Code::Pop_r32 |
            Code::Pop_r16 => self.decode_pop_r(inst),
            // LEA
            Code::Lea_r64_m |
            Code::Lea_r32_m |
            Code::Lea_r16_m => self.decode_lea_r_m(inst),
            // ADD
            Code::Add_rm64_imm8 |
            Code::Add_rm32_imm8 |
            Code::Add_rm16_imm8 |
            Code::Add_rm8_imm8 |
            Code::Add_rm64_imm32 |
            Code::Add_rm32_imm32 |
            Code::Add_rm16_imm16  => self.decode_int_op_rm_imm(inst, NumOp::Add),
            Code::Add_r64_rm64 |
            Code::Add_r32_rm32 |
            Code::Add_r16_rm16 |
            Code::Add_r8_rm8 |
            Code::Add_rm64_r64 |
            Code::Add_rm32_r32 |
            Code::Add_rm16_r16 |
            Code::Add_rm8_r8 => self.decode_int_op_rm_rm(inst, NumOp::Add),
            // SUB
            Code::Sub_rm64_imm8 |
            Code::Sub_rm32_imm8 |
            Code::Sub_rm16_imm8 |
            Code::Sub_rm8_imm8 |
            Code::Sub_rm64_imm32 |
            Code::Sub_rm32_imm32 |
            Code::Sub_rm16_imm16  => self.decode_int_op_rm_imm(inst, NumOp::Sub),
            Code::Sub_r64_rm64 |
            Code::Sub_r32_rm32 |
            Code::Sub_r16_rm16 |
            Code::Sub_r8_rm8 |
            Code::Sub_rm64_r64 |
            Code::Sub_rm32_r32 |
            Code::Sub_rm16_r16 |
            Code::Sub_rm8_r8 => self.decode_int_op_rm_rm(inst, NumOp::Sub),
            // SUB
            Code::Xor_rm64_imm8 |
            Code::Xor_rm32_imm8 |
            Code::Xor_rm16_imm8 |
            Code::Xor_rm8_imm8 |
            Code::Xor_rm64_imm32 |
            Code::Xor_rm32_imm32 |
            Code::Xor_rm16_imm16  => self.decode_int_op_rm_imm(inst, NumOp::Xor),
            Code::Xor_r64_rm64 |
            Code::Xor_r32_rm32 |
            Code::Xor_r16_rm16 |
            Code::Xor_r8_rm8 |
            Code::Xor_rm64_r64 |
            Code::Xor_rm32_r32 |
            Code::Xor_rm16_r16 |
            Code::Xor_rm8_r8 => self.decode_int_op_rm_rm(inst, NumOp::Xor),
            // MOV
            Code::Mov_r64_imm64 |
            Code::Mov_r32_imm32 |
            Code::Mov_r16_imm16 |
            Code::Mov_r8_imm8 |
            Code::Mov_rm64_imm32 |
            Code::Mov_rm32_imm32 |
            Code::Mov_rm16_imm16 |
            Code::Mov_rm8_imm8 => self.decode_mov_rm_imm(inst),
            Code::Mov_r64_rm64 |
            Code::Mov_r32_rm32 |
            Code::Mov_r16_rm16 |
            Code::Mov_r8_rm8 => self.decode_mov_r_rm(inst),
            Code::Mov_rm64_r64 |
            Code::Mov_rm32_r32 |
            Code::Mov_rm16_r16 |
            Code::Mov_rm8_r8 => self.decode_mov_rm_r(inst),
            // MOVSS/MOVSD
            Code::Movss_xmm_xmmm32 => self.decode_movs_r_rm(inst, false),
            Code::Movss_xmmm32_xmm => self.decode_movs_rm_r(inst, false),
            Code::Movsd_xmm_xmmm64 => self.decode_movs_r_rm(inst, true),
            Code::Movsd_xmmm64_xmm => self.decode_movs_rm_r(inst, true),
            // CALL
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
            // TEST
            Code::Test_rm64_r64 |
            Code::Test_rm32_r32 |
            Code::Test_rm16_r16 |
            Code::Test_rm8_r8 => self.decode_test_rm_r(inst),
            // Jcc
            code if code.is_jcc_short_or_near() => self.decode_jcc(inst),
            // JMP
            Code::Jmp_rel8_64 |
            Code::Jmp_rel8_32 |
            Code::Jmp_rel8_16 |
            Code::Jmp_rel32_64 |
            Code::Jmp_rel32_32 => self.decode_jmp(inst),
            // RET
            Code::Retnq |
            Code::Retnd |
            Code::Retnw |
            Code::Retnq_imm16 |
            Code::Retnd_imm16 |
            Code::Retnw_imm16 |
            Code::Retfq |
            Code::Retfd |
            Code::Retfw |
            Code::Retfq_imm16 |
            Code::Retfd_imm16 |
            Code::Retfw_imm16 => self.decode_ret(inst),
            _ => {
                self.push_stmt(Statement::Asm(inst.to_string()));
            }
        }
    } 

    fn sub_sp(&mut self, delta: i32) -> i32 {
        self.stack_pointer -= delta;
        self.stack_pointer
    }

    fn add_sp(&mut self, delta: i32) -> i32 {
        self.stack_pointer += delta;
        self.stack_pointer
    }

    /// Create a dummy register, not linked to anything at this point.
    fn create_register(&mut self) -> Name {
        self.name_factory.next()
    }

    /// Read a stack pointer variable, ensuring that it already exists.
    fn read_stack_var(&mut self, addr: i32) -> IdrVar {
        let (bb, bb_tracker) = self.function.basic_block_mut();
        let param = FunctionParam::Stack(addr);
        match bb_tracker.variables.entry(param) {
            Entry::Occupied(o) => *o.into_mut(),
            Entry::Vacant(v) => {
                let var = self.var_factory.create();
                bb.parameters.push((var, Type::VOIDP));
                bb_tracker.parameters.push(param);
                *v.insert(var)
            }
        }
    }

    /// This function ensures that a given register is mapped to a register name. If no
    /// register is currently mapped, a new register name is created and marked as 
    /// parameter for the current basic block.
    fn read_reg_var(&mut self, reg: Register, ty: Type) -> Name {
        let bb = self.blocks.basic_block_mut();

        let (bb, bb_tracker) = self.function.basic_block_mut();
        let param = FunctionParam::Reg(reg);
        match bb_tracker.variables.entry(param) {
            Entry::Occupied(o) => *o.into_mut(),
            Entry::Vacant(v) => {
                let var = self.var_factory.create();
                bb.parameters.push((var, ty));
                bb_tracker.parameters.push(param);
                *v.insert(var)
            }
        }
    }

    /// The function creates a new register name for later writing to the given register.
    fn write_reg_var(&mut self, reg: Register) -> Name {
        let (_, bb_tracker) = self.function.basic_block_mut();
        let param = FunctionParam::Reg(reg);
        let var = self.name_factory.next();
        bb_tracker.variables.insert(param, var);
        var
    }

    fn get_reg_var(&self, reg: Register) -> Option<Name> {
        let (_, bb_tracker) = self.function.basic_block();
        bb_tracker.variables.get(&FunctionParam::Reg(reg)).copied()
    }

    fn set_reg_var(&mut self, reg: Register, var: IdrVar) {
        let (_, bb_tracker) = self.function.basic_block_mut();
        let param = FunctionParam::Reg(reg);
        bb_tracker.variables.insert(param, var);
    }

    /// Utility method for fast query of constant value stored in
    /// a register.
    fn get_reg_const(&self, reg: Register) -> Option<i64> {
        let var = self.get_reg_var(reg)?;
        self.constants.get(var)
    }

    /// Internal method to push the given statement on the current basic block.
    fn push_stmt(&mut self, stmt: Statement) {
        let bb = self.blocks.basic_block_mut();
        bb.statements.push(stmt);
    }

    /// Internal function to enqueue a statement
    fn push_assign(&mut self, register: Name, ty: Type, value: Expression) {

        // Propagate constant values.
        match value {
            Expression::LiteralInt(val) => self.constants.set(register, val),
            // Expression::Add(from, Value::Val(val)) => 
            //     self.constants.try_add(from, var, val),
            // Expression::Sub(from, Value::Val(val)) =>
            //     self.constants.try_sub(from, var, val),
            _ => {}
        }

        self.push_stmt(Statement::Create(Create { register, ty, value }));

    }

    /// Push a store statement in the current basic block.
    fn push_store(&mut self, pointer_register: Name, value: Expression) {
        self.push_stmt(Statement::Store(Store { pointer_register, value }));
    }

    /// Decode an instruction's memory addressing operand and return the variable where 
    /// the final address is stored. This variable is a pointer type to a given type 
    /// (ty) and can later be used for load or store.
    fn decode_mem_addr(&mut self, inst: &Instruction, ty: Type) -> Name {

        let mem_displ = inst.memory_displacement64() as i64;
        
        let mut var;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                // Special handling for RIP addressing, because displacement contains the
                // absolute value.
                var = self.create_register();
                self.push_assign(var, ty.pointer(1), Expression::LiteralInt(mem_displ));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // If we refer to RSP, we calculate the real address relative to the 
                // function's base. And then we check if that slot already.
                let addr = self.stack_pointer + mem_displ as i32;
                var = self.read_stack_var(addr);
                self.constants.set(var, addr as i64);
            }
            base_reg => {
                // Access relative to other registers.
                var = self.read_reg_var(base_reg, TY_VOID.pointer(1));
                if mem_displ != 0 {
                    let new_var = self.create_register();
                    let expr = Expression::Add(var, Value::Val(mem_displ));
                    self.push_assign(new_var, ty.pointer(1), expr);
                    var = new_var;
                }
            }
        }

        match inst.memory_index() {
            Register::None => {}
            index_reg => {
                // Indexed memory access converts to a GetElementPointer expression.
                var = self.create_register();
                let reg_var = self.read_reg_var(index_reg, TY_DWORD);
                let expr = Expression::GetElementPointer { 
                    pointer: var, 
                    index: reg_var, 
                    stride: inst.memory_index_scale() as u8
                };
                self.push_assign(var, ty.pointer(1), expr);
            }
        }

        var

    }

    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_size = reg.size() as u32;
        let reg_ty = PrimitiveType::Int(reg_size * 8).plain();
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

    fn decode_int_op_rm_imm(&mut self, inst: &Instruction, op: NumOp) {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // <op> [], imm
                let mem_size = inst.memory_size().size() as u16;
                let ty = Type::from_integer_size(mem_size);
                let mem_var = self.decode_mem_addr(inst, ty);
                // Temp variable to store loaded value.
                let val_var = self.create_register();
                self.push_assign(val_var, ty, Expression::Load(mem_var));
                // Temp variable to store result of operation.
                let tmp_var = self.create_register();
                self.push_assign(tmp_var, ty, match op {
                    NumOp::Add => Expression::Add(val_var, Value::Val(imm)),
                    NumOp::Sub => Expression::Sub(val_var, Value::Val(imm)),
                    NumOp::Xor => Expression::Xor(val_var, Value::Val(imm)),
                });
                // Store the final value back on mem pointer.
                self.push_store(mem_var, tmp_var)
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // <op> rsp, imm
                match op {
                    NumOp::Add => self.add_sp(imm as i32),
                    NumOp::Sub => self.sub_sp(imm as i32),
                    _ => panic!("operation {op:?} no support on sp")
                };
            }
            reg => {
                // <op> <reg>, imm
                let reg_size = reg.size() as u16;
                let reg_ty = Type::from_integer_size(reg_size);
                let reg_read_var = self.read_reg_var(reg, reg_ty);
                let reg_write_var = self.write_reg_var(reg);
                self.push_assign(reg_write_var, reg_ty, match op {
                    NumOp::Add => Expression::Add(reg_read_var, Value::Val(imm)),
                    NumOp::Sub => Expression::Sub(reg_read_var, Value::Val(imm)),
                    NumOp::Xor => Expression::Xor(reg_read_var, Value::Val(imm)),
                });
            }
        }
    }

    fn decode_int_op_rm_rm(&mut self, inst: &Instruction, op: NumOp) {
        match (inst.op0_register(), inst.op1_register()) {
            (Register::None, reg1) => {
                // <op> [], <reg1>
                let ty = Type::from_integer_size(reg1.size() as u16);
                let mem_var = self.decode_mem_addr(inst, ty);
                // Temp variable to store loaded value.
                let val_var = self.create_register();
                self.push_assign(val_var, ty, Expression::Load(mem_var));
                // Temp variable to store result of operation.
                let tmp_var = self.create_register();
                let reg1_var = self.read_reg_var(reg1, ty);
                self.push_assign(tmp_var, ty, match op {
                    NumOp::Add => Expression::Add(val_var, Value::Var(reg1_var)),
                    NumOp::Sub => Expression::Sub(val_var, Value::Var(reg1_var)),
                    NumOp::Xor => Expression::Xor(val_var, Value::Var(reg1_var)),
                    
                });
                // Store the final value back on mem pointer.
                self.push_store(mem_var, tmp_var);
            }
            (reg0, Register::None) => {
                let ty = Type::from_integer_size(reg0.size() as u16);
                let mem_var = self.decode_mem_addr(inst, ty);
                // Temp variable to store loaded value.
                let val_var = self.create_register();
                self.push_assign(val_var, ty, Expression::Load(mem_var));
                // Temp variable to store result of operation.
                let reg0_read_var = self.read_reg_var(reg0, ty);
                let reg0_write_var = self.write_reg_var(reg0);
                self.push_assign(reg0_write_var, ty, match op {
                    NumOp::Add => Expression::Add(reg0_read_var, Value::Var(val_var)),
                    NumOp::Sub => Expression::Sub(reg0_read_var, Value::Var(val_var)),
                    NumOp::Xor => Expression::Xor(reg0_read_var, Value::Var(val_var)),
                });
            }
            (reg0, reg1) if op == NumOp::Xor && reg0 == reg1 => {
                let ty = Type::from_integer_size(reg0.size() as u16);
                let reg_var = self.write_reg_var(reg0);
                self.push_assign(reg_var, ty, Expression::Constant(0));
            }
            (reg0, reg1) => {
                let ty = Type::from_integer_size(reg0.size() as u16);
                let reg1_var = self.read_reg_var(reg1, ty);
                let reg0_read_var = self.read_reg_var(reg0, ty);
                let reg0_write_var = self.write_reg_var(reg0);
                self.push_assign(reg0_write_var, ty, match op {
                    NumOp::Add => Expression::Add(reg0_read_var, Value::Var(reg1_var)),
                    NumOp::Sub => Expression::Sub(reg0_read_var, Value::Var(reg1_var)),
                    NumOp::Xor => Expression::Xor(reg0_read_var, Value::Var(reg1_var)),
                });
            }
        }
    }

    fn decode_mov_rm_imm(&mut self, inst: &Instruction) {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // mov [], imm
                let ty = Type::from_integer_size(inst.memory_size().size() as u16);
                let mem_var = self.decode_mem_addr(inst, ty);
                let val_var = self.var_factory.create();
                self.push_assign(val_var, ty, Expression::Constant(imm));
                self.push_store(mem_var, val_var);
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov rsp, imm
                panic!("move to sp cause undefined final address");
            }
            reg => {
                // mov <reg>, imm
                let reg_var = self.write_reg_var(reg);
                let ty = Type::from_integer_size(reg.size() as u16);
                self.push_assign(reg_var, ty, Expression::Constant(imm));
            }
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

    fn decode_movs_r_rm(&mut self, inst: &Instruction, double: bool) {
        let reg0 = inst.op0_register();
        let ty = if double { Type::DOUBLE } else { Type::FLOAT };
        match inst.op1_register() {
            Register::None => {
                // mov <reg0>, []
                let mem_var = self.decode_mem_addr(inst, ty);
                let reg0_var = self.write_reg_var(reg0);
                self.push_assign(reg0_var, ty, Expression::Load(mem_var));
            }
            reg1 => {
                // mov <reg0>, <reg1>
                let reg1_var = self.read_reg_var(reg1, ty);
                self.set_reg_var(reg0, reg1_var);
            }
        }
    }

    fn decode_movs_rm_r(&mut self, inst: &Instruction, double: bool) {
        let reg1 = inst.op1_register();
        let ty = if double { Type::DOUBLE } else { Type::FLOAT };
        match inst.op0_register() {
            Register::None => {
                // mov [], <reg1>
                let mem_var = self.decode_mem_addr(inst, ty);
                let reg1_var = self.read_reg_var(reg1, ty);
                self.push_store(mem_var, reg1_var);
            }
            reg0 => {
                let reg1_var = self.read_reg_var(reg1, ty);
                self.set_reg_var(reg0, reg1_var);
            }
        }
    }

    fn decode_call_rel(&mut self, inst: &Instruction) {
        let pointer = inst.near_branch64();
        let ret_var = self.create_register();
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
            left: left_var,
            right: right_var,
            ty: reg_ty,
            kind: CmpKind::Test,
        });

    }

    fn decode_jcc(&mut self, inst: &Instruction) {
        
        let Some(cmp) = self.cmp.take() else { return; };
        let pointer = inst.near_branch64();

        let cmp_var = self.var_factory.create();

        match cmp.kind {
            CmpKind::Cmp => {
                return; // TODO:
            }
            CmpKind::Test => {

                if cmp.left == cmp.right {

                    let comp = match inst.condition_code() {
                        ConditionCode::e => Comparison::Equal,
                        ConditionCode::ne => Comparison::NotEqual,
                        _ => todo!()
                    };

                    self.push_assign(cmp_var, Type::BOOL, Expression::Cmp(comp, cmp.left, Value::Val(0)));

                } else {
                    return; // TODO:
                }

            }
        }

        // A conditionnal statement creates two basic blocks.
        let then_index = self.function.ensure_basic_block(pointer);
        let else_index = self.function.ensure_basic_block(inst.next_ip());

        let (bb, _) = self.function.basic_block_mut();

        bb.branch = Branch::Conditional { 
            var: cmp_var,
            then_index, 
            then_args: Vec::new(), 
            else_index, 
            else_args: Vec::new(),
        };

    }

    fn decode_jmp(&mut self, inst: &Instruction) {
        
        let pointer = inst.near_branch64();
        let goto_index = self.function.ensure_basic_block(pointer);

        for param in &self.function.basic_block_trackers[goto_index].parameters {
            
        }
        
        let (bb, _) = self.function.basic_block_mut();
        bb.branch = Branch::Unconditional { index: goto_index, args: Vec::new() };

        self.function.basic_block_end();

    }
    
    fn decode_ret(&mut self, _inst: &Instruction) {

        let (bb, _) = self.function.basic_block_mut();
        bb.branch = Branch::Ret;

        self.function.basic_block_end();

    }

}


/// This structure keeps track of all basic blocks in the program and helps resolving all
/// of them.
#[derive(Debug, Default)]
struct BasicBlockResolver {
    /// List of all basic blocks already known to the resolver.
    blocks: Vec<BasicBlockTracker>,
    /// Mapping of instruction pointers to basic blocks.
    blocks_map: HashMap<u64, usize>,
    /// Index of the current basic block being decoded.
    block_index: Option<usize>,
}

/// Tracker structure for a single basic block.
#[derive(Debug, Default)]
struct BasicBlockTracker {
    /// IDR statements of this basic block.
    statements: Vec<Statement>,
    /// Start instruction pointer of this basic block.
    start_ip: u64,
    /// End instruction pointer (excluded) of this basic block, none if not done.
    end_ip: Option<u64>,
    /// Registers that are read by this basic block's instructions.
    input: Vec<Register>,
    /// Registers that are written to by this basic block's instructions.
    output: Vec<Register>,
}

impl BasicBlockResolver {

    #[inline]
    fn basic_block(&self) -> &BasicBlockTracker {
        &self.blocks[self.block_index.unwrap()]
    }

    #[inline]
    fn basic_block_mut(&mut self) -> &mut BasicBlockTracker {
        &mut self.blocks[self.block_index.unwrap()]
    }

    fn forward(&mut self, ip: u64) {

        let bb_index = match self.block_index {
            Some(index) => index,
            None => {
                let index = self.blocks.len();
                self.blocks.push(BasicBlockTracker::default());
                self.block_index = Some(index);
                index
            }
        };

        let bb = &mut self.blocks[bb_index];

        // // If a basic block is already defined at the new IP, we switch to it.
        // if let Some(existing_block) = self.blocks_map.get_mut(&ip) {
        //     // TODO: unconditional jump from bb to this one.
        //     self.block_index = Some()
        // }
        
    }

}


/// A tracker for variables that have constant values known
/// at analysis. This is just a hint for most variables but
/// it's useful when used analyzing optimisations around RSP.
#[derive(Debug, Default)]
struct Constants {
    inner: HashMap<Name, i64>,
}

impl Constants {

    fn set(&mut self, var: Name, val: i64) {
        self.inner.insert(var, val);
    }

    fn get(&self, var: Name) -> Option<i64> {
        self.inner.get(&var).copied()
    }

    /// If the variable `from` has a constant value, map its 
    /// value using the given function to the `to` variable.
    #[inline]
    fn try_map<F>(&mut self, from: Name, to: Name, func: F)
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
    fn try_copy(&mut self, from: Name, to: Name) {
        self.try_map(from, to, |v| v)
    }

    #[inline]
    fn try_add(&mut self, from: Name, to: Name, val: i64) {
        self.try_map(from, to, move |v| v + val)
    }

    #[inline]
    fn try_sub(&mut self, from: Name, to: Name, val: i64) {
        self.try_map(from, to, move |v| v - val)
    }

}


/// Internally used in a common function for all integer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumOp {
    Add,
    Sub,
    Xor,
}


/// Internal structure used to track possible comparisons.
#[derive(Debug, Clone)]
struct Cmp {
    left: Name,
    right: Name,
    ty: Type,
    kind: CmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpKind {
    Cmp,
    Test,
}
