//! Primitive IDR analysis, constructing an non-optimized IDR.

use std::collections::HashMap;

use iced_x86::{Instruction, Code, Register, ConditionCode};

use crate::analyzer::{Analysis, Analyzer};

use crate::idr::{Statement, Place, PlaceFactory, Expression, Bind, Store, Value, Comparison};
use crate::idr::types::{Type, PrimitiveType, TypeSystem};
use crate::idr::print::StatementsDisplay;

use super::Backend;


/// This analysis fetch every instruction and construct a first primitive IDR.
#[derive(Default)]
pub struct IdrAnalysis { }

impl<'data> Analysis<Backend<'data>> for IdrAnalysis {

    fn analyze(&mut self, analyzer: &mut Analyzer<Backend<'data>>) {
        
        let decoder = &mut analyzer.backend.decoder;
        let mut block_decoder = BasicBlockDecoder::new();

        // Start from the first section.
        let Some(section) = analyzer.backend.sections.code.first() else {
            return;
        };

        decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);

        loop {

            while let Some(inst) = decoder.decode() {

                if let Some(new_ip) = block_decoder.feed(inst) {

                    let section = analyzer.backend.sections.get_code_section_at(new_ip)
                        .expect("unknown pointed section");

                    let new_ip_offset = new_ip - section.begin_addr;
                    let section_pos = section.pos + new_ip_offset as usize;
                    decoder.goto_range_at(section_pos, new_ip, section.end_addr);

                }

            }

        }

    }

}


const TY_VOID: Type = PrimitiveType::Int(0).plain();
const TY_BOOL: Type = PrimitiveType::Int(1).plain();
const TY_BYTE: Type = PrimitiveType::Int(8).plain();
const TY_WORD: Type = PrimitiveType::Int(16).plain();
const TY_DWORD: Type = PrimitiveType::Int(32).plain();
const TY_QWORD: Type = PrimitiveType::Int(64).plain();
const TY_FLOAT: Type = PrimitiveType::Float.plain();
const TY_DOUBLE: Type = PrimitiveType::Double.plain();


/// Create an integer type from the given number of bytes.
const fn ty_from_int_bytes(bytes: usize) -> Type {
    PrimitiveType::Int(bytes as u32 * 8).plain()
}


/// This internal decoder is used as the first pass in IDR analysis, it simply find and
/// decode each basic block to a simple IDR. This decoder keeps a lot of intermediate 
/// details about each function's call but doesn't determine which basic blocks are
/// function entries.
struct BasicBlockDecoder {
    /// This structure holds all attribute used to decompile the current basic block to 
    /// the intermediate representation.
    block: Option<BasicBlockTracker>,
    /// Mapping of basic block's entry point adresses to there decoding information.
    blocks: HashMap<u64, BasicBlockInfo>,
    /// Queue for next basic blocks to decode.
    blocks_queue: Vec<u64>,
    /// Type system (for now used for debugging type names).
    type_system: TypeSystem,
}

impl BasicBlockDecoder {

    fn new() -> Self {
        Self {
            block: None,
            blocks: HashMap::new(),
            blocks_queue: Vec::new(),
            type_system: TypeSystem::new(64, 8),
        }
    }

    /// Feed the decoder with a new instruction of the current basic block. 
    /// This may return a new instruction pointer to jump to.
    #[must_use]
    fn feed(&mut self, inst: &Instruction) -> Option<u64> {

        let ip = inst.ip();
        let block = self.block.get_or_insert_with(|| BasicBlockTracker::new(ip));
        
        println!("[{ip:08X} (+{:02})] {inst}", ip - block.start_ip);
        
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
            Code::Push_r16 => block.decode_push_r(inst),
            // POP
            Code::Pop_r64 |
            Code::Pop_r32 |
            Code::Pop_r16 => block.decode_pop_r(inst),
            // LEA
            Code::Lea_r64_m |
            Code::Lea_r32_m |
            Code::Lea_r16_m => block.decode_lea_r_m(inst),
            // ADD
            Code::Add_rm64_imm8 |
            Code::Add_rm32_imm8 |
            Code::Add_rm16_imm8 |
            Code::Add_rm8_imm8 |
            Code::Add_rm64_imm32 |
            Code::Add_rm32_imm32 |
            Code::Add_rm16_imm16  => block.decode_int_op_rm_imm(inst, IntOp::Add),
            Code::Add_r64_rm64 |
            Code::Add_r32_rm32 |
            Code::Add_r16_rm16 |
            Code::Add_r8_rm8 |
            Code::Add_rm64_r64 |
            Code::Add_rm32_r32 |
            Code::Add_rm16_r16 |
            Code::Add_rm8_r8 => block.decode_int_op_rm_rm(inst, IntOp::Add),
            // SUB
            Code::Sub_rm64_imm8 |
            Code::Sub_rm32_imm8 |
            Code::Sub_rm16_imm8 |
            Code::Sub_rm8_imm8 |
            Code::Sub_rm64_imm32 |
            Code::Sub_rm32_imm32 |
            Code::Sub_rm16_imm16  => block.decode_int_op_rm_imm(inst, IntOp::Sub),
            Code::Sub_r64_rm64 |
            Code::Sub_r32_rm32 |
            Code::Sub_r16_rm16 |
            Code::Sub_r8_rm8 |
            Code::Sub_rm64_r64 |
            Code::Sub_rm32_r32 |
            Code::Sub_rm16_r16 |
            Code::Sub_rm8_r8 => block.decode_int_op_rm_rm(inst, IntOp::Sub),
            // SUB
            Code::Xor_rm64_imm8 |
            Code::Xor_rm32_imm8 |
            Code::Xor_rm16_imm8 |
            Code::Xor_rm8_imm8 |
            Code::Xor_rm64_imm32 |
            Code::Xor_rm32_imm32 |
            Code::Xor_rm16_imm16  => block.decode_int_op_rm_imm(inst, IntOp::Xor),
            Code::Xor_r64_rm64 |
            Code::Xor_r32_rm32 |
            Code::Xor_r16_rm16 |
            Code::Xor_r8_rm8 |
            Code::Xor_rm64_r64 |
            Code::Xor_rm32_r32 |
            Code::Xor_rm16_r16 |
            Code::Xor_rm8_r8 => block.decode_int_op_rm_rm(inst, IntOp::Xor),
            // MOV
            Code::Mov_r64_imm64 |
            Code::Mov_r32_imm32 |
            Code::Mov_r16_imm16 |
            Code::Mov_r8_imm8 |
            Code::Mov_rm64_imm32 |
            Code::Mov_rm32_imm32 |
            Code::Mov_rm16_imm16 |
            Code::Mov_rm8_imm8 => block.decode_mov_rm_imm(inst),
            Code::Mov_r64_rm64 |
            Code::Mov_r32_rm32 |
            Code::Mov_r16_rm16 |
            Code::Mov_r8_rm8 => block.decode_mov_r_rm(inst),
            Code::Mov_rm64_r64 |
            Code::Mov_rm32_r32 |
            Code::Mov_rm16_r16 |
            Code::Mov_rm8_r8 => block.decode_mov_rm_r(inst),
            // MOVZX (move zero-extended)
            Code::Movzx_r64_rm16 |
            Code::Movzx_r64_rm8 |
            Code::Movzx_r32_rm16 |
            Code::Movzx_r32_rm8 |
            Code::Movzx_r16_rm16 |
            Code::Movzx_r16_rm8 => block.decode_movzx_r_rm(inst),
            // MOVSS/MOVSD
            Code::Movss_xmm_xmmm32 => block.decode_movs_r_rm(inst, false),
            Code::Movss_xmmm32_xmm => block.decode_movs_rm_r(inst, false),
            Code::Movsd_xmm_xmmm64 => block.decode_movs_r_rm(inst, true),
            Code::Movsd_xmmm64_xmm => block.decode_movs_rm_r(inst, true),
            // TEST
            Code::Test_rm64_r64 |
            Code::Test_rm32_r32 |
            Code::Test_rm16_r16 |
            Code::Test_rm8_r8 => block.decode_test_rm_r(inst),
            // CALL
            Code::Call_rel16 |
            Code::Call_rel32_32 |
            Code::Call_rel32_64 => return self.decode_call_rel(inst),
            Code::Call_rm64 |
            Code::Call_rm32 |
            Code::Call_rm16 => self.decode_call_rm(inst),
            // Code::Cmp_rm64_imm8 |
            // Code::Cmp_rm32_imm8 |
            // Code::Cmp_rm16_imm8 |
            // Code::Cmp_rm64_imm32 |
            // Code::Cmp_rm32_imm32 |
            // Code::Cmp_rm16_imm16 => self.decode_cmp_rm_imm(inst),
            // Jcc
            code if code.is_jcc_short_or_near() => return self.decode_jcc(inst),
            // JMP
            Code::Jmp_rel8_64 |
            Code::Jmp_rel8_32 |
            Code::Jmp_rel8_16 |
            Code::Jmp_rel32_64 |
            Code::Jmp_rel32_32 => return self.decode_jmp(inst),
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
            Code::Retfw_imm16 => return self.decode_ret(inst),
            _ => {
                println!("  (unknown)");
                block.push_stmt(Statement::Asm(inst.to_string()));
            }
        }

        None

    }

    fn decode_call_rel(&mut self, inst: &Instruction) -> Option<u64> {

        // The instruction pointer of the basic block to call, we decode it first so we
        // can later resume the decoding of the current basic block with better knowledge
        // of the input operands.
        // TODO: Check if this points to a know basic block.
        let pointer = inst.near_branch64();

        // We are on a branching instruction, take the current tracker and prepare next
        // one that will track the called basic block.
        let block = self.block.take().unwrap();

        println!("decode_call_rel:\n{}", StatementsDisplay {
            statements: &block.statements,
            type_system: &self.type_system,
        });

        // Before switching to the next block, save the current block's information.
        self.blocks.insert(block.start_ip, BasicBlockInfo { 
            statements: block.statements, 
            start_ip: block.start_ip,
            end_ip: None, // Our basic block is not finished, call will return in it.
        });

        // We need to re-decode this block later...
        self.blocks_queue.push(block.start_ip);

        Some(pointer)

    }

    fn decode_call_rm(&mut self, inst: &Instruction) {
        unimplemented!("decode_call_rm")
        // let ret_var = self.var_factory.create();
        // let pointer_var = match inst.op0_register() {
        //     Register::None => self.decode_mem_addr(inst, Type::VOID),
        //     reg => self.read_reg_var(reg, Type::VOIDP),
        // };
        // self.push_assign(ret_var, Type::VOID, Expression::Call { 
        //     pointer: Value::Var(pointer_var),
        //     arguments: Vec::new(),
        // });
    }

    /*fn decode_cmp_rm_imm(&mut self, inst: &Instruction) {

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

    }*/

    fn decode_jmp(&mut self, inst: &Instruction) -> Option<u64> {
        
        let pointer = inst.near_branch64();

        // Check if the pointed block is already decoded or not, if so we ignore it.
        if let Some(pointed_block) = self.blocks.get(&pointer) {
            if pointed_block.end_ip.is_some() {
                return None;
            }
        }

        // We are on a branching instruction, take the current tracker and prepare next
        // one that will track the called basic block.
        let block = self.block.take().unwrap();

        println!("decode_jmp:\n{}", StatementsDisplay {
            statements: &block.statements,
            type_system: &self.type_system,
        });

        // Before switching to the next block, save the current block's information.
        self.blocks.insert(block.start_ip, BasicBlockInfo { 
            statements: block.statements, 
            start_ip: block.start_ip,
            end_ip: Some(inst.next_ip()), // Our basic block is finished.
        });

        Some(pointer)

    }

    fn decode_jcc(&mut self, inst: &Instruction) -> Option<u64> {

        let mut block = self.block.take().unwrap();
        let cmp = block.cmp.take().expect("missing previous cmp");

        let pointer = inst.near_branch64();

        let cmp_place = block.create_place();
        match cmp.kind {
            // Comparison performs a subtraction.
            CmpKind::Cmp => {
                unimplemented!("decode_jcc: cmp");
            }
            // Test performs a bitwise and.
            CmpKind::Test => {

                // Testing a register against itself is a shortcut for testing if it
                // equals zero or not, other conditional branches are not usual.
                if cmp.left_place == cmp.right_place {

                    let expr_cmp = match inst.condition_code() {
                        ConditionCode::e => Comparison::Equal,
                        ConditionCode::ne => Comparison::NotEqual,
                        _ => unimplemented!("decode_jcc: test same place with unsupported condition")
                    };

                    block.push_bind(cmp_place, TY_BOOL, Expression::Cmp(expr_cmp, Value::Place(cmp.left_place), Value::LiteralInt(0)));

                } else {
                    unimplemented!("decode_jcc: test between different places");
                }

            }
        }

        self.blocks.insert(pointer, BasicBlockInfo::new(pointer));
        self.blocks.insert(inst.next_ip(), BasicBlockInfo::new(inst.next_ip()));

        // We need to decode the next block (second jcc branch) later...
        self.blocks_queue.push(inst.next_ip());

        println!("decode_jcc:\n{}", StatementsDisplay { 
            statements: &block.statements,
            type_system: &self.type_system,
        });

        None

    }
    
    fn decode_ret(&mut self, inst: &Instruction) -> Option<u64> {

        // Return is an unconditional jump to a statically unknown instruction pointer,
        // so we just stop decoding the current basic block and work again and resume
        // the last unfinished basic block.

        // Complete the current basic block and push it in blocks map.
        let block = self.block.take().unwrap();

        println!("decode_ret:\n{}", StatementsDisplay { 
            statements: &block.statements,
            type_system: &self.type_system,
        });
        
        self.blocks.insert(block.start_ip, BasicBlockInfo { 
            statements: block.statements, 
            start_ip: block.start_ip,
            end_ip: Some(inst.next_ip()), // Our basic block is finished.
        });

        self.find_next_block()

    }

    fn find_next_block(&mut self) -> Option<u64> {

        while let Some(next_ip) = self.blocks_queue.pop() {
            // If the block already exists, do not decode it again if it is already done.
            // If it doesn't exists, just go to it.
            if let Some(next_block) = self.blocks.get(&next_ip) {
                if next_block.end_ip.is_none() {
                    return Some(next_ip);
                }
            } else {
                return Some(next_ip);
            }
        }

        None

    }

}

/// Substructure of the IDR decoder that tracks the decoding of the current basic block.
#[derive(Debug, Default)]
struct BasicBlockTracker {
    /// Instruction pointer of the first decoded instruction.
    start_ip: u64,
    /// The name factory for the current basic block.
    place_factory: PlaceFactory,
    /// Location mapping for input places.
    inputs: HashMap<Location, Place>,
    /// Location mapping for output places, this also stores places used for the basic 
    /// block's body decoding.
    place: HashMap<Location, Place>,
    /// Tracker for constant value stored in variables.
    constants: Constants,
    /// Current stack pointer. It is common through all of the function.
    stack_pointer: i32,
    /// Track the last comparison that might be used in a later conditional jump.
    cmp: Option<Cmp>,
    /// IDR statements of this basic block.
    statements: Vec<Statement>,
}

/// Each place is bound to a hardware location known at (de)compile-time (statically-known
/// locations), such locations are hardware registers and stack variables. Each place may
/// be stored in multiple locations at once, it's possible because of the *SSA form* used,
/// so each place have only one value in its lifetime and this value can be stored in 
/// multiple places if needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Location {
    /// The place is located in a x86 hardware register.
    Register(Register),
    /// The place is located in the stack, starting at the given stack offset *(relative
    /// to the basic-block stack frame pointer).
    Stack(i32),
}

impl BasicBlockTracker {

    fn new(start_ip: u64) -> Self {
        Self {
            start_ip,
            ..Self::default()
        }
    }

    /// Subtract a delta from the current stack pointer.
    fn sub_sp(&mut self, delta: i32) -> i32 {
        self.stack_pointer -= delta;
        self.stack_pointer
    }

    /// Add a delta to the current stack pointer.
    fn add_sp(&mut self, delta: i32) -> i32 {
        self.stack_pointer += delta;
        self.stack_pointer
    }

    /// Manually create a new IDR place, this can be used to represent memory locations
    /// that are unknown at static analysis. If the location is known, for example with
    /// registers or stack, please refer to [`read_location`] or [`write_location`].
    fn create_place(&mut self) -> Place {
        self.place_factory.next()
    }

    /// Internal function to get the binding of the given symbolic location.
    /// The returned place should already be bound, so you should only read from it.
    fn read_location(&mut self, mut location: Location) -> Place {

        // For general purpose and vector register, we bind to the 
        // full register (AX -> EAX).
        // TODO: Track last register size used.
        if let Location::Register(ref mut reg) = location {
            *reg = reg.full_register();
        }

        *self.place.get(&location).unwrap_or_else(|| {
            self.inputs.entry(location).or_insert_with(|| self.place_factory.next())
        })

    }

    /// Internal function to create a new place for on the given location and return it.
    /// You must bind it to an expression.
    fn write_location(&mut self, mut location: Location) -> Place {

        // NOTE: Read comments in 'read_location'.
        if let Location::Register(ref mut reg) = location {
            *reg = reg.full_register();
        }

        let place = self.place_factory.next();
        self.place.insert(location, place);
        place

    }

    /// Get the current place of the given location, if there is no place this 
    /// fallback to searching in input places.
    fn get_location(&self, location: Location) -> Option<Place> {
        self.place.get(&location).or_else(|| self.inputs.get(&location)).copied()
    }

    /// Force set a place for the given location.
    fn set_location(&mut self, location: Location, place: Place) {
        self.place.insert(location, place);
    }

    /// Internal method to push the given statement on the current basic block.
    fn push_stmt(&mut self, stmt: Statement) {
        self.statements.push(stmt);
    }

    /// Internal function to bind an expression to a new place.
    fn push_bind(&mut self, place: Place, ty: Type, value: Expression) {

        // Propagate constant values.
        match value {
            Expression::Value(Value::LiteralInt(val)) => self.constants.set(place, val),
            // Expression::Add(from, Value::Val(val)) => 
            //     self.constants.try_add(from, var, val),
            // Expression::Sub(from, Value::Val(val)) =>
            //     self.constants.try_sub(from, var, val),
            _ => {}
        }

        self.push_stmt(Statement::Bind(Bind { place: place, ty, value }));

    }

    /// Push a store statement in the current basic block.
    fn push_store(&mut self, pointer_register: Place, value: Expression) {
        self.push_stmt(Statement::Store(Store { pointer: pointer_register, value }));
    }

    /// Decode an instruction's memory addressing operand and return the decoded operand,
    /// this operand may be an expression that produces a pointer value, or a stack offset
    /// if the memory operand is referring to a stack slot.
    fn decode_mem_operand(&mut self, inst: &Instruction) -> MemOperand {

        let mem_displ = inst.memory_displacement64() as i64;

        let mut operand;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                // Special handling for RIP addressing, because displacement contains the
                // absolute value.
                operand = MemOperand::Pointer(Expression::Value(Value::LiteralInt(mem_displ)));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // Compute real stack offset from currently known stack pointer.
                operand = MemOperand::Stack(self.stack_pointer + mem_displ as i32);
            }
            base_reg => {
                // Access relative to other registers.
                let place = self.read_location(Location::Register(base_reg));
                let expr = if mem_displ == 0 {
                    Expression::Value(Value::Place(place))
                } else {
                    Expression::Add(Value::Place(place), Value::LiteralInt(mem_displ))
                };
                operand = MemOperand::Pointer(expr);
            }
        }

        match inst.memory_index() {
            Register::None => {}
            index_reg => {
                // // Indexed memory access converts to a GetElementPointer expression.
                // let place = self.create_place();
                // self.push_bind(place, TY_VOID.pointer(1), expr);
                // let reg_place = self.read_location(Location::Register(index_reg));
                // expr = Expression::GetElementPointer { 
                //     pointer: place, 
                //     index: reg_place, 
                //     stride: inst.memory_index_scale() as u8
                // };
                unimplemented!("decode_mem_operand: memory index")
            }
        }

        operand

    }

    fn decode_mem_operand_load(&mut self, inst: &Instruction) -> Place {
        match self.decode_mem_operand(inst) {
            MemOperand::Pointer(value) => {
                let place = self.create_place();
                self.push_bind(place, TY_VOID.pointer(1), value);
                place
            }
            MemOperand::Stack(offset) => {
                self.read_location(Location::Stack(offset))
            }
        }
    }

    fn decode_mem_operand_store(&mut self, inst: &Instruction) -> Place {
        match self.decode_mem_operand(inst) {
            MemOperand::Pointer(value) => {
                let place = self.create_place();
                self.push_bind(place, TY_VOID.pointer(1), value);
                place
            }
            MemOperand::Stack(offset) => {
                self.write_location(Location::Stack(offset))
            }
        }
    }

    /// Decode an instruction of the form 'push <reg>'.
    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_size = reg.size();
        let reg_ty = ty_from_int_bytes(reg_size);

        let place = self.read_location(Location::Register(reg));
        let sp = self.sub_sp(reg_size as i32);
        self.set_location(Location::Stack(sp), place);

    }

    /// Decode an instruction of the form 'pop <reg>'.
    fn decode_pop_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_size = reg.size();
        let reg_ty = ty_from_int_bytes(reg_size);

        let sp = self.stack_pointer;
        self.add_sp(reg_size as i32);
        let place = self.read_location(Location::Stack(sp));
        self.set_location(Location::Register(reg), place);

    }

    /// Decode an instruction of the form 'lea <reg>,<m>'.
    fn decode_lea_r_m(&mut self, inst: &Instruction) {

        // mem_size with LEA would be null, so we use the size of the register
        let place = self.decode_mem_operand_store(inst);
        let reg = inst.op0_register();

        self.set_location(Location::Register(reg), place);

    }

    /// Decode an instruction of the form '<op> <rm>,<imm>'
    /// where 'op' is an integer operation.
    fn decode_int_op_rm_imm(&mut self, inst: &Instruction, op: IntOp) {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // <op> <rm>,<imm>
                let ty = ty_from_int_bytes(inst.memory_size().size());
                match self.decode_mem_operand(inst) {
                    MemOperand::Pointer(value) => {
                        let ptr_place = self.create_place();
                        self.push_bind(ptr_place, ty.pointer(1), value);
                        let dst_place = self.create_place();
                        self.push_bind(dst_place, ty, Expression::Load(ptr_place));
                        self.push_store(ptr_place, op.to_expression(Value::Place(dst_place), Value::LiteralInt(imm)));
                    }
                    MemOperand::Stack(offset) => {
                        let src_place = self.read_location(Location::Stack(offset));
                        let dst_place = self.write_location(Location::Stack(offset));
                        self.push_bind(dst_place, ty, op.to_expression(Value::Place(src_place), Value::LiteralInt(imm)));
                    }
                }
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // <op> sp,<imm>
                match op {
                    IntOp::Add => self.add_sp(imm as i32),
                    IntOp::Sub => self.sub_sp(imm as i32),
                    _ => panic!("statically unknown: {op:?} sp,<imm>")
                };
            }
            reg => {
                // <op> <reg>,<imm>
                let reg_ty = ty_from_int_bytes(reg.size());
                let read_place = self.read_location(Location::Register(reg));
                let write_place = self.write_location(Location::Register(reg));
                self.push_store(write_place, op.to_expression(Value::Place(read_place), Value::LiteralInt(imm)));
            }
        }
    }

    /// Decode an instruction of the form '<op> <rm>,<rm>
    /// where 'op' is an integer operation.
    fn decode_int_op_rm_rm(&mut self, inst: &Instruction, op: IntOp) {
        match (inst.op0_register(), inst.op1_register()) {
            (Register::None, reg1) => {
                // <op> <m>,<reg1>
                let ty = ty_from_int_bytes(reg1.size());
                let reg1_place = self.read_location(Location::Register(reg1));
                match self.decode_mem_operand(inst) {
                    MemOperand::Pointer(value) => {
                        let ptr_place = self.create_place();
                        self.push_bind(ptr_place, ty.pointer(1), value);
                        let dst_place = self.create_place();
                        self.push_bind(dst_place, ty, Expression::Load(ptr_place));
                        self.push_store(ptr_place, op.to_expression(Value::Place(dst_place), Value::Place(reg1_place)));
                    }
                    MemOperand::Stack(offset) => {
                        let src_place = self.read_location(Location::Stack(offset));
                        let dst_place = self.write_location(Location::Stack(offset));
                        self.push_bind(dst_place, ty, op.to_expression(Value::Place(src_place), Value::Place(reg1_place)));
                    }
                }
            }
            (reg0, Register::None) => {
                // <op> <reg0>,<m>
                let ty = ty_from_int_bytes(reg0.size());
                let reg0_read_place = self.read_location(Location::Register(reg0));
                let reg0_write_place = self.write_location(Location::Register(reg0));
                match self.decode_mem_operand(inst) {
                    MemOperand::Pointer(value) => {
                        let ptr_place = self.create_place();
                        self.push_bind(ptr_place, ty.pointer(1), value);
                        let mem_read_place = self.create_place();
                        self.push_bind(mem_read_place, ty, Expression::Load(ptr_place));
                        self.push_bind(reg0_write_place, ty, op.to_expression(Value::Place(reg0_read_place), Value::Place(mem_read_place)));
                    }
                    MemOperand::Stack(offset) => {
                        let stack_read_place = self.read_location(Location::Stack(offset));
                        self.push_bind(reg0_write_place, ty, op.to_expression(Value::Place(reg0_read_place), Value::Place(stack_read_place)));
                    }
                }
            }
            (reg0, reg1) if op == IntOp::Xor && reg0 == reg1 => {
                // xor <reg>,<reg>: zero the register.
                let ty = ty_from_int_bytes(reg0.size());
                let reg_place = self.write_location(Location::Register(reg0));
                self.push_bind(reg_place, ty, Expression::Value(Value::LiteralInt(0)));
            }
            (reg0, reg1) => {
                // <op> <reg0>,<reg1>
                let ty = ty_from_int_bytes(reg0.size());
                let reg1_read_place = self.read_location(Location::Register(reg1));
                let reg0_read_place = self.read_location(Location::Register(reg0));
                let reg0_write_place = self.write_location(Location::Register(reg0));
                self.push_bind(reg0_write_place, ty, op.to_expression(Value::Place(reg0_read_place), Value::Place(reg1_read_place)));
            }
        }
    }

    /// Decode an instruction of the form 'mov <rm>,<imm>'.
    fn decode_mov_rm_imm(&mut self, inst: &Instruction) {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // mov <m>,<imm>
                let ty = ty_from_int_bytes(inst.memory_size().size());
                let mem_place = self.decode_mem_operand_store(inst);
                self.push_store(mem_place, Expression::Value(Value::LiteralInt(imm)));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov sp,<imm>
                panic!("statically unknown: mov sp,<imm>");
            }
            reg => {
                // mov <reg>,<imm>
                let reg_place = self.write_location(Location::Register(reg));
                let ty = ty_from_int_bytes(reg.size());
                self.push_bind(reg_place, ty, Expression::Value(Value::LiteralInt(imm)));
            }
        }
    }

    /// Decode an instruction of the form 'mov <reg>,<rm>'.
    fn decode_mov_r_rm(&mut self, inst: &Instruction) {

        let reg0 = inst.op0_register();
        let ty = ty_from_int_bytes(reg0.size());

        match inst.op1_register() {
            Register::None => {
                // mov <reg0>,<m>
                match self.decode_mem_operand(inst) {
                    MemOperand::Pointer(value) => {
                        let ptr_place = self.create_place();
                        self.push_bind(ptr_place, ty.pointer(1), value);
                        let reg0_place = self.write_location(Location::Register(reg0));
                        self.push_bind(reg0_place, ty, Expression::Load(ptr_place));
                    }
                    MemOperand::Stack(offset) => {
                        let stack_write_place = self.read_location(Location::Stack(offset));
                        self.set_location(Location::Register(reg0), stack_write_place);
                    }
                }
            }
            Register::RSP => {
                // mov <reg0>,sp
                panic!("statically unknown: mov <reg>,sp");
            }
            reg1 => {
                if let Register::SP | Register::ESP | Register::RSP = reg0 {
                    // mov sp,<reg1>
                    // TODO:
                    // let reg1_val = self.get_reg_const(reg1)
                    //     .expect("move to sp requires constant value in right register");
                    // self.stack_pointer = reg1_val as i32;
                } else {
                    // mov <reg0>,<reg1>
                    let reg1_place = self.read_location(Location::Register(reg1));
                    self.set_location(Location::Register(reg0), reg1_place);
                }
            }
        }

    }

    /// Decode an instruction of the form 'mov <rm>,<reg>'.
    fn decode_mov_rm_r(&mut self, inst: &Instruction) {

        let reg1 = inst.op1_register();
        let ty = ty_from_int_bytes(reg1.size());

        match inst.op0_register() {
            Register::None => {
                // mov <m>,<reg>
                let reg1_place = self.read_location(Location::Register(reg1));
                match self.decode_mem_operand(inst) {
                    MemOperand::Pointer(value) => {
                        let ptr_place = self.create_place();
                        self.push_bind(ptr_place, ty.pointer(1), value);
                        self.push_store(ptr_place, Expression::Value(Value::Place(reg1_place)));
                    }
                    MemOperand::Stack(offset) => {
                        self.set_location(Location::Stack(offset), reg1_place);
                    }
                }
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov sp,<reg1>
                // TODO:
                // let reg1_val = self.get_reg_const(reg1)
                //     .expect("move to sp requires constant value in right register");
                // self.stack_pointer = reg1_val as i32;
            }
            reg0 => {
                // mov <reg0>,<reg1>
                let reg1_place = self.read_location(Location::Register(reg1));
                self.set_location(Location::Register(reg0), reg1_place);
            }
        }

    }

    /// Decode an instruction of the form 'movzx <reg>,<rm>'.
    fn decode_movzx_r_rm(&mut self, inst: &Instruction) {
        // NOTE: for now we just take it like a regular move.
        self.decode_mov_r_rm(inst)
    }

    /// Decode an instruction of the form 'movs <reg>,<rm>' (with scalar register).
    fn decode_movs_r_rm(&mut self, inst: &Instruction, double: bool) {
        // let reg0 = inst.op0_register();
        // let ty = if double { TY_DOUBLE } else { TY_FLOAT };
        // match inst.op1_register() {
        //     Register::None => {
        //         // movs <reg0>,<m>
        //         let mem_place = self.decode_mem_operand(inst, ty);
        //         let reg0_place = self.write_location(Location::Register(reg0));
        //         self.push_bind(reg0_place, ty, Expression::Load(mem_place));
        //     }
        //     reg1 => {
        //         // movs <reg0>,<reg1>
        //         let reg1_place = self.read_location(Location::Register(reg1));
        //         self.set_location(Location::Register(reg0), reg1_place);
        //     }
        // }
    }

    /// Decode an instruction of the form 'movs <rm>,<reg>' (with scalar register).
    fn decode_movs_rm_r(&mut self, inst: &Instruction, double: bool) {
        // let reg1 = inst.op1_register();
        // let ty = if double { TY_DOUBLE } else { TY_FLOAT };
        // match inst.op0_register() {
        //     Register::None => {
        //         // mov <m>,<reg1>
        //         let mem_place = self.decode_mem_operand(inst, ty);
        //         let reg1_place = self.read_location(Location::Register(reg1));
        //         self.push_store(mem_place, Expression::Value(Value::Place(reg1_place)));
        //     }
        //     reg0 => {
        //         // mov <reg0>,<reg1>
        //         let reg1_place = self.read_location(Location::Register(reg1));
        //         self.set_location(Location::Register(reg0), reg1_place);
        //     }
        // }
    }

    /// Decode an instruction of the form 'test <rm>,<reg>'.
    fn decode_test_rm_r(&mut self, inst: &Instruction) {

        // We actually don't do anything here because we don't really know how the test
        // will be used in later code.
        let right_reg = inst.op1_register();
        let ty = ty_from_int_bytes(right_reg.size());
        let right_place = self.read_location(Location::Register(right_reg));

        let left_place = match inst.op0_register() {
            Register::None => {
                match self.decode_mem_operand(inst) {
                    MemOperand::Pointer(value) => {
                        let ptr_place = self.create_place();
                        self.push_bind(ptr_place, ty.pointer(1), value);
                        let place = self.create_place();
                        self.push_bind(place, ty, Expression::Load(ptr_place));
                        place
                    }
                    MemOperand::Stack(offset) => {
                        self.read_location(Location::Stack(offset))
                    }
                }
            }
            reg => self.read_location(Location::Register(reg))
        };

        self.cmp = Some(Cmp {
            right_place,
            left_place,
            ty,
            kind: CmpKind::Test,
        });

    }

}


/// A partial basic block as stored in the basic block list, it also stores the partial
/// decoded informations needed by the decoder.
#[derive(Debug, Default)]
struct BasicBlockInfo {
    /// Start instruction pointer of this basic block.
    start_ip: u64,
    /// End instruction pointer (excluded) of this basic block, none if the basic block
    /// has not yet been fully decoded. The latter can happen if some jump/call is
    /// encountered, in such case the decoder jump the the pointed basic block to decode
    /// it, and return back to decoding itself when it's done, recursively.
    end_ip: Option<u64>,
    /// IDR statements of this basic block.
    statements: Vec<Statement>,
}

impl BasicBlockInfo {

    fn new(start_ip: u64) -> Self {
        Self {
            start_ip,
            end_ip: None,
            statements: Vec::new(),
        }
    }

}


/// A tracker for variables that have constant values known
/// at analysis. This is just a hint for most variables but
/// it's useful when used analyzing optimisations around RSP.
#[derive(Debug, Default)]
struct Constants {
    inner: HashMap<Place, i64>,
}

impl Constants {

    fn set(&mut self, var: Place, val: i64) {
        self.inner.insert(var, val);
    }

    fn get(&self, var: Place) -> Option<i64> {
        self.inner.get(&var).copied()
    }

    /// If the variable `from` has a constant value, map its 
    /// value using the given function to the `to` variable.
    #[inline]
    fn try_map<F>(&mut self, from: Place, to: Place, func: F)
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
    fn try_copy(&mut self, from: Place, to: Place) {
        self.try_map(from, to, |v| v)
    }

    #[inline]
    fn try_add(&mut self, from: Place, to: Place, val: i64) {
        self.try_map(from, to, move |v| v + val)
    }

    #[inline]
    fn try_sub(&mut self, from: Place, to: Place, val: i64) {
        self.try_map(from, to, move |v| v - val)
    }

}


/// Internally used in a common function for all integer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntOp {
    Add,
    Sub,
    Xor,
}

impl IntOp {

    fn to_expression(self, left: Value, right: Value) -> Expression {
        match self {
            IntOp::Add => Expression::Add(left, right),
            IntOp::Sub => Expression::Sub(left, right),
            IntOp::Xor => Expression::Xor(left, right),
        }
    }

}


/// Internal structure used to track possible comparisons.
#[derive(Debug, Clone)]
struct Cmp {
    right_place: Place,
    left_place: Place,
    ty: Type,
    kind: CmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpKind {
    Cmp,
    Test,
}

/// A result of decoding a memory operand.
#[derive(Debug, Clone)]
enum MemOperand {
    /// The memory operand is available through the given expression, a pointer is
    /// calculated from this expression and can be used to load/store value from/to.
    Pointer(Expression),
    /// The memory operand directly points to a stack place.
    Stack(i32),
}
