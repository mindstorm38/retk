//! Pseudo-code decoder from machine code.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use iced_x86::{Instruction, Code, Register, ConditionCode};

use crate::pseudo::{LocalRef, Function, Statement, Expression, Place, BinaryExpression, Operand, ComparisonOperator};
use crate::ty::{TypeSystem, Type, PrimitiveType};
use crate::analyzer::{Analysis, Analyzer};

use super::Backend;


/// This analysis fetch every instruction and construct a first primitive IDR.
#[derive(Default)]
pub struct PseudoAnalysis { }

impl<'data> Analysis<Backend<'data>> for PseudoAnalysis {

    fn analyze(&mut self, analyzer: &mut Analyzer<Backend<'data>>) {
        
        let decoder = &mut analyzer.backend.decoder;
        let mut pseudo_decoder = PseudoDecoder::new();

        // Start from the first section.
        let Some(section) = analyzer.backend.sections.code.first() else {
            return;
        };

        decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);

        let mut i = 0;
        while let Some(inst) = decoder.decode() {
            pseudo_decoder.feed(inst);
            i += 1;
            if i > 200 {
                break
            }
        }

    }

}


/// The pseudo-code decoder from sequence of x86 instructions.
/// 
/// This structure is not yet optimized for performance, many hash maps are not suited
/// for performance and can be replaced, but it's simpler for now!
struct PseudoDecoder {
    /// Internal pseudo function being decoded.
    function: Function,
    /// The type system we use to compute type sizes and support structs.
    type_system: TypeSystem,
    /// Current stack pointer value.
    stack_pointer: i32,
    /// Mapping of stack offset to the local they are storing.
    stack_locals: HashMap<i32, LocalRef>,
    /// Mapping of local variables and which tuple register/type is holding them. 
    /// Registers in this mapping are in their "full", for example CX/ECX -> RCX.
    /// Storing the type with the register allows us to decode all basic block without
    /// knowing each others required locals, the required locals are resolved in a 
    /// second pass when done with the function.
    register_typed_locals: HashMap<(Register, Type), LocalRef>,
    /// For the current basic block, map each register's family to the optional import
    /// and last local variable bound to the family.
    register_block_locals: HashMap<Register, RegisterBlockLocals>,
    /// For each type of data, provides an allocator temporary local variables, these
    /// variables should not cross basic block boundaries.
    temp_block_locals: HashMap<Type, TempBlockLocals>,
    /// Pending instruction pointers that needs to be mapped to a future statement,
    /// when a function's statement is added, all of these instruction pointers are
    /// associated (in `ip_to_index` map) to this statement.
    ip_pending: Vec<u64>,
    /// Mapping of instruction pointer to statement index.
    ip_to_index: HashMap<u64, usize>,
    /// Mapping of basic blocks pending to be created when their associated instruction
    /// pointer is reached. If reached, the vector contains each statement to relocate.
    basic_blocks: HashMap<u64, Vec<usize>>,
    /// Information about the last comparison.
    last_cmp: Option<Cmp>,
}

impl PseudoDecoder {

    fn new() -> Self {
        Self {
            function: Function::default(),
            type_system: TypeSystem::new(64, 8),
            stack_pointer: 0,
            stack_locals: HashMap::new(),
            register_typed_locals: HashMap::new(),
            register_block_locals: HashMap::new(),
            temp_block_locals: HashMap::new(),
            ip_pending: Vec::new(),
            ip_to_index: HashMap::new(),
            basic_blocks: HashMap::new(),
            last_cmp: None,
        }
    }
    
    /// Finalize the current function, save it and reset the state to go to the next one.
    fn finalize_function(&mut self) {

        // Finalize the last basic block if relevant before finalizing the function.
        self.finalize_basic_block();

        /// Relocate the branch at the given index to target the given index.
        fn relocate_branch(branch: &mut Statement, target_index: usize) {
            match branch {
                Statement::Branch { branch } => *branch = target_index,
                Statement::BranchConditional { branch_true, .. } => *branch_true = target_index,
                stmt => panic!("statement cannot be relocated: {stmt:?}"),
            }
        }

        let mut missing_basic_blocks = Vec::new();

        // Finalize all basic block and ensure that they are existing.
        for (ip, branch_indexes) in self.basic_blocks.drain() {
            
            let index = self.ip_to_index.get(&ip).copied()
                .unwrap_or_else(|| panic!("missing statement index for instruction at {ip:08X}"));

            // Here we check that the statement just before the basic block's index is
            // a branch statement, if not we'll need to create a simple goto statement
            // at this index in order to mark the new basic block.
            if index > 0 && !self.function.statements[index - 1].is_branch() {
                missing_basic_blocks.push((index, branch_indexes));
            } else {
                // If the basic block is valid, relocate all branches to point to it.
                for branch_index in branch_indexes {
                    relocate_branch(&mut self.function.statements[branch_index], index);
                }
            }

        }

        // For each missing basic, in reverse order (because of pop), we add a
        // goto statement at the index where we want to create a basic block.
        // NOTE!! After doing this, the 'ip_to_index' cache is no longer valid, don't use.
        while let Some((index, branch_indexes)) = missing_basic_blocks.pop() {
            
            // We're inserting a branch statement at 'index', so to accommodate for that
            // we need to increment every reference to basic block after that index.
            for stmt in &mut self.function.statements {
                match stmt {
                    Statement::Branch { branch } => {
                        if *branch >= index { *branch += 1; }
                    }
                    Statement::BranchConditional { branch_true, branch_false, .. } => {
                        if *branch_true >= index { *branch_true += 1; }
                        if *branch_false >= index { *branch_false += 1; }
                    }
                    _ => continue
                }
            }

            self.function.statements.insert(index, Statement::Branch { 
                branch: index + 1
            });

            // After the goto statement is added, we update every branch referring it.
            for branch_index in branch_indexes {
                relocate_branch(&mut self.function.statements[branch_index], index + 1);
            }

            // Really important! We need to adjust pending missing basic blocks if there
            // referring branch index is past the statement we inserted.
            for (_, branch_indexes) in &mut missing_basic_blocks {
                for branch_index in branch_indexes {
                    if *branch_index >= index {
                        *branch_index += 1;
                    }
                }
            }

        }

        self.debug_function();

        *self = Self::new();
        // TODO: Save the function.

    }

    /// Finalize the current basic block, reset the state to go to the next one.
    fn finalize_basic_block(&mut self) {

        self.register_block_locals.clear();
        self.last_cmp = None;

        // Free all temporary locals.
        for locals in self.temp_block_locals.values_mut() {
            locals.cursor = 0;
        }

    }

    /// Decode the index part of a memory operand if present, and return the local
    /// variable containing the index, the variable contains the index in bytes.
    /// When found, an integer type with the index's stride is returned.
    fn decode_mem_operand_index(&mut self, inst: &Instruction) -> Option<LocalRef> {
        match inst.memory_index() {
            Register::None => None,
            index_reg => {
                
                let index_stride = inst.memory_index_scale();
                let index_reg_local = self.decode_register_preserve(index_reg, TY_PTR_DIFF);

                if index_stride > 1 {
                    let result_local = self.alloc_temp_local(TY_PTR_DIFF);
                    self.push_assign(Place::new_direct(result_local), Expression::Mul(BinaryExpression {
                        left: Operand::Local(index_reg_local),
                        right: Operand::LiteralUnsigned(index_stride as u64),
                    }));
                    Some(result_local)
                } else {
                    Some(index_reg_local)
                }

            }
        }
    }

    /// Decode the memory operand of an instruction that is intended to be a destination
    /// place for an assignment statement. The type of the pointed value is given as a 
    /// hint to this function.
    fn decode_mem_operand_place(&mut self, inst: &Instruction, ty: Type) -> Place {

        let mem_displ = inst.memory_displacement64() as i64;

        let index_local = self.decode_mem_operand_index(inst);

        let place;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                // Special handling for RIP addressing, because displacement contains the
                // absolute value of the address to load.
                let addr_local = self.alloc_temp_local(ty.pointer(1));
                if let Some(index_local) = index_local {
                    self.push_assign(Place::new_direct(addr_local), Expression::Add(BinaryExpression {
                        left: Operand::LiteralUnsigned(mem_displ as u64),
                        right: Operand::Local(index_local),
                    }));
                } else {
                    self.push_assign(Place::new_direct(addr_local), Expression::Copy(Operand::LiteralUnsigned(mem_displ as u64)));
                }
                place = Place::new_indirect(addr_local, 1);
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {

                // Compute real stack offset from currently known stack pointer.
                let offset = self.stack_pointer + i32::try_from(mem_displ).unwrap();
                let stack_local = self.ensure_stack_local(offset, ty);

                if let Some(index_local) = index_local {

                    let temp_local = self.alloc_temp_local(ty.pointer(1));

                    self.push_assign(Place::new_direct(temp_local), Expression::Ref(stack_local));
                    self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                        left: Operand::Local(temp_local),
                        right: Operand::Local(index_local),
                    }));

                    place = Place::new_indirect(temp_local, 1);

                } else {
                    place = Place::new_direct(stack_local);
                }

            }
            Register::None => unreachable!(),
            base_reg => {

                let mut reg_local = self.decode_register_preserve(base_reg, ty.pointer(1));

                if mem_displ != 0 || index_local.is_some() {

                    let temp_local = self.alloc_temp_local(ty.pointer(1));

                    if mem_displ != 0 {
                        self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                            left: Operand::LiteralUnsigned(mem_displ as u64), 
                            right: Operand::Local(reg_local),
                        }));
                        reg_local = temp_local;
                    }

                    if let Some(index_local) = index_local {
                        self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                            left: Operand::Local(reg_local),
                            right: Operand::Local(index_local),
                        }));
                        reg_local = temp_local;
                    }

                }

                place = Place::new_indirect(reg_local, 1);

            }
        }

        place

    }

    /// Decode the memory operand of an instruction that is intended to be read as the
    /// source for an expression. The type of the pointed value is given as a hint to
    /// this function.
    fn decode_mem_operand_read(&mut self, inst: &Instruction, ty: Type) -> LocalRef {

        let mem_displ = inst.memory_displacement64() as i64;

        let index_local = self.decode_mem_operand_index(inst);

        let local;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {

                local = self.alloc_temp_local(ty);

                let pointer;
                if let Some(index_local) = index_local {
                    
                    let temp_local = self.alloc_temp_local(TY_PTR_DIFF);
                    self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                        left: Operand::LiteralUnsigned(mem_displ as u64),
                        right: Operand::Local(index_local),
                    }));
                    
                    pointer = Operand::Local(temp_local);

                } else {
                    pointer = Operand::LiteralUnsigned(mem_displ as u64);
                }

                self.push_assign(Place::new_direct(local), Expression::Deref {
                    pointer,
                    indirection: 1,
                });

            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                
                // Compute real stack offset from currently known stack pointer.
                let offset = self.stack_pointer + i32::try_from(mem_displ).unwrap();
                let stack_local = self.ensure_stack_local(offset, ty);
                
                // TODO: Later, check if the stride can be used for array-like access.
                if let Some(index_local) = index_local {
                    
                    let temp_local = self.alloc_temp_local(ty.pointer(1));

                    self.push_assign(Place::new_direct(temp_local), Expression::Ref(stack_local));
                    self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                        left: Operand::Local(temp_local),
                        right: Operand::Local(index_local),
                    }));

                    local = self.alloc_temp_local(ty);
                    self.push_assign(Place::new_direct(local), Expression::Deref { 
                        pointer: Operand::Local(temp_local),
                        indirection: 1,
                    });

                } else {
                    local = stack_local;
                }

            }
            Register::None => unreachable!(),
            base_reg => {

                let mut reg_local = self.decode_register_preserve(base_reg, ty.pointer(1));

                if mem_displ != 0 || index_local.is_some() {

                    let temp_local = self.alloc_temp_local(ty.pointer(1));

                    if mem_displ != 0 {
                        self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                            left: Operand::LiteralUnsigned(mem_displ as u64), 
                            right: Operand::Local(reg_local),
                        }));
                        reg_local = temp_local;
                    }

                    if let Some(index_local) = index_local {
                        self.push_assign(Place::new_direct(temp_local), Expression::Add(BinaryExpression {
                            left: Operand::Local(reg_local),
                            right: Operand::Local(index_local),
                        }));
                        reg_local = temp_local;
                    }

                }

                local = self.alloc_temp_local(ty);
                self.push_assign(Place::new_direct(local), Expression::Deref { 
                    pointer: Operand::Local(reg_local),
                    indirection: 1,
                });

            }
        }

        local

    }

    /// Decode `lea <r>,<m>`.
    fn decode_lea_r_m(&mut self, inst: &Instruction) {

        let reg0 = inst.op0_register();
        let mem_displ = inst.memory_displacement64() as i64;

        let index_local = self.decode_mem_operand_index(inst);
        
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                let local = self.decode_register_overwrite(reg0, TY_VOID.pointer(1));
                if let Some(index_local) = index_local {
                    self.push_assign(Place::new_direct(local), Expression::Add(BinaryExpression {
                        left: Operand::LiteralUnsigned(mem_displ as u64),
                        right: Operand::Local(index_local),
                    }));
                } else {
                    self.push_assign(Place::new_direct(local), Expression::Copy(Operand::LiteralUnsigned(mem_displ as u64)));
                }
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                
                // Compute real stack offset from currently known stack pointer.
                let offset = self.stack_pointer + i32::try_from(mem_displ).unwrap();
                let stack_local = self.ensure_stack_local(offset, TY_VOID);
                let stack_ty = self.function.local_type(stack_local);
                let local = self.decode_register_overwrite(reg0, stack_ty.pointer(1));

                self.push_assign(Place::new_direct(local), Expression::Ref(stack_local));
                
                if let Some(index_local) = index_local {
                    self.push_assign(Place::new_direct(local), Expression::Add(BinaryExpression {
                        left: Operand::Local(local),
                        right: Operand::Local(index_local),
                    }));
                }

            }
            Register::None => unreachable!(),
            base_reg => {

                // NOTE: Using void* by default, but it should usually be present.
                let mut base_reg_local = self.decode_register_preserve(base_reg, TY_VOID.pointer(1));
                let base_reg_ty = self.function.local_type(base_reg_local);
                let local = self.decode_register_overwrite(reg0, base_reg_ty);

                if mem_displ != 0 {
                    self.push_assign(Place::new_direct(local), Expression::Add(BinaryExpression {
                        left: Operand::LiteralUnsigned(mem_displ as u64),
                        right: Operand::Local(base_reg_local),
                    }));
                    base_reg_local = local;
                }

                if let Some(index_local) = index_local {
                    self.push_assign(Place::new_direct(local), Expression::Add(BinaryExpression {
                        left: Operand::Local(base_reg_local),
                        right: Operand::Local(index_local),
                    }));
                }

            }
        }

    }
    
    /// Decode `push <r>`.
    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_ty = ty_unsigned_from_bytes(reg.size());

        self.sub_sp(reg.size() as i32);

        let stack_local = self.ensure_stack_local(self.stack_pointer, reg_ty);
        let reg_local = self.decode_register_preserve(reg, reg_ty);

        self.push_assign(Place::new_direct(stack_local), Expression::Copy(Operand::Local(reg_local)));

    }

    /// Decode `pop <r>`.
    fn decode_pop_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_ty = ty_unsigned_from_bytes(reg.size());
        
        let stack_local = self.ensure_stack_local(self.stack_pointer, reg_ty);
        let reg_local = self.decode_register_overwrite(reg, reg_ty);
        
        self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::Local(stack_local)));
        self.add_sp(reg.size() as i32);

    }

    fn decode_mov_rm_imm(&mut self, inst: &Instruction) {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // mov <m>,<imm>
                let mem_ty = ty_signed_from_bytes(inst.memory_size().size());
                let mem_place = self.decode_mem_operand_place(inst, mem_ty);
                self.push_assign(mem_place, Expression::Copy(Operand::LiteralSigned(imm)));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov sp,<imm>
                panic!("statically unknown: mov sp,<imm>");
            }
            reg => {
                // mov <reg>,<imm>
                let reg_ty = ty_signed_from_bytes(reg.size());
                let reg_local = self.decode_register_overwrite(reg, reg_ty);
                self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::LiteralSigned(imm)));
            }
        }
    }

    fn decode_mov_rm_rm(&mut self, inst: &Instruction) {

        let place;
        let operand;

        match (inst.op0_register(), inst.op1_register()) {
            (_, Register::RSP) => panic!("statically unknown: mov <rm>,sp"),
            (Register::RSP, _) => panic!("statically unknown: mov sp,<rm>"),
            (Register::None, reg1) => {
                let ty = ty_signed_from_bytes(reg1.size());
                operand = Operand::Local(self.decode_register_preserve(reg1, ty));
                place = self.decode_mem_operand_place(inst, ty);
            }
            (reg0, Register::None) => {
                let ty = ty_signed_from_bytes(reg0.size());
                operand = Operand::Local(self.decode_mem_operand_read(inst, ty));
                place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
            }
            (reg0, reg1) => {
                let ty = ty_signed_from_bytes(reg0.size());
                operand = Operand::Local(self.decode_register_preserve(reg1, ty));
                place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
            }
        }

        self.push_assign(place, Expression::Copy(operand));

    }

    fn decode_movzx_r_rm(&mut self, inst: &Instruction) {
        self.decode_mov_rm_rm(inst); // FIXME: Add specific support for movzx
    }

    fn decode_movsx_r_rm(&mut self, inst: &Instruction) {
        self.decode_mov_rm_rm(inst); // FIXME: Add specific support for movsx
    }

    /// Decode instruction `movsb/movsw/movsd/movsq`:
    /// - https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq
    /// 
    /// Such instruction moves bytes from string to string.
    fn decode_movs_m_m(&mut self, inst: &Instruction) {

        let mov_stride = inst.memory_size().size();
        let mov_ty = ty_unsigned_from_bytes(mov_stride);
        let mov_ty_ptr = mov_ty.pointer(1);
        
        let src_reg = self.decode_register_preserve(Register::RSI, mov_ty_ptr);
        let dst_reg = self.decode_register_preserve(Register::RDI, mov_ty_ptr);

        // let mut rep_data = None;

        // // NOTE: movs only support REP, not REPZ or REPNZ
        // if inst.has_rep_prefix() {
            
        //     // Repeat for the number of iteration given in RCX.
        //     let count_reg = self.decode_register_preserve(Register::RCX, TY_PTR_DIFF);

        //     let while_index = self.push_statement(Statement::While { 
        //         cond: Expression::Comparison { 
        //             left: Operand::Local(count_reg), 
        //             operator: ComparisonOperator::NotEqual, 
        //             right: Operand::LiteralUnsigned(0),
        //         },
        //         end_index: 0
        //     });

        //     rep_data = Some((count_reg, while_index));

        // }

        // // A simple copy from src to dst.
        // self.push_assign(Place::new_indirect(dst_reg, 1), Expression::Deref { 
        //     pointer: Operand::Local(src_reg), 
        //     indirection: 1,
        // });

        // // TODO: Decrement if DF=1
        
        // self.push_assign(Place::new_direct(src_reg), Expression::Add(BinaryExpression {
        //     left: Operand::Local(src_reg),
        //     right: Operand::LiteralUnsigned(1),
        // }));

        // self.push_assign(Place::new_direct(dst_reg), Expression::Add(BinaryExpression {
        //     left: Operand::Local(dst_reg),
        //     right: Operand::LiteralUnsigned(1),
        // }));

        // if let Some((count_reg, while_index)) = rep_data {

        //     let index = self.push_assign(Place::new_direct(count_reg), Expression::Sub(BinaryExpression { 
        //         left: Operand::Local(count_reg), 
        //         right: Operand::LiteralUnsigned(1),
        //     }));

        //     if let Statement::While { end_index, .. } = &mut self.function.statements[while_index] {
        //         *end_index = index + 1;
        //     } else {
        //         panic!();
        //     }

        // }

        self.finalize_function();
        panic!()

    }

    /// Decode instruction `movss/movsd <rm>,<rm>`: 
    /// - https://www.felixcloutier.com/x86/movss
    /// - https://www.felixcloutier.com/x86/movsd
    /// 
    /// Such instructions move single value between scalar registers.
    fn decode_movs_rm_rm(&mut self, inst: &Instruction, double: bool) {
        
        let ty = if double { TY_DOUBLE } else { TY_FLOAT };
        let place;
        let operand;

        match (inst.op0_register(), inst.op1_register()) {
            (Register::None, reg1) => {
                operand = Operand::Local(self.decode_register_preserve(reg1, ty));
                place = self.decode_mem_operand_place(inst, ty);
            }
            (reg0, Register::None) => {
                operand = Operand::Local(self.decode_mem_operand_read(inst, ty));
                place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
            }
            (reg0, reg1) => {
                operand = Operand::Local(self.decode_register_preserve(reg1, ty));
                place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
            }
        }

        self.push_assign(place, Expression::Copy(operand));

    }

    /// Abstraction function to decode every instruction `<op> <rm>,<imm>` where `op` is
    /// an integer binary operation that write the result in the left operand.
    fn decode_int_op_rm_imm(&mut self, inst: &Instruction, op: IntOp) {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // <op> <rm>,<imm>
                let mem_ty = ty_signed_from_bytes(inst.memory_size().size());
                let mem_place = self.decode_mem_operand_place(inst, mem_ty);
                let mem_local = self.decode_mem_operand_read(inst, mem_ty);
                self.push_assign(mem_place, 
                    op.to_expr(Operand::Local(mem_local), Operand::LiteralUnsigned(imm as u64)));
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
                let reg_ty = ty_signed_from_bytes(reg.size());
                let reg_read_local = self.decode_register_preserve(reg, reg_ty);
                let reg_write_local = self.decode_register_overwrite(reg, reg_ty);
                self.push_assign(Place::new_direct(reg_write_local), 
                    op.to_expr(Operand::Local(reg_read_local), Operand::LiteralUnsigned(imm as u64)));
            }
        }
    }

    /// Abstraction function to decode every instruction `<op> <rm>,<rm>` where `op` is
    /// an integer binary operation that write the result in the left operand.
    fn decode_int_op_rm_rm(&mut self, inst: &Instruction, op: IntOp) {

        let place;
        let left;
        let right;

        match (inst.op0_register(), inst.op1_register()) {
            (_, Register::RSP) => panic!("statically unknown: {op:?} <rm>,sp"),
            (Register::RSP, _) => panic!("statically unknown: {op:?} sp,<rm>"),
            (Register::None, reg1) => {
                let ty = ty_signed_from_bytes(reg1.size());
                place = self.decode_mem_operand_place(inst, ty);
                left = Operand::Local(self.decode_mem_operand_read(inst, ty));
                right = Operand::Local(self.decode_register_preserve(reg1, ty));
            }
            (reg0, Register::None) => {
                let ty = ty_signed_from_bytes(reg0.size());
                right = Operand::Local(self.decode_mem_operand_read(inst, ty));
                left = Operand::Local(self.decode_register_preserve(reg0, ty));
                place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
            }
            (reg0, reg1) if op == IntOp::Xor && reg0 == reg1 => {
                let ty = ty_signed_from_bytes(reg0.size());
                let place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
                self.push_assign(place, Expression::Copy(Operand::LiteralUnsigned(0)));
                return;
            }
            (reg0, reg1) => {
                let ty = ty_signed_from_bytes(reg0.size());
                right = Operand::Local(self.decode_register_preserve(reg1, ty));
                left = Operand::Local(self.decode_register_preserve(reg0, ty));
                place = Place::new_direct(self.decode_register_overwrite(reg0, ty));
            }
        }

        self.push_assign(place, op.to_expr(left, right));

    }

    /// Decode instruction `test <rm>,<r>`:
    /// - https://www.felixcloutier.com/x86/test
    /// 
    /// This instruction make a *bitwise and* between the left and right operand and set
    /// the appropriate flags (SF, ZF, PF), OF and CF are set to zero.
    fn decode_test_rm_r(&mut self, inst: &Instruction) {

        let reg1 = inst.op1_register();
        let ty = ty_signed_from_bytes(reg1.size());
        let right_local = self.decode_register_preserve(reg1, ty);

        let left_local = match inst.op0_register() {
            Register::None => self.decode_mem_operand_read(inst, ty),
            reg0 => self.decode_register_preserve(reg0, ty)
        };

        self.last_cmp = Some(Cmp {
            left: Operand::Local(left_local),
            right: Operand::Local(right_local),
            kind: CmpKind::Test,
        });

    }

    /// Decode the instruction `cmp <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/cmp
    /// 
    /// This instruction subtract the right immediate operand from the left one,
    /// and set the appropriate flags according to the result.
    fn decode_cmp_rm_imm(&mut self, inst: &Instruction) {

        let ty;
        let left_local;
        
        match inst.op0_register() {
            Register::None => {
                ty = ty_signed_from_bytes(inst.memory_size().size());
                left_local = self.decode_mem_operand_read(inst, ty);
            }
            reg => {
                ty = ty_signed_from_bytes(reg.size());
                left_local = self.decode_register_preserve(reg, ty);
            }
        };

        self.last_cmp = Some(Cmp {
            left: Operand::Local(left_local),
            right: Operand::LiteralUnsigned(inst.immediate32to64() as u64),
            kind: CmpKind::Cmp,
        });

    }

    /// Decode the instruction `cmp <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/cmp
    /// 
    /// This instruction subtract the right operand from the left one, 
    /// and set the appropriate flags according to the result.
    fn decode_cmp_rm_rm(&mut self, inst: &Instruction) {

        let ty = ty_signed_from_bytes(inst.memory_size().size());
        let mem_local = self.decode_mem_operand_read(inst, ty);

        let left = match inst.op0_register() {
            Register::None => Operand::Local(mem_local),
            Register::SP |
            Register::ESP |
            Register::RSP => panic!("statically unknown: cmp sp,<rm>"),
            reg0 => Operand::Local(self.decode_register_preserve(reg0, ty)),
        };

        let right = match inst.op1_register() {
            Register::None => Operand::Local(mem_local),
            Register::SP |
            Register::ESP |
            Register::RSP => panic!("statically unknown: cmp <rm>,sp"),
            reg1 => Operand::Local(self.decode_register_preserve(reg1, ty)),
        };

        self.last_cmp = Some(Cmp {
            left,
            right,
            kind: CmpKind::Cmp,
        });

    }

    fn decode_call_rel(&mut self, inst: &Instruction) {
        
        let pointer = inst.memory_displacement64();
        let ret_local = self.decode_register_overwrite(Register::RAX, TY_PTR_DIFF);

        self.push_assign(Place::new_direct(ret_local), Expression::Call { 
            pointer: Operand::LiteralUnsigned(pointer), 
            arguments: Vec::new()
        });

    }

    fn decode_call_rm(&mut self, inst: &Instruction) {

        let pointer_local = match inst.op0_register() {
            Register::None => self.decode_mem_operand_read(inst, TY_VOID.pointer(1)),
            reg => self.decode_register_preserve(reg, TY_VOID.pointer(1)),
        };

        let ret_local = self.decode_register_overwrite(Register::RAX, TY_PTR_DIFF);

        self.push_assign(Place::new_direct(ret_local), Expression::Call {
            pointer: Operand::Local(pointer_local),
            arguments: Vec::new(),
        });

    }

    fn decode_jcc(&mut self, inst: &Instruction) {

        let cmp = self.last_cmp.take()
            .expect("decode_jcc: no previous cmp");

        let pointer = inst.near_branch64();
        let cond_expr;

        match cmp.kind {
            // Comparison performs a subtraction.
            CmpKind::Cmp => {
                
                let operator = match inst.condition_code() {
                   ConditionCode::ne => ComparisonOperator::NotEqual,
                   ConditionCode::e => ComparisonOperator::Equal,
                   // Unsigned...
                   ConditionCode::a => ComparisonOperator::Greater,
                   ConditionCode::ae => ComparisonOperator::GreaterOrEqual,
                   ConditionCode::b => ComparisonOperator::Less,
                   ConditionCode::be => ComparisonOperator::LessOrEqual,
                   // Signed...
                   ConditionCode::g => ComparisonOperator::Greater,
                   ConditionCode::ge => ComparisonOperator::GreaterOrEqual,
                   ConditionCode::l => ComparisonOperator::Less,
                   ConditionCode::le => ComparisonOperator::LessOrEqual,
                   _ => unimplemented!("decode_jcc: cmp {:?}", inst.condition_code())
                };

                cond_expr = Expression::Comparison {
                    left: cmp.left,
                    operator,
                    right: cmp.right,
                };

            }
            // Test performs a bitwise and.
            CmpKind::Test => {

                // If both operands of the test is the same local, the "bitwise and" will
                // result to "equal" if the register is zero, and "not equal" is not zero.
                if cmp.left == cmp.right {

                    let operator = match inst.condition_code() {
                        ConditionCode::ne => ComparisonOperator::NotEqual,
                        ConditionCode::e => ComparisonOperator::Equal,
                        _ => unimplemented!("decode_jcc: cmp {:?}", inst.condition_code())
                    };

                    cond_expr = Expression::Comparison { 
                        left: cmp.left, 
                        operator,
                        right: Operand::LiteralUnsigned(0)
                    };

                } else {
                    todo!()
                }

            }
        }

        let branch_index = self.push_statement_with(|index| {
            Statement::BranchConditional { 
                value: cond_expr, 
                branch_true: 0, // Will be modified if upon basic block creation.
                branch_false: index + 1, // False jcc go to the next instruction.
            }
        });

        self.ensure_basic_block(pointer, branch_index);
        self.finalize_basic_block();

    }

    fn decode_jmp(&mut self, inst: &Instruction) {

        let pointer = inst.near_branch64();
        
        let goto_index = self.push_statement(Statement::Branch { branch: 0 });
        self.ensure_basic_block(pointer, goto_index);
        self.finalize_basic_block();

    }

    fn decode_ret(&mut self, _inst: &Instruction) {

        let ret_place = self.decode_register_preserve(Register::RAX, TY_PTR_DIFF);
        self.push_statement(Statement::Return(ret_place));

        self.finalize_function();

    }

    fn feed(&mut self, inst: &Instruction) {
        
        self.ip_pending.push(inst.ip());
        println!("[{:08X}] {inst}", inst.ip());

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
            Code::Mov_r8_rm8 |
            Code::Mov_rm64_r64 |
            Code::Mov_rm32_r32 |
            Code::Mov_rm16_r16 |
            Code::Mov_rm8_r8 => self.decode_mov_rm_rm(inst),
            // MOVZX (move zero-extended)
            Code::Movzx_r64_rm16 |
            Code::Movzx_r64_rm8 |
            Code::Movzx_r32_rm16 |
            Code::Movzx_r32_rm8 |
            Code::Movzx_r16_rm16 |
            Code::Movzx_r16_rm8 => self.decode_movzx_r_rm(inst),
            // MOVSX (move sign-extended)
            Code::Movsx_r64_rm16 |
            Code::Movsx_r64_rm8 |
            Code::Movsx_r32_rm16 |
            Code::Movsx_r32_rm8 |
            Code::Movsx_r16_rm16 |
            Code::Movsx_r16_rm8 |
            Code::Movsxd_r64_rm32 |
            Code::Movsxd_r32_rm32 |
            Code::Movsxd_r16_rm16 => self.decode_movsx_r_rm(inst),
            // MOVS (mov string)
            Code::Movsq_m64_m64 |
            Code::Movsd_m32_m32 |
            Code::Movsw_m16_m16 |
            Code::Movsb_m8_m8 => self.decode_movs_m_m(inst),
            // MOVSS/MOVSD
            Code::Movss_xmm_xmmm32 |
            Code::Movss_xmmm32_xmm => self.decode_movs_rm_rm(inst, false),
            Code::Movsd_xmm_xmmm64 |
            Code::Movsd_xmmm64_xmm => self.decode_movs_rm_rm(inst, true),
            // ADD
            Code::Add_rm64_imm8 |
            Code::Add_rm32_imm8 |
            Code::Add_rm16_imm8 |
            Code::Add_rm8_imm8 |
            Code::Add_rm64_imm32 |
            Code::Add_rm32_imm32 |
            Code::Add_rm16_imm16  => self.decode_int_op_rm_imm(inst, IntOp::Add),
            Code::Add_r64_rm64 |
            Code::Add_r32_rm32 |
            Code::Add_r16_rm16 |
            Code::Add_r8_rm8 |
            Code::Add_rm64_r64 |
            Code::Add_rm32_r32 |
            Code::Add_rm16_r16 |
            Code::Add_rm8_r8 => self.decode_int_op_rm_rm(inst, IntOp::Add),
            // SUB
            Code::Sub_rm64_imm8 |
            Code::Sub_rm32_imm8 |
            Code::Sub_rm16_imm8 |
            Code::Sub_rm8_imm8 |
            Code::Sub_rm64_imm32 |
            Code::Sub_rm32_imm32 |
            Code::Sub_rm16_imm16  => self.decode_int_op_rm_imm(inst, IntOp::Sub),
            Code::Sub_r64_rm64 |
            Code::Sub_r32_rm32 |
            Code::Sub_r16_rm16 |
            Code::Sub_r8_rm8 |
            Code::Sub_rm64_r64 |
            Code::Sub_rm32_r32 |
            Code::Sub_rm16_r16 |
            Code::Sub_rm8_r8 => self.decode_int_op_rm_rm(inst, IntOp::Sub),
            // SUB
            Code::Xor_rm64_imm8 |
            Code::Xor_rm32_imm8 |
            Code::Xor_rm16_imm8 |
            Code::Xor_rm8_imm8 |
            Code::Xor_rm64_imm32 |
            Code::Xor_rm32_imm32 |
            Code::Xor_rm16_imm16  => self.decode_int_op_rm_imm(inst, IntOp::Xor),
            Code::Xor_r64_rm64 |
            Code::Xor_r32_rm32 |
            Code::Xor_r16_rm16 |
            Code::Xor_r8_rm8 |
            Code::Xor_rm64_r64 |
            Code::Xor_rm32_r32 |
            Code::Xor_rm16_r16 |
            Code::Xor_rm8_r8 => self.decode_int_op_rm_rm(inst, IntOp::Xor),
            // TEST
            Code::Test_rm64_r64 |
            Code::Test_rm32_r32 |
            Code::Test_rm16_r16 |
            Code::Test_rm8_r8 => self.decode_test_rm_r(inst),
            // TMP
            Code::Cmp_rm64_imm8 |
            Code::Cmp_rm32_imm8 |
            Code::Cmp_rm16_imm8 |
            Code::Cmp_rm64_imm32 |
            Code::Cmp_rm32_imm32 |
            Code::Cmp_rm16_imm16 => self.decode_cmp_rm_imm(inst),
            Code::Cmp_rm64_r64 |
            Code::Cmp_rm32_r32 |
            Code::Cmp_rm16_r16 |
            Code::Cmp_rm8_r8 |
            Code::Cmp_r64_rm64 |
            Code::Cmp_r32_rm32 |
            Code::Cmp_r16_rm16 |
            Code::Cmp_r8_rm8 => self.decode_cmp_rm_rm(inst),
            // CALL
            Code::Call_rel16 |
            Code::Call_rel32_32 |
            Code::Call_rel32_64 => self.decode_call_rel(inst),
            Code::Call_rm64 |
            Code::Call_rm32 |
            Code::Call_rm16 => self.decode_call_rm(inst),
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
                self.debug_function();
                unimplemented!("unsupported opcode: {inst:?}");
            }
        }
        
    }

    fn add_sp(&mut self, delta: i32) {
        self.stack_pointer += delta;
        println!("  sp: {}", self.stack_pointer);
    }

    fn sub_sp(&mut self, delta: i32) {
        self.stack_pointer -= delta;
        println!("  sp: {}", self.stack_pointer);
    }

    /// Decode a register access for the given type, if the tuple register/ty doesn't
    /// have a local variable yet, it's created. If a new local variable is created,
    /// and the given `import` argument is true then the value of the register family 
    /// is preserved in the new local, using a cast assignment.
    #[track_caller]
    fn decode_register(&mut self, register: Register, ty: Type, import: bool) -> LocalRef {

        let full_register = register.full_register();

        // Debug purpose asserts to avoid programming errors.
        if full_register.is_gpr() {
            assert!(ty.is_integer() || ty.is_pointer(), "general purpose register can only hold integer type and pointers");
        }

        let local = *self.register_typed_locals.entry((register, ty))
            .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("register: {full_register:?}")));

        match self.register_block_locals.entry(full_register) {
            Entry::Occupied(o) => {

                let locals = o.into_mut();
                let current_local = locals.last;
                locals.last = local;

                if import && self.function.local_type(current_local) != ty {
                    self.push_assign(Place::new_direct(local), Expression::Cast(current_local));
                }

            }
            Entry::Vacant(v) => {
                v.insert(RegisterBlockLocals { 
                    import: import.then_some(local),  // Only import if requested.
                    last: local,
                });
            }
        }

        local

    }

    #[inline]
    fn decode_register_preserve(&mut self, register: Register, ty: Type) -> LocalRef {
        self.decode_register(register, ty, true)
    }

    #[inline]
    fn decode_register_overwrite(&mut self, register: Register, ty: Type) -> LocalRef {
        self.decode_register(register, ty, false)
    }

    /// Get a local usable to write from the given stack offset.
    fn ensure_stack_local(&mut self, offset: i32, ty: Type) -> LocalRef {
        *self.stack_locals.entry(offset)
            .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("stack: {offset}")))
    }

    /// Allocate a temporary variable to hold the given type, the local will be freed
    /// automatically when the current basic block is exited, this local variable can't
    /// be used between basic blocks.
    fn alloc_temp_local(&mut self, ty: Type) -> LocalRef {
        let locals = self.temp_block_locals.entry(ty).or_default();
        let new_local = locals.list.get(locals.cursor)
            .copied()
            .unwrap_or_else(|| {
                let new_local = self.function.new_local(&self.type_system, ty, format!("temporary variable {}", locals.cursor));
                locals.list.push(new_local);
                new_local
            });
        locals.cursor += 1;
        new_local
    }

    /// Push a new statement with a producer closure that take the future statement's
    /// index as parameter.
    fn push_statement_with<F: FnOnce(usize) -> Statement>(&mut self, func: F) -> usize {
        let statement_index = self.function.statements.len();
        self.function.statements.push(func(statement_index));
        for ip_pending in self.ip_pending.drain(..) {
            self.ip_to_index.insert(ip_pending, statement_index);
        }
        statement_index
    }

    /// Push a new statement.
    fn push_statement(&mut self, statement: Statement) -> usize {
        self.push_statement_with(|_| statement)
    }

    fn push_assign(&mut self, place: Place, value: Expression) -> usize {
        self.push_statement(Statement::Assign { place, value })
    }

    /// Ensure that a basic block exists or will exists at the given instruction pointer.
    /// If the basic block cuts an existing basic block, a goto branch is set on the
    /// previous block and point to the new one. The given branch index will be used to
    /// relocate the statement at this index to point to the final index of the basic
    /// block when known.
    fn ensure_basic_block(&mut self, ip: u64, branch_index: usize) {
        self.basic_blocks.entry(ip).or_default().push(branch_index);
    }

    fn debug_function(&self) {
        crate::pseudo::write_function(std::io::stdout().lock(), &self.function, &self.type_system).unwrap();
    }

}


const TY_VOID: Type = PrimitiveType::Void.plain();
const TY_PTR_DIFF: Type = PrimitiveType::Signed(64).plain();
const TY_FLOAT: Type = PrimitiveType::Float.plain();
const TY_DOUBLE: Type = PrimitiveType::Double.plain();


#[inline]
const fn ty_signed_from_bytes(bytes: usize) -> Type {
    PrimitiveType::Signed(bytes as u32 * 8).plain()
}

#[inline]
const fn ty_unsigned_from_bytes(bytes: usize) -> Type {
    PrimitiveType::Unsigned(bytes as u32 * 8).plain()
}

/// Internally used in a common function for all integer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntOp {
    Add,
    Sub,
    Xor,
}

impl IntOp {

    fn to_expr(self, left: Operand, right: Operand) -> Expression {
        match self {
            IntOp::Add => Expression::Add(BinaryExpression { left, right }),
            IntOp::Sub => Expression::Sub(BinaryExpression { left, right }),
            IntOp::Xor => Expression::Xor(BinaryExpression { left, right }),
        }
    }

}

/// Internal structure used to track possible comparisons.
#[derive(Debug, Clone)]
struct Cmp {
    left: Operand,
    right: Operand,
    kind: CmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpKind {
    /// Subtraction of right from left.
    Cmp,
    /// Bitwise right and left.
    Test,
}

/// Saves for each register family, their optional imported local and the last local
/// bound to them for the current basic block being resolved.
#[derive(Debug)]
struct RegisterBlockLocals {
    /// If relevant, the local variable corresponding to this register family that needs
    /// to be given by the caller basic blocks.
    import: Option<LocalRef>,
    /// The last local variable that has been bound to the register family.
    last: LocalRef,
}

/// Provides a local allocator for a given type.
#[derive(Debug, Default)]
struct TempBlockLocals {
    /// Internal list of local for the given type.
    list: Vec<LocalRef>,
    /// Index of the next local to allocate, if that equals the length of the locals,
    /// then a new local will be created.
    cursor: usize,
}
