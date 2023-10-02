//! IDR decoder from machine code.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use iced_x86::{Instruction, Code, Register, ConditionCode, OpKind};
use anyhow::{Result as AnyResult, Error as AnyError, anyhow, bail};

use crate::idr::{LocalRef, Function, Statement, Expression, Place, Index, Operand, 
    ComparisonOperator, BinaryOperator};
use crate::ty::{TypeSystem, Type, PrimitiveType};

use super::early::{EarlyFunctions, EarlyFunction};
use super::Backend;


const DEBUG_FUNCTIONS: &'static [u64] = &[
    // 0x1402E0370, // Example of imul <r/m>
    // 0x140033120, // Example of div
    // 0x140207E00, // Example of idiv with cdq
    // 0x14024E4A0, // Example of stack local f64* -> i8*
    0x140027858, // Example of mov rax, rsp
    0x140208E8C, // Example of mov rax, rsp
];


/// Analyze all IDR functions.
pub fn analyze_idr(backend: &mut Backend, early_functions: &EarlyFunctions) {

    let mut type_system = TypeSystem::new(backend.pointer_size, 8);
    let mut functions = HashMap::new();

    let functions_count = early_functions.functions_count();

    let mut missing_opcodes = HashMap::<_, usize>::new();

    for (i, early_function) in early_functions.iter_functions().enumerate() {

        print!(" = At {:08X} ({:03.0}%)... ", early_function.begin(), i as f32 / functions_count as f32 * 100.0);

        let begin = early_function.begin();
        let section = backend.sections.get_code_section_at(begin).unwrap();
        let offset = begin - section.begin_addr;
        backend.decoder.goto_range_at(section.pos + offset as usize, begin, early_function.end());

        let mut decoder = IdrDecoder::new(&mut type_system, early_function);
        let mut error = false;

        while let Some(inst) = backend.decoder.decode() {

            if DEBUG_FUNCTIONS.contains(&begin) {
                println!("[{:08X}] {inst}", inst.ip());
            }

            if !error {
                if let Err(e) = decoder.feed(inst) {

                    if let Some(inst) = e.downcast_ref::<Instruction>() {
                        *missing_opcodes.entry(inst.code()).or_default() += 1;
                        println!("Error: {inst} ({:?})", inst.code());
                    } else {
                        println!("Error: {e}");
                    }

                    error = true;

                }
            }

        }

        if error {
            continue;
        }

        println!("Done.");

        let function = decoder.finalize_function().unwrap();

        if DEBUG_FUNCTIONS.contains(&begin) {
            function.debug_function(&type_system);
        }

        functions.insert(begin, function);
        
    }

    let mut missing_opcodes = missing_opcodes.into_iter().collect::<Vec<_>>();
    missing_opcodes.sort_unstable_by_key(|&(_code, count)| count);

    println!(" = Missing opcodes ({}):", missing_opcodes.len());
    for (opcode, count) in missing_opcodes {
        println!("   {opcode:?}: {count}");
    }

    println!(" = Success rate: {}%", functions.len() as f32 / functions_count as f32 * 100.0);

}


/// The IDR decoder from sequence of x86 instructions.
/// 
/// This structure is not yet optimized for performance, many hash maps are not suited
/// for performance and can be replaced, but it's simpler for now!
struct IdrDecoder<'e, 't> {
    /// Type system.
    type_system: &'t mut TypeSystem,
    /// The early data of the function being decoded.
    early_function: EarlyFunction<'e>,
    /// Internal pseudo function being decoded.
    function: Function,
    /// Current stack pointer value.
    /// **This is reset between passes.**
    stack_pointer: i32,
    /// Mapping of stack offset to the local they are storing. The layout of the stack is
    /// computed from accesses made to it, it acts like a single big register holding a
    /// complex structure with many fields.
    /// **This is reset between passes.**
    stack_locals: HashMap<i32, LocalRef>,
    /// Mapping of local variables and which tuple register/type is holding them. 
    /// Registers in this mapping are in their "full", for example CX/ECX -> RCX.
    /// Storing the type with the register allows us to decode all basic block without
    /// knowing each others required locals, the required locals are resolved in a 
    /// second pass when done with the function.
    register_typed_locals: HashMap<(Register, Type), LocalRef>,
    /// For the current basic block, map each register's family to the optional import
    /// and last local variable bound to the family.
    /// **This is reset between basic blocks.**
    register_block_locals: HashMap<Register, RegisterBlockLocals>,
    /// For each type of data, provides an allocator temporary local variables, these
    /// variables should not cross basic block boundaries.
    temp_block_locals: HashMap<Type, TempBlockLocals>,
    /// ***WIP*** This register specific to the RDX:RAX couple of register family is 
    /// used to track the last value binding. These two registers are often used for
    /// division and multiply, optionally preceded a sign extend. This is why it needs
    /// special handling with this field.
    rdx_rax_state: RdxRaxState,
    /// Additional informations about basic blocks, these basic blocks are guaranteed
    /// to also be present in the early function's basic blocks.
    basic_blocks: HashMap<u64, BasicBlock>,
    /// Instruction pointer of the current basic block being decoded.
    basic_block_ip: Option<u64>,
    /// Information about how flags were last modified.
    /// **This is reset between basic blocks.**
    flags: Flags,
}

impl<'e, 't> IdrDecoder<'e, 't> {

    fn new(type_system: &'t mut TypeSystem, early_function: EarlyFunction<'e>) -> Self {
        Self {
            type_system,
            early_function,
            function: Function::default(),
            stack_pointer: 0,
            stack_locals: HashMap::new(),
            register_typed_locals: HashMap::new(),
            register_block_locals: HashMap::new(),
            temp_block_locals: HashMap::new(),
            rdx_rax_state: RdxRaxState::None,
            basic_blocks: HashMap::new(),
            basic_block_ip: None, // Will be initialized at first instruction.
            flags: Flags::Undefined,
        }
    }
    
    /// Finalize the current function, save it and reset the state to go to the next one.
    fn finalize_function(mut self) -> AnyResult<Function> {

        // Finalize all basic block and ensure that they are existing.
        for block in self.basic_blocks.values_mut() {
            let index = block.begin_index.ok_or_else(|| anyhow!("block decoding is missing"))?;
            // If the basic block is valid, relocate all branches to point to it.
            // NOTE: We drain this relocation list because we don't want to keep it 
            // for the next pass, it will be reconstructed as needed.
            for branch_index in block.branch_indices_to_relocate.drain(..) {
                match &mut self.function.statements[branch_index] {
                    Statement::Branch { branch } => *branch = index,
                    Statement::BranchConditional { branch_true, .. } => *branch_true = index,
                    stmt => bail!("statement cannot be relocated: {stmt:?}"),
                }
            }
        }

        // Unique imports for each basic block, in these steps it is possible to have
        let mut basic_block_imports = HashMap::<u64, FinalBasicBlock>::new();
        let mut branches_imports = Vec::new();

        for (&block_ip, block) in &self.basic_blocks {

            if let Some(true_branch) = block.true_branch {
                let true_block = self.basic_blocks.get(&true_branch)
                    .ok_or_else(|| anyhow!("cannot find true branch {true_branch:08X} from block {block_ip:08X}"))?;
                branches_imports.extend(true_block.iter_import_register_locals());
                basic_block_imports.entry(true_branch).or_default().parents.push(block_ip);
            }

            if let Some(false_branch) = block.false_branch {
                let false_block = self.basic_blocks.get(&false_branch)
                    .ok_or_else(|| anyhow!("cannot find false branch {false_branch:08X} from block {block_ip:08X}"))?;
                branches_imports.extend(false_block.iter_import_register_locals());
                basic_block_imports.entry(false_branch).or_default().parents.push(block_ip);
            }

            if !branches_imports.is_empty() {
                basic_block_imports.entry(block_ip).or_default().exports
                    .extend(branches_imports.drain(..).map(|t| (t, false)));
            }

        }

        // Here we want to fix every basic block's exported variable for its branches.
        let mut parent_new_exports = Vec::new();
        let mut new_statements = Vec::new();

        let mut i = 0;
        
        loop {

            i += 1;
            if i > 100 {
                bail!("block finalization is not converging");
            }
            
            // Start by propagating all imports.
            for (&block_ip, block) in &self.basic_blocks {
                
                // If the block has some imported locals.
                if let Some(final_block) = basic_block_imports.get_mut(&block_ip) {
                    for (&(reg, export_local), done) in &mut final_block.exports {
                        if !std::mem::replace(done, true) {
                            if let Some(locals) = block.register_locals.get(&reg) {
                                // If the block contains this local, we know that we can 
                                // insert cast statement from last value to imported one.
                                // NOTE: Do not add a cast if the last local is already 
                                // the good local...
                                if locals.last != export_local {
                                    // We need to a cast assignment expression just before the branch.
                                    let branch_index = block.branch_index.unwrap();
                                    new_statements.push((branch_index, Statement::Assign { 
                                        place: Place::new_direct(export_local), 
                                        value: Expression::Cast(Place::new_direct(locals.last)),
                                    }));
                                }
                            } else {
                                // This register family is unknown to this basic block, we
                                // need to propagate the export to the parents.
                                for &parent_block_ip in &final_block.parents {
                                    parent_new_exports.push((parent_block_ip, reg, export_local));
                                }
                            }
                        }
                    }
                }

            }

            // Converged toward no new exports to add to parents.
            if parent_new_exports.is_empty() {
                break;
            }

            // Add required export locals only to parents not done with it yet.
            for (block_ip, reg, export_local) in parent_new_exports.drain(..) {
                basic_block_imports.entry(block_ip).or_default().exports
                    .entry((reg, export_local)).or_insert(false);
            }

        }

        // Our statements need to be order in order to use binary search on them.
        new_statements.sort_unstable_by_key(|&(index, _)| index);

        // Temporary function to count how many statements will be added before a given
        // statement index.
        let count_statements_before = |index: usize| {
            match new_statements.binary_search_by_key(&index, |&(index, _)| index) {
                Ok(index) => index,
                Err(index) => index,
            }
        };

        for statement in &mut self.function.statements {
            match statement {
                Statement::BranchConditional { branch_true, branch_false, .. } => {
                    *branch_true += count_statements_before(*branch_true);
                    *branch_false += count_statements_before(*branch_false);
                }
                Statement::Branch { branch } => {
                    *branch += count_statements_before(*branch);
                }
                _ => {}
            }
        }

        // Insert in reverse order to indices are valid.
        for (index, stmt) in new_statements.into_iter().rev() {
            self.function.statements.insert(index, stmt);
        }

        Ok(self.function)

    }

    /// Finalize the current basic block, reset the state to go to the next one. This
    /// should be called directly after insertion of the branch statement of the basic
    /// block.
    /// 
    /// The true branch can be forced to a given value if needed, this is used if a 
    /// branch statement has been artificially added to form a new basic block.
    fn finalize_basic_block(&mut self, add_true_branch: Option<u64>) {

        // Take the block ip so no double call to this function is possible.
        let Some(block_ip) = self.basic_block_ip.take() else {
            return;
        };

        let block = self.basic_blocks.get_mut(&block_ip).unwrap();        
        block.branch_index = Some(self.function.statements.len() - 1);
        
        if let Some(true_branch) = add_true_branch {
            block.true_branch = Some(true_branch);
        }

        // Steal register block locals, will be used when finalizing the function to
        // add missing registers 
        block.register_locals = std::mem::take(&mut self.register_block_locals);

        // Don't track comparisons across basic blocks.
        self.flags = Flags::Undefined;

        // Free basic block temporary locals.
        for locals in self.temp_block_locals.values_mut() {
            locals.cursor = 0;
        }

    }

    /// Decode a memory operand and return the memory place pointed to by this operand.
    /// The given type is interpreted as the type pointed by the memory operand, and the
    /// returned place is guaranteed to be of that type, **one exception being** if you
    /// request a weak integer, an actual integer of the same size may be returned.
    fn decode_mem_operand(&mut self, inst: &Instruction, ty: Type) -> AnyResult<Place> {

        if !matches!(inst.memory_segment(), Register::DS | Register::SS) {
            // TODO: Decode the "GS" segment for windows:
            // https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
            bail!("decode_mem_operand: unsupported segment for memory operand ({inst})");
        }

        // The displacement is actually 64-bit only for EIP/RIP relative address, 
        // otherwise it can just be casted to 32-bit integer.
        let mem_displ = inst.memory_displacement64();

        let index_scale = inst.memory_index_scale() as u8;
        let index_local = match inst.memory_index() {
            Register::None => None,
            index_reg => Some(self.decode_register_import(index_reg, TY_PTR_DIFF)?),
        };

        let place;
        match inst.memory_base() {
            Register::EIP |
            Register::RIP => {
                
                let addr_local = self.alloc_temp_local(ty.pointer(1));
                self.push_assign(Place::new_direct(addr_local), Expression::Copy(Operand::LiteralUnsigned(mem_displ)));
            
                if let Some(index_local) = index_local {
                    place = Place::new_index_variable(addr_local, index_local, index_scale);
                } else {
                    place = Place::new_index_absolute(addr_local, 0);
                }

            }
            Register::SP |
            Register::ESP |
            Register::RSP => {

                if index_local.is_some() {
                    // TODO: Support this.
                    bail!("decode_mem_operand: unsupported index with sp-relative ({inst})");
                }

                // Compute real stack offset from currently known stack pointer.
                let offset = self.stack_pointer + mem_displ as i32;
                place = self.decode_stack_place(offset, ty);
                
            }
            Register::None => {

                // Note base regsiter is commonly used by lea for easy offsets 
                // calculation (lea r8,[rax*4]).

                bail!("decode_mem_operand: no base");

            }
            base_reg => {
                
                let base_reg_local = self.decode_register_import(base_reg, ty.pointer(1))?;

                place = match (mem_displ, index_local) {
                    (0, Some(index_local)) => Place::new_index_variable(base_reg_local, index_local, index_scale),
                    (_, Some(index_local)) => {
                        let temp_local = self.alloc_temp_local(ty.pointer(1));
                        self.push_assign(Place::new_direct(temp_local), Expression::Binary { 
                            left: Operand::Place(Place::new_direct(base_reg_local)), 
                            right: Operand::LiteralSigned(mem_displ as i32 as i64),
                            operator: BinaryOperator::Add,
                        });
                        Place::new_index_variable(temp_local, index_local, index_scale)
                    }
                    (_, None) => Place::new_index_absolute(base_reg_local, mem_displ as i32),
                };

            }
        }

        Ok(place)

    }

    /// Shortcut for calling [`decode_mem_operand`] with an weak integer type of the given
    /// bytes size. The resulting place is then guaranteed to be of the a 
    /// weak/unsigned/signed integer type of the given size.
    fn decode_mem_operand_int(&mut self, inst: &Instruction, bytes: usize) -> AnyResult<Place> {
        self.decode_mem_operand(inst, IntLayout::Weak.to_type(bytes))
    }

    /// Shortcut for properly decoding the immediate operand of an instruction depending
    /// on the given layout.
    fn decode_int_immediate(&mut self, inst: &Instruction, operand: u32, layout: IntLayout) -> AnyResult<Operand> {
        Ok(match layout {
            IntLayout::Weak | IntLayout::Unsigned => {
                Operand::LiteralUnsigned(match inst.op_kind(operand) {
                    OpKind::Immediate64 => inst.immediate64(),
                    _ => inst.immediate32() as u64
                })
            }
            IntLayout::Signed => {
                Operand::LiteralSigned(match inst.op_kind(operand) {
                    OpKind::Immediate8 | 
                    OpKind::Immediate8to64 | 
                    OpKind::Immediate8to32 | 
                    OpKind::Immediate8to16 => inst.immediate8() as i8 as i64,
                    OpKind::Immediate32 |
                    OpKind::Immediate32to64 => inst.immediate32() as i32 as i64,
                    kind => bail!("decode_int_immediate (signed): unsupported kind {kind:?}: ({inst})")
                })
            }
        })
    }

    /// Decode `lea <r>,<m>`.
    fn decode_lea_r_m(&mut self, inst: &Instruction) -> AnyResult<()> {

        if !matches!(inst.memory_segment(), Register::DS | Register::SS) {
            bail!("decode_mem_operand: unsupported segment for memory operand ({inst})");
        }
        
        let reg = inst.op0_register();

        // Special case when no base register is used (lea r8,[rax*4]). We can inline the
        // offset calculation instead of decoding the operand.
        if let Register::None = inst.memory_base() {

            let mem_displ = inst.memory_displacement32() as i32;
            let index_scale = inst.memory_index_scale() as u8;
            let index_local = match inst.memory_index() {
                Register::None => None,
                index_reg => Some(self.decode_register_import(index_reg, TY_PTR_DIFF)?),
            };

            let reg_place = Place::new_direct(self.decode_register_write(reg, TY_BYTE.pointer(1))?);

            let expr = match (mem_displ, index_local, index_scale) {
                (0, Some(index_local), 0) => Expression::Copy(Operand::new_local(index_local)),
                (0, Some(index_local), _) => Expression::Binary { 
                    left: Operand::new_local(index_local), 
                    right: Operand::LiteralUnsigned(index_scale as u64), 
                    operator: BinaryOperator::Mul,
                },
                (_, Some(index_local), 0) => Expression::Binary { 
                    left: Operand::new_local(index_local), 
                    right: Operand::LiteralSigned(mem_displ as i64), 
                    operator: BinaryOperator::Add,
                },
                (_, Some(index_local), _) => {
                    self.push_assign(reg_place, Expression::Binary { 
                        left: Operand::new_local(index_local), 
                        right: Operand::LiteralUnsigned(index_scale as u64), 
                        operator: BinaryOperator::Mul,
                    });
                    Expression::Binary { 
                        left: Operand::Place(reg_place), 
                        right: Operand::LiteralSigned(mem_displ as i64), 
                        operator: BinaryOperator::Add,
                    }
                }
                _ => bail!("decode_lea_r_m (no base): incoherent memory operand")
            };

            self.push_assign(reg_place, expr);

        } else {

            let mem_place = self.decode_mem_operand(inst, TY_BYTE)?;
            let reg_place = Place::new_direct(self.decode_register_write(reg, TY_BYTE.pointer(1))?);

            // We simplify this case, we can just assign the value to the register.
            if let Some(Index::Absolute(0)) = mem_place.index {
                let simplified_place = Place::new_direct(mem_place.local);
                self.push_assign(reg_place, Expression::Copy(Operand::Place(simplified_place)));
            } else {
                self.push_assign(reg_place, Expression::Ref(mem_place));
            }

        }

        Ok(())

    }
    
    /// Decode `push <r>`.
    fn decode_push_r(&mut self, inst: &Instruction) -> AnyResult<()> {

        let reg = inst.op0_register();
        if let Register::SP | Register::ESP | Register::RSP = reg {
            bail!("decode_push_r: cannot push from sp ({inst})");
        }
        
        self.sub_sp(reg.size() as i32);
        
        let reg_local = self.decode_register_import_int(reg, reg.size())?;
        let reg_ty = self.function.local_type(reg_local);
        let stack_place = self.decode_stack_place(self.stack_pointer, reg_ty);

        self.push_assign(stack_place, Expression::Copy(Operand::new_local(reg_local)));
        Ok(())

    }

    /// Decode `pop <r>`.
    fn decode_pop_r(&mut self, inst: &Instruction) -> AnyResult<()> {

        let reg = inst.op0_register();
        if let Register::SP | Register::ESP | Register::RSP = reg {
            bail!("decode_pop_r: cannot pop to sp ({inst})");
        }

        // TODO: Use 'decode_stack_place' instead.
        let stack_default_ty = IntLayout::Weak.to_type(reg.size());
        let stack_local = self.decode_stack_local(self.stack_pointer, stack_default_ty);
        let stack_ty = self.function.local_type(stack_local);
        let reg_local = self.decode_register_write(reg, stack_ty)?;
        
        self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::new_local(stack_local)));
        self.add_sp(reg.size() as i32);
        Ok(())

    }

    /// Decode instruction `mov <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/mov
    /// 
    /// Move an immediate value into a register or memory.
    fn decode_mov_rm_imm(&mut self, inst: &Instruction) -> AnyResult<()> {
        
        let place;
        match inst.op0_register() {
            Register::None => {
                // mov <m>,<imm>
                place = self.decode_mem_operand_int(inst, inst.memory_size().size())?;
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov sp,<imm>
                bail!("statically unknown: mov sp,<imm> ({inst})");
            }
            reg => {
                // mov <reg>,<imm>
                place = Place::new_direct(self.decode_register_write_int(reg, reg.size())?);
            }
        }

        let place_ty = self.function.place_type(place);
        let place_layout = IntLayout::try_from(place_ty)?;
        let imm = self.decode_int_immediate(inst, 1, place_layout)?;
        self.push_assign(place, Expression::Copy(imm));

        Ok(())

    }

    /// Decode instruction `mov <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/mov
    /// 
    /// Move a register/memory into a register/memory (only one can be memory).
    fn decode_mov_rm_rm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let place;
        let operand;

        match (inst.op0_register(), inst.op1_register()) {
            (_, Register::SP | Register::ESP | Register::RSP) => bail!("statically unknown: mov <rm>,sp ({inst})"),
            (Register::SP | Register::ESP | Register::RSP, _) => bail!("statically unknown: mov sp,<rm> ({inst})"),
            (Register::None, reg1) => {
                let operand_local = self.decode_register_import_int(reg1, reg1.size())?;
                let operand_ty = self.function.local_type(operand_local);
                operand = Operand::new_local(operand_local);
                place = self.decode_mem_operand(inst, operand_ty)?;
            }
            (reg0, Register::None) => {
                let operand_place = self.decode_mem_operand_int(inst, reg0.size())?;
                let operand_ty = self.function.place_type(operand_place);
                operand = Operand::Place(operand_place);
                place = Place::new_direct(self.decode_register_write(reg0, operand_ty)?);
            }
            (reg0, reg1) => {
                let operand_local = self.decode_register_import_int(reg1, reg1.size())?;
                let operand_ty = self.function.local_type(operand_local);
                operand = Operand::new_local(operand_local);
                place = Place::new_direct(self.decode_register_write(reg0, operand_ty)?);
            }
        }

        self.push_assign(place, Expression::Copy(operand));
        Ok(())

    }

    /// Decode instruction `movzx/movsx <r>,<rm>`:
    /// - https://www.felixcloutier.com/x86/movzx
    /// - https://www.felixcloutier.com/x86/movsx:movsxd
    /// 
    /// Move a register/memory into a register/memory (only one can be memory).
    fn decode_mov_extend_r_rm(&mut self, inst: &Instruction, layout: IntLayout) -> AnyResult<()> {

        let src_local;
        match inst.op1_register() {
            Register::None => {
                let mem_ty = layout.to_type(inst.memory_size().size());
                src_local = self.decode_mem_operand(inst, mem_ty)?;
            }
            reg1 => {
                let reg1_ty = layout.to_type(reg1.size());
                src_local = Place::new_direct(self.decode_register_import(reg1, reg1_ty)?);
            }
        }

        let dst_reg = inst.op0_register();
        let dst_ty = layout.to_type(dst_reg.size());
        let dst_local = self.decode_register_write(dst_reg, dst_ty)?;

        self.push_assign(Place::new_direct(dst_local), Expression::Cast(src_local));
        Ok(())

    }

    /// Decode instruction `movsb/movsw/movsd/movsq`:
    /// - https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq
    /// 
    /// Such instruction moves bytes from string to string.
    fn decode_movs_m_m(&mut self, inst: &Instruction) -> AnyResult<()> {

        let mov_stride = inst.memory_size().size();
        let mov_ty = IntLayout::Weak.to_type(mov_stride);
        let mov_ty_ptr = mov_ty.pointer(1);
        
        // NOTE: RSI/RDI/RCX only if pointer size == 64.

        let src_reg = self.decode_register_import(Register::RSI, mov_ty_ptr)?;
        let dst_reg = self.decode_register_import(Register::RDI, mov_ty_ptr)?;
        
        // NOTE: movs only support REP, not REPZ or REPNZ
        let len_reg = if inst.has_rep_prefix() {
            Some(self.decode_register_import(Register::RCX, TY_QWORD)?)
        } else {
            None
        };

        self.push_statement(Statement::MemCopy { 
            src: Operand::new_local(src_reg),
            dst: Operand::new_local(dst_reg), 
            len: match len_reg {
                Some(local) => Operand::new_local(local),
                None => Operand::LiteralUnsigned(1),
            },
        });

        if let Some(len_reg) = len_reg {
            
            self.push_assign(Place::new_direct(src_reg), Expression::Binary { 
                left: Operand::new_local(src_reg),
                right: Operand::new_local(len_reg),
                operator: BinaryOperator::Add,
            });

            self.push_assign(Place::new_direct(dst_reg), Expression::Binary { 
                left: Operand::new_local(dst_reg),
                right: Operand::new_local(len_reg),
                operator: BinaryOperator::Add,
            });

        } else {

            self.push_assign(Place::new_direct(src_reg), Expression::Binary { 
                left: Operand::new_local(src_reg),
                right: Operand::LiteralUnsigned(1),
                operator: BinaryOperator::Add,
            });

            self.push_assign(Place::new_direct(dst_reg), Expression::Binary { 
                left: Operand::new_local(dst_reg),
                right: Operand::LiteralUnsigned(1),
                operator: BinaryOperator::Add,
            });

        }

        Ok(())

    }

    /// Base function for decoding instruction `<op> <rm>,1`, like `inc` and `dec`, but
    /// also short bit shifts.
    fn decode_int_op_rm_one(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout) -> AnyResult<()> {
        
        let place = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, layout.to_type(inst.memory_size().size()))?,
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // FIXME: use right operand's value.
                match op {
                    BinaryOperator::Add => self.add_sp(1),
                    BinaryOperator::Sub => self.sub_sp(1),
                    _ => bail!("statically unknown: <op> sp,<imm> ({inst})"),
                }
                self.flags = Flags::Undefined;
                return Ok(());
            }
            reg => Place::new_direct(self.decode_register_import(reg, layout.to_type(reg.size()))?),
        };

        let index = self.push_assign(place, Expression::Binary { 
            left: Operand::Place(place), 
            right: Operand::LiteralUnsigned(1), 
            operator: op,
        });

        self.flags = Flags::Binary { operator: op, index };
        Ok(())

    }

    /// Abstraction function to decode every instruction `<op> <rm>,<imm>` where `op` is
    /// an integer binary operation that write the result in the left operand.
    fn decode_int_op_rm_imm(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout) -> AnyResult<()> {

        let place = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, layout.to_type(inst.memory_size().size()))?,
            Register::SP |
            Register::ESP |
            Register::RSP => {
                let imm = inst.immediate32() as i32;
                match op {
                    BinaryOperator::Add => self.add_sp(imm),
                    BinaryOperator::Sub => self.sub_sp(imm),
                    _ => bail!("statically unknown: <op> sp,<imm> ({inst})"),
                }
                self.flags = Flags::Undefined;
                return Ok(());
            }
            reg => Place::new_direct(self.decode_register_import(reg, layout.to_type(reg.size()))?),
        };

        let place_type = self.function.place_type(place);
        let place_layout = IntLayout::try_from(place_type)?;

        let right = self.decode_int_immediate(inst, 1, place_layout)?;
        let index = self.push_assign(place, Expression::Binary { 
            left: Operand::Place(place), 
            right, 
            operator: op,
        });

        self.flags = Flags::Binary { operator: op, index };
        Ok(())

    }

    /// Abstraction function to decode every instruction `<op> <rm>,<rm>` where `op` is
    /// an integer binary operation that write the result in the left operand.
    fn decode_int_op_rm_rm(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout) -> AnyResult<()> {

        let left_place;
        let right_place;

        match (inst.op0_register(), inst.op1_register()) {
            (_, Register::SP | Register::ESP | Register::RSP) => bail!("statically unknown: <op> <rm>,sp ({inst})"),
            (Register::SP | Register::ESP | Register::RSP, _) => bail!("statically unknown: <op> sp,<rm> ({inst})"),
            (Register::None, reg1) => {
                let reg_ty = layout.to_type(reg1.size());
                let reg_local = self.decode_register_import(reg1, layout.to_type(reg1.size()))?;
                left_place = self.decode_mem_operand(inst, reg_ty)?;
                right_place = Place::new_direct(reg_local);
            }
            (reg0, Register::None) => {
                let reg_ty = layout.to_type(reg0.size());
                let reg_local = self.decode_register_import(reg0, reg_ty)?;
                left_place = Place::new_direct(reg_local);
                right_place = self.decode_mem_operand(inst, reg_ty)?;
            }
            (reg0, reg1) if op == BinaryOperator::Xor && reg0 == reg1 => {

                let reg_ty = layout.to_type(reg0.size());
                let reg_local = self.decode_register_write(reg0, reg_ty)?;
                let place = Place::new_direct(reg_local);
                self.push_assign(place, Expression::Copy(Operand::LiteralUnsigned(0)));

                // Here we set flags to undefined because such operation have a statically
                // known result (SF=0, ZF=1, PF=1) because it's always 0. This make no
                // sense to have a conditional instruction based on this...
                self.flags = Flags::Undefined;
                
                return Ok(());

            }
            (reg0, reg1) => {
                let reg_ty = layout.to_type(reg0.size());
                left_place = Place::new_direct(self.decode_register_import(reg0, reg_ty)?);
                right_place = Place::new_direct(self.decode_register_import(reg1, reg_ty)?);
            }
        }

        let index = self.push_assign(left_place, Expression::Binary { 
            left: Operand::Place(left_place), 
            right: Operand::Place(right_place), 
            operator: op,
        });

        self.flags = Flags::Binary { operator: op, index };

        Ok(())

    }

    /// Abstraction function to decode every instruction `<op> <r>,<rm>,<imm>` where `op` 
    /// is an integer binary operation from second and third (immediate) operand and 
    /// writes the result in the first operand.
    fn decode_int_op_r_rm_imm(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout) -> AnyResult<()> {

        let left_place = match inst.op1_register() {
            Register::None => self.decode_mem_operand(inst, layout.to_type(inst.memory_size().size()))?,
            reg1 => Place::new_direct(self.decode_register_import(reg1, layout.to_type(reg1.size()))?),

        };

        let left_ty = self.function.place_type(left_place);
        let left_layout = IntLayout::try_from(left_ty)?;

        let right = self.decode_int_immediate(inst, 2, left_layout)?;

        let dst_reg = inst.op0_register();
        let dst_place = Place::new_direct(self.decode_register_write(dst_reg, left_ty)?);

        let index = self.push_assign(dst_place, Expression::Binary { 
            left: Operand::Place(left_place),
            right, 
            operator: op,
        });

        self.flags = Flags::Binary { operator: op, index };

        Ok(())

    }

    /// Decode instruction `cbw/cwde/cdqe <r/m>`: 
    /// - https://www.felixcloutier.com/x86/cbw:cwde:cdqe
    /// 
    /// These instructions sign extends the content of AL/AX/EAX into AX/EAX/RAX.
    fn decode_sign_extend_rax(&mut self, src_reg: Register) -> AnyResult<()> {

        let dst_reg = match src_reg {
            Register::AL => Register::AX,
            Register::AX => Register::EAX,
            Register::EAX => Register::RAX,
            _ => unimplemented!()
        };

        let src_ty = IntLayout::Signed.to_type(src_reg.size());
        let src_local = self.decode_register_import(src_reg, src_ty)?;

        let dst_ty = IntLayout::Signed.to_type(dst_reg.size());
        let dst_local = self.decode_register_write(dst_reg, dst_ty)?;

        self.push_assign(Place::new_direct(dst_local), Expression::Cast(Place::new_direct(src_local)));
        Ok(())

    }

    /// Decode instruction `cwd/cdq/cqo <r/m>`: 
    /// - https://www.felixcloutier.com/x86/cwd:cdq:cqo
    /// 
    /// These instructions sign extends the content of AX/EAX/RAX into 
    /// DX:AX/EDX:EAX/RDX:RAX.
    fn decode_sign_extend_rax_rdx(&mut self, rax_reg: Register) -> AnyResult<()> {
        // Saving the signed integer type that has been sign extended.
        self.rdx_rax_state = RdxRaxState::SignExtend(IntLayout::Signed.to_type(rax_reg.size()));
        Ok(())
    }

    /// Decode instruction `div/idiv <r/m>`: 
    /// - https://www.felixcloutier.com/x86/div
    /// - https://www.felixcloutier.com/x86/idiv
    fn decode_div(&mut self, inst: &Instruction, layout: IntLayout) -> AnyResult<()> {

        let ty_size;
        let ty;
        let operand_place;

        match inst.op0_register() {
            Register::None => {
                ty_size = inst.memory_base().size();
                ty = layout.to_type(ty_size);
                operand_place = self.decode_mem_operand(inst, ty)?;
            }
            reg => {
                ty_size = reg.size();
                ty = layout.to_type(ty_size);
                operand_place = Place::new_direct(self.decode_register_import(reg, ty)?);
            }
        }

        if ty_size == 1 {
            bail!("decode_div ({layout:?}): unsupported 8-bit division ({inst})");
        }

        match self.rdx_rax_state {
            RdxRaxState::SignExtend(extend_ty) if extend_ty == ty => {
                
                // If RAX has been sign extended to RDX, this is basically just a division
                // of RAX by the operand's value.
                let rax_local = self.decode_register_import(Register::RAX, ty)?;
                let rax_place = Place::new_direct(rax_local);
                // The following access will reset the binding.
                let rdx_local = self.decode_register_write(Register::RDX, ty)?;
                
                self.push_assign(Place::new_direct(rdx_local), Expression::Binary { 
                    left: Operand::Place(rax_place), 
                    right: Operand::Place(operand_place), 
                    operator: BinaryOperator::Rem,
                });

                self.push_assign(rax_place, Expression::Binary { 
                    left: Operand::Place(rax_place), 
                    right: Operand::Place(operand_place), 
                    operator: BinaryOperator::Div,
                });

                Ok(())

            }
            _ => bail!("decode_div ({layout:?}): missing binding rdx:rax ({inst})"),
        }

    }

    /// Decode instruction `mul/imul <rm>`: 
    /// - https://www.felixcloutier.com/x86/mul
    /// - https://www.felixcloutier.com/x86/imul
    /// 
    /// Multiply values in RAX register family by the operand's value and store the result
    /// in the RDX:RAX register family tuple.
    fn decode_mul(&mut self, inst: &Instruction, layout: IntLayout) -> AnyResult<()> {

        let ty_size;
        let ty;
        let operand_place;

        match inst.op0_register() {
            Register::None => {
                ty_size = inst.memory_base().size();
                ty = layout.to_type(ty_size);
                operand_place = self.decode_mem_operand(inst, ty)?;
            }
            reg => {
                ty_size = reg.size();
                ty = layout.to_type(ty_size);
                operand_place = Place::new_direct(self.decode_register_import(reg, ty)?);
            }
        }

        if ty_size == 1 {
            bail!("decode_mul ({layout:?}): unsupported 8-bit multiplication ({inst})");
        }

        let rax_local = self.decode_register_import(Register::RAX, ty)?;
        let rax_place = Place::new_direct(rax_local);

        // For now we only assign the RAX part, the overflow part in RDX can be obtained
        // later by modifying the statement from its index.
        let index = self.push_assign(rax_place, Expression::Binary { 
            left: Operand::Place(rax_place),
            right: Operand::Place(operand_place),
            operator: BinaryOperator::Mul,
        });

        self.rdx_rax_state = RdxRaxState::Mul(index);
        Ok(())

    }

    /// Decode instruction `movss/movsd/movaps/movapd <rm>,<rm>`: 
    /// - https://www.felixcloutier.com/x86/movss
    /// - https://www.felixcloutier.com/x86/movsd
    /// - https://www.felixcloutier.com/x86/movaps
    /// - https://www.felixcloutier.com/x86/movapd
    /// 
    /// Such instructions move single value between scalar registers.
    fn decode_mov_simd_rm_rm(&mut self, inst: &Instruction, double: bool, packed: bool) -> AnyResult<()> {
        
        let get_ty = move |bytes: usize| {
            if packed {
                if double {
                    ty_float_vec_from_bytes(bytes)
                } else {
                    ty_double_vec_from_bytes(bytes)
                }
            } else {
                if double { TY_DOUBLE } else { TY_FLOAT }
            }
        };
        
        let dst_place;
        let src_place;

        match (inst.op0_register(), inst.op1_register()) {
            (Register::None, reg1) => {
                let ty = get_ty(reg1.size());
                src_place = Place::new_direct(self.decode_register_import(reg1, ty)?);
                dst_place = self.decode_mem_operand(inst, ty)?;
            }
            (reg0, Register::None) => {
                let ty = get_ty(reg0.size());
                src_place = self.decode_mem_operand(inst, ty)?;
                dst_place = Place::new_direct(self.decode_register_write(reg0, ty)?);
            }
            (reg0, reg1) => {
                let ty = get_ty(reg0.size());
                src_place = Place::new_direct(self.decode_register_import(reg1, ty)?);
                dst_place = Place::new_direct(self.decode_register_write(reg0, ty)?);
            }
        }

        self.push_assign(dst_place, Expression::Copy(Operand::Place(src_place)));
        Ok(())

    }

    /// Decode instruction `xorps/xorpd <r>,<rm>`: 
    /// - https://www.felixcloutier.com/x86/xorps
    /// - https://www.felixcloutier.com/x86/xorpd
    /// 
    /// Perform XOR on two packed vector registers.
    fn decode_xor_simd_r_rm(&mut self, inst: &Instruction, double: bool) -> AnyResult<()> {

        let ty = if double { TY_DOUBLE } else { TY_FLOAT };

        // TODO: For now we only support xorp for zeroing registers.
        // TODO: Support zero-ing the vector, if relevant.
        if inst.op0_register() == inst.op1_register() {

            let reg = inst.op0_register();
            let reg_local = self.decode_register_write(reg, ty)?;
            self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::Zero));

        } else {
            bail!("decode_xorp_r_rm: different registers ({inst})");
        }

        Ok(())

    }

    /// Decode instruction `test <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/test
    /// 
    /// Read above.
    fn decode_test_rm_imm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let left_place = match inst.op0_register() {
            Register::None => {
                let ty = IntLayout::Weak.to_type(inst.memory_size().size());
                self.decode_mem_operand(inst, ty)?
            }
            reg => {
                let ty = IntLayout::Weak.to_type(reg.size());
                Place::new_direct(self.decode_register_import(reg, ty)?)
            }
        };

        self.flags = Flags::Test { 
            left: left_place, 
            right: Operand::LiteralUnsigned(inst.immediate32() as u64),
        };

        Ok(())

    }

    /// Decode instruction `test <rm>,<r>`:
    /// - https://www.felixcloutier.com/x86/test
    /// 
    /// This instruction make a *bitwise and* between the left and right operand and set
    /// the appropriate flags (SF, ZF, PF), OF and CF are set to zero.
    fn decode_test_rm_r(&mut self, inst: &Instruction) -> AnyResult<()> {

        let reg1 = inst.op1_register();
        let ty = IntLayout::Weak.to_type(reg1.size());

        let right_place = Place::new_direct(self.decode_register_import(reg1, ty)?);
        let left_place = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, ty)?,
            reg0 => Place::new_direct(self.decode_register_import(reg0, ty)?),
        };

        self.flags = Flags::Test { 
            left: left_place, 
            right: Operand::Place(right_place),
        };

        Ok(())

    }

    /// Decode the instruction `cmp <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/cmp
    /// 
    /// This instruction subtract the right immediate operand from the left one,
    /// and set the appropriate flags according to the result.
    fn decode_cmp_rm_imm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let left_place = match inst.op0_register() {
            Register::None => {
                let ty = IntLayout::Weak.to_type(inst.memory_size().size());
                self.decode_mem_operand(inst, ty)?
            }
            reg => {
                let ty = IntLayout::Weak.to_type(reg.size());
                Place::new_direct(self.decode_register_import(reg, ty)?)
            }
        };

        let left_ty = self.function.place_type(left_place);
        let left_layout = IntLayout::try_from(left_ty)?;

        let right = self.decode_int_immediate(inst, 1, left_layout)?;

        self.flags = Flags::Cmp { 
            left: left_place, 
            right,
        };

        Ok(())

    }

    /// Decode the instruction `cmp <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/cmp
    /// 
    /// This instruction subtract the right operand from the left one, 
    /// and set the appropriate flags according to the result.
    fn decode_cmp_rm_rm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let ty = IntLayout::Weak.to_type(inst.memory_size().size());

        let left = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, ty)?,
            Register::SP |
            Register::ESP |
            Register::RSP => bail!("statically unknown: cmp sp,<rm> ({inst})"),
            reg0 => Place::new_direct(self.decode_register_import(reg0, ty)?),
        };

        let right = match inst.op1_register() {
            Register::None => Operand::Place(self.decode_mem_operand(inst, ty)?),
            Register::SP |
            Register::ESP |
            Register::RSP => bail!("statically unknown: cmp <rm>,sp ({inst})"),
            reg1 => Operand::new_local(self.decode_register_import(reg1, ty)?),
        };

        self.flags = Flags::Cmp { left, right };
        Ok(())

    }

    /// Decode the conditional expression from an conditional instruction. This depends
    /// on the last instruction's flags.
    fn decode_cond_expr(&mut self, inst: &Instruction) -> AnyResult<Expression> {

        // Get the associated IDR comparison operator with the required signedness.
        let (operator, layout) = match inst.condition_code() {
            ConditionCode::ne => (ComparisonOperator::NotEqual, IntLayout::Weak),
            ConditionCode::e => (ComparisonOperator::Equal, IntLayout::Weak),
            // Unsigned...
            ConditionCode::a => (ComparisonOperator::Greater, IntLayout::Unsigned),
            ConditionCode::ae => (ComparisonOperator::GreaterOrEqual, IntLayout::Unsigned),
            ConditionCode::b => (ComparisonOperator::Less, IntLayout::Unsigned),
            ConditionCode::be => (ComparisonOperator::LessOrEqual, IntLayout::Unsigned),
            // Signed...
            ConditionCode::g => (ComparisonOperator::Greater, IntLayout::Signed),
            ConditionCode::ge => (ComparisonOperator::GreaterOrEqual, IntLayout::Signed),
            ConditionCode::l => (ComparisonOperator::Less, IntLayout::Signed),
            ConditionCode::le => (ComparisonOperator::LessOrEqual, IntLayout::Signed),
            _ => bail!("decode_cond_expr (cmp): unsupported condition ({inst})")
        };

        // TODO:
        // Handle this weird comparison of a double's first byte:
        // [14024E4BB] movsd qword ptr [rsp+60h],xmm0
        // [14024E4C1] cmp byte ptr [rsp+60h],0
        // [14024E4C6] jne short 000000014024E545h

        Ok(match self.flags {
            Flags::Undefined => bail!("decode_cond_expr: undefined flags"),
            Flags::Cmp { mut left, mut right } => {

                // We believe here that our operand are of an integer type, because cmp
                // instruction force use such types.
                left = self.ensure_place_int_layout(left, layout);
                if let Operand::Place(right) = &mut right {
                    *right = self.ensure_place_int_layout(*right, layout);
                }

                Expression::Comparison { left: Operand::Place(left), operator, right }

            }
            // If both operands of the test is the same local, the "bitwise and" will
            // result in comparing the register to 
            Flags::Test { mut left, right: Operand::Place(right) } if left == right => {
                left = self.ensure_place_int_layout(left, layout);
                Expression::Comparison { left: Operand::Place(left), right: Operand::LiteralUnsigned(0), operator }
            }
            // Simple test just use the binary "and" operator, don't care of signedness.
            Flags::Test { left, right } => {
                
                let result_local = self.alloc_temp_local(TY_BYTE);
                self.push_assign(Place::new_direct(result_local), Expression::Binary { 
                    left: Operand::Place(left), 
                    right, 
                    operator: BinaryOperator::And,
                });

                Expression::Comparison { 
                    left: Operand::new_local(result_local), 
                    right: Operand::LiteralUnsigned(0),
                    operator
                }

            }
            // How to handle binary operators actually depends on the condition code used,
            // because zero/non zero condition can simply apply on the operation's result,
            // but other flags such as overflow requires to modify the existing expression
            // with an expression that also produces a boolean with that flag.
            Flags::Binary { operator: _, index } => {

                if !matches!(operator, ComparisonOperator::Equal | ComparisonOperator::NotEqual) {
                    bail!("decode_cond_expr (binary): unsupported condition ({inst})")
                }

                let Statement::Assign { place, .. } = self.function.statements[index] else {
                    bail!("decode_cond_expr (binary): target index {index} is not an assignment");
                };

                Expression::Comparison { left: Operand::Place(place), right: Operand::LiteralUnsigned(0), operator }

            }
        })

    }

    fn decode_call_rel(&mut self, inst: &Instruction) -> AnyResult<()> {
        
        let pointer = inst.memory_displacement64();
        let ret_local = self.decode_register_write(Register::RAX, TY_QWORD)?;

        self.flags = Flags::Undefined;
        self.push_assign(Place::new_direct(ret_local), Expression::Call { 
            pointer: Operand::LiteralUnsigned(pointer), 
            arguments: Vec::new(),
        });

        Ok(())

    }

    fn decode_call_rm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let pointer_place = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, TY_VOID.pointer(1))?,
            reg => Place::new_direct(self.decode_register_import(reg, TY_VOID.pointer(1))?),
        };

        let ret_local = self.decode_register_write(Register::RAX, TY_QWORD)?;
        let ret_place = Place::new_direct(ret_local);

        self.flags = Flags::Undefined;
        self.push_assign(ret_place, Expression::Call {
            pointer: Operand::Place(pointer_place),
            arguments: Vec::new(),
        });

        Ok(())

    }

    fn decode_jcc(&mut self, inst: &Instruction) -> AnyResult<()> {

        let pointer = inst.near_branch64();
        let cond_expr = self.decode_cond_expr(inst)?;

        // If the function doesn't contain the pointed basic block, we guess that it's
        // a conditional tail-call
        if self.early_function.contains_block(pointer) {

            let branch_index = self.push_statement_with(|index| {
                Statement::BranchConditional { 
                    value: cond_expr, 
                    branch_true: 0, // Will be modified if upon basic block creation.
                    branch_false: index + 1, // False jcc go to the next statement.
                }
            });
    
            // Unwrap should be safe because basic block is checked when instruction is fed.
            let block_ip = self.basic_block_ip.unwrap();
            let block = self.basic_blocks.get_mut(&block_ip).unwrap();
            block.true_branch = Some(pointer);
            block.false_branch = Some(inst.next_ip());

            let true_block = self.ensure_basic_block_unchecked(pointer);
            true_block.branch_indices_to_relocate.push(branch_index);
            let _false_block = self.ensure_basic_block(inst.next_ip())?;
            Ok(())

        } else {
            bail!("decode_jcc: conditional tail-call not yet supported ({inst})");
        }

    }

    fn decode_jmp_rel(&mut self, inst: &Instruction) -> AnyResult<()> {

        let pointer = inst.near_branch64();

        if self.early_function.contains_block(pointer) {

            let branch_index = self.push_statement(Statement::Branch { branch: 0 });

            let block_ip = self.basic_block_ip.unwrap();
            let block = self.basic_blocks.get_mut(&block_ip).unwrap();
            block.true_branch = Some(pointer);

            let target_block = self.ensure_basic_block_unchecked(pointer);
            target_block.branch_indices_to_relocate.push(branch_index);
            Ok(())

        } else {

            // If the block is not present in our early function, this means this is a 
            // tail-call, we call and directly return with the value of this function.

            let ret_local = self.decode_register_write(Register::RAX, TY_QWORD)?;

            self.push_assign(Place::new_direct(ret_local), Expression::Call { 
                pointer: Operand::LiteralUnsigned(pointer), 
                arguments: Vec::new(),
            });

            // Forward to decode ret in order to add the return statement and finalize
            // the basic block and function.
            self.decode_ret(inst)

        }

    }

    fn decode_jmp_rm(&mut self, _inst: &Instruction) -> AnyResult<()> {

        // TODO: In the future, it would be great to try to understand if this kind of
        // jump is reading a switch table or not.
        // Here is an example of switch table jump:
        //   [140029C82] lea rcx,[140000000h]
        //   [140029C89] mov eax,[rcx+rax*4+29CF4h]
        //   [140029C90] add rax,rcx
        //   [140029C93] jmp rax

        bail!("decode_jmp_rm: unsupported for now, read code comment");

    }

    fn decode_ret(&mut self, _inst: &Instruction) -> AnyResult<()> {

        let ret_place = self.decode_register_import(Register::RAX, TY_QWORD)?;
        self.push_statement(Statement::Return(ret_place));
        Ok(())

    }

    /// Feed a new instruction to the decoder, if some instruction is returned, the 
    /// feeder must goto to the given instruction and start feed from it.
    /// 
    /// **You must ensure** that the first instruction fed into the decoder is also the
    /// start of the first basic block of the decoded function. When feeding is done
    /// you should call the [`finalize_function`] method to compute all missing data
    /// and return the finalized IDR function.
    fn feed(&mut self, inst: &Instruction) -> AnyResult<()> {

        let ip = inst.ip();

        if self.early_function.contains_block(ip) {
            if let Some(stmt) = self.function.statements.last() {
                let mut add_true_branch = None;
                // Add a simple branch if not already the case to ensure that the block exits.
                if !stmt.is_branch() {
                    // NOTE: Can't use 'push_statement' because of borrowing.
                    let branch_index = self.function.statements.len();
                    self.function.statements.push(Statement::Branch { branch: branch_index + 1 });
                    add_true_branch = Some(ip);
                }
                // If there is at least one statement, this mean that we are past the 
                // first basic block, we can finalize the current one.
                self.finalize_basic_block(add_true_branch);
            }
            // Prepare next basic block.
            let block = self.basic_blocks.entry(ip).or_default();
            block.begin_index = Some(self.function.statements.len());
            // Set the new basic block ip being decoded.
            self.basic_block_ip = Some(ip);
        } else if self.basic_block_ip.is_none() {
            bail!("missing basic block for instruction at {ip:08X}");
        }
        
        if inst.has_lock_prefix() {
            bail!("lock prefix is not yet supported ({inst})");
        }

        match inst.code() {
            // PUSH
            Code::Push_r64 |
            Code::Push_r32 |
            Code::Push_r16 => self.decode_push_r(inst)?,
            // POP
            Code::Pop_r64 |
            Code::Pop_r32 |
            Code::Pop_r16 => self.decode_pop_r(inst)?,
            // LEA
            Code::Lea_r64_m |
            Code::Lea_r32_m |
            Code::Lea_r16_m => self.decode_lea_r_m(inst)?,
            // MOV
            Code::Mov_r64_imm64 |
            Code::Mov_r32_imm32 |
            Code::Mov_r16_imm16 |
            Code::Mov_r8_imm8 |
            Code::Mov_rm64_imm32 |
            Code::Mov_rm32_imm32 |
            Code::Mov_rm16_imm16 |
            Code::Mov_rm8_imm8 => self.decode_mov_rm_imm(inst)?,
            Code::Mov_r64_rm64 |
            Code::Mov_r32_rm32 |
            Code::Mov_r16_rm16 |
            Code::Mov_r8_rm8 |
            Code::Mov_rm64_r64 |
            Code::Mov_rm32_r32 |
            Code::Mov_rm16_r16 |
            Code::Mov_rm8_r8 => self.decode_mov_rm_rm(inst)?,
            // MOVZX (move zero-extended)
            Code::Movzx_r64_rm16 |
            Code::Movzx_r64_rm8 |
            Code::Movzx_r32_rm16 |
            Code::Movzx_r32_rm8 |
            Code::Movzx_r16_rm16 |
            Code::Movzx_r16_rm8 => self.decode_mov_extend_r_rm(inst, IntLayout::Unsigned)?,
            // MOVSX (move sign-extended)
            Code::Movsx_r64_rm16 |
            Code::Movsx_r64_rm8 |
            Code::Movsx_r32_rm16 |
            Code::Movsx_r32_rm8 |
            Code::Movsx_r16_rm16 |
            Code::Movsx_r16_rm8 |
            Code::Movsxd_r64_rm32 |
            Code::Movsxd_r32_rm32 |
            Code::Movsxd_r16_rm16 => self.decode_mov_extend_r_rm(inst, IntLayout::Signed)?,
            // MOVS (mov string)
            Code::Movsq_m64_m64 |
            Code::Movsd_m32_m32 |
            Code::Movsw_m16_m16 |
            Code::Movsb_m8_m8 => self.decode_movs_m_m(inst)?,
            // INC
            Code::Inc_rm8 |
            Code::Inc_rm16 |
            Code::Inc_rm32 |
            Code::Inc_rm64 |
            Code::Inc_r16 |
            Code::Inc_r32 => self.decode_int_op_rm_one(inst, BinaryOperator::Add, IntLayout::Weak)?,
            // DEC
            Code::Dec_rm8 |
            Code::Dec_rm16 |
            Code::Dec_rm32 |
            Code::Dec_rm64 |
            Code::Dec_r16 |
            Code::Dec_r32 => self.decode_int_op_rm_one(inst, BinaryOperator::Sub, IntLayout::Weak)?,
            // ADD
            Code::Add_RAX_imm32 |
            Code::Add_EAX_imm32 |
            Code::Add_AX_imm16 |
            Code::Add_AL_imm8 |
            Code::Add_rm64_imm8 |
            Code::Add_rm32_imm8 |
            Code::Add_rm16_imm8 |
            Code::Add_rm8_imm8 |
            Code::Add_rm64_imm32 |
            Code::Add_rm32_imm32 |
            Code::Add_rm16_imm16  => self.decode_int_op_rm_imm(inst, BinaryOperator::Add, IntLayout::Weak)?,
            Code::Add_r64_rm64 |
            Code::Add_r32_rm32 |
            Code::Add_r16_rm16 |
            Code::Add_r8_rm8 |
            Code::Add_rm64_r64 |
            Code::Add_rm32_r32 |
            Code::Add_rm16_r16 |
            Code::Add_rm8_r8 => self.decode_int_op_rm_rm(inst, BinaryOperator::Add, IntLayout::Weak)?,
            // SUB
            Code::Sub_RAX_imm32 |
            Code::Sub_EAX_imm32 |
            Code::Sub_AX_imm16 |
            Code::Sub_AL_imm8 |
            Code::Sub_rm64_imm8 |
            Code::Sub_rm32_imm8 |
            Code::Sub_rm16_imm8 |
            Code::Sub_rm8_imm8 |
            Code::Sub_rm64_imm32 |
            Code::Sub_rm32_imm32 |
            Code::Sub_rm16_imm16  => self.decode_int_op_rm_imm(inst, BinaryOperator::Sub, IntLayout::Weak)?,
            Code::Sub_r64_rm64 |
            Code::Sub_r32_rm32 |
            Code::Sub_r16_rm16 |
            Code::Sub_r8_rm8 |
            Code::Sub_rm64_r64 |
            Code::Sub_rm32_r32 |
            Code::Sub_rm16_r16 |
            Code::Sub_rm8_r8 => self.decode_int_op_rm_rm(inst, BinaryOperator::Sub, IntLayout::Weak)?,
            // AND
            Code::And_RAX_imm32 |
            Code::And_EAX_imm32 |
            Code::And_AX_imm16 |
            Code::And_AL_imm8 |
            Code::And_rm64_imm8 |
            Code::And_rm32_imm8 |
            Code::And_rm16_imm8 |
            Code::And_rm8_imm8 |
            Code::And_rm64_imm32 |
            Code::And_rm32_imm32 |
            Code::And_rm16_imm16  => self.decode_int_op_rm_imm(inst, BinaryOperator::And, IntLayout::Weak)?,
            Code::And_r64_rm64 |
            Code::And_r32_rm32 |
            Code::And_r16_rm16 |
            Code::And_r8_rm8 |
            Code::And_rm64_r64 |
            Code::And_rm32_r32 |
            Code::And_rm16_r16 |
            Code::And_rm8_r8 => self.decode_int_op_rm_rm(inst, BinaryOperator::And, IntLayout::Weak)?,
            // OR
            Code::Or_RAX_imm32 |
            Code::Or_EAX_imm32 |
            Code::Or_AX_imm16 |
            Code::Or_AL_imm8 |
            Code::Or_rm64_imm8 |
            Code::Or_rm32_imm8 |
            Code::Or_rm16_imm8 |
            Code::Or_rm8_imm8 |
            Code::Or_rm64_imm32 |
            Code::Or_rm32_imm32 |
            Code::Or_rm16_imm16  => self.decode_int_op_rm_imm(inst, BinaryOperator::Or, IntLayout::Weak)?,
            Code::Or_r64_rm64 |
            Code::Or_r32_rm32 |
            Code::Or_r16_rm16 |
            Code::Or_r8_rm8 |
            Code::Or_rm64_r64 |
            Code::Or_rm32_r32 |
            Code::Or_rm16_r16 |
            Code::Or_rm8_r8 => self.decode_int_op_rm_rm(inst, BinaryOperator::Or, IntLayout::Weak)?,
            // XOR
            Code::Xor_RAX_imm32 |
            Code::Xor_EAX_imm32 |
            Code::Xor_AX_imm16 |
            Code::Xor_AL_imm8 |
            Code::Xor_rm64_imm8 |
            Code::Xor_rm32_imm8 |
            Code::Xor_rm16_imm8 |
            Code::Xor_rm8_imm8 |
            Code::Xor_rm64_imm32 |
            Code::Xor_rm32_imm32 |
            Code::Xor_rm16_imm16  => self.decode_int_op_rm_imm(inst, BinaryOperator::Xor, IntLayout::Weak)?,
            Code::Xor_r64_rm64 |
            Code::Xor_r32_rm32 |
            Code::Xor_r16_rm16 |
            Code::Xor_r8_rm8 |
            Code::Xor_rm64_r64 |
            Code::Xor_rm32_r32 |
            Code::Xor_rm16_r16 |
            Code::Xor_rm8_r8 => self.decode_int_op_rm_rm(inst, BinaryOperator::Xor, IntLayout::Weak)?,
            // SAR (shift arithmetic right)
            Code::Sar_rm64_1 |
            Code::Sar_rm32_1 |
            Code::Sar_rm16_1 |
            Code::Sar_rm8_1 => self.decode_int_op_rm_one(inst, BinaryOperator::ShiftRight, IntLayout::Signed)?,
            Code::Sar_rm64_imm8 |
            Code::Sar_rm32_imm8 |
            Code::Sar_rm16_imm8 |
            Code::Sar_rm8_imm8 => self.decode_int_op_rm_imm(inst, BinaryOperator::ShiftRight, IntLayout::Signed)?,
            Code::Sar_rm64_CL |
            Code::Sar_rm32_CL |
            Code::Sar_rm16_CL |
            Code::Sar_rm8_CL => self.decode_int_op_rm_rm(inst, BinaryOperator::ShiftRight, IntLayout::Signed)?,
            // SAR (shift arithmetic right)
            Code::Shr_rm64_1 |
            Code::Shr_rm32_1 |
            Code::Shr_rm16_1 |
            Code::Shr_rm8_1 => self.decode_int_op_rm_one(inst, BinaryOperator::ShiftRight, IntLayout::Unsigned)?,
            Code::Shr_rm64_imm8 |
            Code::Shr_rm32_imm8 |
            Code::Shr_rm16_imm8 |
            Code::Shr_rm8_imm8 => self.decode_int_op_rm_imm(inst, BinaryOperator::ShiftRight, IntLayout::Unsigned)?,
            Code::Shr_rm64_CL |
            Code::Shr_rm32_CL |
            Code::Shr_rm16_CL |
            Code::Shr_rm8_CL => self.decode_int_op_rm_rm(inst, BinaryOperator::ShiftRight, IntLayout::Unsigned)?,
            // SHL (shift left)
            Code::Shl_rm64_1 |
            Code::Shl_rm32_1 |
            Code::Shl_rm16_1 |
            Code::Shl_rm8_1 => self.decode_int_op_rm_one(inst, BinaryOperator::ShiftLeft, IntLayout::Weak)?,
            Code::Shl_rm64_imm8 |
            Code::Shl_rm32_imm8 |
            Code::Shl_rm16_imm8 |
            Code::Shl_rm8_imm8 => self.decode_int_op_rm_imm(inst, BinaryOperator::ShiftLeft, IntLayout::Weak)?,
            Code::Shl_rm64_CL |
            Code::Shl_rm32_CL |
            Code::Shl_rm16_CL |
            Code::Shl_rm8_CL => self.decode_int_op_rm_rm(inst, BinaryOperator::ShiftLeft, IntLayout::Weak)?,
            // CBW/CWDE/CDQE
            Code::Cbw => self.decode_sign_extend_rax(Register::AL)?,
            Code::Cwde => self.decode_sign_extend_rax(Register::AX)?,
            Code::Cdqe => self.decode_sign_extend_rax(Register::EAX)?,
            // CWD/CDQ/CQO
            Code::Cwd => self.decode_sign_extend_rax_rdx(Register::AX)?,
            Code::Cdq => self.decode_sign_extend_rax_rdx(Register::EAX)?,
            Code::Cqo => self.decode_sign_extend_rax_rdx(Register::RAX)?,
            // DIV
            Code::Div_rm64 |
            Code::Div_rm32 |
            Code::Div_rm16 |
            Code::Div_rm8 => self.decode_div(inst, IntLayout::Unsigned)?,
            // IDIV
            Code::Idiv_rm64 |
            Code::Idiv_rm32 |
            Code::Idiv_rm16 |
            Code::Idiv_rm8 => self.decode_div(inst, IntLayout::Signed)?,
            // MUL
            Code::Mul_rm64 |
            Code::Mul_rm32 |
            Code::Mul_rm16 |
            Code::Mul_rm8 => self.decode_mul(inst, IntLayout::Unsigned)?,
            // IMUL
            Code::Imul_rm64 |
            Code::Imul_rm32 |
            Code::Imul_rm16 |
            Code::Imul_rm8 => self.decode_mul(inst, IntLayout::Signed)?,
            Code::Imul_r64_rm64 |
            Code::Imul_r32_rm32 |
            Code::Imul_r16_rm16 => self.decode_int_op_rm_rm(inst, BinaryOperator::Mul, IntLayout::Signed)?,
            Code::Imul_r64_rm64_imm32 |
            Code::Imul_r32_rm32_imm32 |
            Code::Imul_r16_rm16_imm16 |
            Code::Imul_r64_rm64_imm8 |
            Code::Imul_r32_rm32_imm8 |
            Code::Imul_r16_rm16_imm8 => self.decode_int_op_r_rm_imm(inst, BinaryOperator::Mul, IntLayout::Signed)?,
            // MOVSS/MOVSD (mov single f32/f64)
            Code::Movss_xmm_xmmm32 |
            Code::Movss_xmmm32_xmm => self.decode_mov_simd_rm_rm(inst, false, false)?,
            Code::Movsd_xmm_xmmm64 |
            Code::Movsd_xmmm64_xmm => self.decode_mov_simd_rm_rm(inst, false, true)?,
            // MOVAPS/MOVAPD (mov aligned packed f32/f64)
            Code::Movaps_xmmm128_xmm |
            Code::Movaps_xmm_xmmm128 => self.decode_mov_simd_rm_rm(inst, false, true)?,
            Code::Movapd_xmmm128_xmm |
            Code::Movapd_xmm_xmmm128 => self.decode_mov_simd_rm_rm(inst, false, true)?,
            // MOVUPS/MOVUPD (mov aligned packed f32/f64)
            Code::Movups_xmmm128_xmm |
            Code::Movups_xmm_xmmm128 => self.decode_mov_simd_rm_rm(inst, false, true)?,
            Code::Movupd_xmmm128_xmm |
            Code::Movupd_xmm_xmmm128 => self.decode_mov_simd_rm_rm(inst, false, true)?,
            // XORPS (xor packed f32)
            Code::Xorps_xmm_xmmm128 => self.decode_xor_simd_r_rm(inst, false)?,
            Code::Xorpd_xmm_xmmm128 => self.decode_xor_simd_r_rm(inst, true)?,
            // TEST
            Code::Test_RAX_imm32 |
            Code::Test_EAX_imm32 |
            Code::Test_AX_imm16 |
            Code::Test_AL_imm8 |
            Code::Test_rm64_imm32 |
            Code::Test_rm32_imm32 |
            Code::Test_rm16_imm16 |
            Code::Test_rm8_imm8 => self.decode_test_rm_imm(inst)?,
            Code::Test_rm64_r64 |
            Code::Test_rm32_r32 |
            Code::Test_rm16_r16 |
            Code::Test_rm8_r8 => self.decode_test_rm_r(inst)?,
            // CMP
            Code::Cmp_RAX_imm32 |
            Code::Cmp_EAX_imm32 |
            Code::Cmp_AX_imm16 |
            Code::Cmp_AL_imm8 |
            Code::Cmp_rm64_imm8 |
            Code::Cmp_rm32_imm8 |
            Code::Cmp_rm16_imm8 |
            Code::Cmp_rm8_imm8 |
            Code::Cmp_rm8_imm8_82 |
            Code::Cmp_rm64_imm32 |
            Code::Cmp_rm32_imm32 |
            Code::Cmp_rm16_imm16 => self.decode_cmp_rm_imm(inst)?,
            Code::Cmp_rm64_r64 |
            Code::Cmp_rm32_r32 |
            Code::Cmp_rm16_r16 |
            Code::Cmp_rm8_r8 |
            Code::Cmp_r64_rm64 |
            Code::Cmp_r32_rm32 |
            Code::Cmp_r16_rm16 |
            Code::Cmp_r8_rm8 => self.decode_cmp_rm_rm(inst)?,
            // CALL
            Code::Call_rel16 |
            Code::Call_rel32_32 |
            Code::Call_rel32_64 => self.decode_call_rel(inst)?,
            Code::Call_rm64 |
            Code::Call_rm32 |
            Code::Call_rm16 => self.decode_call_rm(inst)?,
            // Jcc
            code if code.is_jcc_short_or_near() => self.decode_jcc(inst)?,
            // JMP
            Code::Jmp_rel8_64 |
            Code::Jmp_rel8_32 |
            Code::Jmp_rel8_16 |
            Code::Jmp_rel32_64 |
            Code::Jmp_rel32_32 => self.decode_jmp_rel(inst)?,
            Code::Jmp_rm64 |
            Code::Jmp_rm32 |
            Code::Jmp_rm16 => self.decode_jmp_rm(inst)?,
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
            Code::Retfw_imm16 => self.decode_ret(inst)?,
            // NOP
            Code::Nopw |
            Code::Nopd |
            Code::Nopq |
            Code::Nop_rm16 |
            Code::Nop_rm32 |
            Code::Nop_rm64 |
            Code::Int3 => {},
            _ => {
                return Err(anyhow!(inst.clone()));
            }
        }

        Ok(())

    }

    fn add_sp(&mut self, delta: i32) {
        self.stack_pointer += delta;
        // println!("  sp: {}", self.stack_pointer);
    }

    fn sub_sp(&mut self, delta: i32) {
        self.stack_pointer -= delta;
        // println!("  sp: {}", self.stack_pointer);
    }

    /// Decode a register access for the given type, if the tuple register/ty doesn't
    /// have a local variable yet, it's created. If a new local variable is created,
    /// and the given `import` argument is true then the value of the register family 
    /// is preserved in the new local, using a cast assignment.
    #[track_caller]
    fn decode_register(&mut self, register: Register, mut ty: Type, usage: RegisterUsage) -> AnyResult<LocalRef> {

        let full_register = register.full_register();

        if full_register == Register::RSP {
            bail!("decode_register: invalid sp register family");
        }

        match self.register_block_locals.entry(full_register) {
            Entry::Occupied(o) => {

                let locals = o.into_mut();
                let last_local = locals.last;
                let last_ty = self.function.local_type(last_local);

                // We want to check for the following cases (only if import mode):
                // - last_ty = actual(last_n), ty = weak(n):
                //   - n == last_n: force ty to last_ty
                //   - n != last_n: force ty to actual(n)
                
                // If the required indirection and the last one corresponds.
                if let RegisterUsage::Import = usage {
                    if last_ty.indirection == ty.indirection {
                        if let Some(last_n) = last_ty.primitive.actual_int_bits() {
                            if let Some(n) = ty.primitive.weak_int_bits() {
                                let mut new_ty = last_ty;
                                if n == last_n {
                                    new_ty.primitive = new_ty.primitive.with_int_bits(n).unwrap();
                                }
                                ty = new_ty
                            }
                        }
                    }
                }

                // TODO: Be careful with the 'rdx_rax_state', if the two registers are
                // bound we should fix their values before using them.

                if ty != last_ty {

                    let new_local = *self.register_typed_locals.entry((register, ty))
                        .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("register: {full_register:?}")));

                    locals.last = new_local;

                    if let RegisterUsage::Import = usage {
                        self.push_assign(Place::new_direct(new_local), Expression::Cast(Place::new_direct(last_local)));
                    }

                    Ok(new_local)

                } else {
                    Ok(last_local)
                }

            }
            Entry::Vacant(v) => {
                
                let local = *self.register_typed_locals.entry((register, ty))
                    .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("register: {full_register:?}")));

                v.insert(RegisterBlockLocals { 
                    import: matches!(usage, RegisterUsage::Import).then_some(local),
                    last: local,
                });

                Ok(local)

            }
        }

    }

    /// Shortcut for calling [`decode_register`] with an "import" usage.
    #[track_caller]
    #[inline]
    fn decode_register_import(&mut self, register: Register, ty: Type) -> AnyResult<LocalRef> {
        self.decode_register(register, ty, RegisterUsage::Import)
    }

    /// Shortcut for calling [`decode_register`] with an "import" and a weak integer type
    /// of the given bytes count, the return local can be any weak/unsigned/signed integer
    /// type of the given bytes size.
    #[track_caller]
    #[inline]
    fn decode_register_import_int(&mut self, register: Register, bytes: usize) -> AnyResult<LocalRef> {
        self.decode_register_import(register, IntLayout::Weak.to_type(bytes))
    }

    /// Shortcut for calling [`decode_register`] with an "write" usage.
    #[track_caller]
    #[inline]
    fn decode_register_write(&mut self, register: Register, ty: Type) -> AnyResult<LocalRef> {
        self.decode_register(register, ty, RegisterUsage::Write)
    }

    /// Shortcut for calling [`decode_register`] with an "write" usage and a weak integer
    /// type of the given bytes count.
    #[track_caller]
    #[inline]
    fn decode_register_write_int(&mut self, register: Register, bytes: usize) -> AnyResult<LocalRef> {
        self.decode_register(register, IntLayout::Weak.to_type(bytes), RegisterUsage::Write)
    }

    /// Get a local usable to write from the given stack offset. The given type is only
    /// associated at local's creation, so **the returned is not guaranteed to be of 
    /// that type**.
    fn decode_stack_local(&mut self, offset: i32, ty: Type) -> LocalRef {
        *self.stack_locals.entry(offset)
            .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("stack: {offset}")))
    }

    /// Decode a stack place given an offset and the type we want the place to be.
    fn decode_stack_place(&mut self, offset: i32, ty: Type) -> Place {

        let stack_local = self.decode_stack_local(offset, ty);
        // We check the effective stack local's type.
        let stack_ty = self.function.local_type(stack_local);
        if stack_ty != ty {

            // Wrong type so we create a pointer and then cast this pointer.
            let temp_local_0 = self.alloc_temp_local(stack_ty.pointer(1));
            self.push_assign(Place::new_direct(temp_local_0), Expression::Ref(Place::new_direct(stack_local)));
            let temp_local_1 = self.alloc_temp_local(ty.pointer(1));
            self.push_assign(Place::new_direct(temp_local_1), Expression::Cast(Place::new_direct(temp_local_0)));

            Place::new_index_absolute(temp_local_1, 0)

        } else {
            Place::new_direct(stack_local)
        }
        
    }

    /// Allocate a temporary variable to hold the given type, the local will be freed
    /// automatically when the current basic block is exited, this local variable
    /// ***should not be used between two basic blocks***.
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

    /// A special function that take a place and ensures that a place as a correct integer
    /// layout, if not a temporary variable is created containing the place's value but
    /// casted to the right integer type.
    fn ensure_place_int_layout(&mut self, place: Place, layout: IntLayout) -> Place {
        let ty = self.function.place_type(place);
        match (ty.primitive, layout) {
            (PrimitiveType::WeakInt(_), IntLayout::Weak) => place,
            (PrimitiveType::UnsignedInt(_), IntLayout::Unsigned | IntLayout::Weak) => place,
            (PrimitiveType::SignedInt(_), IntLayout::Signed | IntLayout::Weak) => place,
            (PrimitiveType::WeakInt(n), _) |
            (PrimitiveType::UnsignedInt(n), _) |
            (PrimitiveType::SignedInt(n), _) => {
                let temp_local = self.alloc_temp_local(layout.to_type_from_bits(n));
                self.push_assign(Place::new_direct(temp_local), Expression::Cast(place));
                Place::new_direct(temp_local)
            }
            _ => panic!("ensure_place_int_layout: given place has non-integer type ({ty:?})"),
        }
    }

    /// Push a new statement with a producer closure that take the future statement's
    /// index as parameter.
    fn push_statement_with<F: FnOnce(usize) -> Statement>(&mut self, func: F) -> usize {
        let statement_index = self.function.statements.len();
        self.function.statements.push(func(statement_index));
        statement_index
    }

    /// Push a new statement.
    fn push_statement(&mut self, statement: Statement) -> usize {
        self.push_statement_with(|_| statement)
    }

    /// Push an assignment statement.
    fn push_assign(&mut self, place: Place, value: Expression) -> usize {
        self.push_statement(Statement::Assign { place, value })
    }

    /// Ensure that a basic block is existing at the given ip, for debugging purpose this
    /// function panics if the given ip is not containing within early function.
    #[track_caller]
    fn ensure_basic_block(&mut self, ip: u64) -> AnyResult<&mut BasicBlock> {
        if !self.early_function.contains_block(ip) {
            bail!("incoherent basic block with early function: {ip:08X}");
        }
        Ok(self.ensure_basic_block_unchecked(ip))
    }

    fn ensure_basic_block_unchecked(&mut self, ip: u64) -> &mut BasicBlock {
        self.basic_blocks.entry(ip).or_default()
    }

}

/// Used to tell if an expression should produce a signed or unsigned integer. This
/// correspond to the `WeakInt`, `UnsignedInt` and `SignedInt` primitive types. It's
/// used to tell an operator to work on unsigned or signed integer, or weak if 
/// unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntLayout {
    /// The integer type that will be used is weak and can be coerced to a 
    /// unsigned/signed one at any time.
    Weak,
    /// The integer type is required to be unsigned.
    Unsigned,
    /// The integer type is required to be signed.
    Signed,
}

impl IntLayout {

    /// Convert this abstract int layout to an actual type given a bits count.
    fn to_type_from_bits(self, bits: u32) -> Type {
        match self {
            IntLayout::Weak => PrimitiveType::WeakInt(bits).plain(),
            IntLayout::Unsigned => PrimitiveType::UnsignedInt(bits).plain(),
            IntLayout::Signed => PrimitiveType::SignedInt(bits).plain(),
        }
    }

    /// Convert this abstract int layout to an actual type given a bytes count.
    fn to_type(self, bytes: usize) -> Type {
        self.to_type_from_bits(bytes as u32 * 8)
    }

}

impl TryFrom<Type> for IntLayout {

    type Error = AnyError;

    fn try_from(value: Type) -> Result<Self, Self::Error> {
        if !value.is_pointer() {
            match value.primitive {
                PrimitiveType::WeakInt(_) => Ok(Self::Weak),
                PrimitiveType::UnsignedInt(_) => Ok(Self::Unsigned),
                PrimitiveType::SignedInt(_) => Ok(Self::Signed),
                _ => bail!("unknown int layout from primitive type {:?}", value.primitive)
            }
        } else {
            bail!("unknown int layout from pointer type {:?}", value)
        }
    }

}

/// Saves for each register family, their optional imported local and the last local
/// bound to them for the current basic block being resolved.
#[derive(Debug)]
struct RegisterBlockLocals {
    /// If this register is read but is not already bound in the current basic block, it
    /// needs to be imported from caller basic block(s). This specifies the type of the
    /// register family local to bind, this register family/type should be present in
    /// the `register_typed_locals` map.
    import: Option<LocalRef>,
    /// The last local variable that has been bound to the register family.
    last: LocalRef,
}

/// This enumeration is used for register decoding and describe how the register's local
/// is going to be used.
#[derive(Debug)]
enum RegisterUsage {
    /// If the register family was already used in the current basic block, the local 
    /// associated to the requested type is returned, if the requested type is not the 
    /// same as the old one, the old previous local is casted into the returned one.
    /// 
    /// If the register family was never used in the current basic block, a new local
    /// is associated and added to the imports of the current basic block.
    Import,
    /// A local variable of the requested type is returned after being associated to
    /// the register family.
    Write,
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

#[derive(Debug)]
enum RdxRaxState {
    /// The two registers are not bound.
    None,
    /// A register of the RAX family has been extended into the RDX family of the same
    /// size. The signed integer type is given, just to check that the future operations
    /// on RDX:RAX are of the same type.
    SignExtend(Type),
    /// The RDX:RAX family tuple is used to store the result of an unsigned or signed
    /// multiplication, the multiplication statement is at the given index.
    Mul(usize),
}

/// Internal structure used to keep track of flags and how they were previously 
/// calculated.
enum Flags {
    /// The last instruction have produces undefined flags, we can't use such state for
    /// resolving conditional instructions.
    Undefined,
    /// The flags were last set by a comparison, basically a subtraction of right from
    /// left, this sets all CF, OF, SF, ZF, AF, PF flags.
    Cmp {
        left: Place,
        right: Operand,
    },
    /// The flags were last set by a test, basically a bitwise and of left and right,
    /// this sets SF, ZF and PF flags.
    Test {
        left: Place,
        right: Operand,
    },
    /// The flag was previously set by a binary operator, flags are set depending on
    /// the operator. For example, boolean operators (and, or, xor) will set SF/ZF/PF
    /// and therefore we can just read the resulting value and do comparison on it.
    /// But for integer operators, it will often be required to just replace the 
    /// binary operation in-place with a expression that also gives us flags infos.
    Binary {
        operator: BinaryOperator,
        index: usize,
    }
}

/// Information about a basic block.
#[derive(Debug, Default)]
struct BasicBlock {
    /// Index of the first statement in the basic block. None means that this basic block
    /// has been added as a back reference by a branch, this means that we know that a
    /// branch statement is missing just before the basic block.
    begin_index: Option<usize>,
    /// Index of the the branch statement of this basic block, by definition this is the
    /// last and only branch statement in this basic block.
    branch_index: Option<usize>,
    /// The list of branch statements indices to relocate to point to this basic block
    /// when the function is finalized. **This is reset between passes.**
    branch_indices_to_relocate: Vec<usize>,
    /// Instruction pointer of the basic block taken if condition is true.
    true_branch: Option<u64>,
    /// Instruction pointer of the basic block token if condition is false.
    false_branch: Option<u64>,
    /// Per register family usage.
    register_locals: HashMap<Register, RegisterBlockLocals>,
}

impl BasicBlock {

    /// Iterate over all register locals that were used by this basic block and needs to
    /// be imported from through the given local (mapped to the given register family).
    fn iter_import_register_locals(&self) -> impl Iterator<Item = (Register, LocalRef)> + '_ {
        self.register_locals.iter().filter_map(|(&register, locals)| {
            Some((register, locals.import?))
        })
    }

}

/// A structure used when finalizing basic blocks imports and exports register locals.
#[derive(Debug, Default)]
struct FinalBasicBlock {
    /// The list of unique exports, note that multiple types of the same register can be
    /// exported at the same type. For each register/local the boolean indicate if true
    /// that the export has been computed and no longer need consideration.
    exports: HashMap<(Register, LocalRef), bool>,
    /// Instruction pointers of parent basic blocks that branch to this one.
    parents: Vec<u64>,
}


const TY_VOID: Type = PrimitiveType::Void.plain();
const TY_BYTE: Type = PrimitiveType::WeakInt(8).plain();
const TY_QWORD: Type = PrimitiveType::WeakInt(64).plain();
const TY_PTR_DIFF: Type = PrimitiveType::SignedInt(64).plain();
const TY_FLOAT: Type = PrimitiveType::Float.plain();
const TY_DOUBLE: Type = PrimitiveType::Double.plain();

#[inline]
const fn ty_float_vec_from_bytes(bytes: usize) -> Type {
    PrimitiveType::FloatVec(bytes as u32 / 4).plain()
}

#[inline]
const fn ty_double_vec_from_bytes(bytes: usize) -> Type {
    PrimitiveType::DoubleVec(bytes as u32 / 8).plain()
}
