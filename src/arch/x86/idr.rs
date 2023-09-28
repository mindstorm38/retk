//! IDR decoder from machine code.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use iced_x86::{Instruction, Code, Register, ConditionCode, OpKind};
use anyhow::{Result as AnyResult, anyhow, bail};

use crate::idr::{LocalRef, Function, Statement, Expression, Place, Index, Operand, 
    ComparisonOperator, BinaryOperator};
use crate::idr::print::{LocalRefDisplay, write_function};
use crate::ty::{TypeSystem, Type, PrimitiveType};

use super::early::{EarlyFunctions, EarlyFunction};
use super::Backend;


const DEBUG_FUNCTION: u64 = 0x1400277A0;


/// Analyze all IDR functions.
pub fn analyze_idr(backend: &mut Backend, early_functions: &EarlyFunctions) {

    let mut type_system = TypeSystem::new(backend.pointer_size, 8);
    let mut functions = HashMap::new();

    let functions_count = early_functions.functions_count();

    let mut missing_opcodes = HashMap::<_, usize>::new();

    'func: for (i, early_function) in early_functions.iter_functions().enumerate() {

        print!(" = At {:08X} ({:03.0}%)... ", early_function.begin(), i as f32 / functions_count as f32 * 100.0);

        let section = backend.sections.get_code_section_at(early_function.begin()).unwrap();
        let offset = early_function.begin() - section.begin_addr;
        backend.decoder.goto_range_at(section.pos + offset as usize, early_function.begin(), early_function.end());

        let mut decoder = IdrDecoder::new(&mut type_system, early_function);

        while let Some(inst) = backend.decoder.decode() {

            if decoder.early_function.begin() == DEBUG_FUNCTION {
                println!("[{:08X}] {inst}", inst.ip());
            }

            if let Err(e) = decoder.feed(inst) {

                if let Some(inst) = e.downcast_ref::<Instruction>() {
                    *missing_opcodes.entry(inst.code()).or_default() += 1;
                    println!("Error: {inst} ({:?})", inst.code());
                } else {
                    println!("Error: {e}");
                }

                continue 'func;

            }

        }

        if decoder.early_function.begin() == DEBUG_FUNCTION {
            decoder.debug_function();
        }

        functions.insert(decoder.early_function.begin(), decoder.function);
        println!("Done.");
        
    }

    let mut missing_opcodes = missing_opcodes.into_iter().collect::<Vec<_>>();
    missing_opcodes.sort_unstable_by_key(|&(code, _)| code.mnemonic());

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
    /// Mapping of stack offset to the local they are storing.
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
    /// Additional informations about basic blocks, these basic blocks are guaranteed
    /// to also be present in the early function's basic blocks.
    basic_blocks: HashMap<u64, BasicBlock>,
    /// Instruction pointer of the current basic block being decoded.
    basic_block_ip: u64,
    /// Information about how flags were last modified.
    /// **This is reset between basic blocks.**
    flags: Flags,
    /// True when the decoding should be done.
    done: bool,
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
            basic_blocks: HashMap::new(),
            basic_block_ip: 0, // Will be initialized at first instruction.
            flags: Flags::Undefined,
            done: false,
        }
    }
    
    /// Finalize the current function, save it and reset the state to go to the next one.
    fn finalize_function(&mut self) -> AnyResult<()> {

        self.done = true;

        // Finalize all basic block and ensure that they are existing.
        for (&block_ip, block) in &mut self.basic_blocks {
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
            // // Collect initial imports.
            // let imports = block.iter_import_register_locals().collect::<HashSet<_>>();
            // if !imports.is_empty() {
            //     basic_block_imports.insert(block_ip, FinalBasicBlock {
            //         imports,
            //     });
            // }
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

        /*// This loop should converge.
        let mut export_fixes = HashSet::new();
        loop {

            for (&block_ip, block) in &self.basic_blocks {
                
                if self.early_function.begin() == DEBUG_FUNCTION {
                    println!("== Basic block {block_ip} = {block:?}");
                }

                if let Some(true_branch) = block.true_branch {
                    let true_block = self.basic_blocks.get(&true_branch)
                        .ok_or_else(|| anyhow!("cannot find true branch {true_branch:08X} from block {block_ip:08X}"))?;
                    branches_imports.extend(true_block.iter_import_register_locals());
                }

                if let Some(false_branch) = block.false_branch {
                    let false_block = self.basic_blocks.get(&false_branch)
                        .ok_or_else(|| anyhow!("cannot find false branch {false_branch:08X} from block {block_ip:08X}"))?;
                    branches_imports.extend(false_block.iter_import_register_locals());
                }

                if self.early_function.begin() == DEBUG_FUNCTION {
                    println!("   branches_imports = {branches_imports:?}");
                }
                
                // For each imported local/register in the branch block, check if we have 
                // this register.
                for (register, import_local) in branches_imports.drain(..) {
                    if let Some(self_locals) = block.register_locals.get(&register) {
                        if self_locals.last == import_local {
                            // Nothing to do, we already export this variable.
                        } else {
                            // We already used the register, but it's of the wrong type.
                            export_fixes.insert(ExportFix {
                                block_ip,
                                register,
                                kind: ExportFixKind::Cast { 
                                    from: self_locals.last,
                                    to: import_local,
                                }
                            });
                        }
                    } else {
                        // We don't know the register yet.
                        export_fixes.insert(ExportFix {
                            block_ip,
                            register,
                            kind: ExportFixKind::Import { 
                                local: import_local,
                            }
                        });
                    }
                }

            }

            if self.early_function.begin() == DEBUG_FUNCTION {
                println!("   export_fixes = {export_fixes:?}");
            }

            i += 1;
            if i > 10 {

                let export_fixes_str = export_fixes.iter()
                    .map(|fix| format!("{:08X}/{:?} {}, ", fix.block_ip, fix.register, match fix.kind {
                        ExportFixKind::Cast { from, to } => format!("cast {} -> {}", LocalRefDisplay(from), LocalRefDisplay(to)),
                        ExportFixKind::Import { local } => format!("import {}", LocalRefDisplay(local)),
                    }))
                    .collect::<String>();

                bail!("block finalization is not converging: export fixes = [{export_fixes_str}]");

            }

            // We converged toward no fixes, break loop to apply fixes if any.
            if export_fixes.is_empty() { break; }

            for export_fix in export_fixes.drain() {
                let block = self.basic_blocks.get_mut(&export_fix.block_ip).unwrap();
                match export_fix.kind {
                    ExportFixKind::Cast { from, to } => {
                        // We need to a cast assignment expression just before the branch.
                        let branch_index = block.branch_index.unwrap();
                        new_statements.push((branch_index, Statement::Assign { 
                            place: Place::new_direct(to), 
                            value: Expression::Cast(Place::new_direct(from)),
                        }));
                        // This register is already existing, we just update last local.
                        block.register_locals.get_mut(&export_fix.register).unwrap().last = to;
                    }
                    ExportFixKind::Import { local } => {
                        // This register local was missing, add it as import-only.
                        block.register_locals.insert(export_fix.register, RegisterBlockLocals { 
                            import: Some(local), 
                            last: local,
                        });
                    }
                };
                
            }

        }*/

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

        Ok(())

    }

    /// Finalize the current basic block, reset the state to go to the next one. This
    /// should be called directly after insertion of the branch statement of the basic
    /// block.
    /// 
    /// The true branch can be forced to a given value if needed, this is used if a 
    /// branch statement has been artificially added to form a new basic block.
    fn finalize_basic_block(&mut self, add_true_branch: Option<u64>) {

        let block = self.basic_blocks.get_mut(&self.basic_block_ip).unwrap();        
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
    /// The given type is interpreted as the type pointed by the memory operand.
    fn decode_mem_operand(&mut self, inst: &Instruction, ty: Type) -> AnyResult<Place> {

        // The displacement is actually 64-bit only for EIP/RIP relative address, 
        // otherwise it can just be casted to 32-bit integer.
        let mem_displ = inst.memory_displacement64();

        let index_scale = inst.memory_index_scale() as u8;
        let index_local = match inst.memory_index() {
            Register::None => None,
            index_reg => Some(self.decode_register_import(index_reg, TY_PTR_DIFF)),
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

                // Compute real stack offset from currently known stack pointer.
                let offset = self.stack_pointer + mem_displ as i32;
                let stack_local = self.ensure_stack_local(offset, ty);
                place = Place::new_direct(stack_local);
                
                if index_local.is_some() {
                    // TODO: Support this.
                    bail!("decode_mem_operand: unsupported index with sp-relative ({inst})");
                }
                
            }
            Register::None => bail!("decode_mem_operand: no base ({inst})"),
            base_reg => {
                
                let base_reg_local = self.decode_register_import(base_reg, ty.pointer(1));

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

    fn decode_signed_imm(&mut self, inst: &Instruction) -> AnyResult<i64> {
        Ok(match inst.op2_kind() {
            OpKind::Immediate8to64 | OpKind::Immediate8to32 | OpKind::Immediate8to16 => inst.immediate8to64(),
            OpKind::Immediate32 | OpKind::Immediate32to64 => inst.immediate32to64(),
            kind => bail!("decode_signed_imm: imm kind {kind:?}: ({inst})")
        })
    }

    /// Decode `lea <r>,<m>`.
    fn decode_lea_r_m(&mut self, inst: &Instruction) -> AnyResult<()> {

        let mem_place = self.decode_mem_operand(inst, TY_BYTE)?;

        let reg = inst.op0_register();
        let reg_place = Place::new_direct(self.decode_register_write(reg, TY_BYTE.pointer(1)));

        // We simplify this case, we can just assign the value to the register.
        if let Some(Index::Absolute(0)) = mem_place.index {
            let simplified_place = Place::new_direct(mem_place.local);
            self.push_assign(reg_place, Expression::Copy(Operand::Place(simplified_place)));
        } else {
            self.push_assign(reg_place, Expression::Ref(mem_place));
        }

        Ok(())

    }
    
    /// Decode `push <r>`.
    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_ty = ty_unsigned_int_from_bytes(reg.size());

        self.sub_sp(reg.size() as i32);

        let stack_local = self.ensure_stack_local(self.stack_pointer, reg_ty);
        let reg_local = self.decode_register_import(reg, reg_ty);

        self.push_assign(Place::new_direct(stack_local), Expression::Copy(Operand::new_local(reg_local)));

    }

    /// Decode `pop <r>`.
    fn decode_pop_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_ty = ty_unsigned_int_from_bytes(reg.size());
        
        let stack_local = self.ensure_stack_local(self.stack_pointer, reg_ty);
        let reg_local = self.decode_register_write(reg, reg_ty);
        
        self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::new_local(stack_local)));
        self.add_sp(reg.size() as i32);

    }

    /// Decode instruction `mov <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/mov
    /// 
    /// Move an immediate value into a register or memory.
    fn decode_mov_rm_imm(&mut self, inst: &Instruction) -> AnyResult<()> {
        let imm = inst.immediate32to64();
        match inst.op0_register() {
            Register::None => {
                // mov <m>,<imm>
                let mem_ty = ty_weak_int_from_bytes(inst.memory_size().size());
                let mem_place = self.decode_mem_operand(inst, mem_ty)?;
                self.push_assign(mem_place, Expression::Copy(Operand::LiteralSigned(imm)));
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // mov sp,<imm>
                bail!("statically unknown: mov sp,<imm> ({inst})");
            }
            reg => {
                // mov <reg>,<imm>
                let reg_ty = ty_weak_int_from_bytes(reg.size());
                let reg_local = self.decode_register_write(reg, reg_ty);
                self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::LiteralSigned(imm)));
            }
        }
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
            (_, Register::RSP) => bail!("statically unknown: mov <rm>,sp ({inst})"),
            (Register::RSP, _) => bail!("statically unknown: mov sp,<rm> ({inst})"),
            (Register::None, reg1) => {
                let ty = ty_weak_int_from_bytes(reg1.size());
                operand = Operand::new_local(self.decode_register_import(reg1, ty));
                place = self.decode_mem_operand(inst, ty)?;
            }
            (reg0, Register::None) => {
                let ty = ty_weak_int_from_bytes(reg0.size());
                operand = Operand::Place(self.decode_mem_operand(inst, ty)?);
                place = Place::new_direct(self.decode_register_write(reg0, ty));
            }
            (reg0, reg1) => {
                let ty = ty_weak_int_from_bytes(reg0.size());
                operand = Operand::new_local(self.decode_register_import(reg1, ty));
                place = Place::new_direct(self.decode_register_write(reg0, ty));
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

        // This register is the destination.
        let reg0 = inst.op0_register();
        let reg0_ty = layout.to_type(reg0.size());
        let reg0_local = self.decode_register_write(reg0, reg0_ty);

        let src_local;

        match inst.op1_register() {
            Register::None => {
                let mem_ty = layout.to_type(inst.memory_size().size());
                src_local = self.decode_mem_operand(inst, mem_ty)?;
            }
            reg1 => {
                let reg1_ty = layout.to_type(reg1.size());
                src_local = Place::new_direct(self.decode_register_import(reg1, reg1_ty));
            }
        }

        self.push_assign(Place::new_direct(reg0_local), Expression::Cast(src_local));
        Ok(())

    }

    /// Decode instruction `movsb/movsw/movsd/movsq`:
    /// - https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq
    /// 
    /// Such instruction moves bytes from string to string.
    fn decode_movs_m_m(&mut self, inst: &Instruction) {

        let mov_stride = inst.memory_size().size();
        let mov_ty = ty_weak_int_from_bytes(mov_stride);
        let mov_ty_ptr = mov_ty.pointer(1);
        
        // NOTE: RSI/RDI/RCX only if pointer size == 64.

        let src_reg = self.decode_register_import(Register::RSI, mov_ty_ptr);
        let dst_reg = self.decode_register_import(Register::RDI, mov_ty_ptr);
        
        // NOTE: movs only support REP, not REPZ or REPNZ
        let len_reg = inst.has_rep_prefix()
            .then(|| self.decode_register_import(Register::RCX, TY_QWORD));

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

        // self.debug_function();

    }

    /// Decode instruction `inc/dec <rm>`: 
    /// - https://www.felixcloutier.com/x86/inc
    /// - https://www.felixcloutier.com/x86/dec
    /// 
    /// Increment or decrement a memory or register by 1.
    fn decode_int_op_rm_literal(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout, literal: i64) -> AnyResult<()> {
        
        let place;
        match inst.op0_register() {
            Register::None => {
                // inc/dec <m>
                let mem_ty = layout.to_type(inst.memory_size().size());
                place = self.decode_mem_operand(inst, mem_ty)?;
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // inc/dec sp
                match op {
                    BinaryOperator::Add => self.add_sp(1),
                    BinaryOperator::Sub => self.sub_sp(1),
                    _ => bail!("decode_int_op_rm_literal: illegal op {op:?}"),
                }
                self.flags = Flags::Undefined; // TODO: Support this.
                return Ok(());
            }
            reg => {
                // inc/dec <reg>
                place = Place::new_direct(self.decode_register_import(reg, layout.to_type(reg.size())));
            }
        }

        self.flags = Flags::Undefined; // TODO: Support this.
        self.push_assign(place, Expression::Binary { 
            left: Operand::Place(place), 
            right: Operand::LiteralSigned(literal), 
            operator: op,
        });

        Ok(())

    }

    /// Abstraction function to decode every instruction `<op> <rm>,<imm>` where `op` is
    /// an integer binary operation that write the result in the left operand.
    fn decode_int_op_rm_imm(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout) -> AnyResult<()> {

        let imm = inst.immediate32to64();
        let place;
        match inst.op0_register() {
            Register::None => {
                // <op> <m>,<imm>
                let mem_ty = layout.to_type(inst.memory_size().size());
                place = self.decode_mem_operand(inst, mem_ty)?;
            }
            Register::SP |
            Register::ESP |
            Register::RSP => {
                // <op> sp,<imm>
                match op {
                    BinaryOperator::Add => self.add_sp(imm as i32),
                    BinaryOperator::Sub => self.sub_sp(imm as i32),
                    _ => bail!("statically unknown: <op> sp,<imm> ({inst})")
                };
                self.flags = Flags::Undefined; // TODO: Support this.
                return Ok(());
            }
            reg => {
                // <op> <reg>,<imm>
                let reg_local = self.decode_register_import(reg, layout.to_type(reg.size()));
                place = Place::new_direct(reg_local);
            }
        }

        let index = self.push_assign(place, Expression::Binary { 
            left: Operand::Place(place), 
            right: Operand::LiteralUnsigned(imm as u64), 
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
            (_, Register::RSP) => bail!("statically unknown: <op> <rm>,sp ({inst})"),
            (Register::RSP, _) => bail!("statically unknown: <op> sp,<rm> ({inst})"),
            (Register::None, reg1) => {
                let reg_ty = layout.to_type(reg1.size());
                let reg_local = self.decode_register_import(reg1, reg_ty);
                left_place = self.decode_mem_operand(inst, reg_ty)?;
                right_place = Place::new_direct(reg_local);
            }
            (reg0, Register::None) => {
                let reg_ty = layout.to_type(reg0.size());
                let reg_local = self.decode_register_import(reg0, reg_ty);
                left_place = Place::new_direct(reg_local);
                right_place = self.decode_mem_operand(inst, reg_ty)?;
            }
            (reg0, reg1) if op == BinaryOperator::Xor && reg0 == reg1 => {
                let reg_ty = layout.to_type(reg0.size());
                let reg_local = self.decode_register_write(reg0, reg_ty);
                let place = Place::new_direct(reg_local);
                self.push_assign(place, Expression::Copy(Operand::LiteralUnsigned(0)));
                self.flags = Flags::Undefined; // TODO: Support this.
                return Ok(());
            }
            (reg0, reg1) => {
                let reg_ty = layout.to_type(reg0.size());
                left_place = Place::new_direct(self.decode_register_import(reg0, reg_ty));
                right_place = Place::new_direct(self.decode_register_import(reg1, reg_ty));
            }
        }

        self.flags = Flags::Undefined; // TODO: Support this.
        self.push_assign(left_place, Expression::Binary { 
            left: Operand::Place(left_place), 
            right: Operand::Place(right_place), 
            operator: op,
        });

        Ok(())

    }

    fn decode_int_op_r_rm_imm(&mut self, inst: &Instruction, op: BinaryOperator, layout: IntLayout) -> AnyResult<()> {

        let dst_reg = inst.op0_register();
        let dst_ty = layout.to_type(dst_reg.size());
        let dst_place = Place::new_direct(self.decode_register_import(dst_reg, dst_ty));

        let src_place = match inst.op1_register() {
            Register::None => self.decode_mem_operand(inst, dst_ty)?,
            reg1 => Place::new_direct(self.decode_register_import(reg1, dst_ty)),
        };

        let imm = self.decode_signed_imm(inst)?;

        self.flags = Flags::Undefined; // TODO: Support this.
        self.push_assign(dst_place, Expression::Binary { 
            left: Operand::Place(src_place), 
            right: Operand::LiteralSigned(imm), 
            operator: op,
        });

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
                src_place = Place::new_direct(self.decode_register_import(reg1, ty));
                dst_place = self.decode_mem_operand(inst, ty)?;
            }
            (reg0, Register::None) => {
                let ty = get_ty(reg0.size());
                src_place = self.decode_mem_operand(inst, ty)?;
                dst_place = Place::new_direct(self.decode_register_write(reg0, ty));
            }
            (reg0, reg1) => {
                let ty = get_ty(reg0.size());
                src_place = Place::new_direct(self.decode_register_import(reg1, ty));
                dst_place = Place::new_direct(self.decode_register_write(reg0, ty));
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
    fn decode_xorp_r_rm(&mut self, inst: &Instruction, double: bool) -> AnyResult<()> {

        let ty = if double { TY_DOUBLE } else { TY_FLOAT };

        // TODO: For now we only support xorp for zeroing registers.
        // TODO: Support zero-ing the vector, if relevant.
        if inst.op0_register() == inst.op1_register() {

            let reg = inst.op0_register();
            let reg_local = self.decode_register_write(reg, ty);
            self.push_assign(Place::new_direct(reg_local), Expression::Copy(Operand::Zero));

        } else {
            bail!("decode_xorp_r_rm: different registers ({inst})");
        }

        Ok(())

    }

    /// Decode instruction `test <rm>,<r>`:
    /// - https://www.felixcloutier.com/x86/test
    /// 
    /// This instruction make a *bitwise and* between the left and right operand and set
    /// the appropriate flags (SF, ZF, PF), OF and CF are set to zero.
    fn decode_test_rm_r(&mut self, inst: &Instruction) -> AnyResult<()> {

        let reg1 = inst.op1_register();
        let ty = ty_weak_int_from_bytes(reg1.size());

        let right_place = Place::new_direct(self.decode_register_import(reg1, ty));

        let left_place = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, ty)?,
            reg0 => Place::new_direct(self.decode_register_import(reg0, ty)),
        };

        self.flags = Flags::Test { 
            left: left_place, 
            right: Operand::Place(right_place),
        };

        Ok(())

    }

    /// Decode instruction `test <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/test
    /// 
    /// Read above.
    fn decode_test_rm_imm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let imm = inst.immediate32to64();

        let left_place = match inst.op0_register() {
            Register::None => {
                let ty = ty_weak_int_from_bytes(inst.memory_size().size());
                self.decode_mem_operand(inst, ty)?
            }
            reg => {
                let ty = ty_weak_int_from_bytes(reg.size());
                Place::new_direct(self.decode_register_import(reg, ty))
            }
        };

        self.flags = Flags::Test { 
            left: left_place, 
            right: Operand::LiteralSigned(imm),
        };

        Ok(())

    }

    /// Decode the instruction `cmp <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/cmp
    /// 
    /// This instruction subtract the right immediate operand from the left one,
    /// and set the appropriate flags according to the result.
    fn decode_cmp_rm_imm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let ty;
        
        let left_place = match inst.op0_register() {
            Register::None => {
                ty = ty_weak_int_from_bytes(inst.memory_size().size());
                self.decode_mem_operand(inst, ty)?
            }
            reg => {
                ty = ty_weak_int_from_bytes(reg.size());
                Place::new_direct(self.decode_register_import(reg, ty))
            }
        };

        self.flags = Flags::Cmp { 
            left: left_place, 
            right: Operand::LiteralUnsigned(inst.immediate32() as u64),
        };

        Ok(())

    }

    /// Decode the instruction `cmp <rm>,<imm>`:
    /// - https://www.felixcloutier.com/x86/cmp
    /// 
    /// This instruction subtract the right operand from the left one, 
    /// and set the appropriate flags according to the result.
    fn decode_cmp_rm_rm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let ty = ty_weak_int_from_bytes(inst.memory_size().size());

        let left = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, ty)?,
            Register::SP |
            Register::ESP |
            Register::RSP => bail!("statically unknown: cmp sp,<rm> ({inst})"),
            reg0 => Place::new_direct(self.decode_register_import(reg0, ty)),
        };

        let right = match inst.op1_register() {
            Register::None => Operand::Place(self.decode_mem_operand(inst, ty)?),
            Register::SP |
            Register::ESP |
            Register::RSP => bail!("statically unknown: cmp <rm>,sp ({inst})"),
            reg1 => Operand::new_local(self.decode_register_import(reg1, ty)),
        };

        self.flags = Flags::Cmp { left, right };
        Ok(())

    }

    /// Decode the conditional expression from an conditional instruction. This depends
    /// on the last instruction's flags.
    fn decode_cond_expr(&mut self, inst: &Instruction) -> AnyResult<Expression> {

        Ok(match self.flags {
            Flags::Undefined => bail!("decode_cond_expr: undefined flags"),
            Flags::Cmp { left, right } => {

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
                    _ => bail!("decode_cond_expr (cmp): unsupported condition ({inst})")
                };

                Expression::Comparison { left: Operand::Place(left), operator, right }

            }
            Flags::Test { left, right: Operand::Place(right) } if left == right => {

                // If both operands of the test is the same local, the "bitwise and" will
                // result to "equal" if the register is zero, and "not equal" is not zero.
                let operator = match inst.condition_code() {
                    ConditionCode::ne => ComparisonOperator::NotEqual,
                    ConditionCode::e => ComparisonOperator::Equal,
                    _ => bail!("decode_cond_expr (test same): unsupported condition ({inst})")
                };

                Expression::Comparison { left: Operand::Place(left), right: Operand::LiteralUnsigned(0), operator }

            }
            Flags::Test { left, right } => {
                Expression::Binary { left: Operand::Place(left), right, operator: BinaryOperator::And }
            }
            Flags::Binary { operator, index } => {

                match operator {
                    BinaryOperator::And |
                    BinaryOperator::Or |
                    BinaryOperator::Xor => {

                        let Statement::Assign { place, .. } = self.function.statements[index] else {
                            bail!("decode_cond_expr (binary bool): target index {index} is not an assignment");
                        };

                        let operator = match inst.condition_code() {
                            ConditionCode::ne => ComparisonOperator::NotEqual,
                            ConditionCode::e => ComparisonOperator::Equal,
                            _ => bail!("decode_cond_expr (binary bool): unsupported condition ({inst})")
                        };

                        Expression::Comparison { left: Operand::Place(place), right: Operand::LiteralUnsigned(0), operator }

                    }
                    _ => bail!("decode_cond_expr (binary): unsupported operator {operator:?} ({inst})")
                }

            }
        })

    }

    fn decode_call_rel(&mut self, inst: &Instruction) {
        
        let pointer = inst.memory_displacement64();
        let ret_local = self.decode_register_write(Register::RAX, TY_QWORD);

        self.push_assign(Place::new_direct(ret_local), Expression::Call { 
            pointer: Operand::LiteralUnsigned(pointer), 
            arguments: Vec::new(),
        });

    }

    fn decode_call_rm(&mut self, inst: &Instruction) -> AnyResult<()> {

        let pointer_place = match inst.op0_register() {
            Register::None => self.decode_mem_operand(inst, TY_VOID.pointer(1))?,
            reg => Place::new_direct(self.decode_register_import(reg, TY_VOID.pointer(1))),
        };

        let ret_local = self.decode_register_write(Register::RAX, TY_QWORD);
        let ret_place = Place::new_direct(ret_local);

        self.push_assign(ret_place, Expression::Call {
            pointer: Operand::Place(pointer_place),
            arguments: Vec::new(),
        });

        Ok(())

    }

    fn decode_jcc(&mut self, inst: &Instruction) -> AnyResult<()> {

        let pointer = inst.near_branch64();
        let cond_expr = self.decode_cond_expr(inst)?;
        
        let branch_index = self.push_statement_with(|index| {
            Statement::BranchConditional { 
                value: cond_expr, 
                branch_true: 0, // Will be modified if upon basic block creation.
                branch_false: index + 1, // False jcc go to the next instruction.
            }
        });

        let block = self.basic_blocks.get_mut(&self.basic_block_ip).unwrap();
        block.true_branch = Some(pointer);
        block.false_branch = Some(inst.next_ip());

        // We added a branch statement, this implied existence of two basic blocks.
        let true_block = self.ensure_basic_block(pointer)?;
        true_block.branch_indices_to_relocate.push(branch_index);
        let _false_block = self.ensure_basic_block(inst.next_ip())?;

        Ok(())

    }

    fn decode_jmp(&mut self, inst: &Instruction) -> AnyResult<()> {

        let pointer = inst.near_branch64();

        if self.early_function.contains_block(pointer) {

            let branch_index = self.push_statement(Statement::Branch { branch: 0 });
            let block = self.basic_blocks.get_mut(&self.basic_block_ip).unwrap();
            block.true_branch = Some(pointer);

            let target_block = self.ensure_basic_block_unchecked(pointer);
            target_block.branch_indices_to_relocate.push(branch_index);
            Ok(())

        } else {

            // If the block is not present in our early function, this means this is a 
            // tail-call, we call and directly return with the value of this function.

            let ret_local = self.decode_register_write(Register::RAX, TY_QWORD);

            self.push_assign(Place::new_direct(ret_local), Expression::Call { 
                pointer: Operand::LiteralUnsigned(pointer), 
                arguments: Vec::new(),
            });

            // Forward to decode ret in order to add the return statement and finalize
            // the basic block and function.
            self.decode_ret(inst)

        }

    }

    fn decode_ret(&mut self, _inst: &Instruction) -> AnyResult<()> {

        let ret_place = self.decode_register_import(Register::RAX, TY_QWORD);
        self.push_statement(Statement::Return(ret_place));

        // We directly finalize the basic block here because our function ends here.
        self.finalize_basic_block(None);
        self.finalize_function()?;

        Ok(())

    }

    /// Feed a new instruction to the decoder, if some instruction is returned, the 
    /// feeder must goto to the given instruction and start feed from it.
    fn feed(&mut self, inst: &Instruction) -> AnyResult<()> {

        if self.done {
            bail!("function decoding is done, cannot accept new instruction");
        }

        let ip = inst.ip();
        // println!("[{:08X}] {inst}", ip);

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
            self.basic_block_ip = ip;
        }
        
        if inst.has_lock_prefix() {
            bail!("lock prefix is not yet supported ({inst})");
        }

        match inst.code() {
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
            Code::Movsb_m8_m8 => self.decode_movs_m_m(inst),
            // INC
            Code::Inc_rm8 |
            Code::Inc_rm16 |
            Code::Inc_rm32 |
            Code::Inc_rm64 |
            Code::Inc_r16 |
            Code::Inc_r32 => self.decode_int_op_rm_literal(inst, BinaryOperator::Add, IntLayout::Weak, 1)?,
            // DEC
            Code::Dec_rm8 |
            Code::Dec_rm16 |
            Code::Dec_rm32 |
            Code::Dec_rm64 |
            Code::Dec_r16 |
            Code::Dec_r32 => self.decode_int_op_rm_literal(inst, BinaryOperator::Sub, IntLayout::Weak, 1)?,
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
            Code::Sar_rm8_1 => self.decode_int_op_rm_literal(inst, BinaryOperator::ShiftRight, IntLayout::Signed, 1)?,
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
            Code::Shr_rm8_1 => self.decode_int_op_rm_literal(inst, BinaryOperator::ShiftRight, IntLayout::Unsigned, 1)?,
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
            Code::Shl_rm8_1 => self.decode_int_op_rm_literal(inst, BinaryOperator::ShiftLeft, IntLayout::Weak, 1)?,
            Code::Shl_rm64_imm8 |
            Code::Shl_rm32_imm8 |
            Code::Shl_rm16_imm8 |
            Code::Shl_rm8_imm8 => self.decode_int_op_rm_imm(inst, BinaryOperator::ShiftLeft, IntLayout::Weak)?,
            Code::Shl_rm64_CL |
            Code::Shl_rm32_CL |
            Code::Shl_rm16_CL |
            Code::Shl_rm8_CL => self.decode_int_op_rm_rm(inst, BinaryOperator::ShiftLeft, IntLayout::Weak)?,
            // IMUL
            // Code::Imul_rm64 |
            // Code::Imul_rm32 |
            // Code::Imul_rm16 |
            // Code::Imul_rm8 => 
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
            Code::Xorps_xmm_xmmm128 => self.decode_xorp_r_rm(inst, false)?,
            Code::Xorpd_xmm_xmmm128 => self.decode_xorp_r_rm(inst, true)?,
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
            Code::Call_rel32_64 => self.decode_call_rel(inst),
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
            Code::Jmp_rel32_32 => self.decode_jmp(inst)?,
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
    fn decode_register(&mut self, register: Register, ty: Type, import: bool) -> LocalRef {

        let full_register = register.full_register();

        match self.register_block_locals.entry(full_register) {
            Entry::Occupied(o) => {

                let locals = o.into_mut();
                let last_local = locals.last;
                let mut last_ty = self.function.local_type(last_local);

                // We want to check for the following cases (only if import mode):
                // - last_ty = weak(last_n), ty = weak(n):
                //   - n == last_n: nothing to do
                //   - n != last_n: new local with cast
                // - last_ty = weak(last_n), ty = actual(n):
                //   - n == last_n: update last_ty to actual(n)
                //   - n != last_n: 
                //     - update last_ty to actual(last_n)
                //     - new local of actual(n)
                
                // If the required indirection and the last one corresponds.
                if import && last_ty.indirection == ty.indirection {
                    if let Some(last_n) = last_ty.primitive.weak_int_bits() {
                        if let Some(n) = ty.primitive.actual_int_bits() {
                            // Prepare the new type (its an actual integer).
                            let mut new_ty = ty;
                            // But if last type has not the right bit count, we need to
                            // modify new type bits to correspond to its old bit count.
                            if n != last_n {
                                // Modify current type to just have 
                                new_ty.primitive = new_ty.primitive.with_int_bits(last_n).unwrap();
                            }
                            // Actually modify the local type.
                            self.function.set_local_type(last_local, &self.type_system, new_ty);
                            last_ty = new_ty;
                        }
                    }
                }

                if ty != last_ty {

                    let new_local = *self.register_typed_locals.entry((register, ty))
                        .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("register: {full_register:?}")));

                    locals.last = new_local;

                    if import {
                        self.push_assign(Place::new_direct(new_local), Expression::Cast(Place::new_direct(last_local)));
                    }

                    new_local

                } else {
                    last_local
                }

            }
            Entry::Vacant(v) => {
                
                let local = *self.register_typed_locals.entry((register, ty))
                    .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("register: {full_register:?}")));

                v.insert(RegisterBlockLocals { 
                    import: import.then_some(local),  // Only import if requested.
                    last: local,
                });

                local

            }
        }

    }

    #[track_caller]
    #[inline]
    fn decode_register_import(&mut self, register: Register, ty: Type) -> LocalRef {
        self.decode_register(register, ty, true)
    }

    #[track_caller]
    #[inline]
    fn decode_register_write(&mut self, register: Register, ty: Type) -> LocalRef {
        self.decode_register(register, ty, false)
    }

    /// Get a local usable to write from the given stack offset.
    fn ensure_stack_local(&mut self, offset: i32, ty: Type) -> LocalRef {
        *self.stack_locals.entry(offset)
            .or_insert_with(|| self.function.new_local(&self.type_system, ty, format!("stack: {offset}")))
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

    fn debug_function(&self) {
        write_function(std::io::stdout().lock(), &self.function, &self.type_system).unwrap();
    }

}

/// Used to tell if an expression should produce a signed or unsigned integer. A special
/// `Inherited` can be used to default to the previous value of registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntLayout {
    Weak,
    Unsigned,
    Signed,
}

impl IntLayout {

    /// Convert this abstract int layout to an actual type given a bytes count.
    fn to_type(self, bytes: usize) -> Type {
        match self {
            IntLayout::Weak => ty_weak_int_from_bytes(bytes),
            IntLayout::Unsigned => ty_unsigned_int_from_bytes(bytes),
            IntLayout::Signed => ty_signed_int_from_bytes(bytes),
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

/// Provides a local allocator for a given type.
#[derive(Debug, Default)]
struct TempBlockLocals {
    /// Internal list of local for the given type.
    list: Vec<LocalRef>,
    /// Index of the next local to allocate, if that equals the length of the locals,
    /// then a new local will be created.
    cursor: usize,
}

/// Internal structure used to keep track of flags and how they were previously 
/// calculated.
#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExportFix {
    /// The block instruction pointer we want to fix.
    block_ip: u64,
    /// The register family of the local variable to export.
    register: Register,
    kind: ExportFixKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExportFixKind {
    /// The export can be fixed by casting from one variable to another.
    Cast {
        from: LocalRef,
        to: LocalRef,
    },
    /// The export can be fixed by importing the variable from outside.
    Import {
        /// The local variable to import.
        local: LocalRef,
    },
}


const TY_VOID: Type = PrimitiveType::Void.plain();
const TY_BYTE: Type = PrimitiveType::WeakInt(8).plain();
const TY_QWORD: Type = PrimitiveType::WeakInt(64).plain();
const TY_PTR_DIFF: Type = PrimitiveType::SignedInt(64).plain();
const TY_FLOAT: Type = PrimitiveType::Float.plain();
const TY_DOUBLE: Type = PrimitiveType::Double.plain();

#[inline]
const fn ty_weak_int_from_bytes(bytes: usize) -> Type {
    PrimitiveType::WeakInt(bytes as u32 * 8).plain()
}

#[inline]
const fn ty_signed_int_from_bytes(bytes: usize) -> Type {
    PrimitiveType::SignedInt(bytes as u32 * 8).plain()
}

#[inline]
const fn ty_unsigned_int_from_bytes(bytes: usize) -> Type {
    PrimitiveType::UnsignedInt(bytes as u32 * 8).plain()
}

#[inline]
const fn ty_float_vec_from_bytes(bytes: usize) -> Type {
    PrimitiveType::FloatVec(bytes as u32 / 4).plain()
}

#[inline]
const fn ty_double_vec_from_bytes(bytes: usize) -> Type {
    PrimitiveType::DoubleVec(bytes as u32 / 8).plain()
}
