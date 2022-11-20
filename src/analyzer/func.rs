//! # Function Analysis implementation.
//! See [`FunctionPass`] structure.

use std::collections::{HashMap, HashSet};

use iced_x86::{Instruction, Code, Register};

use crate::symbol::{BasicBlock, BasicBlockExit, Function, Abi};

use super::{Analyzer, AnalyzerPass};
use super::abi;


/// First pass of functions definition, searching for contiguous 
/// basic blocks and marking all basic blocks that are jumped-to
/// by tail/thunk calls.
#[derive(Default)]
pub struct FunctionFindPass { }

impl AnalyzerPass for FunctionFindPass {

    fn analyze(&mut self, analyzer: &mut Analyzer) {

        // A list of basic blocks that should be considered as functions
        // because they are tail/thunk-called and are not currently 
        // considered as such.
        let mut new_functions = Vec::new();
        // We search function through all basic blocks only on the first
        // iteration.
        let mut first_it = true;

        // This loop should exit because we define more and more function
        // on each loop, and we can at most define the number of basic 
        // blocks.
        while !new_functions.is_empty() || first_it {

            let mut func_resolver = FunctionTreeResolver::new(
                &analyzer.database.basic_blocks
            );

            if first_it {
                for bb in analyzer.database.basic_blocks.values() {
                    if bb.function {
                        func_resolver.resolve_function(bb, &mut analyzer.database.functions);
                    }
                }
                first_it = false;
            } else {
                for bb_ip in new_functions.drain(..) {
                    let bb = &analyzer.database.basic_blocks[&bb_ip];
                    func_resolver.resolve_function(bb, &mut analyzer.database.functions);
                }
            }

            new_functions.extend(func_resolver.iter_called_bbs());
            for bb_ip in &new_functions {
                analyzer.database.basic_blocks.get_mut(bb_ip).unwrap().function = true;
            }

        }

    }

}


#[derive(Default)]
pub struct FunctionAbiPass { }

impl AnalyzerPass for FunctionAbiPass {

    fn analyze(&mut self, analyzer: &mut Analyzer) {

        let mut frame_analyzer = FrameAnalyzer::new();
        let mut inst = Instruction::new();

        // List of basic blocks already analyzed.
        let mut done_bbs = HashSet::new();

        for func in analyzer.database.functions.values() {
            
            frame_analyzer.clear();
            done_bbs.clear();

            let mut bb = &analyzer.database.basic_blocks[&func.begin_ip];

            'main: 
            loop {

                analyzer.runtime.goto_ip(bb.begin_ip);
                done_bbs.insert(bb.begin_ip);

                while analyzer.runtime.decoder.can_decode() && analyzer.runtime.decoder.ip() < bb.end_ip {
                    
                    analyzer.runtime.decoder.decode_out(&mut inst);
                    
                    // Calls to another procedures stops the frame analysis, 
                    // because we want to analyze regiters and stack as-is
                    // without external modifications.
                    match inst.code() {
                        Code::Call_rel16 |
                        Code::Call_rel32_64 |
                        Code::Call_rm16 |
                        Code::Call_rm32 |
                        Code::Call_rm64 |
                        Code::Call_m1616 |
                        Code::Call_m1632 |
                        Code::Call_m1664 => {
                            break 'main;
                        }
                        _ => {}
                    }

                    frame_analyzer.feed(&inst);

                }

                match bb.exit {
                    BasicBlockExit::Unconditionnal { goto_ip } => {
                        let next_bb = &analyzer.database.basic_blocks[&goto_ip];
                        if next_bb.function || done_bbs.contains(&goto_ip) {
                            // Same comment as above, we can't accurately analyze
                            // the register and stack usage after a call.
                            break;
                        } else {
                            bb = next_bb;
                        }
                    }
                    BasicBlockExit::Conditionnal { continue_ip, .. } => {
                        // Note: For now we only explore the continue branch.
                        // In the future we may need to explore all branch and merge
                        // the frame analyzer afterward.
                        bb = &analyzer.database.basic_blocks[&continue_ip];
                    }
                    BasicBlockExit::Unknown => break 'main
                }
                
            }

            if func.begin_ip == 0x14047AA70 {
                println!("Frame analysis:");
                println!("{frame_analyzer:#?}");
            }

        }

    }

}


/// An internal resolver structure 
pub struct FunctionTreeResolver<'db> {
    /// Unique basic block, associating begin_ip <=> end_ip
    unique_bbs: HashMap<u64, &'db BasicBlock>,
    /// Database's basic blocks.
    bbs: &'db HashMap<u64, BasicBlock>,
    /// A list of basic blocks that should be considered as functions
    /// because they are tail/thunk-called and are not currently 
    /// considered as such.
    called_bbs: HashSet<u64>,
}

impl<'db> FunctionTreeResolver<'db> {

    pub fn new(bbs: &'db HashMap<u64, BasicBlock>) -> Self {
        Self {
            unique_bbs: HashMap::new(),
            bbs,
            called_bbs: HashSet::new(),
        }
    }

    /// Resolve a function tree from its given first basic block.
    pub fn resolve_function(&mut self, bb: &'db BasicBlock, functions: &mut HashMap<u64, Function>) {
        let begin_ip = bb.begin_ip;
        self.resolve(bb, begin_ip);
        let end_ip = self.validate(begin_ip);
        functions.insert(begin_ip, Function {
            begin_ip,
            end_ip,
            abi: Abi::Unknown,
        });
    }

    pub fn resolve(&mut self, bb: &'db BasicBlock, func_ip: u64) {
        if self.unique_bbs.insert(bb.begin_ip, bb).is_none() {
            match bb.exit {
                BasicBlockExit::Unconditionnal { goto_ip } => {
                    let goto_bb = &self.bbs[&goto_ip];
                    if goto_ip < func_ip {
                        // We know that unconditionnaly jumping before the function's ip
                        // is very likely to be a tail/thunk-call.
                        // If the basic block is already a function, do nothing.
                        if !goto_bb.function {
                            self.called_bbs.insert(goto_ip);
                        }
                    } else {
                        if !goto_bb.function && !self.called_bbs.contains(&goto_ip) {
                            self.resolve(goto_bb, func_ip);
                        }
                    }
                }
                BasicBlockExit::Conditionnal { goto_ip, continue_ip } => {
                    let goto_bb = &self.bbs[&goto_ip];
                    if goto_ip < func_ip {
                        // Read the comment above.
                        if !goto_bb.function {
                            self.called_bbs.insert(goto_ip);
                        }
                    } else {
                        if !goto_bb.function && !self.called_bbs.contains(&goto_ip) {
                            self.resolve(goto_bb, func_ip);
                            self.resolve(&self.bbs[&continue_ip], func_ip);
                        }
                    }
                }
                BasicBlockExit::Unknown => {}
            }
        }
    }

    /// Validate a function's call tree, ensures that all basic blocks are
    /// contiguous until returned IP.
    /// 
    /// *This also clear the internal state of the resolver.*
    pub fn validate(&mut self, func_ip: u64) -> u64 {

        let mut next_ip = func_ip;
        while let Some(bb) = self.unique_bbs.remove(&next_ip) {
            next_ip = bb.end_ip;
        }

        for (_, bb) in self.unique_bbs.drain() {
            for &entry in &bb.entries_from {
                if entry >= func_ip && entry < next_ip {
                    // This block is directly called by our function,
                    // but is not contiguous, it should be a function.
                    self.called_bbs.insert(bb.begin_ip);
                }
            }
        }

        next_ip

    }

    #[inline]
    pub fn iter_called_bbs(&self) -> impl Iterator<Item = u64> + '_ {
        self.called_bbs.iter().copied()
    }

}


/// A primitive analyzer for stack and register that can help
/// defining the framing and calling convention of a function.
#[derive(Debug)]
pub struct FrameAnalyzer {
    /// For each register used in the code, store how it
    /// is volatile or not.
    register_usage: HashMap<Register, RegisterUsage>,
    /// Current stack length from its base.
    stack_len: u32,
    /// The maximum stack length (see [`FrameAnalyzer::stack_len`]).
    max_stack_len: u32,
}

impl FrameAnalyzer {

    pub fn new() -> Self {
        Self {
            register_usage: HashMap::new(),
            stack_len: 0,
            max_stack_len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.register_usage.clear();
        self.stack_len = 0;
        self.max_stack_len = 0;
    }

    fn update_max_stack_len(&mut self) {
        self.max_stack_len = self.max_stack_len.max(self.stack_len);
    }

    /// Feed the analyzer with an instruction.
    pub fn feed(&mut self, inst: &Instruction) {

        match inst.code() {
            Code::Mov_rm64_r64 | 
            Code::Mov_rm32_r32 | 
            Code::Mov_rm16_r16 if inst.memory_base() == Register::RSP => {
                
                // The instruction manipulate a register and save it to the stack.
                let reg = inst.op1_register().info();
                let reg_len = reg.size() as u8;
                let rsp_off = self.stack_len as i64 + inst.memory_displacement64() as i64;

                // Only get the full register (CX | ECX -> RCX) when saving the register
                // usage.
                self.register_usage.entry(reg.full_register())
                    .or_insert_with(|| RegisterUsage::StackSaved {
                        offset: rsp_off,
                        len: reg_len,
                    });

            }
            Code::Push_r16 | 
            Code::Push_r32 | 
            Code::Push_r64 => {

                let reg = inst.op0_register().info();
                let reg_len = reg.size() as u8;
                self.stack_len += reg_len as u32;
                let rsp_off = self.stack_len;
                self.update_max_stack_len();

                self.register_usage.entry(reg.full_register())
                    .or_insert_with(|| RegisterUsage::StackSaved { 
                        offset: -(rsp_off as i64), 
                        len: reg_len,
                    });

            }
            Code::Sub_rm64_imm8 | 
            Code::Sub_rm64_imm32 
            if inst.memory_base() == Register::None && inst.op0_register() == Register::RSP => {
                self.stack_len += inst.immediate32();
                self.update_max_stack_len();
            }
            Code::Add_rm64_imm8 |
            Code::Add_rm64_imm32
            if inst.memory_base() == Register::None && inst.op0_register() == Register::RSP => {
                self.stack_len = self.stack_len.saturating_sub(inst.immediate32());
            }
            _ => {

                if inst.op1_register() != Register::None {

                    // The register is likely a source.
                    let reg = inst.op1_register().info();
                    let reg_len = reg.size() as u8;
                    self.register_usage.entry(reg.full_register())
                        .or_insert_with(|| RegisterUsage::Read {
                            len: reg_len,
                        });

                }

                if inst.op0_register() != Register::None {

                    // In this case the register is a destination, so if it's the
                    // first write to this register, it is volatile.
                    let reg = inst.op0_register().info();
                    self.register_usage.entry(reg.full_register())
                        .or_insert_with(|| RegisterUsage::Overriden);
    
                }

            }
        }

    }

}

/// Describe how register is handled by a block of code.
#[derive(Debug)]
pub enum RegisterUsage {
    /// The register is overriden without being saved, therefore all callers
    /// should've save this register if they are using it.
    Overriden,
    /// The first operation on this register is a read by an instruction.
    Read {
        /// How many bytes were read from the register.
        len: u8,
    },
    /// The register is saved in stack before being overriden, callers don't
    /// have to save it, but they expect it to be untouched when returning
    /// to them.
    StackSaved {
        /// Offset within the stack where the register has been saved in the
        /// first place. This offset is calculated from the frame's base 
        /// (starting at 0).
        offset: i64,
        /// How many bytes were saved at the stack offset.
        len: u8,
    },
}
