//! # Basic Block Analysis implementation.
//! The goal of this pass is to 
//! Instructions are fetched only once in this pass.
//! 
//! ## Algorithm
//! We walk through each instruction in the analyzer's code
//! and 

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use iced_x86::{Instruction, Code};

use super::{Analyzer, AnalyzerStepPass};
use crate::symbol::{BasicBlock, BasicBlockExit};


/// ## Basic Block Analysis
/// The goal of this pass is to find most of the [`Basic Blocks`]
/// in the analyzer's code. Basic blocks are linear code sequence
/// that have a single branch instruction as the last instruction
/// of the block (called exit) and a single entry point where 
/// other basic blocks jumps to. **The analysis here is static, 
/// and can be inexact** due to relative addressing jumps, this 
/// implies that the "single entry point" assertion is not 
/// guaranteed by this implementation.
/// 
/// *Instructions are fetched only once in this pass.*
/// 
/// ### Algorithm
/// During the processing of the input, an "incomplete block" 
/// structure is used to hold temporary data required during 
/// analysis. It contains three fields: "begin IP", "calls count"
/// and "previous exit".
/// 
/// We walk through each instruction in the analyzer's code. When
/// we get a branch instruction, `jmp`, `jcc`, `call` or `ret` we
/// know three things:
/// - We leave the current basic block;
/// - We have to create a basic block just after the branch 
///   instruction, this is used to delimit the end of the current
///   block; this block contains the exit condition of the current
///   block, known from the branch instruction;
/// - If the instruction's target IP is statically known, ensure
///   that a block exists at this position. If this block is new, 
///   its "previous exit" is set to an unconditionnal jump to 
///   itself, in order to continue the execution flow.
/// 
/// After all these incomplete blocks have been defined, we sort
/// all of them by beginning IP. And then we iterate them in reverse
/// order to define all basic blocks in the analyzer's database
/// while apply the "previous exit" field recursively, we also
/// set the "end IP" of defined basic blocks.
/// 
/// [`Basic Blocks`]: https://en.wikipedia.org/wiki/Basic_block
#[derive(Default)]
pub struct BasicBlockPass {
    /// Temporary basic blocks being built.
    /// We directly use a vector because we will sort them in-place
    /// in order to apply exit conditions. Once this is done, each
    /// finished basic block is added to the database.
    blocks: Vec<IncompleteBlock>,
    /// Maps from basic blocks 
    blocks_map: HashMap<u64, usize>,
}

/// A structure temporarily used to construct basic blocks.
#[derive(Debug)]
struct IncompleteBlock {
    /// The beginning Instruction Position for the future basic block.
    begin_ip: u64,
    /// Number of calls to this block.
    calls_count: u32,
    /// The exit statement that should be defined for the the previous block.
    prev_exit: BasicBlockExit,
}

impl BasicBlockPass {

    /// Internal function that ensure's that an incomplete block is defined
    /// at the given IP. The block's mutable ref is returned.
    fn ensure_basic_block(&mut self, begin_ip: u64) -> &mut IncompleteBlock {
        
        let index = match self.blocks_map.entry(begin_ip) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let idx = self.blocks.len();
                self.blocks.push(IncompleteBlock {
                    begin_ip,
                    calls_count: 0,
                    // New blocs set the previous exit to unconditionnaly jump to 
                    // themself, this will be override if a jump precede this block.
                    prev_exit: BasicBlockExit::Unconditionnal { goto_ip: begin_ip }
                });
                *v.insert(idx)
            },
        };

        &mut self.blocks[index]

    }

}

impl AnalyzerStepPass for BasicBlockPass {

    fn accept(&mut self, _analyzer: &mut Analyzer, inst: &Instruction) {

        // We only cover x86_64 jumps/calls for now.
        let (target_ip, cond, call) = match inst.code() {
            // Unconditionnal jumps
            Code::Jmp_rel8_64   => (inst.near_branch64(), false, false),
            Code::Jmp_rel32_64  => (inst.near_branch64(), false, false),
            Code::Jmp_rm64      => (0,                    false, false),
            // Conditional jumps
            code if code.is_jcc_short_or_near() 
                                => (inst.near_branch64(), true, false),
            // Procedure calls
            Code::Call_rel32_64 => (inst.near_branch64(), false, true),
            Code::Call_rm64     => return, 
            Code::Retnq         => (0,                    false, false),
            // Unhandled
            _ => return,
        };

        // Update the targetted basic block with entries addresses.
        // Target IP=0 if the destination is not statically known.
        if target_ip != 0 {
            let target_bb = self.ensure_basic_block(target_ip);
            if call {
                target_bb.calls_count += 1;
            }
        }

        // Don't cut the current basic block for calls.
        if call {
            return;
        }
        
        // Because we took a jump (conditionnal or not), start a new
        // basic block just after it.
        let next_ip = inst.next_ip();
        let next_bb = self.ensure_basic_block(next_ip);
        
        if target_ip == 0 {
            // If the destination is unknown, use adequate exit.
            next_bb.prev_exit = BasicBlockExit::Unknown;
        } else if cond {
            next_bb.prev_exit = BasicBlockExit::Conditionnal { 
                then_ip: target_ip, 
                else_ip: next_ip,
            };
        } else {
            next_bb.prev_exit = BasicBlockExit::Unconditionnal { 
                goto_ip: target_ip 
            };
        }
            

    }

    fn after(&mut self, analyzer: &mut Analyzer) {
        
        if self.blocks.is_empty() {
            // Do not process continue if empty.
            return;
        }

        // Sort incomplete blocks by IP.
        self.blocks.sort_by_key(|block| block.begin_ip);

        // A reverse iterator to propage the exit statement to previous block.
        let blocks_len = self.blocks.len();
        let mut blocks_it = self.blocks.drain(..);

        // These are initially set to an imaginary bblock on the EOF.
        let mut next_exit = BasicBlockExit::Unknown;
        let mut next_ip = analyzer.runtime.data_ip() + analyzer.runtime.data_len() as u64;

        let mut cross_refs = Vec::with_capacity(blocks_len);

        // Propate end IP for basic blocks.
        while let Some(block) = blocks_it.next_back() {

            match next_exit {
                BasicBlockExit::Unconditionnal { goto_ip } => {
                    cross_refs.push((block.begin_ip, goto_ip, 0));
                },
                BasicBlockExit::Conditionnal { then_ip, else_ip } => {
                    cross_refs.push((block.begin_ip, then_ip, else_ip));
                },
                BasicBlockExit::Unknown => {},
            }

            analyzer.database.basic_blocks.insert(block.begin_ip, BasicBlock { 
                begin_ip: block.begin_ip, 
                end_ip: next_ip, 
                entries_from: Vec::new(), 
                entries_count: block.calls_count, 
                calls_count: block.calls_count, 
                exit: next_exit
            });

            next_exit = block.prev_exit;
            next_ip = block.begin_ip;

        }

        // The last pass compute back references to callers.
        // SAFETY: We can unwrap because we expect the goto blocks to be defined.
        for (from_ip, goto0, goto1) in cross_refs {

            let bb0 = analyzer.database.basic_blocks.get_mut(&goto0).unwrap();
            bb0.entries_count += 1;
            bb0.entries_from.push(from_ip);

            if goto1 != 0 {
                let bb1 = analyzer.database.basic_blocks.get_mut(&goto1).unwrap();
                bb1.entries_count += 1;
                bb1.entries_from.push(from_ip);
            }

        }

    }

}
