//! This module provides a way to resolve basic block
//! list, only from branching instructions. Because
//! this module is doesn't interact with arch-specific
//! code, you must specialize it for arch analysis.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use super::{BasicBlockExit, BasicBlock};


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
#[derive(Debug, Default)]
pub struct ListResolver {
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
    /// True if this block is called.
    function: bool,
    /// The exit statement that should be defined for the the previous block.
    prev_exit: BasicBlockExit,
}

impl ListResolver {

    /// Push a new branch to the basic blocks.
    /// The branch consists of:
    /// - A goto instruction pointer (IP) where to branch goto if entered.
    ///   **Can be zero** if the branch has a statically unknown return address (typically
    ///   a function's return or indirect addressed jumps).
    ///   ***You should not** call this function if the goto IP is out of the code's
    ///   range.*
    /// - A next IP, this is the IP of the next instruction after the branch instruction,
    ///   this should be always a valid IP even if the branch unconditionnaly go not to
    ///   this pointer.
    /// - A condition flag, indicating if the branch is conditionnal.
    /// - A call flag, indicating if the branch is a function call, in such case no
    ///   basic block is created but a basic block is created on the goto IP, and it
    ///   is marked as "called", which is later used to find functions.
    pub fn push_branch(&mut self, goto_ip: u64, next_ip: u64, cond: bool, call: bool) {

        // Update the targetted basic block with entries addresses.
        // Target IP=0 if the destination is not statically known.
        if goto_ip != 0 {
            let target_bb = self.ensure_basic_block(goto_ip);
            if call {
                target_bb.function = true;
            }
        }

        // Don't cut the current basic block for calls.
        if call {
            return;
        }
        
        // Because we took a jump (conditionnal or not), start a new
        // basic block just after it.
        let next_bb = self.ensure_basic_block(next_ip);
        
        if goto_ip == 0 {
            // If the destination is unknown, use adequate exit.
            next_bb.prev_exit = BasicBlockExit::Unknown;
        } else if cond {
            next_bb.prev_exit = BasicBlockExit::Conditionnal { 
                goto_ip, 
                continue_ip: next_ip,
            };
        } else {
            next_bb.prev_exit = BasicBlockExit::Unconditionnal { 
                goto_ip, 
            };
        }

    }

    /// Internal function that ensure's that an incomplete block is defined
    /// at the given IP. The block's mutable ref is returned.
    fn ensure_basic_block(&mut self, begin_ip: u64) -> &mut IncompleteBlock {
        
        let index = match self.blocks_map.entry(begin_ip) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                let idx = self.blocks.len();
                self.blocks.push(IncompleteBlock {
                    begin_ip,
                    function: false,
                    // New blocs set the previous exit to unconditionnaly jump to 
                    // themself, this will be override if a jump precede this block.
                    prev_exit: BasicBlockExit::Unconditionnal { goto_ip: begin_ip }
                });
                *v.insert(idx)
            },
        };

        &mut self.blocks[index]

    }

    /// Finalize internal basic blocks that are partially created
    /// and push them to the basic blocks database given in parameters.
    /// 
    /// The caller should give the maximum possible instruction pointer,
    /// it's used to correctly define the last basic block.
    pub fn finalize(&mut self, max_ip: u64, bbs: &mut HashMap<u64, BasicBlock>) {

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
        let mut next_ip = max_ip;

        let mut cross_refs = Vec::with_capacity(blocks_len);

        // Propate end IP for basic blocks.
        while let Some(block) = blocks_it.next_back() {

            match next_exit {
                BasicBlockExit::Unconditionnal { goto_ip } => {
                    cross_refs.push((block.begin_ip, goto_ip, 0));
                },
                BasicBlockExit::Conditionnal { goto_ip, continue_ip } => {
                    cross_refs.push((block.begin_ip, goto_ip, continue_ip));
                },
                BasicBlockExit::Unknown => {},
            }

            bbs.insert(block.begin_ip, BasicBlock { 
                begin_ip: block.begin_ip, 
                end_ip: next_ip, 
                entries_from: Vec::new(), 
                entries_count: 0, 
                function: block.function, 
                exit: next_exit
            });

            next_exit = block.prev_exit;
            next_ip = block.begin_ip;

        }

        // The last pass compute back references to callers.
        for (from_ip, goto0, goto1) in cross_refs {

            if let Some(bb0) = bbs.get_mut(&goto0) {
                bb0.entries_count += 1;
                bb0.entries_from.push(from_ip);
            }

            if goto1 != 0 {
                if let Some(bb1) = bbs.get_mut(&goto1) {
                    bb1.entries_count += 1;
                    bb1.entries_from.push(from_ip);
                }
            }

        }

    }

}
