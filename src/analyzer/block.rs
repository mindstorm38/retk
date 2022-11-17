//! Calls analyzer passes.
//! 
//! The first pass ensure that all symbols exists for each jumped-to address.
//! The second pass complete the graph.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use iced_x86::{Instruction, Code};

use super::{Analyzer, AnalyzerStepPass};
use crate::symbol::{BasicBlock, BasicBlockExit};


/// The role of this pass is to cover the whole code behind basic blocks.
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
    /// The uncomplete basic block being built.
    basic_block: BasicBlock,
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
                    basic_block: BasicBlock::new(begin_ip),
                    prev_exit: BasicBlockExit::Unknown
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
            self.ensure_basic_block(target_ip);
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
        self.blocks.sort_by_key(|block| block.basic_block.begin_ip);
        
        // A reverse iterator to propage the exit statement to previous block.
        let mut blocks_it = self.blocks.drain(..);
        let mut next_exit;
        let mut next_ip;

        {
            
            // SAFETY: We can unwrap because the iterator is not empty.
            let last_block = blocks_it.next_back().unwrap();
            
            next_exit = last_block.prev_exit.clone();
            next_ip = last_block.basic_block.begin_ip;

            analyzer.database.basic_blocks.insert(next_ip, last_block.basic_block);

        }

        // Propate end IP for basic blocks.
        while let Some(mut block) = blocks_it.next_back() {

            block.basic_block.end_ip = next_ip;
            block.basic_block.exit = next_exit.clone();
            
            next_exit = block.prev_exit;
            next_ip = block.basic_block.begin_ip;

            analyzer.database.basic_blocks.insert(next_ip, block.basic_block);

        }

    }

}
