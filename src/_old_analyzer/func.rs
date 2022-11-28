//! # Function Analysis implementation.
//! See [`FunctionPass`] structure.

use std::collections::{HashMap, HashSet};

use crate::symbol::{BasicBlock, BasicBlockExit, Function, Abi};

use super::{Analyzer, AnalyzerPass};


/// This pass tries to find all function. A function, as defined by
/// this pass, consists of a group of contiguous basic blocks where
/// the first basic block is called (defined below) by other basic
/// blocks of code.
/// 
/// A call to a function can be detected either by a `call` instruction
/// to an statically-known address and basic block, or a `jmp`/`jcc` 
/// instruction to an statically-known address that is out of the scope
/// of the currently analyzed function (before the function's IP or to
/// a non-contiguous basic block after the function).
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
