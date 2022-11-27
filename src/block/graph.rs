//! This module provides a way to resolve basic block
//! graphs for functions.

use std::collections::{HashMap, HashSet};

use super::{BasicBlock, BasicBlockExit};


/// This resolver provides a way to find contiguous blocks that
/// are in the same graph. A basic block graph consist of all
/// basic blocks linked by exit branches. This means that if
/// a basic block is linked to but not contiguous to another
/// block, it will not be included in the contiguous graph.
pub struct ContiguousGraphResolver<'db> {
    /// Database's basic blocks.
    bbs: &'db HashMap<u64, BasicBlock>,
    /// Unique basic block found in a graph. Used to avoid
    /// infinite cycles and for contiguous graph validation.
    unique_bbs: HashMap<u64, &'db BasicBlock>,
    /// A list of basic blocks that should be considered as functions
    /// because they are tail/thunk-called and are not currently 
    /// considered as such.
    called_bbs: HashSet<u64>,
}

impl<'db> ContiguousGraphResolver<'db> {

    /// Create a new resolver with the given basic blocks database.
    pub fn new(bbs: &'db HashMap<u64, BasicBlock>) -> Self {
        Self {
            bbs,
            unique_bbs: HashMap::new(),
            called_bbs: HashSet::new(),
        }
    }

    /// Resolve a contiguous blocks graph starting at the given basic block.
    /// The final instruction pointer range is returned.
    pub fn resolve_graph(&mut self, bb: &'db BasicBlock) -> (u64, u64) {
        let begin_ip = bb.begin_ip;
        self.resolve(bb, begin_ip);
        let end_ip = self.validate(begin_ip);
        (begin_ip, end_ip)
    }

    pub fn resolve(&mut self, bb: &'db BasicBlock, first_ip: u64) {
        if self.unique_bbs.insert(bb.begin_ip, bb).is_none() {
            match bb.exit {
                BasicBlockExit::Unconditionnal { goto_ip } => {
                    let goto_bb = &self.bbs[&goto_ip];
                    if goto_ip < first_ip {
                        // We know that unconditionnaly jumping before the function's ip
                        // is very likely to be a tail/thunk-call.
                        // If the basic block is already a function, do nothing.
                        if !goto_bb.function {
                            self.called_bbs.insert(goto_ip);
                        }
                    } else {
                        if !goto_bb.function && !self.called_bbs.contains(&goto_ip) {
                            self.resolve(goto_bb, first_ip);
                        }
                    }
                }
                BasicBlockExit::Conditionnal { goto_ip, continue_ip } => {
                    let goto_bb = &self.bbs[&goto_ip];
                    if goto_ip < first_ip {
                        // Read the comment above.
                        if !goto_bb.function {
                            self.called_bbs.insert(goto_ip);
                        }
                    } else {
                        if !goto_bb.function && !self.called_bbs.contains(&goto_ip) {
                            self.resolve(goto_bb, first_ip);
                            self.resolve(&self.bbs[&continue_ip], first_ip);
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
    pub fn validate(&mut self, first_ip: u64) -> u64 {

        let mut next_ip = first_ip;
        while let Some(bb) = self.unique_bbs.remove(&next_ip) {
            next_ip = bb.end_ip;
        }
        let end_ip = next_ip;

        for (_, bb) in self.unique_bbs.drain() {
            for &entry in &bb.entries_from {
                if entry >= first_ip && entry < end_ip {
                    // This block is directly called by our function,
                    // but is not contiguous, it should be a function.
                    self.called_bbs.insert(bb.begin_ip);
                }
            }
        }

        end_ip

    }

    /// Iterate over basic blocks that were called by the resolve
    /// graphs, these blocks are not currently considered as calls,
    /// but should be.
    /// 
    /// *This can happen because of tail/thunk-calls.*
    #[inline]
    pub fn iter_called_bbs(&self) -> impl Iterator<Item = u64> + '_ {
        self.called_bbs.iter().copied()
    }

}
