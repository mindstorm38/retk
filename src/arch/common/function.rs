//! Common function graph analysis. This is common to all architectures
//! because the analysis just consist of reading the basic blocks
//! (themselves produced by architecture-specific code).

use crate::analyzer::{Analysis, Analyzer};
use crate::block::ContiguousGraphResolver;
use crate::func::Function;


/// This analysis tries to find all functions. A function, as defined
///  by this analysis, consists of a group of contiguous basic blocks 
/// where the first basic block is called (defined below) by other basic
/// blocks of code.
/// 
/// A call to a function can be detected either by a `call` instruction
/// to an statically-known address and basic block, or a `jmp`/`jcc` 
/// instruction to an statically-known address that is out of the scope
/// of the currently analyzed function (before the function's IP or to
/// a non-contiguous basic block after the function).
#[derive(Default)]
pub struct FunctionGraphAnalysis { }

impl<R> Analysis<R> for FunctionGraphAnalysis {

    fn analyze(&mut self, analyzer: &mut Analyzer<R>) {

        // A list of basic blocks that should be considered as functions
        // because they are tail/thunk-called and are not currently 
        // considered as such.
        let mut new_functions = Vec::new();
        // We search function through all basic blocks only on the first
        // iteration.
        let mut first_it = true;

        let db = &mut analyzer.database;

        // This loop should exit because we define more and more function
        // on each loop, and we can at most define the number of basic 
        // blocks.
        while !new_functions.is_empty() || first_it {

            let mut func_resolver = ContiguousGraphResolver::new(&db.basic_blocks);

            if first_it {
                for bb in db.basic_blocks.values() {
                    if bb.function {
                        let (begin_ip, end_ip) = func_resolver.resolve_graph(bb);
                        db.functions.insert(begin_ip, Function::new(begin_ip, end_ip));
                    }
                }
                first_it = false;
            } else {
                for bb_ip in new_functions.drain(..) {
                    let bb = &db.basic_blocks[&bb_ip];
                    let (begin_ip, end_ip) = func_resolver.resolve_graph(bb);
                    db.functions.insert(begin_ip, Function::new(begin_ip, end_ip));
                }
            }

            new_functions.extend(func_resolver.iter_called_bbs());
            for bb_ip in &new_functions {
                db.basic_blocks.get_mut(bb_ip).unwrap().function = true;
            }

        }

    }

}
