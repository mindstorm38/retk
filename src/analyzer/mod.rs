//! Generic analyzer structure.

use std::collections::HashMap;

use crate::block::BasicBlock;
use crate::func::Function;
use crate::ty::TypeSystem;


/// A generic analyzer implementation.
pub struct Analyzer<R> {
    pub runtime: R,
    pub database: Database
}

/// Analyzer's database. The database aims to be as more generic
/// as possible, objects contained in the database doesn't contains
/// architecture-specific objects.
pub struct Database {
    /// All basic blocks associated to their instruction pointer. 
    pub basic_blocks: HashMap<u64, BasicBlock>,
    /// All functions associated to their instruction pointer.
    pub functions: HashMap<u64, Function>,
    /// Type system.
    pub types: TypeSystem,
}

/// A specific analysis implementation.
pub trait Analysis<R> {

    /// Perform the analysis on the given analyzer.
    fn analyze(&mut self, analyzer: &mut Analyzer<R>);

}

// Default impl for mutable reference, therefore allowing
// to reused analysis.
impl<R, A: Analysis<R>> Analysis<R> for &'_ mut A {
    fn analyze(&mut self, analyzer: &mut Analyzer<R>) {
        Analysis::analyze(&mut **self, analyzer);
    }
}


impl<R> Analyzer<R> {

    #[inline]
    pub fn new(runtime: R, pointer_size: u32) -> Self {
        Self { 
            runtime, 
            database: Database {
                basic_blocks: HashMap::new(),
                functions: HashMap::new(),
                types: TypeSystem::new(pointer_size),
            }
        }
    }

    #[inline]
    pub fn run<A: Analysis<R>>(&mut self, mut analysis: A) {
        analysis.analyze(self)
    }

}
