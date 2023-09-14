//! Generic analyzer structure.


/// A generic analyzer implementation.
pub struct Analyzer<R> {
    /// The arch-specific backend of the analyzer.
    pub backend: R,
    /// The arch-independent database.
    pub database: Database
}

/// Analyzer's database. The database aims to be as more generic
/// as possible, objects contained in the database doesn't contains
/// architecture-specific objects.
pub struct Database {
    
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
            backend: runtime, 
            database: Database {
            }
        }
    }

    #[inline]
    pub fn run<A: Analysis<R>>(&mut self, mut analysis: A) {
        analysis.analyze(self)
    }

}
