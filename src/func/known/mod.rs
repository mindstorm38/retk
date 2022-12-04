//! This is a module for documenting functions from
//! well-known shared libraries. The goal is to provide
//! their signature.

use std::collections::HashMap;

use crate::ty::TypeSystem;

use super::Signature;

pub mod ws2;
pub mod cpp;


pub trait Library {
    fn init(types: &mut TypeSystem) -> Box<Self>;
    fn function(&self, name: &[u8], types: &mut TypeSystem, signature: &mut Signature);
}


/// Full known function database, with all registered 
pub struct LibraryDatabase {
    libraries: HashMap<&'static [u8], Box<dyn UntypedLibraryHandler>>,
}

impl LibraryDatabase {

    pub fn new() -> Self {
        Self {
            libraries: HashMap::new(),
        }
    }

    pub fn new_lib<L: Library + 'static>(&mut self, name: &'static [u8]) {
        self.libraries.insert(name, Box::new(LibraryHandler {
            constructor: L::init,
            library: None,
        }));
    }

}


struct LibraryHandler<L: Library> {
    constructor: fn(&mut TypeSystem) -> Box<L>,
    library: Option<Box<L>>,
}

trait UntypedLibraryHandler {
    fn function(&mut self, name: &[u8], types: &mut TypeSystem, signature: &mut Signature);
}

impl<L: Library> UntypedLibraryHandler for LibraryHandler<L> {
    fn function(&mut self, name: &[u8], types: &mut TypeSystem, signature: &mut Signature) {
        self.ensure_lib(types).function(name, types, signature)
    }
}

impl<L: Library> LibraryHandler<L> {
    fn ensure_lib(&mut self, types: &mut TypeSystem) -> &mut L {
        self.library.get_or_insert_with(|| {
            (self.constructor)(types)
        })
    }
}
