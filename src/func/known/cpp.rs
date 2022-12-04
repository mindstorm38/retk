//! C++ automatic demangler.

use crate::func::Signature;
use crate::ty::TypeSystem;

use super::Library;


pub struct CppDemangler {

}

impl Library for CppDemangler {

    fn init(_types: &mut TypeSystem) -> Box<Self> {
        Box::new(Self {})
    }

    fn function(&self, name: &[u8], types: &mut TypeSystem, signature: &mut Signature) {
        


    }

}
