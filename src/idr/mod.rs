//! Intermediate Decompilation Representation
//! 
//! This representation aims to abstract itself from the 
//! machine-level instruction-set. This reprensentation
//! only present places and assignments, no more registers
//! nor actual memory addressing.
//! 
//! This representation uses Static Single-Assignment,
//! which is notably used in LLVM IR. Here we use a simpler
//! Intermediate Representation where some details can be
//! ommited, because we can't know some of these in the 
//! first place.
//! 
//! This representation is mainly used to find and guess
//! data types and structures. Code folding and branch/loops
//! representation should be done after all these passes.

use std::num::NonZeroU32;

mod ty;
pub use ty::IdrType;

mod fmt;


/// A function is composed of statements and labels,
/// these labels are used to delimit basic blocks and the
/// last statement of the basic block is an exit statement.
#[derive(Debug, Default)]
pub struct IdrFunction {
    /// All statements of this function.
    pub statements: Vec<IdrStatement>,
    /// Indices of labels, labels are the beginning of
    /// basic blocks.
    pub labels: Vec<usize>,
}


/// An IDR statement.
#[derive(Debug, Clone)]
pub enum IdrStatement {
    /// An error happened while producing IDR statement.
    Error,
    /// Inline assembly statement.
    Asm,
    /// Assignement of an expression's result to a variable.
    Assign {
        /// The variable where the expression is assigned.
        var: IdrVar,
        /// Type of the variable.
        ty: IdrType,
        /// The expression that computes the value that will
        /// be assigned to the place.
        expr: IdrExpression,
    },
    /// Store a variable's value to a slot pointed to by 
    /// another var.
    Store {
        /// The pointer to the slot where the variable's value
        /// will be copied.
        pointer: IdrVar,
        /// The variable to store in the 
        var: IdrVar,
    },
    /// A branch to another statement.
    Branch {
        pointer: u64,
        left_var: IdrVar,
        right_var: IdrVar,
        cond: IdrCondition,
    }
}

impl Default for IdrStatement {
    fn default() -> Self {
        Self::Error
    }
}


/// An expression that produce a value that is then assigned
#[derive(Debug, Clone)]
pub enum IdrExpression {
    /// Constant value.
    Constant(i64),
    /// Copy the value of another variable.
    Copy(IdrVar),
    /// Allocating a slot on the stack and return a pointer
    /// to this slot, the given length is allocated.
    Alloca(u16),
    /// Interpret the given place as an pointer-sized integer
    /// type and dereference it.
    Deref {
        /// The variable used as the base value to deref.
        base: IdrVar,
        /// The offset applied to the base value before deref.
        offset: i64,
    },
    DerefIndexed {
        /// The variable used as the base value to deref.
        base: IdrVar,
        /// The offset applied to the base value before deref.
        offset: i32,
        /// The variable used as the index, added to base and
        /// offset and multiplied by scale before deref.
        index: IdrVar,
        /// Scale to apply to the index, usually a power of two.
        scale: u8,
    }, 
    /// An absolute call to a function.
    Call {
        /// Address of the function to call.
        pointer: u64,
        /// Variables to pass as function's arguments.
        args: Vec<IdrVar>,
    },
    /// An indirect call to a function.
    CallIndirect {
        /// The variable that contains the function's pointer 
        /// to call.
        pointer: IdrVar,
        /// Variables to pass as function's arguments.
        args: Vec<IdrVar>,
    },
    Add(IdrVar, IdrVar),
    AddImm(IdrVar, i64),
    Sub(IdrVar, IdrVar),
    SubImm(IdrVar, i64),
    Mul(IdrVar, IdrVar),
    MulImm(IdrVar, i64),
    Div(IdrVar, IdrVar),
    DivImm(IdrVar, i64),
    And(IdrVar, IdrVar),
    AndImm(IdrVar, i64),
    Or(IdrVar, IdrVar),
    OrImm(IdrVar, i64),
    Xor(IdrVar, IdrVar),
    XorImm(IdrVar, i64),
}


#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum IdrCondition {
    Equal,
    NotEqual,
    UnsignedLower,
    UnsignedLowerOrEqual,
    UnsignedGreater,
    UnsignedGreaterOrEqual,
    SignedLower,
    SignedLowerOrEqual,
    SignedGreater,
    SignedGeaterOrEqual,
}

/// Represent a variable in the 
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdrVar(NonZeroU32);


/// A factory to use to create a unique [`IdrVar`].
/// This is the only way to create variable because this
/// type is opaque.
pub struct IdrVarFactory {
    index: NonZeroU32,
}

impl Default for IdrVarFactory {
    fn default() -> Self {
        Self { index: NonZeroU32::new(1).unwrap() }
    }
}

impl IdrVarFactory {

    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&mut self) -> IdrVar {
        let index = self.index;
        self.index = self.index.checked_add(1)
            .expect("reached maximum number of idr variables");
        IdrVar(index)
    }

}
