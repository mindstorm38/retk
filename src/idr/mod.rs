//! Intermediate Decompilation Representation
//! 
//! This representation aims to abstract itself from the machine-level instruction-set. 
//! This representation only present places and assignments, no more registers nor actual 
//! memory addressing.
//! 
//! This representation uses Static Single-Assignment, which is notably used in LLVM IR. 
//! Here we use a simpler Intermediate Representation where some details can be omitted,
//! because we can't know some of these in the first place.
//! 
//! This representation is mainly used to find and guess data types and structures. Code 
//! folding and branch/loops representation should be done after all these passes for the
//! final pseudo-code representation.

use std::num::NonZeroU32;

pub mod print;
pub mod types;

use types::Type;


/// An function's Intermediate Decompilation Representation.
#[derive(Debug, Default, Clone)]
pub struct Function {
    /// The calling convention of this function, used to know how to decode calls to it.
    pub calling_convention: CallingConvention,
    /// All lines/statements of the function.
    pub basic_blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Unknown calling convention.
    Unknown,
    /// Unix C x86.
    Cdecl,
    /// WINAPI.
    Stdcall,
    /// Windows x86.
    Fastcall,
    /// Windows x64.
    Win64,
    /// System V AMD 64.
    Amd64,
    /// For leaf function calling convention, no argument or framing.
    Leaf,
}

impl Default for CallingConvention {
    fn default() -> Self {
        Self::Unknown
    }
}

/// A basic block in a function's IDR.
#[derive(Debug, Default, Clone)]
pub struct BasicBlock {
    /// The statement of this line. If none this line is empty and should be replaced by 
    /// the next added statement.
    pub statements: Vec<Statement>,
    /// The branch to exit this basic block.
    pub branch: Branch,
}

/// Represent a unique place for storing a value in a basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Place(NonZeroU32);

/// Describe the effective value for an expression, can be either a variable or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// The value is come from a place's value.
    Place(Place),
    /// A constant value.
    LiteralInt(i64),
}

/// A statement.
#[derive(Debug, Clone)]
pub enum Statement {
    /// Store an expression's value to a pointed value.
    Store(Store),
    /// Create a new place associated to a given expression.
    Bind(Bind),
    /// A raw assembly instruction, **currently** just string.
    Asm(String),
}

#[derive(Debug, Clone)]
pub struct Store {
    /// The place that stores the pointer where the source place's value should by
    /// copied to.
    pub pointer: Place,
    /// The source expression from which the value is copied in the pointed location.
    pub value: Expression,
}

#[derive(Debug, Clone)]
pub struct Bind {
    /// The new place that is being created.
    pub place: Place,
    /// Type of the variable.
    pub ty: Type,
    /// The expression used that calculate the value to assign.
    pub value: Expression,
}

/// An exit branch for a basic block.
#[derive(Debug, Clone)]
pub enum Branch {
    /// Unknown branching, usually impossible after a full analysis.
    Unknown,
    /// Unconditional branch to the given basic block.
    Unconditional {
        /// Index of the basic block to goto.
        index: usize,
        /// Arguments of the basic block.
        args: Vec<Place>,
    },
    /// Conditional branch depending on a boolean variable.
    Conditional {
        place: Place,
        /// Index of the basic block to goto if the condition is met.
        then_index: usize,
        /// Arguments of the basic block to goto if the condition is met.
        then_args: Vec<Place>,
        /// Index of the basic block to goto if the condition is not met.
        else_index: usize,
        /// Arguments of the basic block to goto if the condition is not met.
        else_args: Vec<Place>,
    },
    /// Returning from the function.
    Ret {
        place: Place,
    },
}

impl Default for Branch {
    fn default() -> Self {
        Branch::Unknown
    }
}


/// Represent an rvalue in an assignment.
#[derive(Debug, Clone)]
pub enum Expression {
    /// A direct value.
    Value(Value),
    /// Load a value by dereferencing the given register.
    Load(Place),
    /// Stack allocation of a given size. *Value type is a pointer.*
    Stack(u64),
    /// A call to another function.
    Call {
        /// The value of the pointer.
        pointer: Value,
        /// Arguments given to the function.
        arguments: Vec<Value>,
    },
    /// Offset a given pointer by a given index and stride.
    GetElementPointer {
        /// The pointer we want to offset.
        pointer: Place,
        /// The variable containing the offset.
        index: Place,
        /// The bytes stride when index increments by one.
        stride: u8
    },
    /// Compare two values and place return a boolean.
    Cmp(Comparison, Value, Value),
    /// Add a value to a variable. Both values should have the same type, *and this is 
    /// the returned type*.
    Add(Value, Value),
    /// Sub a value from a variable. Both values should have the same type, *and this is 
    /// the returned type*.
    Sub(Value, Value),
    /// Mul a value to a variable. Both values should have the same type, *and this is 
    /// the returned type*.
    Mul(Value, Value),
    /// Div a value to a variable. Both values should have the same type, *and this is
    /// the returned type*.
    Div(Value, Value),
    /// XOR a value to a variable. Both values should have the same type, *and this is
    /// the returned type*.
    Xor(Value, Value),
}

/// Kind of comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    NotEqual,
}


#[derive(Debug, Clone)]
pub struct PlaceFactory {
    index: NonZeroU32,
}

impl Default for PlaceFactory {
    fn default() -> Self {
        Self { index: NonZeroU32::new(1).unwrap() }
    }
}

impl PlaceFactory {

    /// Create a new place unique to this factory.
    pub fn next(&mut self) -> Place {
        let index = self.index;
        self.index = self.index.checked_add(1)
            .expect("reached maximum number of idr places");
        Place(index)
    }

}
