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

/// Represent a variable's unique name in a function's IDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Name(NonZeroU32);

/// Describe the effective value for an expression, can be either a variable or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// The value is come from a register.
    Register(Name),
    /// A constant value.
    LiteralInt(i64),
}

/// A statement.
#[derive(Debug, Clone)]
pub enum Statement {
    /// Store an expression's value to a pointed value.
    Store(Store),
    /// Create a new register of a given name, type and definitive value. Its name should
    /// be unique through the whole function.
    Create(Create),
    /// A raw assembly instruction, **currently** just string.
    Asm(String),
}

#[derive(Debug, Clone)]
pub struct Store {
    /// The register that stores the pointer where the source register's value should by
    /// copied to.
    pub pointer_register: Name,
    /// The source expression from which the value is copied in the pointed location.
    pub value: Expression,
}

#[derive(Debug, Clone)]
pub struct Create {
    /// The new register that is being created.
    pub register: Name,
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
        args: Vec<Name>,
    },
    /// Conditional branch depending on a boolean variable.
    Conditional {
        var: Name,
        /// Index of the basic block to goto if the condition is met.
        then_index: usize,
        /// Arguments of the basic block to goto if the condition is met.
        then_args: Vec<Name>,
        /// Index of the basic block to goto if the condition is not met.
        else_index: usize,
        /// Arguments of the basic block to goto if the condition is not met.
        else_args: Vec<Name>,
    },
    /// Returning from the function.
    Ret {
        var: Name,
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
    /// A literal value.
    LiteralInt(i64),
    /// Load a value by dereferencing the given register.
    Load(Name),
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
        pointer: Name, 
        index: Name, 
        stride: u8
    },
    /// Compare two values and place return a boolean.
    Cmp(Comparison, Value, Value),
    /// Add a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Add(Value, Value),
    /// Sub a value from a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Sub(Value, Value),
    /// Mul a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Mul(Value, Value),
    /// Div a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Div(Value, Value),
    /// XOR a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Xor(Value, Value),
}

/// Kind of comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    NotEqual,
}


#[derive(Debug, Clone)]
pub struct NameFactory {
    index: NonZeroU32,
}

impl Default for NameFactory {
    fn default() -> Self {
        Self { index: NonZeroU32::new(1).unwrap() }
    }
}

impl NameFactory {

    /// Create a new IDR variable unique to this factory.
    pub fn next(&mut self) -> Name {
        let index = self.index;
        self.index = self.index.checked_add(1)
            .expect("reached maximum number of idr variables");
        Name(index)
    }

}
