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
//! representation should be done after all these passes for
//! the final pseudo-code representation.

use std::num::NonZeroU32;

use crate::ty::Type;

pub mod print;


/// An IDR function.
#[derive(Debug, Default)]
pub struct IdrFunction {
    /// All lines/statements of the function.
    pub basic_blocks: Vec<IdrBasicBlock>,
}


/// A basic block.
#[derive(Debug)]
pub struct IdrBasicBlock {
    /// Variables defined as parameters for the rest of the basic block.
    pub parameters: Vec<(IdrVar, Type)>,
    /// The statement of this line. If none this line is empty and
    /// should be replaced by the next added statement.
    pub statements: Vec<Statement>,
    /// The branch to exit this basic block.
    pub branch: Branch,
}

impl Default for IdrBasicBlock {
    fn default() -> Self {
        Self { 
            parameters: Vec::new(), 
            statements: Vec::new(),
            branch: Branch::Unknown,
        }
    }
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

    /// Create a new IDR variable unique to this factory.
    pub fn create(&mut self) -> IdrVar {
        let index = self.index;
        self.index = self.index.checked_add(1)
            .expect("reached maximum number of idr variables");
        IdrVar(index)
    }

}


/// A statement.
#[derive(Debug)]
pub enum Statement {
    /// Store an expression's value to a pointed value.
    Store(Store),
    /// Create a new variable assignment.
    /// 
    /// The variable is guaranteed to be unique within
    /// the statement's basic block.
    Assign(Assign),
    /// A raw assembly instruction, **currently** just string.
    Asm(String),
}

#[derive(Debug)]
pub struct Store {
    /// The variable that is the pointer.
    pub ptr: IdrVar,
    /// The variable that has the value to store in the pointer.
    pub var: IdrVar,
}

#[derive(Debug)]
pub struct Assign {
    /// Variable assigned.
    pub var: IdrVar,
    /// Type of the variable.
    pub ty: Type,
    /// The expression used that calculate the value to assign.
    pub val: Expression,
}

impl Statement {

    /// Get all variables read by the statement.
    pub fn get_read_variables(&self, variables: &mut Vec<IdrVar>) {
        match self {
            Statement::Store(store) => {
                variables.push(store.ptr);
                variables.push(store.var);
            }
            Statement::Assign(assign) => {
                match assign.val {
                    Expression::Constant(_) => {}
                    Expression::Load(var) => variables.push(var),
                    Expression::Alloca(_) => {}
                    Expression::Call { pointer, ref arguments } => {

                        if let Value::Var(pointer) = pointer {
                            variables.push(pointer);
                        }

                        variables.extend(arguments.iter().filter_map(|val| {
                            match val {
                                Value::Var(var) => Some(*var),
                                _ => None,
                            }
                        }));

                    }
                    Expression::GetElementPointer { pointer, index, stride: _ } => {
                        variables.push(pointer);
                        variables.push(index);
                    }
                    Expression::Cmp(_, var, val) |
                    Expression::Add(var, val) |
                    Expression::Sub(var, val) |
                    Expression::Mul(var, val) |
                    Expression::Div(var, val) |
                    Expression::Xor(var, val) => {
                        variables.push(var);
                        if let Value::Var(val) = val {
                            variables.push(val);
                        }
                    }
                }
            }
            Statement::Asm(_) => {}
        }
    }

}


/// An exit branch for a basic block.
#[derive(Debug)]
pub enum Branch {
    /// Unknown branching, usually impossible after a full analysis.
    Unknown,
    /// Unconditionnal branch to the given basic block.
    Unconditionnal {
        /// Index of the basic block to goto.
        index: usize,
        /// Arguments of the basic block.
        args: Vec<IdrVar>,
    },
    /// Conditinnal branch depending on a boolean variable.
    Conditionnal {
        var: IdrVar,
        /// Index of the basic block to goto if the condition is met.
        then_index: usize,
        /// Arguments of the basic block to goto if the condition is met.
        then_args: Vec<IdrVar>,
        /// Index of the basic block to goto if the condition is not met.
        else_index: usize,
        /// Arguments of the basic block to goto if the condition is not met.
        else_args: Vec<IdrVar>,
    },
    /// Returning from the function.
    Ret,
}


/// Represent an rvalue in an assignment or store.
#[derive(Debug)]
pub enum Expression {
    /// A constant value.
    Constant(i64),
    /// Load a value by dereferencing the given variable.
    Load(IdrVar),
    /// Stack allocation of a given size. *Value type is a pointer.*
    Alloca(u16),
    /// A call to another function.
    Call {
        /// The value of the pointer.
        pointer: Value,
        /// Arguments given to the function.
        arguments: Vec<Value>,
    },
    /// Offset a given pointer by a given index and stride.
    GetElementPointer {
        pointer: IdrVar, 
        index: IdrVar, 
        stride: u8
    },
    /// Compare two values and place return a boolean.
    Cmp(Comparison, IdrVar, Value),
    /// Add a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Add(IdrVar, Value),
    /// Sub a value from a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Sub(IdrVar, Value),
    /// Mul a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Mul(IdrVar, Value),
    /// Div a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Div(IdrVar, Value),
    /// XOR a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Xor(IdrVar, Value),
}

/// Kind of comparison
#[derive(Debug)]
pub enum Comparison {
    Equal,
    NotEqual,
}


/// Describe the effective value for an expression,
/// can be either a variable or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// The value is a variable.
    Var(IdrVar),
    /// A constant value.
    Val(i64)
}


// #[derive(Debug, Clone, PartialEq, Eq, Copy)]
// pub enum IdrCondition {
//     Equal,
//     NotEqual,
//     UnsignedLower,
//     UnsignedLowerOrEqual,
//     UnsignedGreater,
//     UnsignedGreaterOrEqual,
//     SignedLower,
//     SignedLowerOrEqual,
//     SignedGreater,
//     SignedGeaterOrEqual,
// }
