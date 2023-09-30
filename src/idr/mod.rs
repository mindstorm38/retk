//! Intermediate Decompilation Representation.

use crate::ty::{Type, Layout, TypeSystem, PrimitiveType};

pub mod print;


/// Represent a local variable.
#[derive(Debug, Clone)]
pub struct Local {
    /// Type of the local variable.
    pub ty: Type,
    /// Layout of the local variable's type.
    pub layout: Layout,
    /// An optional comment to help debugging the local when displayed.
    pub comment: String,
}

impl Local {

    /// Update the cached layout of a local variable.
    pub fn update_layout(&mut self, type_system: &TypeSystem) {
        self.layout = type_system.layout(self.ty).expect("type has no layout")
    }

}

/// Reference to a local variable, used in left values and expressions to reference 
/// the variable. 
/// 
/// TODO: Maybe use non-zero u32 in order to gain space through niches everywhere?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalRef(u32);

/// Describe type of index used for indirect place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Index {
    /// The indexing is absolute.
    Absolute(i32),
    /// The indexing is given from a local variable's value.
    Variable {
        /// The local variable containing the index.
        index: LocalRef,
        /// The stride to apply to the index value.
        stride: u8,
    },
}

/// Represent a memory place that can be referenced and dereferenced for pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// The local variable that contains either the local to assign or a pointer if
    /// indirection is used.
    pub local: LocalRef,
    /// The optional index to apply to this local, requiring it to be a pointer. The
    /// index is not necessarily aligned. An index is displayed like 
    /// `*(a + index * stride)`, but if the index is guaranteed to be a multiple of
    /// the type's size, then it is displayed like `a[index]`.
    /// 
    /// *If the given local variable is not a pointer type, the type must at least
    /// be an integer and will be interpreted as a byte pointer.*
    pub index: Option<Index>,
}

impl Place {

    pub const fn new_direct(local: LocalRef) -> Self {
        Self { local, index: None }
    }

    pub const fn new_index_absolute(local: LocalRef, index: i32) -> Self {
        Self { local, index: Some(Index::Absolute(index)) }
    }

    pub const fn new_index_variable(local: LocalRef, index: LocalRef, stride: u8) -> Self {
        Self { local, index: Some(Index::Variable { index, stride }) }
    }

}

/// Represent an operand in an expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// Special constant for zero constant, can be applied to int, floats and vectors.
    Zero,
    /// A literal unsigned 64-bit integer.
    LiteralUnsigned(u64),
    /// A literal signed 64-bit integer.
    LiteralSigned(i64),
    /// The value of the operand come from a memory place.
    Place(Place),
}

impl Operand {

    /// Shortcut function to create a place operand with a local directly referenced.
    pub const fn new_local(local: LocalRef) -> Self {
        Self::Place(Place::new_direct(local))
    }

}

/// En expression that produces a value and is used for assignments to places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// Bitwise copy of the operand's value.
    Copy(Operand),
    /// Get a pointer to a memory place.
    Ref(Place),
    /// An explicit cast from source local of a given type to another to the destination
    /// type of assigned local variable. Such a cast is required to be able to change a
    /// value's type.
    Cast(Place),
    /// Call a function from a pointer and an argument list.
    Call {
        /// The function pointer, either static or dynamic from a place.
        pointer: Operand,
        /// List of arguments to pass to the function.
        arguments: Vec<Operand>,
    },
    /// Perform a binary comparison that produces a boolean value. The two operands 
    /// are required to be of the same type.
    Comparison {
        left: Operand,
        right: Operand,
        operator: ComparisonOperator,
    },
    /// A binary expression with two operands and a binary operator. The two operands 
    /// are required to be of the same type.
    Binary {
        left: Operand,
        right: Operand,
        operator: BinaryOperator,
    },
    /// One's complement of an integer.
    Not(Operand),
    /// Two's complement of an integer.
    Neg(Operand),
}

/// Represent a statement in a pseudo-code function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// Assignment of an expression to a left value.
    Assign {
        /// The place to assign the value to.
        place: Place,
        /// The value to assign to the left value.
        value: Expression,
    },
    /// Memory copy intrinsic.
    MemCopy {
        /// The source pointer of the memory copy.
        src: Operand,
        /// The destination pointer of the memory copy.
        dst: Operand,
        /// The length of the copy, in bytes.
        len: Operand,
    },
    /// A divergence in the basic block graph depending on a boolean condition.
    BranchConditional {
        /// The expression that produces a boolean value to take the correct branch.
        value: Expression,
        /// The index of the statement starting the basic block to take if the
        /// value of the expression resolves to true (!= 0).
        branch_true: usize,
        /// The index of the statement starting the basic block to take if the
        /// value of the expression resolves to false (== 0).
        branch_false: usize,
    },
    /// Unconditionally go to another statement that starts a new basic block.
    Branch {
        branch: usize,
    },
    /// Return the given local's value from the function.
    Return(LocalRef),
}

impl Statement {

    /// Return true if this statement is a branch to another basic block or return.
    pub const fn is_branch(&self) -> bool {
        matches!(self, Self::BranchConditional { .. } | Self::Branch { .. } | Self::Return(_))
    }

}

/// Kind of binary expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    /// Add two number, valid for integers, floats and vectors.
    Add,
    /// Subtract two number, valid for integers, floats and vectors.
    Sub,
    /// Multiply two number, valid for integers, floats and vectors.
    Mul,
    /// Divide two number, valid for integers, floats and vectors and get the quotient.
    Div,
    /// Divide two integers are get the remainder (signed).
    Rem,
    And,
    Or,
    Xor,
    ShiftLeft,
    ShiftRight,
}

/// Kind of comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOperator {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

/// An intermediate decompilation representation function. Basically a list of basic
/// blocks, each containing statements.
#[derive(Debug, Clone, Default)]
pub struct Function {
    /// List of local variables, parameters are also part of the these locals.
    pub locals: Vec<Local>,
    /// Sequence of statements, this sequence of statements ultimately forms a sequence
    /// of basic blocks. Basic blocks are a sequence of assignments that are not branch
    /// statements (branch(cond)/ret), each branch statements marks the end of a basic
    /// block, and the start of another one directly after it, basic blocks are referred
    /// to by the index of their first statement.
    pub statements: Vec<Statement>,
}

impl Function {

    /// Create a new local in this function.
    pub fn new_local(&mut self, type_system: &TypeSystem, ty: Type, comment: impl Into<String>) -> LocalRef {

        let index = u32::try_from(self.locals.len())
            .expect("out of locals");

        let mut local = Local { 
            ty, 
            layout: Layout::default(), 
            comment: comment.into(),
        };

        local.update_layout(type_system);

        self.locals.push(local);
        LocalRef(index)

    }

    /// Get the type associated to the given local variable.
    pub fn local_type(&self, local: LocalRef) -> Type {
        self.locals[local.0 as usize].ty
    }

    /// Get the type referenced by a memory place.
    pub fn place_type(&self, place: Place) -> Type {
        let ty = self.local_type(place.local);
        if place.index.is_some() {
            // If there is an index, the type is expected to be a pointer/integer.
            if ty.is_pointer() {
                ty.deref(1)
            } else {
                PrimitiveType::Void.plain()
            }
        } else {
            ty
        }
    }

    /// Get the memory layout associated to the given local variable's type.
    pub fn local_layout(&self, local: LocalRef) -> Layout {
        self.locals[local.0 as usize].layout
    }

    /// Modify the type of an existing local variable.
    pub fn set_local_type(&mut self, local: LocalRef, type_system: &TypeSystem, ty: Type) {
        let local = &mut self.locals[local.0 as usize];
        local.ty = ty;
        local.update_layout(type_system);
    }

    pub fn debug_function(&self, type_system: &TypeSystem) {
        print::write_function(std::io::stdout().lock(), self, &type_system).unwrap();
    }

}
