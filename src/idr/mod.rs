//! Intermediate Decompilation Representation.

use std::fmt::{self, Write as _};
use std::io;

use crate::ty::{Type, Layout, TypeSystem, PrimitiveType};


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

/// Represent a statement in a pseudo-code function.
#[derive(Debug, Clone)]
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

/// Reference to a local variable, used in left values and expressions to reference 
/// the variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalRef(u32);

/// Represent a place where a value can be stored, 
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// The local variable that contains either the local to assign or a pointer if
    /// indirection is used.
    pub local: LocalRef,
    /// The optional indirection of this assignment.
    pub indirection: u8,
}

/// Represent an operand in an expression.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operand {
    /// A literal unsigned 64-bit integer.
    LiteralUnsigned(u64),
    /// A literal signed 64-bit integer.
    LiteralSigned(i64),
    /// A literal floating point number.
    LiteralFloat(f64),
    /// The value of the operand come from the local.
    Local(LocalRef),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// Bitwise copy of the operand's value.
    Copy(Operand),
    /// Load the value pointed by a pointer local.
    Deref {
        /// Index of the local that should be a pointer.
        pointer: Operand,
        /// Level of indirection of the dereference.
        indirection: u8,
    },
    /// Get a pointer to a local variable.
    Ref(LocalRef),
    /// Cast a source local of a given type to another to the destination type of
    /// assigned local variable.
    Cast(LocalRef),
    /// Call a function from a pointer and an argument list.
    Call {
        /// The function pointer, either static or dynamic from a place.
        pointer: Operand,
        /// List of arguments to pass to the function.
        arguments: Vec<Operand>,
    },
    /// Perform a binary comparison that produces a boolean value (theoretically 1-bit).
    Comparison {
        left: Operand,
        operator: ComparisonOperator,
        right: Operand,
    },
    Add(BinaryExpression),
    Sub(BinaryExpression),
    Mul(BinaryExpression),
    Div(BinaryExpression),
    And(BinaryExpression),
    Or(BinaryExpression),
    Xor(BinaryExpression),
    ShiftLeft(BinaryExpression),
    ShiftRight(BinaryExpression),
}

/// Base type for binary expressions.
#[derive(Debug, Clone, PartialEq)]
pub struct BinaryExpression {
    /// Left local on the binary expression.
    pub left: Operand,
    /// Right local of the binary expression.
    pub right: Operand,
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

impl Place {

    pub const fn new_direct(local: LocalRef) -> Self {
        Self { local, indirection: 0 }
    }

    pub const fn new_indirect(local: LocalRef, indirection: u8) -> Self {
        Self { local, indirection }
    }

}

impl Local {

    /// Update the cached layout of a local variable.
    pub fn update_layout(&mut self, type_system: &TypeSystem) {
        self.layout = type_system.layout(self.ty).expect("type has no layout")
    }

}

impl Statement {

    /// Return true if this statement is a branch to another basic block or return.
    pub const fn is_branch(&self) -> bool {
        matches!(self, Self::BranchConditional { .. } | Self::Branch { .. } | Self::Return(_))
    }

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

    pub fn place_type(&self, place: Place) -> Type {
        let ty = self.local_type(place.local);
        if ty.indirection >= place.indirection {
            ty.deref(place.indirection)
        } else {
            PrimitiveType::Void.plain()
        }
    }

    pub fn local_type(&self, local: LocalRef) -> Type {
        self.locals[local.0 as usize].ty
    }

    pub fn local_layout(&self, local: LocalRef) -> Layout {
        self.locals[local.0 as usize].layout
    }

    pub fn set_local_type(&mut self, local: LocalRef, type_system: &TypeSystem, ty: Type) {
        let local = &mut self.locals[local.0 as usize];
        local.ty = ty;
        local.update_layout(type_system);
    }

}


impl fmt::Display for LocalRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const BASE: u32 = 26;
        let mut rem = self.0;
        loop {
            let idx = rem % BASE;
            f.write_char(char::from_u32('a' as u32 + idx).unwrap())?;
            rem = rem / BASE;
            if rem == 0 {
                break;
            } else {
                rem -= 1;
            }
        }
        Ok(())
        // write!(f, "_{}", self.0)
    }
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..self.indirection {
            f.write_char('*')?;
        }
        write!(f, "{}", self.local)
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Operand::LiteralUnsigned(int @ 0..=9) => write!(f, "{int}"),
            Operand::LiteralUnsigned(int) => write!(f, "0x{int:X}"),
            Operand::LiteralSigned(int) => write!(f, "{int}"),
            Operand::LiteralFloat(num) => write!(f, "{num}"),
            Operand::Local(local) => write!(f, "{local}"),
        }
    }
}

impl fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            ComparisonOperator::Equal => "==",
            ComparisonOperator::NotEqual => "!=",
            ComparisonOperator::Greater => ">",
            ComparisonOperator::GreaterOrEqual => ">=",
            ComparisonOperator::Less => "<",
            ComparisonOperator::LessOrEqual => "<=",
        })
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        fn write_binary(
            f: &mut fmt::Formatter<'_>, 
            expr: &BinaryExpression, 
            op: &'static str
        ) -> fmt::Result {
            write!(f, "{} {op} {}", expr.left, expr.right)
        }

        match *self {
            Expression::Copy(op) => write!(f, "{op}"),
            Expression::Deref { pointer, indirection } => {
                for _ in 0..indirection {
                    f.write_char('*')?;
                }
                write!(f, "{pointer}")
            }
            Expression::Ref(local) => write!(f, "&{local}"),
            Expression::Cast(local) => write!(f, "{local} as _"),
            Expression::Call { pointer, ref arguments } => {
                match pointer {
                    Operand::LiteralUnsigned(int) => write!(f, "fn_{int:08X}")?,
                    Operand::LiteralSigned(int) => write!(f, "fn_{int:08X}")?,
                    Operand::Local(local) => write!(f, "({local})")?,
                    Operand::LiteralFloat(_) => unimplemented!(),
                }
                write!(f, "(args: {})", arguments.len())
            }
            Expression::Comparison { 
                left, 
                operator, 
                right
            } => {
                write!(f, "{left} {operator} {right}")
            }
            Expression::Add(ref b) => write_binary(f, b, "+"),
            Expression::Sub(ref b) => write_binary(f, b, "-"),
            Expression::Mul(ref b) => write_binary(f, b, "*"),
            Expression::Div(ref b) => write_binary(f, b, "/"),
            Expression::And(ref b) => write_binary(f, b, "&"),
            Expression::Or(ref b) => write_binary(f, b, "|"),
            Expression::Xor(ref b) => write_binary(f, b, "^"),
            Expression::ShiftLeft(ref b) => write_binary(f, b, "<<"),
            Expression::ShiftRight(ref b) => write_binary(f, b, ">>"),
        }

    }
}

/// An expression with additional context of the type that it should produce, it's used
/// as debug purpose and provides a display implementation for expressions.
pub struct ContextualExpression<'e, 't> {
    pub inner: &'e Expression,
    pub type_system: &'t TypeSystem,
    pub ty: Type,
}

impl fmt::Display for ContextualExpression<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        if let Expression::Cast(local) = *self.inner {
            write!(f, "{local} as {}", self.type_system.name(self.ty))
        } else {
            self.inner.fmt(f)
        }

    }
}


pub fn write_function(mut f: impl io::Write, function: &Function, type_system: &TypeSystem) -> io::Result<()> {

    writeln!(f, "---------------------")?;

    for (i, local) in function.locals.iter().enumerate() {
        writeln!(f, "{} {}   \t// {}", type_system.name(local.ty), LocalRef(i as _), local.comment)?;
    }

    const TY_BOOL: Type = PrimitiveType::Unsigned(1).plain();

    // Indicate if the next statement is the first of a new basic block.
    let mut basic_block_start = true;

    for (i, stmt) in function.statements.iter().enumerate() {

        if basic_block_start {
            writeln!(f, "----+----------------")?;
            basic_block_start = false;
        }

        write!(f, "{i:03} | ")?;

        match *stmt {
            Statement::Assign { 
                place, 
                ref value
            } => {

                // Shorthand binary expression, like +=
                if place.indirection == 0 {

                    let right = match value {
                        Expression::Add(b) | 
                        Expression::Sub(b) |
                        Expression::Mul(b) |
                        Expression::Div(b) |
                        Expression::And(b) |
                        Expression::Or(b) |
                        Expression::Xor(b)
                        if b.left == Operand::Local(place.local) => Some(b.right),
                        _ => None,
                    };

                    if let Some(right) = right {

                        let op = match value {
                            Expression::Add(_) => "+=",
                            Expression::Sub(_) => "-=",
                            Expression::Mul(_) => "*=",
                            Expression::Div(_) => "/=",
                            Expression::And(_) => "&=",
                            Expression::Or(_) => "|=",
                            Expression::Xor(_) => "^=",
                            _ => unreachable!()
                        };

                        writeln!(f, "{place} {op} {right}")?;
                        continue;

                    }

                }

                let ty = function.place_type(place);
                writeln!(f, "{place} = {}", ContextualExpression { inner: value, type_system, ty })?;

            }
            Statement::MemCopy { src, dst, len } => {
                writeln!(f, "memcpy {src} -> {dst} ({len})")?;
            }
            Statement::BranchConditional { 
                ref value,
                branch_true,
                branch_false
            } => {
                basic_block_start = true;
                writeln!(f, "branch {} ? {branch_true:03} : {branch_false:03}", 
                    ContextualExpression { inner: value, type_system, ty: TY_BOOL })?;
            }
            Statement::Branch { 
                branch
            } => {
                basic_block_start = true;
                writeln!(f, "branch {branch:03}")?;
            }
            Statement::Return(local) => {
                basic_block_start = true;
                writeln!(f, "return {local}")?;
            }
        }
        
    }

    writeln!(f, "---------------------")?;
    
    Ok(())

}
