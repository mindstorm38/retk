//! Module for representing a reverse-engineered pseudo-code.

use std::fmt::{self, Write as _};
use std::io;

use crate::idr::types::{Type, Layout, TypeSystem};


#[derive(Debug, Clone, Default)]
pub struct Function {
    /// List of local variables, parameters are also part of the these locals.
    pub locals: Vec<Local>,
    /// Parameters as reference to local variables.
    pub parameters: Vec<LocalRef>,
    /// Sequence of statements.
    pub statements: Vec<Statement>,
}

/// Represent a local variable.
#[derive(Debug, Clone)]
pub struct Local {
    /// Type of the local variable.
    pub ty: Type,
    /// Layout of the local variable's type.
    pub layout: Layout,
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
    /// A conditional code.
    If {
        /// The expression that returns an integer, true if different from zero.
        cond: Expression,
        /// Index of the first statement to execute if condition is true.
        then_index: usize,
        /// Index of the first statement to execute if the condition is false. This is
        /// also the end of the *then* section.
        else_index: usize, 
        /// Exclusive index of the last statement of the *else* section.
        end_index: usize,
    },
    /// Goto a specific statement's index.
    Goto(usize),
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
    local: LocalRef,
    /// The optional indirection of this assignment.
    indirection: u32,
}

/// Represent an operand in an expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// A literal 64-bit integer.
    LiteralInt(u64),
    /// The value of the operand come from the local.
    Local(LocalRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// Bitwise copy of the operand's value.
    Copy(Operand),
    /// Load the value pointed by a pointer local.
    Deref {
        /// Index of the local that should be a pointer.
        pointer: Operand,
        /// Level of indirection of the dereference.
        indirection: u32,
    },
    /// Get a pointer to a local variable.
    Ref(LocalRef),
    /// Cast a source local of a given type to another destination type.
    Cast(LocalRef),
    Call {
        /// The function pointer, either static or dynamic from a place.
        pointer: Operand,
        /// List of arguments to pass to the function.
        arguments: Vec<Operand>,
    },
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
}

/// Base type for binary expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    pub const fn new_indirect(local: LocalRef, indirection: u32) -> Self {
        Self { local, indirection }
    }

}

impl Local {

    /// Update the cached layout of a local variable.
    pub fn update_layout(&mut self, type_system: &TypeSystem) {
        self.layout = type_system.layout(self.ty).expect("type has no layout")
    }

}

impl Function {

    /// Create a new local in this function.
    pub fn new_local(&mut self, type_system: &TypeSystem, ty: Type) -> LocalRef {

        let index = u32::try_from(self.locals.len())
            .expect("out of locals");

        let mut local = Local { ty, layout: Layout::default() };
        local.update_layout(type_system);

        self.locals.push(local);
        LocalRef(index)

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
            Operand::LiteralInt(int @ 0..=9) => write!(f, "{int}"),
            Operand::LiteralInt(int) => write!(f, "0x{int:X}"),
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
                    Operand::LiteralInt(int) => write!(f, "fn_{int:08X}")?,
                    Operand::Local(local) => write!(f, "({local})")?,
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
        }

    }
}


pub fn write_function(mut f: impl io::Write, function: &Function, type_system: &TypeSystem) -> io::Result<()> {

    writeln!(f, "---------")?;

    for (i, local) in function.locals.iter().enumerate() {
        writeln!(f, "{} {}", type_system.name(local.ty), LocalRef(i as _))?;
    }

    writeln!(f, "---------")?;

    #[derive(Clone, Copy)]
    enum PrintKind {
        Else,
        CloseBlock,
    }

    let mut next_prints = Vec::new();
    let mut indent = String::new();

    for (i, stmt) in function.statements.iter().enumerate() {

        if let Some(&(next_print_i, next_print_kind)) = next_prints.last() {
            if next_print_i == i {

                next_prints.pop().unwrap();
                if let PrintKind::CloseBlock = next_print_kind {
                    indent.truncate(indent.len() - 2);
                }

                write!(f, "    | {indent}")?;
                match next_print_kind {
                    PrintKind::Else => writeln!(f, "}} else {{")?,
                    PrintKind::CloseBlock => writeln!(f, "}}")?,
                }

            }
        }

        write!(f, "{i:03} | {indent}")?;

        match *stmt {
            Statement::Assign { 
                place, 
                ref value
            } => writeln!(f, "{place} = {value}")?,
            Statement::If {
                ref cond, 
                then_index: _, 
                else_index, 
                end_index
            } => {

                writeln!(f, "if ({cond}) {{")?;

                indent.push_str("  ");

                if end_index > i {
                    next_prints.push((end_index, PrintKind::CloseBlock));
                }
                
                // If there is an else branch.
                if else_index > i && else_index < end_index {
                    next_prints.push((else_index, PrintKind::Else));
                }

            }
            Statement::Goto(index) => writeln!(f, "goto {index:03}")?,
            Statement::Return(local) => writeln!(f, "return {local}")?,
        }
        
    }

    writeln!(f, "---------")?;
    
    Ok(())

}
