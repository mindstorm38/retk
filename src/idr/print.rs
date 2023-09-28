//! Utilities for pretty print/human readable of IDR functions.

use std::fmt::{self, Write as _};
use std::io;

use super::{LocalRef, Place, Index, Function, Operand, ComparisonOperator, BinaryOperator, Expression};
use crate::idr::Statement;
use crate::ty::{TypeSystem, Type, PrimitiveType};


/// Get string representation of a binary operator.
fn binary_operator_sym(op: BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Add => "+",
        BinaryOperator::Sub => "-",
        BinaryOperator::Mul => "*",
        BinaryOperator::Div => "/",
        BinaryOperator::And => "&",
        BinaryOperator::Or => "|",
        BinaryOperator::Xor => "^",
        BinaryOperator::ShiftLeft => "<<",
        BinaryOperator::ShiftRight => ">>",
    }
}

/// Get string representation of a binary operator for short assignment form.
fn binary_operator_short_sym(op: BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Add => "+=",
        BinaryOperator::Sub => "-=",
        BinaryOperator::Mul => "*=",
        BinaryOperator::Div => "/=",
        BinaryOperator::And => "&=",
        BinaryOperator::Or => "|=",
        BinaryOperator::Xor => "^=",
        BinaryOperator::ShiftLeft => "<<=",
        BinaryOperator::ShiftRight => ">>=",
    }
}
/// Get string representation of a comparison operator.
fn comparison_operator_sym(op: ComparisonOperator) -> &'static str {
    match op {
        ComparisonOperator::Equal => "==",
        ComparisonOperator::NotEqual => "!=",
        ComparisonOperator::Greater => ">",
        ComparisonOperator::GreaterOrEqual => ">=",
        ComparisonOperator::Less => "<",
        ComparisonOperator::LessOrEqual => "<=",
    }
}

/// Internal display support for local variable reference.
pub struct LocalRefDisplay(pub LocalRef);
impl fmt::Display for LocalRefDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const BASE: u32 = 26;
        let mut rem = self.0.0;
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
    }
}

/// Internal display support for memory places.
struct PlaceDisplay<'a> {
    inner: Place, 
    function: &'a Function,
    type_system: &'a TypeSystem,
}

impl fmt::Display for PlaceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        
        let local: LocalRef = self.inner.local;
        let local_type = self.function.local_type(local);
        let index = self.inner.index;

        if let Some(index) = index {

            let layout_size;
            if local_type.is_pointer() {
                layout_size = self.type_system.layout(local_type.deref(1)).unwrap().size as i32;
            } else {
                layout_size = self.type_system.byte_size() as i32;
            }
            
            match index {
                Index::Absolute(0) => {
                    write!(f, "*{}", LocalRefDisplay(local))
                }
                Index::Absolute(n) if n % layout_size == 0 => {
                    write!(f, "{}[{}]", LocalRefDisplay(local), n / layout_size)
                }
                Index::Absolute(n) => {
                    write!(f, "*({} + {n})", LocalRefDisplay(local))
                }
                Index::Variable { index, stride } if stride as i32 == layout_size => {
                    write!(f, "{}[{}]", LocalRefDisplay(local), LocalRefDisplay(index))
                }
                Index::Variable { index, stride: 1 } => {
                    write!(f, "*({} + {})", LocalRefDisplay(local), LocalRefDisplay(index))
                }
                Index::Variable { index, stride } => {
                    write!(f, "*({} + {} * {stride})", LocalRefDisplay(local), LocalRefDisplay(index))
                }
            }

        } else {
            write!(f, "{}", LocalRefDisplay(local))
        }

    }
}

/// Internal display support for operand.
struct OperandDisplay<'a> {
    inner: Operand,
    function: &'a Function,
    type_system: &'a TypeSystem,
}

impl fmt::Display for OperandDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner {
            Operand::Zero => f.write_str("0"),
            Operand::LiteralUnsigned(int @ 0..=9) => write!(f, "{int}"),
            Operand::LiteralUnsigned(int) => write!(f, "0x{int:X}"),
            Operand::LiteralSigned(int) => write!(f, "{int}"),
            Operand::Place(inner) => write!(f, "{}", PlaceDisplay { 
                inner, 
                function: self.function,
                type_system: self.type_system,
            }),
        }
    }
}

/// Internal display support for expression.
struct ExpressionDisplay<'a> {
    inner: &'a Expression,
    ty: Type,
    function: &'a Function,
    type_system: &'a TypeSystem,
}

impl fmt::Display for ExpressionDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self.inner {
            Expression::Copy(inner) => write!(f, "{}", OperandDisplay {
                inner,
                function: self.function,
                type_system: self.type_system,
            }),
            Expression::Ref(inner) => write!(f, "&{}", PlaceDisplay {
                inner,
                function: self.function,
                type_system: self.type_system,
            }),
            Expression::Cast(inner) => write!(f, "{} as {}", PlaceDisplay {
                inner,
                function: self.function,
                type_system: self.type_system,
            }, self.type_system.name(self.ty)),
            Expression::Call { pointer, ref arguments } => {
                match pointer {
                    Operand::Zero => unimplemented!(),
                    Operand::LiteralUnsigned(int) => write!(f, "fn_{int:08X}")?,
                    Operand::LiteralSigned(int) => write!(f, "fn_{int:08X}")?,
                    Operand::Place(inner) => write!(f, "({})", PlaceDisplay {
                        inner,
                        function: self.function,
                        type_system: self.type_system,
                    })?,
                }
                write!(f, "(args: {})", arguments.len())
            }
            Expression::Comparison { 
                left, 
                right,
                operator, 
            } => {
                write!(f, "{} {} {}", 
                    OperandDisplay { inner: left, function: self.function, type_system: self.type_system },
                    comparison_operator_sym(operator),
                    OperandDisplay { inner: right, function: self.function, type_system: self.type_system })
            }
            Expression::Binary {
                left, 
                right, 
                operator
            } => {
                write!(f, "{} {} {}", 
                    OperandDisplay { inner: left, function: self.function, type_system: self.type_system },
                    binary_operator_sym(operator),
                    OperandDisplay { inner: right, function: self.function, type_system: self.type_system })
            }
            Expression::Not(inner) => write!(f, "!{}", OperandDisplay { 
                inner, 
                function: &self.function, 
                type_system: &self.type_system,
            }),
            Expression::Neg(inner) => write!(f, "-{}", OperandDisplay { 
                inner, 
                function: &self.function, 
                type_system: &self.type_system,
            }),
        }
    }
}


pub fn write_function(mut f: impl io::Write, function: &Function, type_system: &TypeSystem) -> io::Result<()> {

    writeln!(f, "---------------------")?;

    for (i, local) in function.locals.iter().enumerate() {
        writeln!(f, "{:12} // {}",
            format!("{} {}", type_system.name(local.ty), LocalRefDisplay(LocalRef(i as _))),
            local.comment)?;
    }

    const TY_BOOL: Type = PrimitiveType::UnsignedInt(1).plain();

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
                value: Expression::Binary {
                    left: Operand::Place(left),
                    right,
                    operator,
                },
            } if place == left => {
                writeln!(f, "{} {} {}", 
                    PlaceDisplay { inner: left, function, type_system },
                    binary_operator_short_sym(operator),
                    OperandDisplay { inner: right, function, type_system })?;
            }
            Statement::Assign { 
                place, 
                ref value
            } => {
                let ty = function.place_type(place);
                writeln!(f, "{} = {}",
                    PlaceDisplay { inner: place, function, type_system },
                    ExpressionDisplay { inner: value, ty, function, type_system })?;
            }
            Statement::MemCopy { src, dst, len } => {
                writeln!(f, "memcpy {} -> {} ({})",
                    OperandDisplay { inner: src, function, type_system },
                    OperandDisplay { inner: dst, function, type_system },
                    OperandDisplay { inner: len, function, type_system })?;
            }
            Statement::BranchConditional { 
                ref value,
                branch_true,
                branch_false
            } => {
                basic_block_start = true;
                writeln!(f, "branch {} ? {branch_true:03} : {branch_false:03}", 
                    ExpressionDisplay { inner: value, ty: TY_BOOL, function, type_system })?;
            }
            Statement::Branch { 
                branch
            } => {
                basic_block_start = true;
                writeln!(f, "branch {branch:03}")?;
            }
            Statement::Return(local) => {
                basic_block_start = true;
                writeln!(f, "return {}", LocalRefDisplay(local))?;
            }
        }
        
    }

    writeln!(f, "---------------------")?;
    
    Ok(())

}
