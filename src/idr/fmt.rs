//! Formatting for IDR types.


use std::fmt::{self, Write as _};

use super::{IdrVar, IdrStatement, IdrExpression, IdrCondition};


impl fmt::Display for IdrVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const BASE: u32 = 26;
        let mut rem = self.0.get() - 1;
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

impl fmt::Display for IdrStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Error => write!(f, "/*error*/"),
            Self::Asm => write!(f, "/*asm(todo)*/"),
            Self::Assign { var, ref ty, ref expr } => {
                write!(f, "{var}: {ty:?} = {expr}")
            }
            Self::Store { pointer, var } => {
                write!(f, "*{pointer} = {var}")
            }
            Self::Branch { pointer, left_var, right_var, cond } => {
                let op = match cond {
                    IdrCondition::Equal => "==",
                    IdrCondition::NotEqual => "!=",
                    IdrCondition::UnsignedLower => "<",
                    IdrCondition::UnsignedLowerOrEqual => "<=",
                    IdrCondition::UnsignedGreater => ">",
                    IdrCondition::UnsignedGreaterOrEqual => ">=",
                    IdrCondition::SignedLower => "<",
                    IdrCondition::SignedLowerOrEqual => "<=",
                    IdrCondition::SignedGreater => ">",
                    IdrCondition::SignedGeaterOrEqual => ">=",
                    
                };
                write!(f, "if {left_var} {op} {right_var} => 0x{pointer:X}")
            }
        }
    }
}

impl fmt::Display for IdrExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IdrExpression::*;
        match *self {
            Extern => write!(f, "<extern>"),
            Constant(n) => write!(f, "{n}"),
            Copy(place) => write!(f, "{place}"),
            Alloca(n) => {
                write!(f, "alloca {n}")
            }
            Deref { offset, base } => {
                if offset == 0 {
                    write!(f, "*{base}")
                } else {
                    write!(f, "*({base}+0x{offset:X})")
                }
            }
            DerefIndexed { offset, base, index, scale } => {
                write!(f, "*({base}+0x{offset:X}+{index}*{scale})")
            }
            Call { pointer, ref args } => {
                write!(f, "fn_{pointer:X}(")?;
                for (i, &arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            CallIndirect { pointer, ref args } => {
                write!(f, "({pointer})(")?;
                for (i, &arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            Add(p0, p1) => write!(f, "{p0} + {p1}"),
            AddImm(p0, n) => write!(f, "{p0} + {n}"),
            Sub(p0, p1) => write!(f, "{p0} - {p1}"),
            SubImm(p0, n) => write!(f, "{p0} - {n}"),
            Mul(p0, p1) => write!(f, "{p0} * {p1}"),
            MulImm(p0, n) => write!(f, "{p0} * {n}"),
            Div(p0, p1) => write!(f, "{p0} / {p1}"),
            DivImm(p0, n) => write!(f, "{p0} / {n}"),
            And(p0, p1) => write!(f, "{p0} & {p1}"),
            AndImm(p0, n) => write!(f, "{p0} & {n}"),
            Or(p0, p1) => write!(f, "{p0} | {p1}"),
            OrImm(p0, n) => write!(f, "{p0} | {n}"),
            Xor(p0, p1) => write!(f, "{p0} ^ {p1}"),
            XorImm(p0, n) => write!(f, "{p0} ^ {n}"),
        }
    }
}
