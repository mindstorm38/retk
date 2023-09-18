use std::fmt;

use super::{Statement, Expression, Value, Place, Comparison};
use super::types::TypeSystem;


struct PlaceDisplay(Place);
impl fmt::Display for PlaceDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0.0)

        // const BASE: u32 = 26;
        // let mut rem = self.0.0.get() - 1;
        // f.write_char('%')?;
        // loop {
        //     let idx = rem % BASE;
        //     f.write_char(char::from_u32('a' as u32 + idx).unwrap())?;
        //     rem = rem / BASE;
        //     if rem == 0 {
        //         break;
        //     } else {
        //         rem -= 1;
        //     }
        // }
        // Ok(())
    }
}


struct ValueDisplay(Value);
impl fmt::Display for ValueDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Value::Place(var) => write!(f, "{}", PlaceDisplay(var)),
            Value::LiteralInt(val) => write!(f, "0x{val:X}"),
        }
    }
}


struct ExpressionDisplay<'a>(&'a Expression);
impl fmt::Display for ExpressionDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self.0 {
            Expression::Value(value) => write!(f, "{}", ValueDisplay(value)),
            Expression::Load(var) => write!(f, "load {}", PlaceDisplay(var)),
            Expression::Stack(size) => write!(f, "stack {size}"),
            Expression::Call { pointer, ref arguments } => {
                write!(f, "call {}", ValueDisplay(pointer))?;
                for &arg in arguments {
                    write!(f, ", {}", ValueDisplay(arg))?;
                }
                Ok(())
            }
            Expression::GetElementPointer { pointer, index, stride } => {
                write!(f, "gep {}, {} * {stride}", PlaceDisplay(pointer), PlaceDisplay(index))
            }
            Expression::Cmp(cmp, left, right) => {
                write!(f, "cmp {}, {}, {}", match cmp {
                    Comparison::Equal => "eq",
                    Comparison::NotEqual => "neq",
                }, ValueDisplay(left), ValueDisplay(right))
            }
            Expression::Add(left, right) => write!(f, "add {}, {}", ValueDisplay(left), ValueDisplay(right)),
            Expression::Sub(left, right) => write!(f, "sub {}, {}", ValueDisplay(left), ValueDisplay(right)),
            Expression::Mul(left, right) => write!(f, "mul {}, {}", ValueDisplay(left), ValueDisplay(right)),
            Expression::Div(left, right) => write!(f, "div {}, {}", ValueDisplay(left), ValueDisplay(right)),
            Expression::Xor(left, right) => write!(f, "xor {}, {}", ValueDisplay(left), ValueDisplay(right)),
        }
    }
}


pub struct StatementsDisplay<'a, 'b> {
    pub statements: &'a [Statement],
    pub type_system: &'b TypeSystem,
}

impl fmt::Display for StatementsDisplay<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for stmt in self.statements {
            match stmt {
                Statement::Store(store) => {
                    let ptr = PlaceDisplay(store.pointer).to_string();
                    writeln!(f, " *{ptr:>3}           = {}", ExpressionDisplay(&store.value))?;
                }
                Statement::Bind(bind) => {
                    let var = PlaceDisplay(bind.place).to_string();
                    let ty = self.type_system.name(bind.ty);
                    writeln!(f, "  {var:>3}: {ty:8} = {}", ExpressionDisplay(&bind.value))?;
                }
                Statement::Asm(asm) => {
                    writeln!(f, "                  asm '{asm}'")?;
                }
            }
        }
        Ok(())
    }
}
