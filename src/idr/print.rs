use std::fmt::{self, Write};

use super::{Function, Statement, Expression, Value, Name, Comparison};
use crate::idr::Branch;


struct NameDisplay(Name);
impl fmt::Display for NameDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const BASE: u32 = 26;
        let mut rem = self.0.0.get() - 1;
        f.write_char('%')?;
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


struct ValueDisplay(Value);
impl fmt::Display for ValueDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Value::Register(var) => write!(f, "{}", NameDisplay(var)),
            Value::LiteralInt(val) => write!(f, "{val}"),
        }
    }
}


struct ExpressionDisplay<'a>(&'a Expression);
impl<'a> fmt::Display for ExpressionDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Expression::LiteralInt(val) => write!(f, "{val}"),
            Expression::Load(var) => write!(f, "load {}", NameDisplay(*var)),
            Expression::Stack(size) => write!(f, "stack {size}"),
            Expression::Call { pointer, arguments } => {
                write!(f, "call {}", ValueDisplay(*pointer))?;
                for arg in arguments {
                    write!(f, ", {}", ValueDisplay(*arg))?;
                }
                Ok(())
            }
            Expression::GetElementPointer { pointer, index, stride } => {
                write!(f, "gep {}, {} * {stride}", NameDisplay(*pointer), NameDisplay(*index))
            }
            Expression::Cmp(cmp, var, val) => {
                write!(f, "cmp ")?;
                match cmp {
                    Comparison::Equal => write!(f, "eq")?,
                    Comparison::NotEqual => write!(f, "neq")?,
                }
                write!(f, ", {}, {}", ValueDisplay(*var), ValueDisplay(*val))
            }
            Expression::Add(var, val) => write!(f, "add {}, {}", ValueDisplay(*var), ValueDisplay(*val)),
            Expression::Sub(var, val) => write!(f, "sub {}, {}", ValueDisplay(*var), ValueDisplay(*val)),
            Expression::Mul(var, val) => write!(f, "mul {}, {}", ValueDisplay(*var), ValueDisplay(*val)),
            Expression::Div(var, val) => write!(f, "div {}, {}", ValueDisplay(*var), ValueDisplay(*val)),
            Expression::Xor(var, val) => write!(f, "xor {}, {}", ValueDisplay(*var), ValueDisplay(*val)),
        }
    }
}


pub fn print_function(func: &Function) {

    // for (bb_index, bb) in func.basic_blocks.iter().enumerate() {

    //     print!("bb{bb_index}(");
    //     for (i, (var, ty)) in bb.parameters.iter().enumerate() {
    //         if i != 0 {
    //             print!(", ");
    //         }
    //         print!("{}: {ty:?}", NameDisplay(*var));
    //     }
    //     println!(")");

    //     for stmt in &bb.statements {
    //         match stmt {
    //             Statement::Store(store) => {
    //                 let ptr = NameDisplay(store.pointer_register).to_string();
    //                 println!(" *{ptr:>3}           = {}", NameDisplay(store.register));
    //             }
    //             Statement::Create(assign) => {
    //                 let var = NameDisplay(assign.register).to_string();
    //                 let ty = format!("{:?}", assign.ty);
    //                 println!("  {var:>3}: {ty:8} = {}", ExpressionDisplay(&assign.value));
    //             }
    //             Statement::Asm(asm) => {
    //                 println!("                  asm '{asm}'");
    //             }
    //         }
    //     }
        
    //     match bb.branch {
    //         Branch::Unknown => {
    //             println!("                  br ???");
    //         }
    //         Branch::Unconditional { index, ref args } => {
    //             println!("                  br bb{index}");
    //         }
    //         Branch::Conditional { 
    //             var, 
    //             then_index, ref then_args, 
    //             else_index, ref else_args 
    //         } => {
    //             println!("                  br {}, then bb{then_index}, else bb{else_index}", NameDisplay(var));
    //         }
    //         Branch::Ret => {
    //             println!("                  ret");
    //         }
    //     }

    // }

}
