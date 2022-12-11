use crate::idr::Branch;

use super::{IdrFunction, Statement, Expression, Value, IdrVar, Comparison};
use std::fmt::{self, Write};


struct VarDisplay(IdrVar);
impl fmt::Display for VarDisplay {
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


struct ValDisplay(Value);
impl fmt::Display for ValDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Value::Var(var) => write!(f, "{}", VarDisplay(var)),
            Value::Val(val) => write!(f, "{val}"),
        }
    }
}


struct ExprDisplay<'a>(&'a Expression);
impl<'a> fmt::Display for ExprDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Expression::Constant(val) => write!(f, "{val}"),
            Expression::Load(var) => write!(f, "load {}", VarDisplay(*var)),
            Expression::Alloca(size) => write!(f, "alloca {size}"),
            Expression::Call { pointer, arguments } => {
                write!(f, "call {}", ValDisplay(*pointer))?;
                for arg in arguments {
                    write!(f, ", {}", ValDisplay(*arg))?;
                }
                Ok(())
            }
            Expression::GetElementPointer { pointer, index, stride } => {
                write!(f, "gep {}, {} * {stride}", VarDisplay(*pointer), VarDisplay(*index))
            }
            Expression::Cmp(cmp, var, val) => {
                write!(f, "cmp ")?;
                match cmp {
                    Comparison::Equal => write!(f, "eq")?,
                    Comparison::NotEqual => write!(f, "neq")?,
                }
                write!(f, ", {}, {}", VarDisplay(*var), ValDisplay(*val))
            }
            Expression::Add(var, val) => write!(f, "add {}, {}", VarDisplay(*var), ValDisplay(*val)),
            Expression::Sub(var, val) => write!(f, "sub {}, {}", VarDisplay(*var), ValDisplay(*val)),
            Expression::Mul(var, val) => write!(f, "mul {}, {}", VarDisplay(*var), ValDisplay(*val)),
            Expression::Div(var, val) => write!(f, "div {}, {}", VarDisplay(*var), ValDisplay(*val)),
            Expression::Xor(var, val) => write!(f, "xor {}, {}", VarDisplay(*var), ValDisplay(*val)),
        }
    }
}


pub fn print_function(func: &IdrFunction) {

    for (bb_index, bb) in func.basic_blocks.iter().enumerate() {

        print!("bb{bb_index}(");
        for (i, (var, ty)) in bb.parameters.iter().enumerate() {
            if i != 0 {
                print!(", ");
            }
            print!("{}: {ty:?}", VarDisplay(*var));
        }
        println!(")");

        for stmt in &bb.statements {
            match stmt {
                Statement::Store(store) => {
                    let ptr = VarDisplay(store.ptr).to_string();
                    println!(" *{ptr:>3}           = {}", VarDisplay(store.var));
                }
                Statement::Assign(assign) => {
                    let var = VarDisplay(assign.var).to_string();
                    let ty = format!("{:?}", assign.ty);
                    println!("  {var:>3}: {ty:8} = {}", ExprDisplay(&assign.val));
                }
                Statement::Asm(asm) => {
                    println!("                  asm '{asm}'");
                }
            }
        }
        
        match bb.branch {
            Branch::Unknown => {
                println!("                  br ???");
            }
            Branch::Unconditionnal { index, ref args } => {
                println!("                  br bb{index}");
            }
            Branch::Conditionnal { 
                var, 
                then_index, ref then_args, 
                else_index, ref else_args 
            } => {
                println!("                  br {}, then bb{then_index}, else bb{else_index}", VarDisplay(var));
            }
            Branch::Ret => {
                println!("                  ret");
            }
        }

    }

}
