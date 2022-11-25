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

use std::fmt::{self, Write as _};

mod ty;
pub use ty::IdrType;


/// An analyzer that produces IDR statements.
pub trait IdrAnalyzer {

    /// Decode the next IDR instruction and place the result
    /// in the given statement.
    fn decode(&mut self, dst: &mut IdrStatement);

    /// Get the storage type of a place.
    fn place_type(&self, place: u32) -> &IdrType;

}

#[derive(Debug, Clone)]
pub enum IdrStatement {
    /// No statement has been created from this call.
    None,
    /// An error happened while producing IDR statement.
    Error,
    /// Inline assembly statement.
    Asm,
    /// Assignement of an expression's result to a place.
    Assign {
        /// The place index where the value will be assigned.
        place: u32,
        /// The expression that computes the value that will
        /// be assigned to the place.
        expr: IdrExpression,
    },
    /// Store a place's value in a destination place that is
    /// interpreted as a pointer.
    /// 
    /// TODO:
    /// 
    /// add [ecx], 2
    /// =>
    ///  a: i8      = <extern>
    ///  b: i8      = *a
    ///  c: i8      = b + 2
    /// *a          = c
    Store {
        /// The place containing the pointer to the cell where
        /// we want to store the value of the source place.
        ptr_place: u32,

        src_place: u32,
    }
}

#[derive(Debug, Clone)]
pub enum IdrExpression {
    /// Constant value.
    Constant(i64),
    /// Copy the value of another place.
    Copy(u32),
    /// Interpret the given place as an pointer-sized integer
    /// type and dereference it.
    Deref {
        offset: i64,
        base: u32,
    },
    DerefIndexed {
        offset: i32,
        base: u32,
        index: u32,
        scale: u8,
    }, 
    /// An absolute call to a function.
    Call {
        /// Address of the function to call.
        addr: u64,
        /// Places for each arguments passed to the function.
        args_places: Vec<u32>,
    },
    /// An indirect call to a function.
    CallIndirect {
        /// Place where the address of the function to call is located.
        addr_place: u32,
        /// Places for each arguments passed to the function.
        args_places: Vec<u32>,
    },
    Add(u32, u32),
    AddImm(u32, i64),
    Sub(u32, u32),
    SubImm(u32, i64),
    Mul(u32, u32),
    MulImm(u32, i64),
    Div(u32, u32),
    DivImm(u32, u32),
    And(u32, u32),
    AndImm(u32, i64),
    Or(u32, u32),
    OrImm(u32, i64),
    Xor(u32, u32),
    XorImm(u32, i64),
}

impl Default for IdrStatement {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for IdrStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::None => write!(f, "/*none*/"),
            Self::Error => write!(f, "/*error*/"),
            Self::Asm => write!(f, "/*asm(todo)*/"),
            Self::Assign { place, ref expr } => {
                write!(f, "{} = {expr}", PlaceFmt(place))
            }
            Self::Store { ptr_place, src_place } => {
                write!(f, "*{} = {}", PlaceFmt(ptr_place), PlaceFmt(src_place))
            }
        }
    }
}

impl fmt::Display for IdrExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IdrExpression::*;
        match *self {
            Constant(n) => write!(f, "{n}"),
            Copy(place) => write!(f, "{}", PlaceFmt(place)),
            Deref { offset, base } => {
                if offset == 0 {
                    write!(f, "*{}", PlaceFmt(base))
                } else {
                    write!(f, "*({}+0x{offset:X})", PlaceFmt(base))
                }
            }
            DerefIndexed { offset, base, index, scale } => {
                write!(f, "*({}+0x{offset:X}+{}*{scale})", PlaceFmt(base), PlaceFmt(index))
            }
            Call { addr, ref args_places } => {
                write!(f, "fn_{addr:X}(")?;
                for (i, &arg_place) in args_places.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", PlaceFmt(arg_place))?;
                }
                write!(f, ")")
            }
            CallIndirect { addr_place, ref args_places } => {
                write!(f, "({})(", PlaceFmt(addr_place))?;
                for (i, &arg_place) in args_places.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", PlaceFmt(arg_place))?;
                }
                write!(f, ")")
            }
            Add(p0, p1) => write!(f, "{} + {}", PlaceFmt(p0), PlaceFmt(p1)),
            AddImm(p0, n) => write!(f, "{} + {n}", PlaceFmt(p0)),
            Sub(p0, p1) => write!(f, "{} - {}", PlaceFmt(p0), PlaceFmt(p1)),
            SubImm(p0, n) => write!(f, "{} - {n}", PlaceFmt(p0)),
            Mul(p0, p1) => write!(f, "{} * {}", PlaceFmt(p0), PlaceFmt(p1)),
            MulImm(p0, n) => write!(f, "{} * {n}", PlaceFmt(p0)),
            Div(p0, p1) => write!(f, "{} / {}", PlaceFmt(p0), PlaceFmt(p1)),
            DivImm(p0, n) => write!(f, "{} / {n}", PlaceFmt(p0)),
            And(p0, p1) => write!(f, "{} & {}", PlaceFmt(p0), PlaceFmt(p1)),
            AndImm(p0, n) => write!(f, "{} & {n}", PlaceFmt(p0)),
            Or(p0, p1) => write!(f, "{} | {}", PlaceFmt(p0), PlaceFmt(p1)),
            OrImm(p0, n) => write!(f, "{} | {n}", PlaceFmt(p0)),
            Xor(p0, p1) => write!(f, "{} ^ {}", PlaceFmt(p0), PlaceFmt(p1)),
            XorImm(p0, n) => write!(f, "{} ^ {n}", PlaceFmt(p0)),
        }
    }
}

struct PlaceFmt(u32);
impl fmt::Display for PlaceFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rem = self.0;
        loop {
            let idx = rem % 26;
            f.write_char(char::from_u32('a' as u32 + idx).unwrap())?;
            rem = rem / 26;
            if rem == 0 {
                break;
            }
        }
        Ok(())
    }
}
