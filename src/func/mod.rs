//! Module related to function's analysis and decompilation.

use std::sync::Arc;
use std::fmt;

use crate::ty::{Type, DataType};

pub mod known;


/// Function symbol details, signature and return types.
#[derive(Debug, Clone)]
pub struct Function {
    /// An optional name for the symbol.
    pub name: Option<String>,
    /// The function's signature.
    pub signature: Signature,
    /// True if this function is exported.
    pub exported: bool,
    /// Some import information is this function symbol is imported.
    pub imported: Option<Import>,
    /// Body of the function, only if present in the code sections.
    pub body: Option<Body>,
}

impl Function {

    pub fn with_body_range(begin_ip: u64, end_ip: u64) -> Self {
        Self {
            name: None,
            signature: Signature::default(),
            exported: false,
            imported: None,
            body: Some(Body { 
                begin_ip, 
                end_ip,
            }),
        }
    }

    pub fn with_imported(library: Arc<[u8]>, kind: ImportSymbol) -> Self {
        Self {
            name: None,
            signature: Signature::default(),
            exported: false,
            imported: Some(Import { library, symbol: kind }),
            body: None,
        }
    }

}


/// Describes how a function is imported.
#[derive(Clone)]
pub struct Import {
    /// The library name, in bytes. Sometimes UTF-8 text.
    /// This data is shared because many imports might 
    /// come from the same library.
    pub library: Arc<[u8]>,
    /// The kind of import, by ordinal or name.
    pub symbol: ImportSymbol,
}

impl fmt::Debug for Import {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Import")
            .field("library", &AsciiFmt(&*self.library))
            .field("symbol", &self.symbol)
            .finish()
    }
}


/// Kind of import for a function.
#[derive(Clone)]
pub enum ImportSymbol {
    /// Import by name for the function.
    Name(Box<[u8]>),
    /// Import by ordinal for the function.
    Ordinal(u16),
}

impl fmt::Debug for ImportSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "{:?}", AsciiFmt(&**name)),
            Self::Ordinal(ord) => write!(f, "{ord}"),
        }
    }
}


/// Body of a function. Describing content of the function within
/// the code sections.
#[derive(Debug, Clone)]
pub struct Body {
    /// First basic block of the function.
    pub begin_ip: u64,
    /// End IP of the function (exclusive).
    pub end_ip: u64,
}


/// Signature of a function, its return type, parameters and
/// ABI for calling convention.
#[derive(Clone)]
pub struct Signature {
    /// Calling convention's ABI.
    pub abi: Abi,
    /// Return type.
    pub return_type: Type,
    /// All parameters in definition order, associating their
    /// name and type.
    pub parameters: Vec<(String, Type)>,
}

impl Default for Signature {
    fn default() -> Self {
        Self { 
            abi: Abi::default(), 
            return_type: DataType::Void.into(),
            parameters: Vec::new(),
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let abi_str = match self.abi {
            Abi::Unknown => "",
            Abi::Cdecl => "cedcl ",
            Abi::Stdcall => "stdcall ",
            Abi::Fastcall => "fastcall ",
            Abi::Win64 => "win64 ",
            Abi::Leaf => "leaf ",
        };

        write!(f, "{abi_str}fn(")?;
        for (i, (name, ty)) in self.parameters.iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{name}: {ty:?}")?;
        }
        write!(f, ") -> {:?}", self.return_type)

    }
}

impl Signature {

    pub fn set_parameters<I, S>(&mut self, it: I)
    where
        I: IntoIterator<Item = (S, Type)>,
        S: Into<String>,
    {
        self.parameters.clear();
        for (name, ty) in it {
            self.parameters.push((name.into(), ty));
        }
    }

}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    /// Unknown ABI.
    Unknown,
    /// Unix C x86.
    Cdecl,
    /// WINAPI.
    Stdcall,
    /// Windows x86.
    Fastcall,
    /// Windows x64.
    Win64,
    /// For leaf function calling convention, no 
    /// argument or framing.
    Leaf,
}

impl Default for Abi {
    fn default() -> Self {
        Self::Unknown
    }
}


/// Internally used structure for ascii printing of bytes arrays.
struct AsciiFmt<'a>(&'a [u8]);
impl<'a> fmt::Debug for AsciiFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in self.0 {
            write!(f, "{}", std::ascii::escape_default(b))?;
        }
        Ok(())
    }
}
