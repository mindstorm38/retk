//! Data type system for Intermediate Decompilation Representation.

use std::fmt;


/// Represent a hierarchy for a data type, this enum is later
/// frozen in the [`DataType`] structure that will cache its 
/// final size and alignment (without reordering of structures).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdrType {
    /// An integer type of a specified byte *(usually an octet)* 
    /// size and alignment.
    Integer(u16, u16),
    /// A floating point type of a specified byte *(usually an octet)* 
    /// size and alignment.
    Float(u16, u16),
    /// An array type, of a specified length. Alignment of this structure
    /// is the same as the one of its components.
    Array(Box<IdrType>, u32),
    /// A structure type, composed of many other types and an alignment.
    /// **Note** that no padding is added when computing the total length. 
    /// 
    /// *Note that [`Type::struct_aligned`] can be used to create an
    /// automatically aligned structure.*
    Struct(Vec<(String, IdrType)>, u32),
    /// A pointer to a specific type and of a specific size.
    /// The pointer's alignment is equal to its size.
    Pointer(Box<IdrType>, u16),
}

impl IdrType {

    pub const VOID: Self = Self::integer_aligned(0);

    /// A single-byte type. Usually an octet on modern architures.
    pub const BYTE: Self = Self::integer_aligned(1);

    /// A double-byte type (2 bytes).
    pub const WORD: Self = Self::integer_aligned(2);

    /// A double-word type (4 bytes).
    pub const DWORD: Self = Self::integer_aligned(4);

    /// A quad-word type (8 bytes).
    pub const QWORD: Self = Self::integer_aligned(8);

    /// A single-precision floating point type (4 bytes).
    pub const FLOAT: Self = Self::Float(4, 4);

    /// A double-precision floating point type (8 bytes).
    pub const DOUBLE: Self = Self::Float(8, 8);

    /// Build an aligned structure type.
    pub fn struct_aligned(fields: impl IntoIterator<Item = (String, IdrType)>) -> Self {
        
        let mut tys = Vec::new();
        let mut struct_size = 0;
        let mut struct_align = 0;
        let mut pad_count = 0;

        for (name, ty) in fields {
            let ty_align = ty.alignment();
            let modulus = struct_size % struct_align;
            if modulus != 0 {
                let padding = ty_align - modulus;
                let padding_name = format!("_pad{pad_count}");
                pad_count += 1;
                struct_size += padding;
                if padding == 1 {
                    tys.push((padding_name, IdrType::BYTE));
                } else {
                    tys.push((padding_name, IdrType::Array(Box::new(IdrType::BYTE), padding)));
                }
            }
            struct_align = struct_align.max(ty_align);
            struct_size += ty.size();
            tys.push((name, ty));
        }

        Self::Struct(tys, struct_align)

    }

    #[inline]
    pub const fn integer_aligned(size: u16) -> IdrType {
        IdrType::Integer(size, size)
    }

    pub const fn alignment(&self) -> u32 {
        match *self {
            Self::Integer(_, align) |
            Self::Float(_, align) => align as u32,
            Self::Array(ref ty, _) => ty.alignment(),
            Self::Struct(_, align) => align,
            Self::Pointer(_, size) => size as u32,
        }
    }

    pub fn size(&self) -> u32 {
        match *self {
            Self::Integer(size, _) |
            Self::Float(size, _) => size as u32,
            Self::Array(ref ty, count) => ty.size() * count,
            Self::Struct(ref tys, _) => {
                tys.iter().map(|(_, t)| t.size()).sum()
            }
            Self::Pointer(_, size) => size as u32,
        }
    }

}

impl fmt::Display for IdrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Integer(0, 0) => write!(f, "void"),
            Self::Integer(n, _) => write!(f, "i{n}"),
            Self::Float(n, _) => write!(f, "f{n}"),
            Self::Array(ref ty, len) => write!(f, "[{ty}; {len}]"),
            Self::Struct(ref fields, _) => {
                write!(f, "struct {{")?;
                for (i, (name, ty)) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{name}: {ty}")?;
                }
                write!(f, "}}")
            }
            Self::Pointer(ref ty, _) => {
                write!(f, "{ty}*")
            }
        }
    }
}
