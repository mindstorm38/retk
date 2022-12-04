//! Data type system.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::{self, Write as _};


/// A structure for querying [`DataType`]'s properties, such
/// as size, alignement.
#[derive(Debug)]
pub struct TypeSystem {
    /// Size of pointers on this system, in bytes.
    pointer_size: u32,
    /// Registered structure types.
    structs: Vec<StructDef>,
    /// Association between structure names and their index
    /// in the structure vector.
    structs_named: HashMap<String, u32>,
}

impl TypeSystem {

    pub fn new(pointer_size: u32) -> Self {
        Self {
            pointer_size,
            structs: Vec::new(),
            structs_named: HashMap::new(),
        }
    }

    #[inline]
    pub fn pointer_size(&self) -> u32 {
        self.pointer_size
    }

    /// Get the layout of a type, consisting of its size and
    /// alignment returned in a tuple (in this order).
    /// 
    /// The size follow the same specification as Rust's one:
    /// > This is the offset in bytes between successive 
    /// > elements in an array with that item type including
    /// > alignment padding
    /// 
    /// The size and alignment depends on the type system 
    /// because the pointer size is depending on the system.
    /// 
    /// The values are returned in bytes.
    pub fn layout(&self, ty: Type) -> Option<(u32, u32)> {
        
        let (size, align) = if ty.pointer_level > 0 {
            (self.pointer_size, self.pointer_size)
        } else {
            match ty.data_type {
                DataType::Void => (0, 0),
                DataType::Byte => (1, 1),
                DataType::Word => (2, 2),
                DataType::Dword => (4, 4),
                DataType::Qword => (8, 8),
                DataType::Float => (4, 4),
                DataType::Double => (8, 8),
                DataType::Size => (self.pointer_size, self.pointer_size),
                DataType::Struct(handle) => {
                    let s = self.structs.get(handle.0 as usize)?;
                    if s.opaque {
                        return None;
                    }
                    (s.size, s.align)
                }
            }
        };

        Some((size * ty.array_len as u32, align))

    }

    /// Get a struct type from its name, if no structure is found,
    /// None is returned.
    /// 
    /// *Note that the returned type is a raw [`DataType`], which
    /// can be promoted to a [`FullType`] to become useful.*
    pub fn get_struct(&self, name: &str) -> Option<StructType> {
        self.structs_named.get(name).copied().map(StructType)
    }

    /// Create a new structure given its name. If a structure already
    /// exists with this name, the current type is returned.
    /// 
    /// The created structure is "opaque".
    pub fn new_struct<S: Into<String>>(&mut self, name: S) -> StructType {
        let name: String = name.into();
        match self.structs_named.entry(name.clone()) {
            Entry::Occupied(o) => StructType(*o.into_mut()),
            Entry::Vacant(v) => {
                let idx = self.structs.len();
                let idx = idx.try_into().expect("to much structures defined");
                self.structs.push(StructDef::new_opaque(name));
                v.insert(idx);
                StructType(idx)
            }
        }
    }

    /// Given a created structure, returns a builder for constructing 
    /// it. Returns None if the given structure type does not exists 
    /// in this type system.
    #[must_use]
    pub fn define_struct(&mut self, ty: StructType) -> Option<StructBuilder<'_>> {
        if (ty.0 as usize) < self.structs.len() {
            Some(StructBuilder {
                system: self,
                ty,
                packed: false,
                size: 0,
                align: 0,
                fields: Vec::new(),
            })
        } else {
            None
        }
    }

    /// Combine [`new_struct`] and [`define_struct`].
    #[must_use]
    pub fn define_new_struct<S: Into<String>>(&mut self, name: S) -> StructBuilder<'_> {
        let ty = self.new_struct(name);
        self.define_struct(ty).unwrap()
    }

}


/// A builder that should be used to define 
pub struct StructBuilder<'a> {
    /// The type system back reference, used when defining fields.
    system: &'a mut TypeSystem,
    /// The actual structure type being built.
    ty: StructType,
    /// Current packing status for 
    packed: bool,
    /// Current size of the structure.
    size: u32,
    /// Current alignment of the structure.
    align: u32,
    /// All field definitions.
    fields: Vec<FieldDef>,
}

impl<'a> StructBuilder<'a> {

    /// Make the next fields packed after the current ones,
    /// no padding will be added and fields might be
    /// misaligned.
    #[inline]
    #[must_use]
    pub fn packed(&mut self) -> &mut Self {
        self.packed = true;
        self
    }

    /// Make the next fields padded in order to be aligned
    /// to their type's alignment. **This is the default
    /// behaviour.**
    #[inline]
    #[must_use]
    pub fn padded(&mut self) -> &mut Self {
        self.packed = false;
        self
    }

    /// Force the alignment to a given bytes size.
    /// 
    /// **You should call this after all fields are defining,
    /// because the alignment is always redefined by a field
    /// if its type has a greater alignment that the current
    /// one.**
    #[inline]
    #[must_use]
    pub fn align(&mut self, align: u32) -> &mut Self {
        self.align = align;
        self
    }

    /// Add a field to this struct, using the current alignment
    /// configuration for 
    #[inline]
    #[must_use]
    pub fn field<S: Into<String>>(&mut self, name: S, ty: Type) -> &mut Self {
        
        let name: String = name.into();

        let (ty_size, ty_align) = self.system.layout(ty)
            .expect("the given field type has unknown layout");

        if !self.packed {
            let field_misalignment = self.size % ty_align;
            if field_misalignment != 0 {
                let field_misalignment = ty_align - field_misalignment; 
                self.size += field_misalignment;
            }
        }

        if ty_align > self.align {
            self.align = ty_align;
        }

        self.fields.push(FieldDef { 
            offset: self.size, 
            name, 
            ty,
        });

        self.size += ty_size;

        self

    }

    /// Finally build the structure, applying all changes
    /// to the real structure definition.
    pub fn build(&mut self) -> StructType {

        // Same as for fields, we pad the size of this structure.
        let struct_misalignment = self.size % self.align;
        if struct_misalignment != 0 {
            let struct_misalignment = self.align - struct_misalignment;
            self.size += struct_misalignment;
        }

        let def = &mut self.system.structs[self.ty.0 as usize];

        def.fields.splice(.., self.fields.iter().cloned());
        def.opaque = false;
        def.size = self.size;
        def.align = self.align;

        self.ty

    }

}


/// An opaque pointer to a structure definition. 
/// This type is defined to be small, and to fit in 
/// the small [`DataType`] enumeration and can be 
/// promoted to using `into` implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructType(u32);

impl StructType {

    /// Convert this struct type to an usable type.
    pub const fn to_type(self) -> Type {
        DataType::Struct(self).to_type()
    }

}


/// All real types, no indirection can be defined using this
/// enumeration, look at [`FullType`] for full type definition,
/// with optionnal indirection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    /// No byte, used to represent no data returned by function.
    Void,
    /// A single byte.
    Byte,
    /// Integer of 2 bytes.
    Word,
    /// Integer of 4 bytes.
    Dword,
    /// Integer of 8 bytes.
    Qword,
    /// Single-precision floating point number.
    Float,
    /// Double-precision floating point number.
    Double,
    /// An integer type that has the same number
    /// of byte as a pointer.
    /// 
    /// FIXME: Maybe rename it in the future.
    Size,
    /// A struct type.
    Struct(StructType),
}

impl DataType {

    /// Convert this data type to an usable type.
    pub const fn to_type(self) -> Type {
        Type {
            data_type: self,
            pointer_level: 0,
            array_len: 1,
        }
    }

}


/// A type that optionnaly wraps a primitive type behind a given
/// level of indirection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Type {
    /// The type pointed by if there are indirection,
    /// or the type itself it not.
    pub data_type: DataType,
    /// If greater than 0, this indicates that the type
    /// is a pointer of a specific level to the data type.
    /// Level 1 means `type*`, 2 means `type**` and so on.
    pub pointer_level: u8,
    /// The length of the array. Used to define an array
    /// type, note that multidimensionnal arrays is not
    /// currently possible, and that an array length of
    /// 1 is not considered as an array, and 0 as invalid.
    pub array_len: u16,
}

impl Type {

    pub const VOID: Self = DataType::Void.to_type();
    pub const BYTE: Self = DataType::Byte.to_type();
    pub const CHAR: Self = Self::BYTE; // Alias
    pub const BOOL: Self = Self::BYTE; // Alias
    pub const WORD: Self = DataType::Word.to_type();
    pub const DWORD: Self = DataType::Dword.to_type();
    pub const QWORD: Self = DataType::Qword.to_type();
    pub const FLOAT: Self = DataType::Float.to_type();
    pub const DOUBLE: Self = DataType::Double.to_type();
    pub const SIZE: Self = DataType::Size.to_type();

    /// Return a new type that is a pointer to the data type,
    /// of the given level. Level 0 means that it's not a pointer.
    pub const fn to_pointer(&self, level: u8) -> Self {
        Self {
            data_type: self.data_type,
            pointer_level: level,
            array_len: self.array_len,
        }
    }

    pub const fn to_array(&self, len: u16) -> Self {
        Self {
            data_type: self.data_type,
            pointer_level: self.pointer_level,
            array_len: len,
        }
    }

    #[track_caller]
    pub fn from_integer_size(size: u16) -> Self {
        match size {
            1 => Self::BYTE,
            2 => Self::WORD,
            4 => Self::DWORD,
            8 => Self::QWORD,
            _ => panic!("unsupported integer size: {size}")
        }
    }

}

impl From<DataType> for Type {
    fn from(ty: DataType) -> Self {
        ty.to_type()
    }
}

impl From<StructType> for Type {
    fn from(ty: StructType) -> Self {
        ty.to_type()
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        f.write_str(match self.data_type {
            DataType::Void => "void",
            DataType::Byte => "byte",
            DataType::Word => "word",
            DataType::Dword => "dword",
            DataType::Qword => "qword",
            DataType::Float => "float",
            DataType::Double => "double",
            DataType::Size => "size",
            DataType::Struct(_) => "struct",
        })?;

        for _ in 0..self.pointer_level {
            f.write_char('*')?;
        }

        if self.array_len > 1 {
            write!(f, "[{}]", self.array_len)?;
        }

        Ok(())

    }
}


/// Represent the complex definition of a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructDef {
    /// Type name.
    name: String,
    /// Fields of this structure type.
    fields: Vec<FieldDef>,
    /// This structure is opaque. Can only be used behind a
    /// pointer.
    opaque: bool,
    /// Size of this structure, in bytes.
    size: u32,
    /// Alignment of this structure, in bytes.
    align: u32,
}

/// Represent the complex definition of a structure field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    /// Offset of the field.
    offset: u32,
    /// Name of the field.
    name: String,
    /// Type of the field.
    ty: Type,
}

impl StructDef {

    fn new_opaque(name: String) -> Self {
        Self {
            name,
            fields: Vec::new(),
            opaque: true,
            size: 0,
            align: 0,
        }
    }

}
