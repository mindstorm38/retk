//! Type system module for IDR, providing a way of defining complex data types.

use std::collections::HashMap;
use std::fmt::Write;


/// The type system.
pub struct TypeSystem {
    /// Pointer size on this system, in bits.
    pointer_size: u64,
    /// Size of bytes on this system, in bits.
    byte_size: u64,
    /// Cache for type names (TODO: rework it to avoid needing mutation).
    name_cache: HashMap<Type, String>,
    /// The list of struct definitions.
    struct_defs: Vec<(String, Option<StructDef>)>,
}

impl TypeSystem {

    pub fn new(pointer_size: u64, byte_size: u64) -> Self {
        Self { 
            pointer_size,
            byte_size,
            name_cache: HashMap::new(),
            struct_defs: Vec::new(),
        }
    }

    /// Get the pointer size of this type system, int bits.
    pub fn pointer_size(&self) -> u64 {
        self.pointer_size
    }

    /// Get the byte size of this type system, int bits.
    pub fn byte_size(&self) -> u64 {
        self.byte_size
    }

    /// Return the name of the given type.
    pub fn name(&self, ty: Type) -> String {
        // self.name_cache.entry(ty).or_insert_with_key(|&k| {
        //     let mut name = String::new();
        //     match k.primitive {
        //         PrimitiveType::Int(n) => write!(name, "i{n}").unwrap(),
        //         PrimitiveType::Float => name.write_str("f32").unwrap(),
        //         PrimitiveType::Double => name.write_str("f64").unwrap(),
        //         PrimitiveType::Struct(s) => {
        //             let struct_name = &self.struct_defs[s.0 as usize].0;
        //             write!(name, "struct {struct_name}").unwrap();
        //         }
        //     }
        //     name.extend(std::iter::repeat('*').take(k.indirection as _));
        //     name
        // }).as_str()
        let mut name = String::new();
        match ty.primitive {
            PrimitiveType::Int(n) => write!(name, "i{n}").unwrap(),
            PrimitiveType::Float => name.write_str("f32").unwrap(),
            PrimitiveType::Double => name.write_str("f64").unwrap(),
            PrimitiveType::Struct(s) => {
                let struct_name = &self.struct_defs[s.0 as usize].0;
                write!(name, "struct {struct_name}").unwrap();
            }
        }
        name.extend(std::iter::repeat('*').take(ty.indirection as _));
        name
    }

    /// Round the given number of bits up to get the number of bytes needed to store.
    pub fn bits_to_bytes(&self, bits: u64) -> u64 {
        (bits + self.byte_size - 1) / self.byte_size
    }

    /// Calculate the number of bits given a number of bytes.
    pub fn bytes_to_bits(&self, bytes: u64) -> u64 {
        bytes * self.byte_size
    }

    /// Return the layout of the given type
    pub fn layout(&self, ty: Type) -> Option<Layout> {

        if ty.indirection != 0 {
            let bytes = self.bits_to_bytes(self.pointer_size);
            return Some(Layout { size: bytes, align: bytes });
        }

        match ty.primitive {
            PrimitiveType::Int(n) => {
                let bytes = self.bits_to_bytes(n as u64);
                Some(Layout { size: bytes, align: bytes })
            }
            PrimitiveType::Float => Some(Layout { size: 4, align: 4 }),
            PrimitiveType::Double => Some(Layout { size: 8, align: 8 }),
            PrimitiveType::Struct(s) => {
                let def = self.struct_defs[s.0 as usize].1.as_ref()?;
                Some(Layout { size: def.size, align: def.align })
            }
        }

    }

    /// Declare an opaque structure type, it can be defined layer as needed.
    pub fn declare_opaque_struct(&mut self, name: impl Into<String>) -> StructType {
        let idx: u32 = self.struct_defs.len().try_into().unwrap();
        self.struct_defs.push((name.into(), None));
        StructType(idx)
    }

    /// Define an already declared opaque struct.
    pub fn define_opaque_struct(&mut self, ty: StructType) -> StructBuilder<'_> {
        assert!(self.struct_defs[ty.0 as usize].1.is_none(), "struct is already defined");
        StructBuilder { 
            system: self, 
            def: StructDef {
                fields: Vec::new(),
                size: 0,
                align: 0,
            }, 
            def_index: ty.0 as usize, 
            packed: false
        }
    }

    pub fn define_struct(&mut self, name: impl Into<String>) -> StructBuilder<'_> {
        let s = self.declare_opaque_struct(name);
        self.define_opaque_struct(s)
    }

}


/// Represent the byte layout of a type, computed by the type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Layout {
    /// The size of the type **in bytes**.
    pub size: u64,
    /// The alignment of the type **in bytes and power of two**
    pub align: u64,
}

/// Opaque structure type handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StructType(u32);

/// Primitive data type definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveType {
    /// An integer of the given bits size.
    Int(u32),
    /// Single-precision IEEE-754 floating point number.
    Float,
    /// Double-precision IEEE-754 floating point number.
    Double,
    /// A structure type, referenced by its handle.
    Struct(StructType),
}

/// A full type definition with the indirection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Type {
    /// The primitive type pointed by this type.
    pub primitive: PrimitiveType,
    /// Indirection level of this type.
    pub indirection: u8,
}

impl From<PrimitiveType> for Type {
    fn from(value: PrimitiveType) -> Self {
        Self { primitive: value, indirection: 0 }
    }
}

impl PrimitiveType {

    /// Create a plain type (not a pointer) from this primitive type.
    pub const fn plain(self) -> Type {
        Type { primitive: self, indirection: 0 }
    }

    /// Create a point type with specific level of indirection from this primitive type.
    pub const fn pointer(self, indirection: u8) -> Type {
        Type { primitive: self, indirection }
    }

}

impl Type {

    /// Get a pointer to the current type with the given number of indirection. If the
    /// current type is already a pointer, this indirection is added to the existing one.
    pub const fn pointer(self, indirection: u8) -> Type {
        Type { primitive: self.primitive, indirection: self.indirection + indirection }
    }

}

/// Represent the complex definition of a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructDef {
    /// Fields of this structure type.
    pub fields: Vec<FieldDef>,
    /// Size of this structure **in bytes**.
    pub size: u64,
    /// Alignment of this structure **in bytes**. An alignment of zero is invalid an
    /// serves as a marker for an *opaque structure*, that has no definition yet and
    /// can only be used through indirection.
    pub align: u64,
}

/// Represent the complex definition of a structure field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    /// Offset of the field **in bytes**.
    pub offset: u64,
    /// Name of the field.
    pub name: String,
    /// Type of the field.
    pub ty: Type,
}


/// A builder that should be used to define 
pub struct StructBuilder<'a> {
    /// The type system, internally using to get layout of the fields.
    system: &'a mut TypeSystem,
    /// Definition of the structure.
    def: StructDef,
    /// Index of the struct def in the type system.
    def_index: usize,
    /// Indicate if the builder is currently packing fields or not.
    packed: bool,
}

impl<'a> StructBuilder<'a> {

    /// Make the next fields packed after the current ones, no padding will be added and 
    /// fields might be misaligned.
    #[inline]
    #[must_use]
    pub fn packed(&mut self) -> &mut Self {
        self.packed = true;
        self
    }

    /// Make the next fields padded in order to be aligned to their type's alignment. 
    /// **This is the default behavior.**
    #[inline]
    #[must_use]
    pub fn padded(&mut self) -> &mut Self {
        self.packed = false;
        self
    }

    /// Force the alignment to a given bytes size.
    /// 
    /// **You should call this after all fields are defined, because the alignment is 
    /// always redefined by a field if its type has a greater alignment that the current
    /// one.**
    #[inline]
    #[must_use]
    pub fn align(&mut self, align: u64) -> &mut Self {
        self.def.align = align;
        self
    }

    /// Add a field to this struct, using the current alignment configuration.
    #[inline]
    #[must_use]
    pub fn field(&mut self, name: impl Into<String>, ty: Type) -> &mut Self {
        
        let name: String = name.into();

        let layout = self.system.layout(ty).unwrap();

        if !self.packed {
            let field_misalignment = self.def.size % layout.align;
            if field_misalignment != 0 {
                let field_misalignment = layout.align - field_misalignment; 
                self.def.size += field_misalignment;
            }
        }

        if layout.align > self.def.align {
            self.def.align = layout.align;
        }

        self.def.fields.push(FieldDef { 
            offset: self.def.size, 
            name, 
            ty,
        });

        self.def.size += layout.size;

        self

    }

    /// Finally build the structure, applying all changes
    /// to the real structure definition.
    pub fn define(mut self) -> StructType {

        // Same as for fields, we pad the size of this structure.
        let struct_misalignment = self.def.size % self.def.align;
        if struct_misalignment != 0 {
            let struct_misalignment = self.def.align - struct_misalignment;
            self.def.size += struct_misalignment;
        }

        self.system.struct_defs[self.def_index].1 = Some(self.def);
        
        // We can can this to u32 directly because we know that it's a valid index 
        // because it's already declared.
        StructType(self.def_index as u32)

    }

}
