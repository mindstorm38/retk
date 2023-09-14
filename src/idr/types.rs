//! Type system crate, providing a way of defining complex data types.

use std::cell::OnceCell;


/// The type system.
pub struct TypeSystem {
    /// Pointer size on this system, in bits.
    pointer_size: u64,
    /// Size of bytes on this system, in bits.
    byte_size: u64,
    /// All registered types in the type system.
    type_defs: Vec<TypeDefCache>,
}

struct TypeDefCache {
    /// The actual type def.
    inner: Box<dyn TypeDef>,
    /// The cached name of this type, to avoid reallocating again and again when name is
    /// requested.
    name: OnceCell<String>,
}

impl TypeSystem {

    pub fn new(pointer_size: u64, byte_size: u64) -> Self {
        Self { 
            pointer_size,
            byte_size,
            type_defs: Vec::new(),
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
    pub fn name(&self, ty: Type) -> &str {
        self.type_defs[ty.0].name.get_or_init(|| {
            self.type_defs[ty.0].inner.name(self)
        })
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

        let type_def = &self.type_defs[ty.0];
        if type_def.inner.opaque() {
            return None
        }

        let bits = type_def.inner.bits(self);
        let align = type_def.inner.align(self);

        // Get minimum byte size and them make it a multiple of the given alignment.
        let raw_size = self.bits_to_bytes(bits);
        let size = (raw_size + align - 1) / align * align;

        Some(Layout {
            size,
            align,
        })

    }

    /// Define the given type and get a unique handle to it.
    pub fn define(&mut self, ty: impl TypeDef + 'static) -> Type {
        let ret = Type(self.type_defs.len());
        self.type_defs.push(TypeDefCache { 
            inner: Box::new(ty), 
            name: OnceCell::new(),
        });
        ret
    }

    /// Get a build for building a structure, and then define it to this 
    pub fn define_structure(&mut self) -> StructBuilder<'_> {
        StructBuilder { 
            system: self, 
            packed: false, 
            size: 0, 
            align: 0, 
            fields: Vec::new(),
        }
    }

}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// The size of the type **in bytes**.
    pub size: u64,
    /// The alignment of the type **in bytes and power of two**
    pub align: u64,
}


/// Opaque handle to a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Type(usize);


/// Abstract type trait, used for registering a type.
pub trait TypeDef {

    /// Return the name of **this type**.
    fn name(&self, system: &TypeSystem) -> String;

    /// Size of this type **in bits**.
    fn bits(&self, system: &TypeSystem) -> u64;

    /// Alignment of this type, **in bytes**, you should guarantee that this is a power
    /// of two, if not the case this could break the type system.
    fn align(&self, system: &TypeSystem) -> u64;

    /// Return true if the type is opaque and can only be used for pointers. It doesn't
    /// have known layout at this time.
    fn opaque(&self) -> bool { false }

}



/// Pointer to a given type.
pub struct Ptr(pub Type);

impl TypeDef for Ptr {

    fn name(&self, system: &TypeSystem) -> String {
        format!("{}*", system.name(self.0))
    }

    fn bits(&self, system: &TypeSystem) -> u64 {
        system.pointer_size() as _
    }

    fn align(&self, system: &TypeSystem) -> u64 {
        system.pointer_size() / system.byte_size()
    }

}


/// An repetition of the given type for a given count.
pub struct Array(pub Type, pub u32);

impl TypeDef for Array {

    fn name(&self, system: &TypeSystem) -> String {
        format!("[{}; {}]", system.name(self.0), self.1)
    }

    fn bits(&self, system: &TypeSystem) -> u64 {
        system.layout(self.0).unwrap().size as u64 * system.byte_size() as u64
    }

    fn align(&self, system: &TypeSystem) -> u64 {
        system.layout(self.0).unwrap().align
    }

}


/// An integer type of the given bits count.
pub struct Int(pub u64);

impl TypeDef for Int {

    fn name(&self, _system: &TypeSystem) -> String {
        format!("i{}", self.0)
    }
    
    fn bits(&self, _system: &TypeSystem) -> u64 {
        self.0
    }

    fn align(&self, system: &TypeSystem) -> u64 {
        // Get minimum number of bytes required, and them compute next power of two.
        system.bits_to_bytes(self.0).next_power_of_two()
    }

}


/// Single-precision IEEE-754 floating point number.
pub struct Float;
/// Double-precision IEEE-754 floating point number.
pub struct Double;


impl TypeDef for Float {

    fn name(&self, _system: &TypeSystem) -> String {
        "f32".into()
    }
    
    fn bits(&self, _system: &TypeSystem) -> u64 {
        32
    }

    fn align(&self, _system: &TypeSystem) -> u64 {
        4
    }

}

impl TypeDef for Double {

    fn name(&self, _system: &TypeSystem) -> String {
        "f64".into()
    }
    
    fn bits(&self, _system: &TypeSystem) -> u64 {
        64
    }

    fn align(&self, _system: &TypeSystem) -> u64 {
        8
    }

}


/// Represent the complex definition of a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Struct {
    /// Type name.
    name: String,
    /// Fields of this structure type.
    fields: Vec<Field>,
    /// Size of this structure **in bytes**.
    size: u64,
    /// Alignment of this structure **in bytes**.
    align: u64,
}

/// Represent the complex definition of a structure field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Offset of the field **in bytes**.
    offset: u64,
    /// Name of the field.
    name: String,
    /// Type of the field.
    ty: Type,
}

impl TypeDef for Struct {

    fn name(&self, _system: &TypeSystem) -> String {
        self.name.clone()
    }

    fn bits(&self, system: &TypeSystem) -> u64 {
        system.bytes_to_bits(self.size)
    }

    fn align(&self, _system: &TypeSystem) -> u64 {
        self.align
    }

}


/// A builder that should be used to define 
pub struct StructBuilder<'a> {
    /// The type system back reference, used when defining fields.
    system: &'a mut TypeSystem,
    /// Current packing status for 
    packed: bool,
    /// Current size of the structure.
    size: u64,
    /// Current alignment of the structure.
    align: u64,
    /// All field definitions.
    fields: Vec<Field>,
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
    /// **You should call this after all fields are defining, because the alignment is 
    /// always redefined by a field if its type has a greater alignment that the current
    /// one.**
    #[inline]
    #[must_use]
    pub fn align(&mut self, align: u64) -> &mut Self {
        self.align = align;
        self
    }

    /// Add a field to this struct, using the current alignment configuration.
    #[inline]
    #[must_use]
    pub fn field(&mut self, name: impl Into<String>, ty: Type) -> &mut Self {
        
        let name: String = name.into();

        let layout = self.system.layout(ty).unwrap();

        if !self.packed {
            let field_misalignment = self.size % layout.align;
            if field_misalignment != 0 {
                let field_misalignment = layout.align - field_misalignment; 
                self.size += field_misalignment;
            }
        }

        if layout.align > self.align {
            self.align = layout.align;
        }

        self.fields.push(Field { 
            offset: self.size, 
            name, 
            ty,
        });

        self.size += layout.size;

        self

    }

    /// Finally build the structure, applying all changes
    /// to the real structure definition.
    pub fn define(mut self, name: impl Into<String>) -> Type {

        // Same as for fields, we pad the size of this structure.
        let struct_misalignment = self.size % self.align;
        if struct_misalignment != 0 {
            let struct_misalignment = self.align - struct_misalignment;
            self.size += struct_misalignment;
        }

        self.system.define(Struct {
            name: name.into(),
            fields: self.fields,
            size: self.size,
            align: self.align,
        })

    }

}
