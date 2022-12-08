use crate::ty::Type;

use super::IdrVar;


#[derive(Debug, Default)]
pub struct Function {
    /// All lines/statements of the function.
    lines: Vec<Line>,
}

impl Function {

    /// Clear all liens of this function.
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Get a slice to all lines of the function.
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// Add an empty line.
    pub fn add_line(&mut self) -> usize {
        let index = self.lines.len();
        self.lines.push(Line::default());
        index
    }

    pub fn set_statement(&mut self, index: usize, statement: Statement) {
        self.lines[index].statement = Some(statement);
    }

    pub fn add_statement(&mut self, statement: Statement) -> usize {
        let index = self.add_line();
        self.set_statement(index, statement);
        index
    }

    pub fn get_statement(&self, index: usize) -> &Statement {
        &self.lines[index].statement.as_ref().unwrap()
    }

    /// Define a basic block on the given line index.
    /// If a basic block already exists, it is overwritten.
    pub fn set_basic_block(&mut self, index: usize) {
        self.lines[index].basic_block = Some(BasicBlock::default());
    }

    pub fn get_basic_block(&self, index: usize) -> Option<&BasicBlock> {
        self.lines[index].basic_block.as_ref()
    }

    pub fn get_basic_block_mut(&mut self, index: usize) -> Option<&mut BasicBlock> {
        self.lines[index].basic_block.as_mut()
    }

}


/// Represent a function's line, every line is a statement but can 
/// have a basic block start.
#[derive(Debug, Default)]
pub struct Line {
    /// The statement of this line. If none this line is empty and
    /// should be replaced by the next added statement.
    pub statement: Option<Statement>,
    /// If this statement is the first of a basic block, this contains
    /// the basic block. 
    pub basic_block: Option<BasicBlock>,
}

/// A basic block.
#[derive(Debug, Default)]
pub struct BasicBlock {
    /// Variables defined as parameters for the rest of the basic block.
    parameters: Vec<(IdrVar, Type)>,
}

impl BasicBlock {

    pub fn parameters(&self) -> &[(IdrVar, Type)] {
        &self.parameters
    }

    pub fn add_param(&mut self, var: IdrVar, ty: Type) -> usize {
        let index = self.parameters.len();
        self.parameters.push((var, ty));
        index
    }

}

/// A statement.
#[derive(Debug)]
pub enum Statement {
    /// Store an expression's value to a pointed value.
    Store(Store),
    /// Create a new variable assignment.
    /// 
    /// The variable is guaranteed to be unique within
    /// the statement's basic block.
    Assign(Assign),
    /// A raw assembly instruction, **currently** just string.
    Asm(String),
}

#[derive(Debug)]
pub struct Store {
    /// The variable that is the pointer.
    pub ptr: IdrVar,
    /// The variable that has the value to store in the pointer.
    pub var: IdrVar,
}

#[derive(Debug)]
pub struct Assign {
    /// Variable assigned.
    pub var: IdrVar,
    /// Type of the variable.
    pub ty: Type,
    /// The expression used that calculate the value to assign.
    pub val: Expression,
}


/// Represent an rvalue in an assignment or store.
#[derive(Debug)]
pub enum Expression {
    /// A constant value.
    Constant(i64),
    /// Load a value by dereferencing the given variable.
    Load(IdrVar),
    /// Stack allocation of a given size. *Value type is a pointer.*
    Alloca(u16),
    /// A call to another function.
    Call {
        /// The value of the pointer.
        pointer: Value,
        /// Arguments given to the function.
        arguments: Vec<Value>,
    },
    /// Offset a given pointer by a given index and stride.
    GetElementPointer {
        pointer: IdrVar, 
        index: IdrVar, 
        stride: u8
    },
    /// Add a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Add(IdrVar, Value),
    /// Sub a value from a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Sub(IdrVar, Value),
    /// Mul a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Mul(IdrVar, Value),
    /// Div a value to a variable. Both values should have the same 
    /// type, *and this is the returned type*.
    Div(IdrVar, Value),
}

/// Describe the effective value for an expression,
/// can be either a variable or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// The value is a variable.
    Var(IdrVar),
    /// A constant value.
    Val(i64)
}
