//! Module related to function's analysis and decompilation.


/// Function symbol details, signature and return types.
#[derive(Debug, Clone)]
pub struct Function {
    /// First basic block of the function.
    pub begin_ip: u64,
    /// End IP of the function (exclusive).
    pub end_ip: u64,
    /// Calling convention's ABI.
    pub abi: Abi,
}

impl Function {

    pub fn new(begin_ip: u64, end_ip: u64) -> Self {
        Self {
            begin_ip,
            end_ip,
            abi: Abi::Unknown,
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
