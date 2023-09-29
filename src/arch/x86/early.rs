//! Early basic block and function analysis.

use std::collections::HashSet;

use iced_x86::Code;

use super::Backend;


/// Analyze all functions and their basic blocks from the given x86 backend.
pub fn analyze_early_functions(backend: &mut Backend) -> EarlyFunctions {

    let mut called_basic_blocks = HashSet::new();

    for section in &backend.sections.code {
        backend.decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);
        while let Some(inst) = backend.decoder.decode() {
            match inst.code() {
                Code::Call_rel16 |
                Code::Call_rel32_32 |
                Code::Call_rel32_64 => {
                    called_basic_blocks.insert(inst.memory_displacement64());
                }
                _ => {}
            }
        }
    }

    let mut ret = EarlyFunctions::default();

    for section in &backend.sections.code {

        backend.decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);

        let mut function_start = None;

        while let Some(inst) = backend.decoder.decode() {

            // println!("[{:08X}] {inst}", inst.ip());

            let mut is_nop = false;

            match inst.code() {
                // NOP
                Code::Nopw |
                Code::Nopd |
                Code::Nopq |
                Code::Nop_rm16 |
                Code::Nop_rm32 |
                Code::Nop_rm64 |
                Code::Int3 => {
                    is_nop = true;
                }
                // Jcc
                code if code.is_jcc_short_or_near() => {
                    ret.basic_blocks.insert(inst.near_branch64());
                    ret.basic_blocks.insert(inst.next_ip());
                }
                // JMP
                Code::Jmp_rel8_64 |
                Code::Jmp_rel8_32 |
                Code::Jmp_rel8_16 |
                Code::Jmp_rel32_64 |
                Code::Jmp_rel32_32 => {
                    ret.basic_blocks.insert(inst.near_branch64());
                    ret.basic_blocks.insert(inst.next_ip());
                }
                _ => {}
            }

            if !is_nop && function_start.is_none() {
                // If the instruction is not a no-op we can start function if relevant.
                // Also add a basic block at the function's start.
                ret.basic_blocks.insert(inst.ip());
                function_start = Some(inst.ip());
            } else {

                let end_ip;
                if is_nop {
                    // If current instruction is a no-op then we can directly end this
                    // function here (exclusive end).
                    end_ip = inst.ip();
                } else if called_basic_blocks.contains(&inst.next_ip()) {
                    // If the current instruction is not a no-op but a new function is
                    // starting on the next instruction, function ends on the next one.
                    end_ip = inst.next_ip();
                } else {
                    continue;
                }

                // If this is a no-op and we have a function start, finish the function.
                // If the next ip is a called basic block, we also terminate the function.
                if let Some(function_start) = function_start.take() {
                    ret.functions.push((function_start, end_ip));
                }

            }

        }

    }

    ret

}


/// This structure contains information about "early functions" and their basic blocks.
/// This functions are called "early" because they are required to actually decompile
/// to IDR, and they only contains basic blocks for each function, but not their  
#[derive(Debug, Default)]
pub struct EarlyFunctions {
    /// Mapping of all basic blocks.
    basic_blocks: HashSet<u64>,
    /// Listing of function with their first (inclusive) and last (exclusive) instruction.
    functions: Vec<(u64, u64)>,
}

impl EarlyFunctions {

    /// Iterate over all functions.
    pub fn iter_functions(&self) -> impl Iterator<Item = EarlyFunction<'_>> + '_ {
        self.functions.iter()
            .map(|&(start, end)| EarlyFunction { 
                basic_blocks: &self.basic_blocks, 
                begin: start, 
                end,
            })
    }

    /// Iterate over all basic blocks.
    pub fn iter_basic_blocks(&self) -> impl Iterator<Item = u64> + '_ {
        self.basic_blocks.iter().copied()
    }

    /// Return the number of functions.
    pub fn functions_count(&self) -> usize {
        self.functions.len()
    }

    /// Return the number of basic blocks.
    pub fn basic_blocks_count(&self) -> usize {
        self.basic_blocks.len()
    }

}

/// A reference to an early function, produced by 
#[derive(Debug, Clone)]
pub struct EarlyFunction<'a> {
    basic_blocks: &'a HashSet<u64>,
    begin: u64,
    end: u64,
}

impl EarlyFunction<'_> {

    /// Return the start instruction pointer of this function.
    pub fn begin(&self) -> u64 {
        self.begin
    }

    /// Return the end instruction pointer of this function.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Returns true if this function contains the given basic block's instruction.
    pub fn contains_block(&self, ip: u64) -> bool {
        if ip >= self.begin && ip < self.end {
            self.basic_blocks.contains(&ip)
        } else {
            false
        }
    }

}
