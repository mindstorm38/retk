//! Early basic block and function analysis.

use std::collections::HashSet;

use iced_x86::Code;

use super::Backend;


/// Analyze all functions and their basic blocks from the given x86 backend.
pub fn analyze_early_functions(backend: &mut Backend) -> EarlyFunctions {

    let mut ret = EarlyFunctions::default();

    for section in &backend.sections.code {

        backend.decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);
        
        let mut function_start = None;
        let mut maybe_tail_call = None;

        while let Some(inst) = backend.decoder.decode() {

            // Do not start the function while nop instruction.
            if function_start.is_none() {
                match inst.code() { 
                    Code::Nopw |
                    Code::Nopd |
                    Code::Nopq |
                    Code::Nop_rm16 |
                    Code::Nop_rm32 |
                    Code::Nop_rm64 |
                    Code::Int3 => continue,
                    _ => {
                        function_start = Some(inst.ip());
                        // There is at least one basic block at function's entry.
                        ret.basic_blocks.insert(inst.ip());
                    }
                }
            }

            let mut function_end = false;

            match inst.code() {
                // Jcc
                code if code.is_jcc_short_or_near() => {
                    ret.basic_blocks.insert(inst.near_branch64());
                    ret.basic_blocks.insert(inst.next_ip());
                    maybe_tail_call = None;
                }
                // JMP
                Code::Jmp_rel8_64 |
                Code::Jmp_rel8_32 |
                Code::Jmp_rel8_16 |
                Code::Jmp_rel32_64 |
                Code::Jmp_rel32_32 => {

                    let true_branch = inst.near_branch64();
                    maybe_tail_call = None;

                    if true_branch < function_start.unwrap() {
                        // Branching before the function's start means a tail-call.
                        function_end = true;
                    } else {
                        // Branching elsewhere can be a real branch so we register it.
                        ret.basic_blocks.insert(true_branch);
                        // But if the branch goes beyond the current instruction, note
                        // that it can be a tail-call.
                        if true_branch > inst.ip() {
                            maybe_tail_call = Some(true_branch);
                        }
                    }
                    
                }
                // RET
                Code::Retnq |
                Code::Retnd |
                Code::Retnw |
                Code::Retnq_imm16 |
                Code::Retnd_imm16 |
                Code::Retnw_imm16 |
                Code::Retfq |
                Code::Retfd |
                Code::Retfw |
                Code::Retfq_imm16 |
                Code::Retfd_imm16 |
                Code::Retfw_imm16 => {
                    function_end = true;
                    maybe_tail_call = None;
                }
                Code::Nopw |
                Code::Nopd |
                Code::Nopq |
                Code::Nop_rm16 |
                Code::Nop_rm32 |
                Code::Nop_rm64 |
                Code::Int3 => {
                    // If last instruction maybe a tail call and this is a nop, valid.
                    if let Some(tail_call_ip) = maybe_tail_call.take() {
                        // Remove the basic block that was created by the tail call.
                        ret.basic_blocks.remove(&tail_call_ip);
                        ret.functions.push((function_start.take().unwrap(), inst.ip()));
                    }
                }
                _ => {
                    // Other instruction cannot be tail-calls.
                    maybe_tail_call = None;
                }
            }

            if function_end {
                ret.functions.push((function_start.take().unwrap(), inst.next_ip()));
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
