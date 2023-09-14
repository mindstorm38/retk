//! Basic block analysis specific to x86.

use iced_x86::Code;

use crate::analyzer::{Analysis, Analyzer};
use crate::block::ListResolver;

use super::Backend;


/// Basic block analysis for x86.
#[derive(Default)]
pub struct BasicBlockAnalysis {
    resolver: ListResolver,
}

impl<'data> Analysis<Backend<'data>> for BasicBlockAnalysis {

    fn analyze(&mut self, analyzer: &mut Analyzer<Backend<'data>>) {
        
        let decoder = &mut analyzer.backend.decoder;

        for section in &analyzer.backend.sections.code {

            decoder.goto_range_at(section.pos, section.begin_addr, section.end_addr);

            while let Some(inst) = decoder.decode() {

                let (goto_ip, cond, call) = match inst.code() {
                    // Unconditionnal jumps
                    Code::Jmp_rel8_64 |
                    Code::Jmp_rel8_32 |
                    Code::Jmp_rel8_16 |
                    Code::Jmp_rel32_64 |
                    Code::Jmp_rel32_32  => 
                        (inst.near_branch64(), false, false),
                    // Unconditionnal jump to unknown IP
                    Code::Jmp_rm64 |
                    Code::Jmp_rm32 |
                    Code::Jmp_rm16 => 
                        (0, false, false),
                    // Conditional jumps
                    code if code.is_jcc_short_or_near() =>
                        (inst.near_branch64(), true, false),
                    // Calls
                    Code::Call_rel16 |
                    Code::Call_rel32_64 |
                    Code::Call_rel32_32 => 
                        (inst.near_branch64(), false, true),
                    // Calls to unknown IP, go to next instruction
                    Code::Call_rm64 |
                    Code::Call_rm32 |
                    Code::Call_rm16 => continue, 
                    // Return, by definition to unknown IP
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
                    Code::Retfw_imm16 => 
                        (0, false, false),
                    // Unhandled
                    _ => continue
                };
    
                if goto_ip == 0 || analyzer.backend.sections.in_code_range(goto_ip) {
                    self.resolver.push_branch(goto_ip, inst.next_ip(), cond, call);
                }

            }

            // This also clear the resolver, so we can continue in the new section.
            self.resolver.finalize(section.end_addr, &mut analyzer.database.basic_blocks);

        }

    }

}
