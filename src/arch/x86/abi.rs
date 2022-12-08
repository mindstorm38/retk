//! Fast ABI analysis on x86.

use iced_x86::{Code, Register};

use crate::analyzer::{Analysis, Analyzer};

use crate::arch::x86::{self, Section};
use crate::func::Abi;


/// ## ABI analysis
/// The goal of this analysis is to determine, as fast
/// as possible, the ABI and calling convention for each
/// function. Only the ABI is analyzed, number of arguments
/// and return types are not.
/// 
/// This analysis is to be executed after function finding 
/// one.
#[derive(Default)]
pub struct AbiAnalysis {

}

impl<'data> Analysis<x86::Runtime<'data>> for AbiAnalysis {

    fn analyze(&mut self, analyzer: &mut Analyzer<x86::Runtime<'data>>) {
        
        let decoder = &mut analyzer.runtime.decoder;

        let mut section = Section { pos: 0, begin_addr: 0, end_addr: 0 };

        for func in analyzer.database.functions.values_mut() {
            if let Some(body) = &func.body {

                if body.begin_ip < section.begin_addr || body.end_ip >= section.end_addr {
                    section = match analyzer.runtime.sections.get_code_section_at(body.begin_ip) {
                        Some(section) => section.clone(),
                        None => continue,
                    };
                }
                
                // Goto the function's body instructions.
                let offset = body.begin_ip - section.begin_addr;
                decoder.goto_range_at(section.pos + offset as usize, body.begin_ip, body.end_ip);

                let mut sp = 0;
                let mut abi = Abi::Unknown;

                while let Some(inst) = decoder.decode() {

                    match inst.code() {
                        Code::Mov_rm64_r64 => {
                            
                            if let (Register::RSP, Register::None) = (inst.memory_base(), inst.memory_index()) {
                                // Any of these displacement is typically from windows x64.
                                if let 8 | 16 | 24 | 30 = inst.memory_displacement64() {
                                    abi = Abi::Win64;
                                    break;
                                }
                            }

                        }
                        Code::Push_r64 => {
                            if let Register::RBP = inst.op0_register() {
                                // Typical of 
                                abi = Abi::Amd64;
                            }
                            sp += 8;
                        }
                        _ => break,
                    }

                }

                func.signature.abi = abi;

            }
        }
        
        todo!()

    }

}