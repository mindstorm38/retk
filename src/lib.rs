//! # Reverse Engineering Toolkit for Rust language
//! 
//! This reverse engineering toolkit aims at providing a powerful
//! and complete backend to any reverse engineering frontend.
//! The goal is to provide ways to proceduraly disassemble and 
//! decompile a target binary, such as it would be reproducible 
//! by anyone with the same binary and the same procedure.
//! It should also work with newer versions of the binary.

use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

use object::{Object, ObjectSection, Architecture, SectionKind};
use object::read::pe::PeFile64;

pub mod analyzer;
pub mod symbol;
pub mod idr;

pub mod x86;

use analyzer::{
    Analyzer, 
    BasicBlockPass,
    FunctionFindPass,
    FunctionAbiPass,
};

use symbol::{BasicBlock, BasicBlockExit};

use x86::X86IdrAnalyzer;

use crate::idr::{IdrAnalyzer, IdrStatement};


pub fn analyse(data: &[u8]) {

    let file = PeFile64::parse(data).unwrap();

    if file.architecture() != Architecture::X86_64 {
        eprintln!("ERROR: Expected x86_64 architecture.");
        return;
    }

    for section in file.sections() {
        if section.kind() == SectionKind::Text {
            
            let section_name = section.name().unwrap();
            let section_data = section.data().unwrap();
            let section_vaddr = section.address();

            println!("== Section name: {section_name}");
            println!(" = Section data length: {}", section_data.len());
            println!(" = Section vaddr: {section_vaddr:08X}");

            println!("== Analysis...");
            let mut analyzer = Analyzer::new(section_data, section_vaddr);

            print!(" = Basic Block pass... ");
            std::io::stdout().flush().unwrap();
            analyzer.analyze(BasicBlockPass::default());
            println!("done: {} basic blocks", analyzer.database.basic_blocks.len());

            print!(" = Function find pass... ");
            std::io::stdout().flush().unwrap();
            analyzer.analyze(FunctionFindPass::default());
            println!("done: {} functions", analyzer.database.functions.len());

            // print!(" = Function ABI pass... ");
            // std::io::stdout().flush().unwrap();
            // analyzer.analyze(FunctionAbiPass::default());
            // println!("done");

            let func = &analyzer.database.functions[&0x141F31D20];
            let begin_ip = func.begin_ip;
            let end_ip = func.end_ip;
            analyzer.print(begin_ip, end_ip, true);

            analyzer.runtime.goto_ip(begin_ip);
            let mut idr_analyzer = X86IdrAnalyzer::new(&mut analyzer.runtime.decoder);
            let mut idr_stmt = IdrStatement::default();
            loop {
                let ip = idr_analyzer.ip();
                if ip > end_ip {
                    break;
                }
                print!("{ip:010X} ");
                idr_analyzer.decode(&mut idr_stmt);
                if let IdrStatement::Assign { place, .. } = idr_stmt {
                    let place_ty = idr_analyzer.place_type(place);
                    print!("{place_ty} ");
                }
                println!("{idr_stmt}");
            }


            // println!("== Priting function asm");

            // println!("== Printing basic block tree for function");
            // walk_bb_tree(&analyzer.database.basic_blocks, 0x1400A1500, &mut String::new(), "func ");

            std::thread::sleep(Duration::from_secs(10));

            // analyzer.print(0, u64::MAX);

            // println!();
            // println!();
            // println!();

            // for (vaddr, sym) in analyzer.database.iter_symbols() {
            //     print!("{vaddr:016X} {sym:?}");
            // }

        }
    }

}


fn walk_bb_tree(bbs: &HashMap<u64, BasicBlock>, ip: u64, padding: &mut String, prefix: &str) {
    let bb = &bbs[&ip];
    print!("{padding}{prefix}0x{:08X} -> 0x{:08X} ", bb.begin_ip, bb.end_ip);
    padding.push_str("  ");
    match bb.exit {
        BasicBlockExit::Unconditionnal { goto_ip } => {
            println!("jmp");
            walk_bb_tree(bbs, goto_ip, padding, "goto ");
        }
        BasicBlockExit::Conditionnal { goto_ip: then_ip, continue_ip: else_ip } => {
            println!("jcc");
            walk_bb_tree(bbs, then_ip, padding, "then ");
            walk_bb_tree(bbs, else_ip, padding, "else ");
        }
        BasicBlockExit::Unknown => {
            println!("ret|unk");
        }
    }
    padding.truncate(padding.len() - 2);
}
