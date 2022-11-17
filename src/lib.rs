//! # Reverse Engineering Toolkit for Rust language
//! 
//! This reverse engineering toolkit aims at providing a powerful
//! and complete backend to any reverse engineering frontend.
//! The goal is to provide ways to proceduraly disassemble and 
//! decompile a target binary, such as it would be reproducible 
//! by anyone with the same binary and the same procedure.
//! It should also work with newer versions of the binary.

use std::collections::HashMap;

use object::{Object, ObjectSection, Architecture, SectionKind};
use object::read::pe::PeFile64;

pub mod analyzer;
pub mod symbol;

use analyzer::{
    Analyzer, 
    BasicBlockPass,
};

use symbol::{BasicBlock, BasicBlockExit};


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

            // let sub_data = &section_data[0x140473531 - section_vaddr as usize..0x14047358D - section_vaddr as usize];
            // let sub_ip = 0x140473531;

            let mut analyzer = Analyzer::new(section_data, section_vaddr);

            println!("===================================");
            println!("==== {section_name:^25} ====");
            println!("===================================");

            print!("BasicBlockPass... ");
            analyzer.analyze(BasicBlockPass::default());
            println!("done");

            println!("Printing basic block tree for function");
            walk_bb_tree(&analyzer.database.basic_blocks, 0x1403AF610, &mut String::new(), "func ");

            // std::thread::sleep(Duration::from_secs(10));

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
        BasicBlockExit::Conditionnal { then_ip, else_ip } => {
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
