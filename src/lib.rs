//! # Reverse Engineering Toolkit for Rust language
//! 
//! This reverse engineering toolkit aims at providing a powerful
//! and complete backend to any reverse engineering frontend.
//! The goal is to provide ways to proceduraly disassemble and 
//! decompile a target binary, such as it would be reproducible 
//! by anyone with the same binary and the same procedure.
//! It should also work with newer versions of the binary.

use std::sync::Arc;

use object::{Object, ObjectSection, Architecture, SectionKind};
use object::read::pe::{PeFile64, Import};
use object::pe::ImageNtHeaders64;
use object::LittleEndian as LE;

pub mod analyzer;
pub mod idr;
pub mod arch;


pub fn analyse(data: &[u8]) {

    use analyzer::Analyzer;
    use arch::x86;

    let mut analyzer = Analyzer::new(x86::Backend::new(data, 64), 8);

    // LOADING PE //

    let file = PeFile64::parse(data).unwrap();

    if file.architecture() != Architecture::X86_64 {
        eprintln!("ERROR: Expected x86_64 architecture.");
        return;
    }

    // let libs = LibraryDatabase::new();
    // let rva_base = file.relative_address_base();
    // let import_table = file.import_table().unwrap().unwrap();
    // let mut import_desc_it = import_table.descriptors().unwrap();
    // while let Some(desc) = import_desc_it.next().unwrap() {

    //     let mut name: Arc<[u8]> = import_table.name(desc.name.get(LE)).unwrap().into();

    //     // Make the library name lowercase, in place.
    //     Arc::get_mut(&mut name).unwrap().make_ascii_lowercase();

    //     let mut current_thunk_rva = desc.first_thunk.get(LE);
    //     let mut thunks = import_table.thunks(current_thunk_rva).unwrap();

    //     while let Some(thunk) = thunks.next::<ImageNtHeaders64>().unwrap() {
            
    //         let import = import_table.import::<ImageNtHeaders64>(thunk).unwrap();
    //         let import_kind = match import {
    //             Import::Ordinal(ord) => ImportSymbol::Ordinal(ord),
    //             Import::Name(_, name) => ImportSymbol::Name(Box::from(name)),
    //         };

    //         let function = Function::with_imported(Arc::clone(&name), import_kind);
    //         analyzer.database.functions.insert(rva_base + current_thunk_rva as u64, function);

    //         current_thunk_rva += 8; // Sizeof thunk in PE64 (actually PE32+)

    //     }

    // }

    for section in file.sections() {
        if section.kind() == SectionKind::Text {
            if let Some((pos, size)) = section.file_range() {
                let addr = section.address();
                analyzer.backend.sections.add_code_section(pos as usize, addr, addr + size);
            }
        }
    }

    // print!(" = Basic Block pass... ");
    // std::io::stdout().flush().unwrap();
    // analyzer.run(x86::BasicBlockAnalysis::default());
    // println!("done: {} basic blocks", analyzer.database.basic_blocks.len());

    // print!(" = Function find pass... ");
    // std::io::stdout().flush().unwrap();
    // analyzer.run(common::FunctionGraphAnalysis::default());
    // println!("done: {} functions", analyzer.database.functions.len());

    analyzer.run(x86::IdrAnalysis::default());

    // let func = &analyzer.database.functions[&0x1409AB740];
    // let begin_ip = func.body.as_ref().unwrap().begin_ip;
    // let end_ip = func.body.as_ref().unwrap().end_ip;
    // println!("{begin_ip:08X} -> {end_ip:08X}");
    // let mut idr_analyzer = x86::IdrDecoder::new();
    // analyzer.backend.goto(begin_ip, end_ip);
    // idr_analyzer.init();
    // while let Some(inst) = analyzer.backend.decoder.decode() {
    //     idr_analyzer.feed(&inst);
    // }
    
    // let func = idr_analyzer.function();
    // crate::idr::print::print_function(func);

    // let section_name = section.name().unwrap();
    // let section_data = section.data().unwrap();
    // let section_vaddr = section.address();

    // println!("== Section name: {section_name}");
    // println!(" = Section data length: {}", section_data.len());
    // println!(" = Section vaddr: {section_vaddr:08X}");

    // println!("== Analysis...");
    // let mut analyzer = Analyzer::new(section_data, section_vaddr);

    // print!(" = Basic Block pass... ");
    // std::io::stdout().flush().unwrap();
    // analyzer.analyze(BasicBlockPass::default());
    // println!("done: {} basic blocks", analyzer.database.basic_blocks.len());

    // print!(" = Function find pass... ");
    // std::io::stdout().flush().unwrap();
    // analyzer.analyze(FunctionFindPass::default());
    // println!("done: {} functions", analyzer.database.functions.len());

    // // print!(" = Function ABI pass... ");
    // // std::io::stdout().flush().unwrap();
    // // analyzer.analyze(FunctionAbiPass::default());
    // // println!("done");

    // let func = &analyzer.database.functions[&0x141F31D20];
    // let begin_ip = func.begin_ip;
    // let end_ip = func.end_ip;
    // analyzer.print(begin_ip, end_ip, true);


    // // println!("== Priting function asm");

    // // println!("== Printing basic block tree for function");
    // // walk_bb_tree(&analyzer.database.basic_blocks, 0x1400A1500, &mut String::new(), "func ");

    // std::thread::sleep(Duration::from_secs(10));

    // // analyzer.print(0, u64::MAX);

    // // println!();
    // // println!();
    // // println!();

    // // for (vaddr, sym) in analyzer.database.iter_symbols() {
    // //     print!("{vaddr:016X} {sym:?}");
    // // }


}
