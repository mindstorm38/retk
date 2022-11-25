//! x86 specific implementations.


use std::collections::VecDeque;

use iced_x86::{Decoder, Instruction, Code, Register};

use crate::idr::{IdrAnalyzer, IdrStatement, IdrExpression, IdrType};


pub struct X86IdrAnalyzer<'dec, 'data> {
    /// The x86 decoder for decoding machine instructions. 
    decoder: &'dec mut Decoder<'data>,
    /// Cached instruction.
    inst: Instruction,
    /// Internal data.
    data: AnalyzerData,
    /// If some instructions are too complicated to fit in
    /// a single statement, the additionnal statements are
    /// pushed to this vector and poped later decoding.
    pending_stmts: VecDeque<IdrStatement>,
}

impl<'dec, 'data> X86IdrAnalyzer<'dec, 'data> {

    pub fn new(decoder: &'dec mut Decoder<'data>) -> Self {
        Self {
            decoder,
            inst: Instruction::new(),
            data: AnalyzerData::default(),
            pending_stmts: VecDeque::new(),
        }
    }

    pub fn ip(&self) -> u64 {
        self.decoder.ip()
    }
    
}

impl<'dec, 'data> IdrAnalyzer for X86IdrAnalyzer<'dec, 'data> {

    fn decode(&mut self, dst: &mut IdrStatement) {
        
        if let Some(stmt) = self.pending_stmts.pop_front() {
            *dst = stmt;
            return;
        }

        if !self.decoder.can_decode() {
            *dst = IdrStatement::Error;
            return;
        }

        let inst = &mut self.inst;
        let data = &mut self.data;
        self.decoder.decode_out(inst);

        match inst.code() {
            Code::Push_r64 |
            Code::Push_r32 |
            Code::Push_r16 => data.decode_push_r(inst),
            Code::Sub_rm64_imm8 |
            Code::Sub_rm64_imm32 => data.decode_sub_rm_imm(inst),
            Code::Mov_r64_rm64 |
            Code::Mov_r32_rm32 |
            Code::Mov_r16_rm16 => {

                let reg0 = inst.op0_register();
                let reg0_place = data.create_register_place(reg0);

                let reg1 = inst.op1_register();
                if reg1 == Register::None {
                    
                    let mem_reg = inst.memory_base();
                    let mem_reg_place = data.ensure_register_place(mem_reg);
                    let mem_displ = inst.memory_displacement64() as i64;
                    // let mem_scale = inst.memory_index_scale();
                    // let mem_index = inst.memory_index();

                    *dst = IdrStatement::Assign { 
                        place: reg0_place, 
                        expr: IdrExpression::Deref { 
                            offset: mem_displ, 
                            base: mem_reg_place,
                        }
                    };
                    
                } else {
                    let reg1_place = data.ensure_register_place(reg1);
                    *dst = IdrStatement::Assign { 
                        place: reg0_place, 
                        expr: IdrExpression::Copy(reg1_place),
                    };
                }

            }
            Code::Call_rm64 |
            Code::Call_rm32 |
            Code::Call_rm16 => {
                
                let ret_place = data.places.create_integer(8);

                let reg0 = inst.op0_register();
                if reg0 == Register::None {

                } else {
                    let reg0_place = data.ensure_register_place(reg0);
                    *dst = IdrStatement::Assign { 
                        place: ret_place, 
                        expr: IdrExpression::CallIndirect { 
                            addr_place: reg0_place, 
                            args_places: Vec::new(),
                        }
                    };
                }

            }
            _ => {
                *dst = IdrStatement::Error;
            }
        }

    }

    fn place_type(&self, place: u32) -> &IdrType {
        self.data.places.get_type(place)
    }

    

}


#[derive(Debug, Default)]
struct AnalyzerData {
    places: AnalyzerPlaces,
    registers: AnalyzerRegisters,
    stack: AnalyzerStack,
    /// Currently decoded statements.
    statements: VecDeque<IdrStatement>,
}

impl AnalyzerData {

    /// Ensure that a register has a place, if it's not the case,
    /// a new place is created with a type set to an integer that
    /// has the same bytes count as the register.
    /// 
    /// The place is returned together with a boolean that indicates
    /// weither or not the place has just been created.
    fn ensure_register_place(&mut self, register: Register) -> u32 {
        if let Some(place) = self.registers.get_place(register) {
            place
        } else {
            let size = register.size() as u16;
            let place = self.places.create(IdrType::Integer(size, size), true);
            self.registers.set_place(register, place);
            place
        }
    }

    /// Create a new place initially bound to the register.
    fn create_register_place(&mut self, register: Register) -> u32 {
        let place = self.places.create_integer(register.size());
        self.registers.set_place(register, place);
        place
    }

    /// Internal function to enqueue a statement
    #[inline]
    fn enqueue_assign(&mut self, place: u32, expr: IdrExpression) {
        self.statements.push_back(IdrStatement::Assign { 
            place, 
            expr,
        });
    }

    fn decode_mem_addr(&mut self, inst: &Instruction) -> IdrExpression {

        let mem_reg = inst.memory_base();
        let mem_reg_place = self.ensure_register_place(mem_reg);
        let mem_displ = inst.memory_displacement64() as i64;
        // let mem_scale = inst.memory_index_scale();
        // let mem_index = inst.memory_index();

        IdrExpression::Deref { 
            offset: mem_displ, 
            base: mem_reg_place,
        }

    }

    fn decode_push_r(&mut self, inst: &Instruction) {

        let reg = inst.op0_register();
        let reg_place = self.ensure_register_place(reg);
        let stack_place = self.places.create_integer(reg.size());

        self.stack.stack_pointer -= 8;
        self.stack.store(self.stack.stack_pointer, 8, stack_place);
        
        self.enqueue_assign(stack_place, IdrExpression::Copy(reg_place));

    }

    fn decode_sub_rm_imm(&mut self, inst: &Instruction) {
        
        match inst.op0_register() {
            Register::None => {
                // Memory addressing
                self.statements.push_back(IdrStatement::Error);
            }
            Register::RSP => {
                // Special handling for RSP
                self.stack.stack_pointer -= inst.immediate64() as i64 as i32;
            }
            reg => {
                let reg_place = self.ensure_register_place(reg);
                self.enqueue_assign(reg_place, IdrExpression::AddImm(reg_place, inst.immediate64() as i64));
            }
        }

    }

}


/// Used to keep track of each 
#[derive(Debug, Default)]
struct AnalyzerPlaces {
    /// All places.
    places: Vec<AnalyzerPlace>,
}

#[derive(Debug)]
struct AnalyzerPlace {
    /// Type of the place.
    ty: IdrType,
    /// Number of references to this place.
    ref_count: u32,
    /// True if the place is external. This means that the place
    /// was not initialized in the first place by an IDR statement.
    external: bool,

    // TODO: Add last storage
}

impl AnalyzerPlaces {

    /// Create a new place with a type and external state.
    fn create(&mut self, ty: IdrType, external: bool) -> u32 {
        let idx = self.places.len();
        assert!(idx <= u32::MAX as usize, "to much idr types");
        self.places.push(AnalyzerPlace { 
            ty, 
            ref_count: 0,
            external,
        });
        idx as u32
    }

    /// Create an integer place of the given size, this size
    /// will also be the alignment of the type. This place
    /// will not be defined as "external".
    #[inline]
    fn create_integer(&mut self, int_size: usize) -> u32 {
        let int_size = int_size as u16;
        self.create(IdrType::Integer(int_size, int_size), false)
    }

    /// Increment reference count of a place.
    fn inc_ref_count(&mut self, place: u32) {
        self.places[place as usize].ref_count += 1;
    }

    /// Get the type of a place.
    fn get_type(&self, place: u32) -> &IdrType {
        &self.places[place as usize].ty
    }

}


/// Used to keep track of registers.
#[derive(Debug, Default)]
struct AnalyzerRegisters {
    /// RAX/RCX/RDX/RBX/RSI/RDI/R8-R15
    gp: [AnalyzerGpRegister; 16],
}

#[derive(Debug, Default)]
struct AnalyzerGpRegister {
    /// Place index stored at this location
    place: u32,
    /// Byte length actually used in this register.
    len: u16,
}

impl AnalyzerRegisters {

    fn get_place(&self, register: Register) -> Option<u32> {
        if register.is_gpr() {
            let gp = &self.gp[register.number()];
            (gp.len > 0).then_some(gp.place) 
        } else {
            None
        }
    }

    fn set_place(&mut self, register: Register, place: u32) {
        if register.is_gpr() {
            let gp = &mut self.gp[register.number()];
            gp.len = register.size() as u16;
            gp.place = place;
        } else {
            unimplemented!("this kind of register is not yet supported");
        }
    }

}


/// Simulation of the stack, used to track which place is used
/// for which variable.
#[derive(Debug, Default)]
struct AnalyzerStack {
    /// Associate to each stack byte a place.
    stack: VecDeque<u32>,
    /// Address of the first byte in the stack.
    stack_base: i32,
    /// Current stack pointer.
    stack_pointer: i32,
}

impl AnalyzerStack {

    fn store(&mut self, addr: i32, len: u32, place: u32) {

        if addr < self.stack_base {
            for _ in addr..self.stack_base {
                self.stack.push_front(0);
                self.stack_base -= 1;
            }
        }

        let end_addr = addr + len as i32;
        let current_end_addr = self.stack_base + self.stack.len() as i32;

        if end_addr > current_end_addr {
            for _ in current_end_addr..end_addr {
                self.stack.push_back(0);
            }
        }

        for i in addr..(addr + len as i32) {
            let idx = (i - self.stack_base) as usize;
            self.stack[idx] = place;
        }

    }

}
