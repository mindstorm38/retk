//! Signatures database for the "Windows Sockets 2" DLL.
//! 
//! This provides UNIX like sockets on Windows.

use crate::func::{Signature, Abi};
use crate::ty::{TypeSystem, StructType, Type};

use super::{Library};


pub struct Ws2 {
    s_sockaddr: StructType,
    s_addrinfo: StructType,
}

impl Library for Ws2 {

    fn init(types: &mut TypeSystem) -> Box<Self> {
        
        let s_sockaddr = types.define_new_struct("ws2::sockaddr")
            .field("sa_family", Type::WORD)
            .field("sa_data", Type::BYTE.to_array(14))
            .build();

        let s_addrinfo = types.new_struct("ws2::addrinfo");
        types.define_struct(s_addrinfo).unwrap()
            .field("ai_flags", Type::DWORD)
            .field("ai_family", Type::DWORD)
            .field("ai_socktype", Type::DWORD)
            .field("ai_protocol", Type::DWORD)
            .field("ai_addrlen", Type::SIZE)
            .field("ai_canonname", Type::CHAR.to_pointer(1))
            .field("ai_addr", s_sockaddr.to_type().to_pointer(1))
            .field("ai_next", s_addrinfo.to_type().to_pointer(1))
            .build();

        Box::new(Self {
            s_sockaddr,
            s_addrinfo,
        })

    }

    fn function(&self, name: &[u8], types: &mut TypeSystem, signature: &mut Signature) {

        signature.abi = Abi::Stdcall;

        match name {
            b"getaddrinfo" => {
                signature.return_type = Type::DWORD;
                signature.set_parameters([
                    ("node_name", Type::CHAR.to_pointer(1)),
                    ("service_name", Type::CHAR.to_pointer(1)),
                    ("hints", self.s_addrinfo.to_type().to_pointer(1)),
                    ("result", self.s_addrinfo.to_type().to_pointer(2)),
                ]);
            }
            _ => {}
        }

    }

}
