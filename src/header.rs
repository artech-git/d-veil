#![allow(dead_code)]

use tokio::io::Result; 

use crate::packet::{ResultCode, BytePacketBuffer};

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16, // 16 bits 

    pub header: u16, // 16 bits seprate header space
    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits // 0b_0000_0000
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}


impl DnsHeader {
    pub fn new() -> Self { 
        Self { 
            ..Default::default()
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()>  { 
        self.id = buffer.read_u16()?; 

        let flags = buffer.read_u16()?; 

        let a = (flags >> 8) as u8; 
        let b = (flags & 0xFF) as u8; 

        self.header = flags; 

        self.recursion_desired = (a & ( 1 << 0 )) > 0; 
        self.truncated_message = (a & ( 1 << 1 )) > 0;
        self.authoritative_answer = (a & ( 1 << 2 )) > 0; 
        self.opcode = (a >> 3 ) & 0x0F;
        self.response = (a & (1 << 7)) > 0; 

        self.rescode = ResultCode::from_num(b & 0x0F); 
        self.checking_disabled = ( b & ( 1 << 4)) > 0; 
        self.authed_data = (b & ( 1 << 5 )) > 0; 
        self.z = (b & ( 1 << 6 )) > 0; 
        self.recursion_available = (b & ( 1 << 7 )) > 0; 

        self.questions = buffer.read_u16()?; 
        self.answers = buffer.read_u16()?; 
        self.authoritative_entries = buffer.read_u16()?; 
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn get_headers(&self) -> Result<[u8; 2]> {
        let resp = self.header.to_be_bytes();
        
        Ok(resp)
    }
    pub fn get_id(&self) -> Result<[u8; 2]> { 
        let resp = self.id.to_be_bytes(); 
        Ok(resp)
    }

    
}