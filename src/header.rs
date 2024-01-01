#![allow(dead_code)]

use tokio::io::Result; 

use crate::packet::{ResultCode, BytePacketBuffer};


#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16, // 16 bits 

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

        self.recursion_desired = (a & ( 1 << 0 )) > 0; 
        self.truncated_message = (a & ( 1 << 1 )) > 0;
        self.authoritative_answer = (a & ( 1 << 2 )) > 0; 
        self.opcode = (a >> 3 ) & 0x0F;
        self.response = (a & (1 << 7)) > 0; 

        // if self.opcode != 0  {
        //     self.rescode = ResultCode::from_num(4); 
        // }
        self.rescode = ResultCode::from_num(4);

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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()>{ 
        buffer.write_u16(self.id)?;

        let h1 = ((self.recursion_desired as u8) << 0
            | ((self.truncated_message as u8) << 1)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.opcode as u8) << 3)
            | ((self.response as u8) << 7)) as u8; 

        buffer.write_u8(h1)?;

        let h2 = ((self.rescode as u8)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7)) as u8;

        buffer.write_u8(h2)?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;
        
        Ok(())
    }

    // pub fn get_headers(&self) -> Result<[u8; 2]> {
    //     let resp = self.header.to_be_bytes();
        
    //     Ok(resp)
    // }
    pub fn get_id(&self) -> Result<[u8; 2]> { 
        let resp = self.id.to_be_bytes(); 
        Ok(resp)
    }

    
}