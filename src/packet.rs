
#![allow(dead_code, unused)]


use std::net::Ipv4Addr;

use tokio::io::Result;

use crate::header::DnsHeader; 

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer { 
    
    pub fn new(buf: [u8; 512] ) -> Self { 
        Self { 
            buf: buf, 
            pos: 0
        }
    }

    pub fn pos(&self) -> usize { 
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<()> { 
        self.pos += steps; 
        Ok(())
    }

    pub fn seek(&mut self, step: usize) -> Result<()> { 
        self.pos = step; 
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8> { 
        if self.pos >= 512 { 
            return Err(std::io::ErrorKind::OutOfMemory.into()); 
        }
        let res = self.buf[self.pos]; 
        self.pos += 1; 

        Ok(res)
    }

    #[inline(always)]
    pub fn get(&self, pos: usize) -> Result<u8> { 
        if pos >= 512 || self.pos >= 512 { 
            return Err(std::io::ErrorKind::OutOfMemory.into()); 
        }

        Ok(self.buf[pos])
    }

    #[inline(always)]
    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> { 
        if start + len >= 512 { 
            return Err(std::io::ErrorKind::OutOfMemory.into()); 
        }
        let range = start .. (start + len); 
        Ok(&self.buf[range])
    }

    pub fn set_range(&mut self, start: usize, len: usize, data: &[u8]) -> Result<()> {

        if (start + len >= 512) || (data.len() != len) { 
            return Err(std::io::ErrorKind::OutOfMemory.into()); 
        }

        let range = start .. (start + len); 

        for pos in range { 
            self.buf[pos] = data[pos-start];
        }

        Ok(())

    }

}


impl BytePacketBuffer { 

    // Read first two bytes and modify the pos pointer 
    pub fn read_u16(&mut self) -> Result<u16> {

        // Get the current two numbers ! 
        let primary_byte = self.read()?;  // the position at which current cursor at, for ex. 0x20 = 0b_0010_0000
        let followed_byte = self.read()?;  // second position followed by before cursor for ex. 0x18 = 0b_0001_0111 

        // bit shift the primary bytes to 8 bits forward for getting new u16 type with trailling zeros
        // bit perform bit wise OR operation for combining both into a 16 bits long integer  
        let res = ((primary_byte as u16) << 8 ) | ((followed_byte as u16));

        Ok(res)
    }

    // Read four bytes from the, and step by four bytes 
    pub fn read_u32(&mut self) -> Result<u32> { 

        //get the first four bytes from the current cursor position
        let byte_1 = self.read()? as u32; 
        let byte_2 = self.read()? as u32; 
        let byte_3 = self.read()? as u32;  
        let byte_4 = self.read()? as u32; 

        // perform the logic operation

        let res = (byte_1 << 24) | (byte_2 << 16) | (byte_3 << 8) | (byte_4);

        Ok(res)
    }

    // read the query_name from the bytes 
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> { 
        let mut pos = self.pos; 

        let mut jumped = false; 
        let max_jumps = 5; 
        let mut jumps_performed = 0; 

        let mut delim = ""; 

        loop { 
            
            // prevent's aganist the packet jumping attack 
            if jumps_performed > max_jumps { 
                return Err(std::io::ErrorKind::OutOfMemory.into()); 
            }

            let len = self.get(pos)?; 

            if (len & 0xC0) == 0xC0 {
                
                if !jumped { 
                    self.seek(pos + 2)?; 
                }

                let b2 = self.get(pos + 1)? as u16; 
                let offset = ( ((len as u16) & 0xC0) << 8 ) | b2; 

                pos = offset as usize; 
                jumped = true; 
                jumps_performed += 1; 

                continue; 

            }
            else { 
                pos += 1 ; 

                if len == 0 { 
                    break; 
                }

                outstr.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize)?; 
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase()); 

                delim = "."; 
                
                pos += len as usize;
            }


        }

        if !jumped { 
            self.seek(pos)?; 
        }

        Ok(())
    }

}



#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ResultCode {
    #[default]
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}


#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub enum QueryType { 
    UNKNOWN(u16), 
    A, 
}

impl QueryType { 
    
    pub fn to_num(&self) -> u16 { 
        match *self { 
            QueryType::A => 1, 
            QueryType::UNKNOWN(x) => x
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num { 
            1 => QueryType::A, 
            _ => QueryType::UNKNOWN(num)
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion { 
    pub name: String, 
    pub qtype: QueryType,
}

impl DnsQuestion { 
    pub fn new(name: String, qtype: QueryType) -> Self { 
         Self { 
            name, 
            qtype
         }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> { 
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?; 

        Ok(())
    }
}



#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnsRecord { 
    UNKNOWN {
        domain: String,
        qtype: u16, 
        data_len: u16, 
        ttl: u32
    },
    A { 
        domain: String,
        addr: Ipv4Addr, 
        ttl: u32
    }
}

impl DnsRecord { 
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {

        let mut domain = String::new(); 
        buffer.read_qname(&mut domain)?; 
        let qtype_num = buffer.read_u16()?;

        let qtype = QueryType::from_num(qtype_num); 
        let _ = buffer.read_u16()?; 
        let ttl = buffer.read_u32()?; 
        let data_len = buffer.read_u16()?;

        match qtype {
                QueryType::A => { 

                    let raw_addr = buffer.read_u32()?; 
                    let addr = Ipv4Addr::new(
                        ((raw_addr >> 24) &  0xFF) as u8,
                        ((raw_addr >> 16) & 0xFF) as u8, 
                        ((raw_addr >> 8) & 0xFF) as u8, 
                        ((raw_addr >> 0) & 0xFF) as u8
                    ); 

                    Ok(Self::A { 
                        domain: domain, 
                        addr: addr, 
                        ttl: raw_addr
                    })

                },

                QueryType::UNKNOWN(_) => { 
                    buffer.step(data_len as usize)?; 

                    Ok(Self::UNKNOWN{ 
                        domain: domain, 
                        qtype: qtype_num, 
                        data_len: data_len, 
                        ttl: ttl 
                    })
                }
        }

    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket { 
    pub header: DnsHeader, 
    pub questions: Vec<DnsQuestion>, 
    pub answers: Vec<DnsRecord>, 
    pub authorities: Vec<DnsRecord>, 
    pub resources: Vec<DnsRecord> 
}

impl DnsPacket { 
    pub fn new() -> Self {
        Self { 
            header: DnsHeader::new(), 
            questions: Vec::new(), 
            answers: Vec::new(), 
            authorities: Vec::new(), 
            resources: Vec::new()
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self>  {
        
        let mut result = DnsPacket::new(); 
        result.header.read(buffer)?;

        for _ in 0..result.header.questions { 
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers { 
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec); 
        }

        for _ in 0..result.header.authoritative_entries { 
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 1..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

}