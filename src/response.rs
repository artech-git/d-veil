#![allow(dead_code)]



#[derive(Debug, PartialEq, PartialOrd, Eq)]
pub struct DnsResponse { 
    id: u16, 
    headers: u16, 
    
}

impl std::convert::From<DnsResponse> for Vec<u8> {
    fn from(_value: DnsResponse) -> Self {
        vec![]
    }
}