use dns::{DNSType, DNSValue};

mod dns;
mod ssh;

pub trait KnownProtocol {
    fn classify_proto(payload: Vec<u8>) -> Result<ProtocolType, ()>;
    fn extract_info(&self, payload: Vec<u8>) -> ExtractedInfo;
}

#[derive(Debug)]
pub enum ProtocolType {
    DNS(DNSType),
}

#[derive(Debug)]
pub enum ExtractedInfo {
    DNSQuery(DNSValue),
}

pub fn extract_info(ptype: ProtocolType, payload: Vec<u8>) -> Option<ExtractedInfo> {
    match ptype {
        ProtocolType::DNS(x) => match x {
            DNSType::Query => {
                return Some(ExtractedInfo::DNSQuery(dns::analyse_dns_query(payload)));
            }
            DNSType::Response => return None,
        },
    }
}

pub fn match_protocol(payload: Vec<u8>) -> Result<ProtocolType, ()> {
    if let Ok(x) = dns::is_dns(payload) {
        return Ok(ProtocolType::DNS(x));
    };
    Err(())
}
