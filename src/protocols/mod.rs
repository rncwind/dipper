use dns::{DNSType, DNSValue};

mod dns;

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
    match dns::is_dns(payload) {
        Ok(x) => return Ok(ProtocolType::DNS(x)),
        Err(_) => {}
    };
    return Err(());
}
