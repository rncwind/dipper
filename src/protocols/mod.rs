use dns::{DNSType, DNSValue};
use log::info;
use ssh::SSHType;

mod dns;
mod ssh;

pub trait KnownProtocol {
    fn classify_proto(payload: Vec<u8>) -> Result<ProtocolType, ()>;
    fn extract_info(&self, payload: Vec<u8>) -> ExtractedInfo;
}

#[derive(Debug)]
pub enum ProtocolType {
    DNS(DNSType),
    SSH,
}

#[derive(Debug)]
pub enum ExtractedInfo {
    DNSQuery(DNSValue),
}

pub fn extract_info(ptype: ProtocolType, payload: Vec<u8>) -> Option<ExtractedInfo> {
    match ptype {
        ProtocolType::DNS(x) => match x {
            //DNSType::Query => Some(ExtractedInfo::DNSQuery(dns::analyse_dns_query(payload))),
            DNSType::Query => Some(x.extract_info(payload)),
            DNSType::Response => {
                info!("DNS Response processing not handled yet!");
                None
            }
        },
        ProtocolType::SSH => {
            todo!()
        }
    }
}

pub fn match_protocol(payload: Vec<u8>) -> Result<ProtocolType, ()> {
    if let Ok(x) = dns::DNSType::classify_proto(payload) {
        return Ok(x);
    }
    Err(())
}
