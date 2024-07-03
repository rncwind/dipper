use crate::{util::*, ExtractedInfo, KnownProtocol, ProtocolType};

pub type SSHType = ();

impl KnownProtocol for SSHType {
    fn classify_proto(payload: Vec<u8>) -> Result<ProtocolType, ()> {
        if payload[0] == 0x53 && payload[1] == 0x53 && payload[2] == 0x48 {
            Ok(ProtocolType::SSH)
        } else {
            Err(())
        }
    }

    fn extract_info(&self, payload: Vec<u8>) -> ExtractedInfo {
        todo!()
    }
}
