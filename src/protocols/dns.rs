use crate::util::*;
use nom::{
    bytes::complete::{tag, take},
    combinator::map,
    multi::{length_data, many_till},
    sequence::tuple,
    IResult, Parser,
};

use tracing::*;

#[derive(Debug)]
pub enum DNSType {
    Query,
    Response,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DNSValue {
    pub txid: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_rrs: u16,
    pub auth_rrs: u16,
    pub additional_rrs: u16,
    pub questions: Option<Vec<String>>,
    pub answers: Option<Vec<String>>,
    pub question_type: u16,
    pub question_class: u16,
    pub remainder: Option<Vec<u8>>,
}

pub fn is_dns(payload: Vec<u8>) -> Result<DNSType, ()> {
    if is_dns_query(&payload) {
        return Ok(DNSType::Query);
    }
    if is_dns_response(&payload) {
        return Ok(DNSType::Response);
    }
    Err(())
}

fn is_dns_query(payload: &[u8]) -> bool {
    payload[2] == 0x01 && payload[3] == 0x00
}

fn is_dns_response(payload: &[u8]) -> bool {
    payload[2] == 0x81 && payload[3] == 0x80
}

fn ld(s: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(nom::number::complete::u8)(s)
}

fn parse_dns_string(payload: &[u8]) -> IResult<&[u8], (Vec<&[u8]>, &[u8])> {
    let mut parser = many_till(ld, tag([0x00]));
    parser.parse(payload)
}

fn take_two_as_u16(payload: &[u8]) -> IResult<&[u8], u16> {
    let mut parser = map(take(2_u8), |s: &[u8]| as_u16(s[0], s[1]));
    parser.parse(payload)
}

fn parse_dns_preamble(payload: &[u8]) -> IResult<&[u8], (u16, u16, u16, u16, u16, u16)> {
    let mut parser = tuple((
        take_two_as_u16,
        take_two_as_u16,
        take_two_as_u16,
        take_two_as_u16,
        take_two_as_u16,
        take_two_as_u16,
    ));
    parser.parse(payload)
}

fn parse_query_postamble(payload: &[u8]) -> IResult<&[u8], (u16, u16)> {
    let mut parser = tuple((take_two_as_u16, take_two_as_u16));
    parser.parse(payload)
}

fn parsed_dns_string_to_real_string(data: Vec<Vec<u8>>) -> String {
    let mut domain_name = String::from("");
    for (i, subpart) in data.into_iter().enumerate() {
        let as_str = String::from_utf8_lossy(&subpart);
        if i == 0 {
            domain_name = as_str.to_string()
        } else {
            domain_name = format!("{}.{}", domain_name, as_str);
        }
    }
    domain_name
}

pub fn analyse_dns_query(payload: Vec<u8>) -> DNSValue {
    let mut parser = tuple((parse_dns_preamble, parse_dns_string, parse_query_postamble));
    let result = parser.parse(&payload).unwrap();
    let remainder = result.0;
    let preamble = result.1 .0;
    let string_fragments = result.1 .1 .0;
    let postamble = result.1 .2;
    trace!("Preamble : {:02X?}", preamble);
    trace!("strings {:02X?}", string_fragments);
    trace!("postamble {:02X?}", postamble);
    let mut string_parts: Vec<Vec<u8>> = Vec::new();
    for substring in string_fragments {
        string_parts.push(substring.to_vec());
    }
    let real_query_string = parsed_dns_string_to_real_string(string_parts);

    let real_remainder = if remainder.is_empty() {
        None
    } else {
        Some(remainder.to_vec())
    };

    DNSValue {
        txid: preamble.0,
        flags: preamble.1,
        question_count: preamble.2,
        answer_rrs: preamble.3,
        auth_rrs: preamble.4,
        additional_rrs: preamble.5,
        question_type: postamble.0,
        question_class: postamble.1,
        remainder: real_remainder,
        questions: Some(vec![real_query_string]),
        answers: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_txt_query_parse() {
        let packet_bytes: [u8; 28] = [
            0x10, 0x32, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01,
        ];
        let parsed_query = analyse_dns_query(packet_bytes.to_vec());

        let expected = DNSValue {
            txid: 0x1032,
            flags: 0x0100,
            question_count: 1,
            answer_rrs: 0,
            auth_rrs: 0,
            additional_rrs: 0,
            questions: Some(vec!["google.com".to_string()]),
            answers: None,
            question_type: 16,
            question_class: 0x0001,
            remainder: None,
        };

        assert!(parsed_query == expected);
    }

    #[test]
    fn test_parse_dns_string() {
        let packet_bytes: [u8; 13] = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x01,
        ];
        let (_, result) = parse_dns_string(&packet_bytes).unwrap();
        let mut string_parts: Vec<Vec<u8>> = Vec::new();
        for substring in result.0 {
            string_parts.push(substring.to_vec());
        }
        let real_string = parsed_dns_string_to_real_string(string_parts);

        assert!(real_string == *"google.com")
    }

    #[test]
    fn test_dns_a_record_query_parse() {
        let packet_bytes: [u8; 32] = [
            0x75, 0xc0, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x6e, 0x65, 0x74, 0x62, 0x73, 0x64, 0x03, 0x6f, 0x72, 0x67, 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let parsed_query = analyse_dns_query(packet_bytes.to_vec());

        let expected = DNSValue {
            txid: 0x75c0,
            flags: 0x0100,
            question_count: 1,
            answer_rrs: 0,
            auth_rrs: 0,
            additional_rrs: 0,
            questions: Some(vec!["www.netbsd.org".to_string()]),
            answers: None,
            question_type: 1,
            question_class: 0x0001,
            remainder: None,
        };

        assert!(parsed_query == expected);
    }
}
