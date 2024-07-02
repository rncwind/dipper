use std::fmt;
use std::fmt::Display;

pub fn as_u16(a: u8, b: u8) -> u16 {
    (a as u16) << 8 | b as u16
}

pub struct Stats {
    pub total_packets: usize,
    pub known_packets: usize,
    pub unknown_packets: usize,
    pub errored_packets: usize,
    pub empty_payload: usize,
    pub analyzed: usize,
}

impl Stats {
    pub fn new() -> Stats {
        Stats {
            total_packets: 0,
            known_packets: 0,
            unknown_packets: 0,
            errored_packets: 0,
            empty_payload: 0,
            analyzed: 0,
        }
    }

    fn percent_known(self) -> f64 {
        self.total_packets as f64 / self.known_packets as f64
    }

    fn percent_error(self) -> f64 {
        self.total_packets as f64 / self.errored_packets as f64
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Total: {}\nKnown/Analyzed: {}({})\nUnknown: {}\nErrored: {}\nEmpty: {}",
            self.total_packets,
            self.known_packets,
            self.analyzed,
            self.unknown_packets,
            self.errored_packets,
            self.empty_payload
        )
    }
}
