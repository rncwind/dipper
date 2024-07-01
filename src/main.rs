mod protocols;
mod util;

use std::path::PathBuf;

use clap::Parser;
use pcap::*;
use tracing::*;

use crate::protocols::*;
use crate::util::Stats;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Opts {
    #[arg(short, long)]
    pcap_file: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    print_analysis: bool,
}

#[tracing::instrument]
fn main() {
    tracing_subscriber::fmt()
        .pretty()
        .with_thread_names(true)
        .with_max_level(tracing::Level::TRACE)
        .init();
    let opt = Opts::parse();
    let mut pcap = match opt.pcap_file {
        Some(pf) => Capture::from_file(pf).expect("Invalid pcap file provided"),
        None => {
            warn!("Using example.pcap as no pcap was provided");
            Capture::from_file(PathBuf::from("./pcaps/ssh_test.pcap"))
                .expect("./pcaps/ssh_test.pcap does not exist")
        }
    };
    info!("Pcap loaded");

    let mut stats = Stats::new();

    while let Ok(packet) = pcap.next_packet() {
        stats.total_packets += 1;
        match etherparse::SlicedPacket::from_ethernet(packet.data) {
            Err(e) => {
                error!(
                    "Slicing packet {} resulted in error {:?}",
                    stats.total_packets, e
                );
                stats.errored_packets += 1;
                continue;
            }
            Ok(sliced) => {
                if !sliced.payload.is_empty() {
                    match match_protocol(sliced.payload.to_vec()) {
                        Ok(x) => {
                            stats.known_packets += 1;
                            trace!("Known packet type found: {:?}", x);
                            let extracted = extract_info(x, sliced.payload.to_vec());
                            if opt.print_analysis {
                                info!("{:?}", extracted);
                            }
                        }
                        Err(_) => stats.unknown_packets += 1,
                    }
                }
            }
        }
    }
    println!("pcap processing complete.");
    println!("{}", stats);
    //info!("There were {} packets in the pcap", pkts);
}
