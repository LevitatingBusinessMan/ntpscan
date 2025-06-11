#![feature(file_buffered)]
use chrono::Local;
use clap::Parser;
use nix::sys::socket::SockaddrIn;
use nix::sys::socket::SockaddrIn6;
use socket::SockAddrInet;
use std::fs;
use std::io::BufRead;
use std::str::FromStr;
use std::time::Instant;

mod send;
mod socket;
mod args;
// mod receive;
mod packets;
mod identify;
mod scan;
#[macro_use]
mod log;
mod monlist;
mod variables;
mod save;

fn main() -> anyhow::Result<()> {
    let args = args::Args::parse();
    log::set_level(args.verbose);
    vprintln!("ntpscan was executed with the following arguments:\n{:?}", args);

    let targets: Box<dyn Iterator<Item = String>> = if args.target.is_some() {
        Box::new(args.target.as_ref().unwrap().iter().map(|s| s.clone()))
    } else {
        let path = args.iplist.expect("Neither TARGET nor iplist is set");
        let file = fs::File::open_buffered(path)?;
        Box::new(file.lines().map(|l| l.expect("malformed line")))
    };

    // convert addresses
    let addresses: Vec<SockAddrInet> = targets.map(|target| {
        let addr: socket::SockAddrInet;
        if let Ok(addr4) = SockaddrIn::from_str(&format!("{target}:123")) {
            addr = SockAddrInet::IPv4(addr4)
        } else if let Ok(addr6) = SockaddrIn6::from_str(&format!("[{target}]:123")) {
            addr = SockAddrInet::IPv6(addr6)
        } else {
            panic!("Invalid IPv4 or Ipv6 {target}");
        };
        addr
    }).collect();

    let start_time = Instant::now();

    let targets_p_thread = addresses.len().div_ceil(args.threads.into());

    let mut receivers = vec![];

    for chunk in addresses.chunks(targets_p_thread) {
        let rx = scan::start_thread(chunk.to_vec(), args.retries, args.targets_per_thread, args.poll, args.spread);
        receivers.push(rx);
    }

    vprintln!("Scanning {} targets using {} threads each scanning at most {} targets concurrently", addresses.len(), receivers.len(), args.targets_per_thread);

    loop {
        receivers.retain(|rx| {
            match rx.recv() {
                Ok(res) => {
                    save::save_result(res);
                    true
                },
                Err(_) => {
                    false
                },
            }
        });
        if receivers.is_empty() {
            break;
        }
    }

    println!("Scan ended on {} after {}s", Local::now().format("%A %B %d %Y at %H:%M:%S"), start_time.elapsed().as_secs());

    // let mut results = vec![];

    // for target in targets {
    //     let addr: Box<dyn SockaddrLike>;
    //     if let Ok(addr4) = SockaddrIn::from_str(&format!("{target}:123")) {
    //         addr = Box::new(addr4);
    //     } else if let Ok(addr6) = SockaddrIn6::from_str(&format!("[{target}]:123")) {
    //         addr = Box::new(addr6);
    //     } else {
    //         bail!("Invalid IPv4 or Ipv6 {target}");
    //     };
    //     let (vs, guess) = identify::version_check(addr.as_ref(), args.verbose, args.retries, &target)?;
    //     results.push(ScanResult {
    //         ip: target,
    //         daemon_guess: guess,
    //         versions: vs,
    //     });
    // }

    // if let Some(path) = args.output_file {
    //     let mut file = fs::OpenOptions::new()
    //         .create(true)
    //         .write(true)
    //         .open(path)?;
    //     match args.output_format {
    //         args::OutputFormat::CSV => {
    //             file.write(ScanResult::csv_header().as_bytes())?;
    //             file.write(b"\n")?;
    //             for res in results {
    //                 file.write(res.csv().as_bytes())?;
    //                 file.write(b"\n")?;
    //             }
    //         },
    //         _ => todo!(),
    //     }
    // }

    Ok(())
}
