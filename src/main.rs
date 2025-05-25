#![feature(file_buffered)]
use clap::Parser;
use nix::errno::Errno;
use nix::poll::poll;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::sys::socket::recvfrom;
use nix::sys::socket::SockaddrIn;
use nix::sys::socket::SockaddrLike;
use packets::NTPPacket;
use std::collections::HashMap;
use std::fs;
use std::io::BufRead;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::str::FromStr;

mod send;
mod socket;
mod args;
mod receive;
mod packets;

fn main() -> anyhow::Result<()> {
    let args = args::Args::parse();
    if args.verbose > 1 {
        println!("ntpscan was executed with the following arguments:\n{:?}", args);
    }

    let targets: Box<dyn Iterator<Item = String>> = if args.target.is_some() {
        Box::new(args.target.as_ref().unwrap().iter().map(|s| s.clone()))
    } else {
        let path = args.iplist.expect("Neither TARGET or iplist is set");
        let file = fs::File::open_buffered(path)?;
        Box::new(file.lines().map(|l| l.expect("malformed line")))
    };

    for target in targets {
        let ip = SockaddrIn::from_str(&format!("{target}:123"))?;
        version_check(&ip, args.verbose)?;
    }

    Ok(())
}

pub fn version_check(target: &dyn SockaddrLike, verbosity: u8) -> anyhow::Result<()> {
    use nix::sys::socket::SockaddrIn;

    let versions = [1,3,7];

    let maxretries = 2;
    let mut retries = HashMap::<u8, u8>::from(versions.map(|vi| (vi, 0)));
    let mut discovered_versions = vec![];

    if verbosity > 0 {
        println!("Attempting mode 3 requests with versions {versions:?}");
    }

    let sockfd = socket::setup_socket().expect("Failed to bind UDP socket");

    let mut tryversions = versions.to_vec();

    loop {
        let mut out = vec![];
        for vi in &tryversions {
            let mut msg = NTPPacket::empty();
            msg.version = *vi;
            msg.mode = 3;
            out.push(msg);
        }
        send::sendmany(&out, sockfd.as_fd(), vec![target].as_slice())?;
        tryversions.clear();

        let mut recvbuf: [u8; 1024] = [0; 1024];

        let timeout = PollTimeout::from(1000 as u16);

        if verbosity > 0 {
            println!("Polling for {}ms...", timeout.as_millis().unwrap());
        }

        let npoll = poll(&mut [PollFd::new(sockfd.as_fd(), PollFlags::POLLIN)], timeout)?;
        if npoll > 0 {
            // read until EAGAIN
            loop {
                match recvfrom::<SockaddrIn>(sockfd.as_raw_fd(), &mut recvbuf) {
                    Ok((nread, src)) => {
                        let pkt = packets::parse(&recvbuf[0..nread])?;
                        if verbosity > 1 {
                            println!("{nread} bytes from {src:?}");
                            println!("{pkt:#?}");
                            println!("");
                        }
                        if verbosity > 0 {
                            println!("target responded with version {}", pkt.version);
                        }
                        if !discovered_versions.contains(&pkt.version) {
                            discovered_versions.push(pkt.version);
                        }
                    },
                    Err(Errno::EAGAIN) => {
                        break;
                    },
                    Err(e) => return Err(e.into()),
                }
            }
        }

        for vi in versions {
            if discovered_versions.contains(&vi) {
                continue;
            }
            let mut tries = *retries.get(&vi).unwrap();
            if tries < maxretries {
                tries += 1;
                retries.insert(vi, tries);
                tryversions.push(vi);
                if verbosity > 0 {
                    println!("Retrying w/ version {vi} ({tries}/{maxretries})")
                }
            }
        }

        if tryversions.is_empty() {
            break;
        }
    }

    discovered_versions.sort();

    if verbosity > 0 {
        println!("target responded with versions {discovered_versions:?}");
    }

    let guess = match discovered_versions.as_slice() {
        [1, 3, 7] => "ntpd",
        [1, 3] => "chronyd",
        [3] => "ntpd-rs",
        _ => "Unknown",
    };

    println!("Guessing daemon is: {guess}");

    Ok(())
}
