use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use nix::errno::Errno;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::poll::poll;
use nix::sys::socket::recvfrom;
use nix::sys::socket::SockaddrIn;
use crate::packets;
use crate::socket;
use crate::packets::NTPPacket;
use crate::send;

pub fn version_check(target: &SockaddrIn, verbosity: u8, retries: u8) -> anyhow::Result<(Vec<u8>, &'static str)> {
    use nix::sys::socket::SockaddrIn;

    let versions = [1,3,7];

    let maxretries = retries;
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
        send::sendmany(&out, sockfd.as_fd(), &[target])?;
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
                            println!("{nread} bytes from {:?}", src.unwrap().ip());
                            println!("{pkt:#?}");
                        }
                        if verbosity > 0 {
                            println!("Target responded with version {}", pkt.version);
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
        println!("Target responded with versions {discovered_versions:?}");
    }

    let guess = match discovered_versions.as_slice() {
        [1, 3, 7] => "ntpd",
        [1, 3] => "chronyd",
        [3] => "ntpd-rs",
        [] => "offline",
        _ => "unknown",
    };

    println!("Guessing daemon is: {guess} ({})", target.ip());

    Ok((discovered_versions, guess))
}
