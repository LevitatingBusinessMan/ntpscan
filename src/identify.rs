use std::collections::HashMap;
use std::iter::Scan;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::time::Duration;
use nix::errno::Errno;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::poll::poll;
use nix::sys::socket::recvfrom;
use nix::sys::socket::SockaddrLike;
use crate::packets;
use crate::scan::ScanTypeStatus;
use crate::socket;
use crate::packets::NTPPacket;
use crate::send;
use crate::scan::ScanState;
use crate::vprintln;
use crate::vvprintln;

pub fn init(target: &mut ScanState) {
    // we only attempt these versions because they provide the most interesting results,
    // sending too many packets may lead to ratelimiting
    let versions_to_scan = [1,3,4,7];

    // push all version packets onto the queue
    for vi in versions_to_scan {
        let mut msg = NTPPacket::empty();
        msg.version = vi;
        msg.mode = 3;
        msg.xmt = rand::random::<u64>();
        target.versions.insert(vi, VersionState { retries: 0, xmt: msg.xmt, response: None });
        target.queue.push_back(msg);
    }
}

/// state of an attempt to test a version response
#[derive(Clone)]
pub struct VersionState {
    retries: u8,
    xmt: u64,
    response: Option<NTPPacket>
}

pub fn receive(target: &mut ScanState, pkt: &NTPPacket) -> ScanTypeStatus {
    // rate kods are already handled timeout wise
    // but when receiving one we should requeue a bunch of stuff

    let mypkt = target.versions.iter_mut().find(|(_v, vs)| {
        vs.xmt == pkt.org
    });

    match mypkt {
        Some((version_sent, vs)) => {
            match vs.response {
                Some(_) => println!("{}: received response to version {version_sent} twice?", target.address),
                None => {
                    vprintln!("{}: version {version_sent} was responded to with {}", target.address, pkt.version);
                    vs.response = Some(pkt.clone());
                },
            }
        },
        None => {
            println!("{}: received og timestamp which we did not send?", target.address);
        },
    }

    if pkt.is_kod() {
        // all unresolved packets should be retransmitted
        // without increasing the retry counter
        for (vi, vs) in &target.versions {
            if vs.response.is_none() && target.queue.iter().find(|p| p.xmt == vs.xmt).is_none() {
                let mut msg = NTPPacket::empty();
                msg.version = *vi;
                msg.mode = 3;
                msg.xmt = vs.xmt;
                target.queue.push_back(msg);
            }
        } 
    }

    if target.versions.iter().all(|(_, vs)| vs.response.is_some()) {
        target.daemon_guess = Some(daemon_guess(target.versions.clone()));
        return ScanTypeStatus::Done
    }

    ScanTypeStatus::Continue
}

pub fn timeout(target: &mut ScanState) -> ScanTypeStatus {
    // TODO retries should be available in the state, let's use a default for now
    let maxretries = 1;

    if !target.queue.is_empty() {
        return ScanTypeStatus::Continue
    }

    if target.versions.iter().all(|(_vi, vs)| {
        vs.response.is_some() || vs.retries == maxretries
    }) {
        vvprintln!("{}: identify scan, accepting timeout", target.address);
        target.daemon_guess = Some(daemon_guess(target.versions.clone()));
        return ScanTypeStatus::Done;
    }

    for (vi, vs) in &mut target.versions {
        if vs.response.is_none() {
            if vs.retries < maxretries {
                let mut msg = NTPPacket::empty();
                msg.version = *vi;
                msg.mode = 3;
                msg.xmt = vs.xmt;
                vs.retries += 1;
                target.queue.push_back(msg);
            }
        }
    }

    ScanTypeStatus::Continue

}

pub fn daemon_guess(versions: HashMap<u8, VersionState>) -> &'static str {
    if versions.iter().all(|(_vi, vs)| vs.response.is_none()) {
        return "offline"
    };
    return "unknown"
}

pub fn version_check(target: &dyn SockaddrLike, verbosity: u8, retries: u8, targetstr: &str) -> anyhow::Result<(Vec<u8>, &'static str)> {
    use nix::sys::socket::SockaddrIn;

    let versions = [1,3,7];

    let maxretries = retries;
    let mut retries = HashMap::<u8, u8>::from(versions.map(|vi| (vi, 0)));
    let mut discovered_versions = vec![];

    let sockfd = socket::setup_socket(target.family().unwrap()).expect("Failed to bind UDP socket");

    let mut tryversions = versions.to_vec();

    /* Rate limit variables */
    let mut spread = None;
    let mut rate_timeout = Duration::new(10, 0);
    let mut kod_count = 0;
    let poll_timeout = PollTimeout::from(1000 as u16);

    if verbosity > 0 {
        println!("Attempting mode 3 requests with versions {versions:?} (poll {}ms)", poll_timeout.as_millis().unwrap());
    }

    'outer: loop {
        let mut out = vec![];
        for vi in &tryversions {
            let mut msg = NTPPacket::empty();
            msg.version = *vi;
            msg.mode = 3;
            out.push(msg);
        }
        send::sendmany(&out, sockfd.as_fd(), &[target], spread)?;
        tryversions.clear();

        let mut recvbuf: [u8; 1024] = [0; 1024];

        // if verbosity > 0 {
        //     println!("Polling for {}ms...", poll_timeout.as_millis().unwrap());
        // }

        let npoll = poll(&mut [PollFd::new(sockfd.as_fd(), PollFlags::POLLIN)], poll_timeout)?;
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
                        if pkt.stratum == 0 {
                            if verbosity > 0 {
                                println!("Kiss-o'-Death packet received '{}'. ({targetstr})", pkt.refidstr().unwrap_or("invalid utf-8"));
                            }
                            if pkt.refidstr() == Some("RATE") {
                                match &mut spread {
                                    Some(spread) => *spread *= 2,
                                    None => spread = Some(Duration::new(6, 0)),
                                }
                                if verbosity > 0 {
                                    println!("I will sleep for {}s and use a send interval of {}s", rate_timeout.as_secs(), spread.unwrap().as_secs());
                                }
                                std::thread::sleep(rate_timeout);
                                rate_timeout *= 2;
                                kod_count += 1;
                            } else {
                                println!("Stopping enumeration due to KoD packet '{}' ({:?})", pkt.refidstr().unwrap_or("invalid utf-8"), pkt.refid);
                                break 'outer;
                            }
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
            if tries < maxretries - kod_count {
                tries += 1;
                retries.insert(vi, tries);
                tryversions.push(vi);
                if verbosity > 0 {
                    println!("Retrying w/ version {vi} (retry {tries}/{maxretries}+{kod_count}) (poll {}ms)", poll_timeout.as_millis().unwrap())
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

    println!("Guessing daemon is: {guess} ({targetstr})");

    Ok((discovered_versions, guess))
}
