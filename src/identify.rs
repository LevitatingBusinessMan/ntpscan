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
        vvprintln!("{}: identify scan is accepting timeout", target.address);
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
