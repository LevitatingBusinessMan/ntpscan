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
use crate::packets::AnyNTPPacket;
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
    let versions_to_scan = [0,1,2,3,4,5,6,7];

    // push all version packets onto the queue
    for vi in versions_to_scan {
        let mut msg = NTPPacket::empty();
        msg.version = vi;
        msg.mode = 3;
        msg.xmt = rand::random::<u64>();
        target.versions.insert(vi, VersionState { retries: 0, xmt: msg.xmt, response: None });
        target.queue.push_back(AnyNTPPacket::Standard(msg));
    }
}

/// state of an attempt to test a version response
#[derive(Clone)]
pub struct VersionState {
    retries: u32,
    xmt: u64,
    pub response: Option<NTPPacket>
}

pub fn receive(target: &mut ScanState, pkt: &AnyNTPPacket) -> ScanTypeStatus {
    let pkt = match pkt {
        AnyNTPPacket::Standard(ntppacket) => ntppacket,
        AnyNTPPacket::Control(_) => {
            vprintln!("{} received control packet during version scan??", target.address);
            return ScanTypeStatus::Continue;
        },
        AnyNTPPacket::Private(p) => {
            vprintln!("{} received mode 7 packet during version scan?? {:?}", target.address, p);
            return ScanTypeStatus::Continue;
        },
        _ => unreachable!(),
    };

    // rate kods are already handled timeout wise
    // but when receiving one we should requeue a bunch of stuff

    let mypkt = target.versions.iter_mut().find(|(_v, vs)| {
        vs.xmt == pkt.org
    });

    match mypkt {
        Some((version_sent, vs)) => {
            match vs.response {
                Some(_) => vprintln!("{} received duplicate response to version {version_sent}?", target.address),
                None => {
                    vprintln!("{} version {version_sent} was responded to with {}", target.address, pkt.version);
                    vs.response = Some(pkt.clone());
                },
            }
        },
        None => {
            vprintln!("{} received og timestamp which we did not send?", target.address);
        },
    }

    if pkt.is_kod() && pkt.refidstr() == Some("RATE") {
        // all unresolved packets should be retransmitted
        // without increasing the retry counter
        for (vi, vs) in &target.versions {
            if vs.response.is_none() && target.queue
                .iter()
                .filter_map(|p| p.as_standard())
                .find(|p| p.xmt == vs.xmt).is_none() {
                let mut msg = NTPPacket::empty();
                msg.version = *vi;
                msg.mode = 3;
                msg.xmt = vs.xmt;
                target.queue.push_back(AnyNTPPacket::Standard(msg));
            }
        } 
    }
    
    // the following behavior and commented code was properly due to a bug of my own
    //
    // I have found that on some ntpd versions any subsequent requests are dropped
    // as a temporary? fix we just give all unresolved versions
    // another free try when a response is received
    // target.versions.iter_mut()
    // .filter(|(_vi, vs)| vs.response.is_none())
    // .for_each(|(_vi, vs)| {
    //     vs.retries = vs.retries.saturating_sub(1);
    // });

    if target.versions.iter().all(|(_, vs)| vs.response.is_some()) {
        r#final(target);
        return ScanTypeStatus::Done
    }

    ScanTypeStatus::Continue
}

pub fn timeout(target: &mut ScanState) -> ScanTypeStatus {
    if !target.queue.is_empty() {
        return ScanTypeStatus::Continue
    }

    if target.versions.iter().all(|(_vi, vs)| {
        vs.response.is_some() || vs.retries == target.maxretries
    }) {
        vprintln!("{}: identify scan is accepting timeout", target.address);
        r#final(target);
        return ScanTypeStatus::Done;
    }

    vvprintln!("{} retrying mode 3 version(s)", target.address);

    for (vi, vs) in &mut target.versions {
        if vs.response.is_none() {
            if vs.retries < target.maxretries {
                let mut msg = NTPPacket::empty();
                msg.version = *vi;
                msg.mode = 3;
                msg.xmt = vs.xmt;
                vs.retries += 1;
                target.queue.push_back(AnyNTPPacket::Standard(msg));
            }
        }
    }

    ScanTypeStatus::Continue

}

pub fn r#final(state: &mut ScanState) {
    vprintln!("{} responded with versions: {}", state.address, craft_version_state_str(&state.versions));
    state.daemon_guess = Some(daemon_guess(state.versions.clone()));
}

fn craft_version_state_str(versions: &HashMap<u8, VersionState>) -> String {
    let mut versions_vec = versions
        .iter()
        .collect::<Vec<(&u8, &VersionState)>>();
    versions_vec.sort_by_key(|(vi, _vs)| **vi);
    let versions_str = versions_vec.iter()
        .filter_map(|(vi, vs)| if vs.response.is_some() { Some((vi, vs.response.as_ref().unwrap().version)) } else { None })
        .map(|(vi,vi2)| format!("{}->{}, ", vi, vi2))
        .collect::<String>();
    versions_str
}

pub fn daemon_guess(versions: HashMap<u8, VersionState>) -> &'static str {
    if versions.iter().all(|(_vi, vs)| vs.response.is_none()) {
        return "offline"
    };
    return "unknown"
}
