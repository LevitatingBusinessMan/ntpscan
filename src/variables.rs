//! in a previous revision this module was called version
use crate::packets::AnyNTPPacket;
use crate::packets::NtpControlMessage;
use crate::scan::ScanState;
use crate::scan::ScanTypeStatus;

pub struct VersionRequestStatus {
    retries: u32,
}

impl VersionRequestStatus {
    pub fn new() -> Self {
        Self {
            retries: 0,
        }
    }
}

pub struct Mode6Variables {
    pub str: String,
}

pub fn init(state: &mut ScanState) {
    let mut msg = NtpControlMessage::empty();
    msg.version = 3;
    msg.opcode = 2;
    state.queue.push_back(AnyNTPPacket::Control(msg));
}

pub fn receive(state: &mut ScanState, pkt: &AnyNTPPacket) -> ScanTypeStatus {
    match pkt {
        AnyNTPPacket::Control(pkt) => {
            if pkt.opcode == 2 {
                if pkt.response != true {
                    vprintln!("{} (mode 6) received request instead of response, quitting", state.address);
                    // it might've just echo'd our request
                    return ScanTypeStatus::Done
                }
                if pkt.error == true {
                    vprintln!("{} (mode 6) received error response", state.address);
                    //return ScanTypeStatus::Done;
                }
                eprintln!("{} mode 6 variables response: {}", state.address, pkt.datastr().map(|s| s.trim_end_matches(char::is_whitespace))
                    .unwrap_or("failed to convert to utf-8"));
                state.mode6_variables = Some(Mode6Variables {
                    str: pkt.datastr().unwrap_or("failed to convert to utf-8").to_owned()
                });
                return ScanTypeStatus::Done;
            } else {
                vvprintln!("{} (mode 6) variables command received response with other opcode than 2", state.address)
            }
        },
        _ => {
            vvprintln!("{} (mode 6) variables command received non-control packet", state.address)
        }
    }

    ScanTypeStatus::Continue
}

pub fn timeout(state: &mut ScanState) -> ScanTypeStatus {
    if state.version_request_status.retries < state.maxretries {
        let mut msg = NtpControlMessage::empty();
        msg.version = 3;
        msg.opcode = 2;
        state.queue.push_back(AnyNTPPacket::Control(msg));
        state.version_request_status.retries += 1;
        ScanTypeStatus::Continue
    } else {
        vprintln!("{} mode 6 timed out", state.address);
        ScanTypeStatus::Done
    }
}
