use crate::packets;
use crate::packets::AnyNTPPacket;
use crate::packets::NtpControlMessage;
use crate::packets::NtpdPrivatePacket;
use crate::scan::ScanState;
use crate::scan::ScanTypeStatus;
use crate::variables::Mode6Variables;

pub struct MonlistRequestStatus {
    retries: u32,
}

impl MonlistRequestStatus {
    pub fn new() -> Self {
        Self {
            retries: 0
        }
    }
}

pub fn init(state: &mut ScanState) {
    let mut msg = NtpdPrivatePacket::empty();
    msg.version = 2;
    msg.implementation = packets::private::IMPL_XNTPD;
    msg.reqcode = crate::packets::private::REQ_MON_GETLIST;
    state.queue.push_back(AnyNTPPacket::Private(msg));

    /* TODO
     * ntpdc will actually attempt multiple types of requests to get an actual response
     * because the interface has changed,
     * we need to do the same
     */

}

pub fn receive(state: &mut ScanState, pkt: &AnyNTPPacket) -> ScanTypeStatus {
    match pkt {
        AnyNTPPacket::Private(pkt) => {

            if pkt.reqcode != crate::packets::private::REQ_MON_GETLIST_1 && pkt.reqcode != crate::packets::private::REQ_MON_GETLIST  {
                vprintln!("{} (mode 7) monlist request received a mode 7 response with a different reqcode {:x?}", state.address, pkt.reqcode);
            } else if pkt.response != true {
                vprintln!("{} (mode 7) received private request instead of response, quitting", state.address);
                // it might've just echo'd our request
                return ScanTypeStatus::Done
            }
            else if pkt.error != 0 {
                vprintln!("{} received monlist response with error", state.address);
            } else {
                state.supports_monlist = true;
                vprintln!("{} received monlist response!!! ({} items)", state.address, pkt.nitems);
                return ScanTypeStatus::Done;
            }
        },
        _other => {
            vprintln!("{} (mode 7) monlist request received non-private mode response", state.address)
        }
    }

    ScanTypeStatus::Continue
}

pub fn timeout(state: &mut ScanState) -> ScanTypeStatus {
    if state.monlist_request_status.retries < state.maxretries {
        let mut msg = NtpdPrivatePacket::empty();
        msg.version = 2;
        // retry with older implementation
        msg.implementation = packets::private::IMPL_XNTPD_OLD;
        msg.reqcode = crate::packets::private::REQ_MON_GETLIST_1;
        state.queue.push_back(AnyNTPPacket::Private(msg));
        state.monlist_request_status.retries += 1;
        ScanTypeStatus::Continue
    } else {
        vprintln!("{} (mode 7) monlist timed out", state.address);
        ScanTypeStatus::Done
    }
}
