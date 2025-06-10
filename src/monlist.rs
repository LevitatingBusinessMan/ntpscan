use crate::packets;
use crate::packets::AnyNTPPacket;
use crate::packets::NtpControlMessage;
use crate::packets::NtpdPrivatePacket;
use crate::scan::ScanState;
use crate::scan::ScanTypeStatus;
use crate::variables::Mode6Variables;

pub fn init(state: &mut ScanState) {
    let mut msg = NtpdPrivatePacket::empty();
    msg.version = 2;
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
            } else {
                state.supports_monlist = true;
                println!("{} received monlist response!!! ({} items)", state.address, pkt.nitems);
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
    vvprintln!("{} monlist scan accepting timeout", state.address);
    ScanTypeStatus::Done
}
