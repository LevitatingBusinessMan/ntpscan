use crate::packets;
use crate::scan::ScanState;

fn init(state: &mut ScanState) {
    let msg = packets::NTPPacket::empty();
}
