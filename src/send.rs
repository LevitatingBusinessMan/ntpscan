use std::os::fd::AsRawFd;
use nix::sys::socket::{sendto, MsgFlags, SockaddrLike};

use crate::packets::NTPPacket;

// TODO sendmmsgs could be useful
/// send many packets to many adresses
pub fn sendmany<T: AsRawFd>(pks: &[NTPPacket], fd: T, addrs: &[&dyn SockaddrLike]) -> nix::Result<()>{
    for pk in pks {
        for addr in addrs {
            let out: &[u8] = &pk.pack();
            let nsent = sendto(fd.as_raw_fd(), out, *addr, MsgFlags::empty())?;

            if nsent != out.len() {
                return Err(nix::Error::UnknownErrno)
            }
        }
    }
    Ok(())
}
