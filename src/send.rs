use std::os::fd::AsRawFd;
use std::time::Duration;
use nix::sys::socket::{sendto, MsgFlags, SockaddrLike};

use crate::{packets::NTPPacket, socket::SockAddrInet};

// TODO sendmmsgs could be useful
/// Send many packets to many adresses.
/// 
/// Special care should be taken when sending packets to addresses in succession.
/// As the ratelimiting methods differs from daemon and default configurations.
/// Some allow quick burts, some don't.
/// 
/// https://chrony-project.org/doc/3.4/chrony.conf.html.
/// https://support.ntp.org/Support/AccessRestrictions
pub fn sendmany<T: AsRawFd>(pks: &[NTPPacket], fd: T, addrs: &[&dyn SockaddrLike], spread: Option<Duration>) -> nix::Result<()>{
    for addr in addrs {
        for (i, pk) in pks.iter().enumerate() {
            let out: &[u8] = &pk.pack();
            let nsent = sendto(fd.as_raw_fd(), out, *addr, MsgFlags::empty())?;
            if nsent != out.len() {
                return Err(nix::Error::UnknownErrno)
            }
            if let Some(spread) = spread && i < pks.len()-1 {
                std::thread::sleep(spread);
            }
        }
    }

    Ok(())
}

pub fn send<T: AsRawFd>(pkt: &NTPPacket, fd: &T, addr: &SockAddrInet) -> nix::Result<()>{
    let out: &[u8] = &pkt.pack();
    let nsent = sendto(fd.as_raw_fd(), &out, addr.as_sockaddr_like(), MsgFlags::empty())?;
    if nsent != out.len() {
        // could this occur in practice?
        return Err(nix::Error::UnknownErrno)
    }
    Ok(())
}
