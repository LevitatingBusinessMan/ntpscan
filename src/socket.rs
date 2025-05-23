use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::str::FromStr;
use nix::errno::Errno;
use nix::sys::socket::*;

/// Create a udp socket using [nix::sys::socket::socket].
/// When used it will automatically bind to `INADDR_ANY` and a random port.
/// See also man udp(7).
pub fn setup_socket() -> Result<OwnedFd, Errno> {
    socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None
    )
}
