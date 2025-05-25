use std::os::fd::OwnedFd;
use nix::errno::Errno;
use nix::sys::socket::*;

/// Create a udp socket using [nix::sys::socket::socket].
/// It be non-blocking.
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
