use std::fmt::Display;
use std::os::fd::OwnedFd;
use nix::errno::Errno;
use nix::sys::socket::*;

/// Create a udp socket using [nix::sys::socket::socket].
/// It be non-blocking.
/// When used it will automatically bind to `INADDR_ANY` and a random port.
/// See also man udp(7).
pub fn setup_socket(family: AddressFamily) -> Result<OwnedFd, Errno> {
    socket(
        family,
        SockType::Datagram,
        SockFlag::empty(),
        None
    )
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, Debug)]
pub enum SockAddrInet {
    IPv4(SockaddrIn),
    IPv6(SockaddrIn6),
}

impl SockAddrInet {
    pub fn as_sockaddr_like(&self) -> &dyn SockaddrLike {
        match self {
            SockAddrInet::IPv4(addr) => addr,
            SockAddrInet::IPv6(addr) => addr,
        }
    }
}

impl Display for SockAddrInet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SockAddrInet::IPv4(sockaddr_in) => sockaddr_in.fmt(f),
            SockAddrInet::IPv6(sockaddr_in6) => sockaddr_in6.fmt(f),
        }
    }
}

// impl SockaddrLike for SockAddrInet {
//     unsafe fn from_raw(
//         addr: *const nix::libc::sockaddr,
//         len: Option<nix::libc::socklen_t>,
//     ) -> Option<Self>
//     where Self: Sized {
//         let family = AddressFamily::from_i32(unsafe {
//             (*addr).sa_family as i32
//         })?;
//         match family {
//             AddressFamily::Inet => Some(SockAddrInet::IPv4(unsafe { SockaddrIn::from_raw(addr, len)? })),
//             AddressFamily::Inet6 => Some(SockAddrInet::IPv6(unsafe { SockaddrIn6::from_raw(addr, len)? })),
//             _ => None,
//         }
//     }
// }
