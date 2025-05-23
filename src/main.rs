#![feature(file_buffered)]
use clap::Parser;
use std::io;
use std::fs;
use std::io::BufRead;
use std::os::fd::AsRawFd;

mod send;
mod socket;
mod args;
mod receive;
mod packets;

fn main() -> io::Result<()> {
    let args = args::Args::parse();
    if args.verbose > 0 {
        println!("ntpscan was executed with the following arguments:\n{:?}", args);
    }
    let targets = if args.target.is_some() {
        args.target.unwrap()
    } else {
        let path = args.iplist.expect("Neither TARGET or iplist is set");
        let file = fs::File::open_buffered(path)?;
        // collecting isn't a great idea
        file.lines().map(|l| l.expect("malformed line")).collect()
    };

    let sockfd = socket::setup_socket().expect("Failed to bind UDP socket");

    // Some socket test code
    use nix::sys::socket::*;
    use std::str::FromStr;
    sendto(sockfd.as_raw_fd(), packets::STANDARD_CLIENT_MODE, &SockaddrIn::from_str("127.0.0.1:123").unwrap(), MsgFlags::empty())?;
    std::thread::sleep(std::time::Duration::new(1,0));
    let mut recvbuf: [u8; 1024] = [0; 1024];
    let (nread, src) = recvfrom::<SockaddrIn>(sockfd.as_raw_fd(), &mut recvbuf).expect("Failed to recvfrom");

    println!("{nread} bytes from {src:?}\n{recvbuf:x?}");

    Ok(())
}
