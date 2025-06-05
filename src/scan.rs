use std::collections::HashMap;
use std::collections::VecDeque;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::thread;
use std::time::SystemTime;
use std::time::Duration;
use std::sync::mpsc;
use nix::poll::poll;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::sys::socket::recvfrom;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockaddrIn;
use nix::sys::socket::SockaddrIn6;
use crate::identify;
use crate::packets;
use crate::packets::NTPPacket;
use crate::scan;
use crate::send;
use crate::socket;
use crate::socket::SockAddrInet;
use crate::vprintln;
use crate::vvprintln;

/// What scan type is being done currently?
enum ScanType {
    Prepare,
    Identify,
    Version,
    Monlist,
    Done,
}

/// This structure is the scan state of an address
pub struct ScanState {
    pub address: SockAddrInet,
    pub daemon_guess: Option<&'static str>,
    /// key is the version sent,
    /// value is the retry count, xmt and response
    pub versions: HashMap<u8, identify::VersionState>,
    pub timeout_till: Option<SystemTime>,
    pub timeout_on_rate_kod: Duration,
    pub interval: Option<Duration>,
    /// the outgoing packet queue, packets placed here
    /// will be sent when the timout allows it
    pub queue: VecDeque<NTPPacket>,
    current_type: ScanType,
}

pub enum ScanTypeStatus {
    Continue,
    Done,
}

impl ScanState {
    fn new(address: SockAddrInet) -> Self {
        ScanState {
            address,
            daemon_guess: None,
            versions: HashMap::new(),
            timeout_till: None,
            timeout_on_rate_kod: Duration::from_secs(10),
            interval: None,
            current_type: ScanType::Prepare,
            queue: VecDeque::new(),
        }
    }
    fn start_next_scan(&mut self) {
        match self.current_type {
            ScanType::Prepare => {
                self.current_type = ScanType::Identify;
                identify::init(self);
            },
            ScanType::Identify => todo!(),
            ScanType::Version => todo!(),
            ScanType::Monlist => todo!(),
            ScanType::Done => todo!(),
        }
    }
    fn choose_sock<T: AsRawFd>(&self, sockfd4: T, sockfd6: T) -> T {
        match self.address {
            SockAddrInet::IPv4(_) => sockfd4,
            SockAddrInet::IPv6(_) => sockfd6,
        }
    }
    fn flush<T: AsRawFd>(&mut self, sock: T) -> nix::Result<()> {
        vvprintln!("{}: attempting to flush {} packets", self.address, self.queue.len());
        loop {
            if self.may_send() {
                let msg = self.queue.pop_front();
                match msg {
                    Some(msg) => {
                        vvprintln!("{}: sending packet", self.address);
                        send::send(&msg, &sock, &self.address)?;
                        if let Some(interval) = self.interval {
                            self.timeout_till = Some(SystemTime::now() + interval);
                        }
                    },
                    None => break,
                }
            } else {
                break;
            }
        }
        Ok(())
    }
    fn may_send(&self) -> bool {
        if let Some(timeout) = self.timeout_till {
            timeout < SystemTime::now()
        } else {
            true
        }
    }
    fn recpkt(&mut self, pkt: &NTPPacket) -> ScanTypeStatus {
        match self.current_type {
            ScanType::Prepare => unreachable!(),
            ScanType::Identify => identify::receive(self, pkt),
            ScanType::Version => todo!(),
            ScanType::Monlist => todo!(),
            ScanType::Done => todo!(),
        }
    }
    fn handle_timeout(&mut self) -> ScanTypeStatus {
        match self.current_type {
            ScanType::Prepare => unreachable!(),
            ScanType::Identify => identify::timeout(self),
            ScanType::Version => todo!(),
            ScanType::Monlist => todo!(),
            ScanType::Done => todo!(),
        }
    }
    fn handle_rate_kod(&mut self) {
        self.timeout_till = Some(SystemTime::now() + self.timeout_on_rate_kod);
        self.timeout_on_rate_kod *= 2;
        match self.interval {
            Some(d) => self.interval = Some(d * 2),
            None => self.interval = Some(Duration::from_secs(6)),
        }
        vvprintln!("{}: waiting {}s, interval is {}s", self.address, self.timeout_on_rate_kod.as_secs()/2, self.interval.unwrap().as_secs());
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub version_guess: &'static str,
}

pub fn start_thread(targets: Vec<SockAddrInet>, retries: u8, concurrent: usize) -> mpsc::Receiver<ScanResult> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        scan_thread(tx, &targets, retries, concurrent);
    });
    rx
}

fn scan_thread(tx: mpsc::Sender<ScanResult>, targets: &[SockAddrInet], retries: u8, concurrent: usize) {
    let i = concurrent.min(targets.len());
    let mut states: HashMap<SockAddrInet, ScanState> = HashMap::new();
    for state in targets[0..i].iter().map(|a| ScanState::new(*a)) {
        if states.contains_key(&state.address) {
            println!("duplicate address {}", state.address);
        } else {
            states.insert(state.address, state);
        }
    }
    
    let sockfd4 = socket::setup_socket(AddressFamily::Inet).expect("Failed to bind IPv4 UDP socket");
    let sockfd6 = socket::setup_socket(AddressFamily::Inet6).expect("Failed to bind IPv6 UDP socket");

    // TODO the following code usees various unwraps and expects that have to be handled appropiately

    // initialize the first scan for all targets
    for (_, state) in states.iter_mut() {
        state.start_next_scan();
        // TODO remove unwrap
        state.flush(state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).unwrap();
    }

    let mut pollfds = [
        PollFd::new(sockfd4.as_fd(), PollFlags::POLLIN),
        PollFd::new(sockfd6.as_fd(), PollFlags::POLLIN),
    ];
    let poll_timeout = PollTimeout::from(1000 as u16);
    let mut recvbuf: [u8; 1024] = [0; 1024];

    'outer: loop {
        vvprintln!("polling...");
        let npoll = poll(&mut pollfds, poll_timeout).expect("poll(2) failed");
        if npoll > 0 {
            // the src ip will be mapped to a [SockAddrInet]
            let recvfromres;
            if pollfds[0].any() == Some(true) {
                recvfromres = recvfrom::<SockaddrIn>(sockfd4.as_raw_fd(), &mut recvbuf)
                    .map(|(n, osrc)| (n, osrc.map(|src| SockAddrInet::IPv4(src))));
            } else if pollfds[1].any() == Some(true) {
                recvfromres = recvfrom::<SockaddrIn6>(sockfd6.as_raw_fd(), &mut recvbuf)
                    .map(|(n, osrc)| (n, osrc.map(|src| SockAddrInet::IPv6(src))));
            } else {
                unreachable!()
            }
            match recvfromres {
                Ok((nread, Some(src))) => {
                    let pkt = packets::parse(&recvbuf[0..nread]).expect("Failed to parse pkt");
                    vvprintln!("{nread} bytes from {src}");
                    vvprintln!("{pkt:?}");

                    match states.get_mut(&src) {
                        Some(state) => {
                            // TODO handle DENY and RSTR
                            if pkt.is_kod() && pkt.refidstr() == Some("RATE") {
                                vprintln!("{}: Kiss o' Death RATE received", state.address);
                                state.handle_rate_kod();
                            }
                            let scanstatus = state.recpkt(&pkt);
                            state.flush(state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).expect("error flushing");
                            if matches!(scanstatus, ScanTypeStatus::Done) {
                                state.start_next_scan();
                            }
                        },
                        None => {
                            println!("received packet from {src}, which isn't part of the target list???");
                        },
                    }
                },
                Err(e) => println!("received errno {e:?} from recvfrom"),
                _ => unreachable!(),
            }
        } else {
            vvprintln!("poll timeout");
            for (addr, state) in states.iter_mut() {
                let scanstatus = state.handle_timeout();
                state.flush(state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).expect("error flushing");
                if matches!(scanstatus, ScanTypeStatus::Done) {
                    state.start_next_scan();
                }
            }
        }
    }

}
