use std::cmp;
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
use crate::monlist;
use crate::monlist::MonlistRequestStatus;
use crate::packets;
use crate::packets::AnyNTPPacket;
use crate::send;
use crate::socket;
use crate::socket::SockAddrInet;
use crate::variables;
use crate::variables::Mode6Variables;
use crate::variables::VersionRequestStatus;
use crate::vprintln;
use crate::vvprintln;
use crate::vvvprintln;
use crate::log::Loggable;

/// What scan type is being done currently
#[derive(Debug)]
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
    /// key is the version sent
    pub versions: HashMap<u8, identify::VersionState>,
    pub timeout_till: Option<SystemTime>,
    pub timeout_on_rate_kod: Duration,
    pub interval: Option<Duration>,
    /// the outgoing packet queue, packets placed here
    /// will be sent when the timout allows it
    pub queue: VecDeque<AnyNTPPacket>,
    /// a record of all received packets
    pub pkts_received: Vec<AnyNTPPacket>,
    pub version_request_status: VersionRequestStatus,
    pub mode6_variables: Option<Mode6Variables>,
    pub maxretries: u32,
    pub supports_monlist: bool,
    pub monlist_request_status: MonlistRequestStatus,
    current_type: ScanType,
    rate_kod_received: bool,
    /// should the identify scan be executed
    identify: bool,
}

pub enum ScanTypeStatus {
    Continue,
    Done,
}

impl ScanState {
    fn new(address: SockAddrInet, maxretries: u32, spread: Option<u64>, identify: bool) -> Self {
        ScanState {
            address,
            daemon_guess: None,
            versions: HashMap::new(),
            timeout_till: None,
            timeout_on_rate_kod: Duration::from_secs(10),
            interval: spread.map(Duration::from_secs),
            current_type: ScanType::Prepare,
            pkts_received: vec![],
            maxretries,
            queue: VecDeque::new(),
            version_request_status: VersionRequestStatus::new(),
            mode6_variables: None,
            supports_monlist: false,
            monlist_request_status: MonlistRequestStatus::new(),
            rate_kod_received: false,
            identify,
        }
    }
    /// note that this queues the packets but does not flush them
    fn start_next_scan(&mut self) {
        self.queue.clear();
        match self.current_type {
            ScanType::Prepare => {
                self.current_type = ScanType::Version;
                vvprintln!("{} starting mode 6 read variables scan", self.address);
                variables::init(self);
            },
            ScanType::Version => {
                self.current_type = ScanType::Monlist;
                vvprintln!("{} starting mode 7 monlist scan", self.address);
                monlist::init(self);
            },
            ScanType::Monlist => {
                if self.identify {
                    self.current_type = ScanType::Identify;
                    vvprintln!("{} starting mode 3 identify scan", self.address);
                    identify::init(self);
                }
                else {
                    self.current_type = ScanType::Done;
                }
            },
            ScanType::Identify => { 
                self.current_type = ScanType::Done;
            },
            ScanType::Done => {},
        }
    }
    fn choose_sock<T: AsRawFd>(&self, sockfd4: T, sockfd6: T) -> T {
        match self.address {
            SockAddrInet::IPv4(_) => sockfd4,
            SockAddrInet::IPv6(_) => sockfd6,
        }
    }
    fn flush<T: AsRawFd>(&mut self, sock: T) -> nix::Result<()> {
        if !self.queue.is_empty() {
            vvprintln!("{} attempting to flush {} packets", self.address, self.queue.len());
        }
        loop {
            if self.may_send() {
                let msg = self.queue.pop_front();
                match msg {
                    Some(msg) => {
                        vvprintln!("{} sending packet", self.address);
                        vvvprintln!("{} -> {:x?}", self.address, msg);
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
    fn recpkt(&mut self, pkt: &AnyNTPPacket) -> ScanTypeStatus {
        match self.current_type {
            ScanType::Prepare => unreachable!(),
            ScanType::Identify => identify::receive(self, pkt),
            ScanType::Version => variables::receive(self, pkt),
            ScanType::Monlist => monlist::receive(self, pkt),
            ScanType::Done => ScanTypeStatus::Done,
        }
    }
    fn handle_timeout(&mut self) -> ScanTypeStatus {
        match self.current_type {
            ScanType::Prepare => unreachable!(),
            ScanType::Identify => identify::timeout(self),
            ScanType::Version => variables::timeout(self),
            ScanType::Monlist => monlist::timeout(self),
            ScanType::Done => unreachable!(),
        }
    }
    fn handle_rate_kod(&mut self) {
        self.timeout_till = Some(SystemTime::now() + self.timeout_on_rate_kod);
        self.timeout_on_rate_kod *= 2;
        match self.interval {
            Some(d) => if d < Duration::from_secs(6) {
                self.interval = Some(cmp::max(Duration::from_secs(6), d*2))
            } else {
                self.interval = Some(d * 2)
            },
            None => self.interval = Some(Duration::from_secs(6)),
        }
        vvprintln!("{}: waiting {}s, interval is {}s", self.address, self.timeout_on_rate_kod.as_secs()/2, self.interval.unwrap().as_secs());

        // an upper limit on how long we are willing to wait
        if self.timeout_on_rate_kod >= Duration::from_secs(120) {
            self.current_type = ScanType::Done;
        }
    }

    fn to_result(&self) -> ScanResult {
        let mode4pkt = self.pkts_received
            .iter()
            .filter_map(|p| p.as_standard())
            .find(|pk| pk.mode == 4 && pk.refidstr().unwrap_or("") != "RATE");
        let refid = match mode4pkt {
            Some(p) => match p.refidstr() {
                Some(str) => Some(RefId::Ascii(str.to_string())),
                None => Some(RefId::Other(p.refid)),
            },
            None => None,
        };
        let versions = self.versions.clone().iter().map(|(vi, vs)| (*vi, vs.response.as_ref().map(|p| p.version))).collect();
        ScanResult {
            address: self.address,
            daemon_guess: self.daemon_guess.unwrap_or(""),
            refid: refid,
            versions,
            monlist: self.supports_monlist,
            variables: self.mode6_variables.as_ref().map(|v| v.str.clone()),
            rate_kod: self.rate_kod_received,
        }
    }

}

#[derive(Debug)]
pub enum RefId {
    Ascii(String),
    Other([u8; 4]),
}

impl RefId {
    pub fn to_csv_str(refid: &Option<RefId>) -> String {
        match refid {
            Some(RefId::Ascii(ascii_str)) => {
                ascii_str.as_bytes().iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            (b as char).to_string()
                        } else {
                            format!("\\x{:02x}", b)
                        }
                    })
                    .collect()
            },
            Some(Self::Other(bytes)) => {
                bytes.iter()
                    .map(|&b| {
                        format!("\\x{:02x}", b)
                    })
                    .collect()
            },
            None => "".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub address: SockAddrInet,
    pub daemon_guess: &'static str,
    pub refid: Option<RefId>,
    pub versions: HashMap<u8, Option<u8>>,
    pub monlist: bool,
    pub variables: Option<String>,
    pub rate_kod: bool,
}

pub fn start_thread(targets: Vec<SockAddrInet>, retries: u32, concurrent: usize, polltimeout: u32, spread: Option<u64>, identify: bool) -> mpsc::Receiver<ScanResult> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        scan_thread(tx, &targets, retries, concurrent, polltimeout, spread, identify);
    });
    rx
}

fn scan_thread(tx: mpsc::Sender<ScanResult>, targets: &[SockAddrInet], maxretries: u32, concurrent: usize, polltimeout: u32, spread: Option<u64>, identify: bool) {
    let mut i = concurrent.min(targets.len());
    let mut states: HashMap<SockAddrInet, ScanState> = HashMap::new();
    for state in targets[0..i].iter().map(|a| ScanState::new(*a, maxretries, spread, identify)) {
        if states.contains_key(&state.address) {
            println!("duplicate address {}", state.address);
        } else {
            states.insert(state.address, state);
        }
    }

    let sockfd4 = socket::setup_socket(AddressFamily::Inet).expect("Failed to bind IPv4 UDP socket");
    let sockfd6 = socket::setup_socket(AddressFamily::Inet6).expect("Failed to bind IPv6 UDP socket");

    // initialize the first scan for all targets
    for (_, state) in states.iter_mut() {
        state.start_next_scan();
        state.flush(state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).expect("error flushing");
    }

    let mut pollfds = [
        PollFd::new(sockfd4.as_fd(), PollFlags::POLLIN),
        PollFd::new(sockfd6.as_fd(), PollFlags::POLLIN),
    ];
    let poll_timeout = PollTimeout::from(polltimeout as u16);
    let mut recvbuf: [u8; 1024] = [0; 1024];

    'outer: loop {
        let mut done = vec![];
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
                    let pkt_option = packets::parse(&recvbuf[0..nread]);
                    if pkt_option.is_none() {
                        vprintln!("failed to parse {nread} byte pkt from {src}");
                        continue;
                    }
                    let pkt = pkt_option.unwrap();
                    vvprintln!("{nread} bytes from {src}");
                    vvprintln!("{pkt:?}");

                    match states.get_mut(&src) {
                        Some(state) => {
                            // save packet
                            state.pkts_received.push(pkt.clone());

                            // TODO handle DENY and RSTR
                            if let AnyNTPPacket::Standard(pkt) = pkt.clone() {
                                if pkt.is_kod() && pkt.refidstr() == Some("RATE") {
                                    vprintln!("{} Kiss o' Death RATE received", state.address);
                                    state.rate_kod_received = true;
                                    state.handle_rate_kod();
                                } else if pkt.is_kod() && (pkt.refidstr() == Some("DENY") || pkt.refidstr() == Some("RSTR") ) {
                                    eprintln!("{} Kiss o' Death {} received, quitting", state.address, pkt.refidstr().unwrap());
                                    state.current_type = ScanType::Done;
                                }
                            }
                            let scanstatus = state.recpkt(&pkt);
                            if matches!(scanstatus, ScanTypeStatus::Done) {
                                state.start_next_scan();
                            }
                            if matches!(state.current_type, ScanType::Done) {
                                done.push(state.address);
                            }
                            state.flush(state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).expect("error flushing");
                        },
                        None => {
                            eprintln!("received packet from {src}, which isn't part of the target list???");
                        },
                    }
                },
                Err(e) => println!("received errno {e:?} from recvfrom"),
                _ => unreachable!(),
            }
        } else {
            vvprintln!("poll timeout");
            for (addr, state) in states.iter_mut() {
                if state.queue.is_empty() {
                    let scanstatus = state.handle_timeout();
                    if matches!(scanstatus, ScanTypeStatus::Done) {
                        state.start_next_scan();
                        if matches!(state.current_type, ScanType::Done) {
                            done.push(state.address);
                        }
                    }
                }
                state.flush(state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).expect("error flushing");
            }
        }
        for a in done {
            tx.send(states.remove(&a).unwrap().to_result()).unwrap();

            // potentially add a new target
            if i < targets.len() {
                let mut new_state = ScanState::new(targets[i], maxretries, spread, identify);
                if states.contains_key(&new_state.address) {
                    eprintln!("duplicate address {}", new_state.address);
                } else {
                    vvprintln!("added {} to concurrent targets", new_state.address);
                    new_state.start_next_scan();
                    new_state.flush(new_state.choose_sock(sockfd4.as_raw_fd(), sockfd6.as_raw_fd())).expect("error flushing");
                    states.insert(new_state.address, new_state);
                }
                i += 1;
            }
        }
        
        if states.is_empty() {
            break;
        }

    }

    vprintln!("a thread finished");

}
