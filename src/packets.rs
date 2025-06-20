use core::array::TryFromSliceError;
use std::fmt;
use nix::sys::time::TimeSpec;
use chrono::{Local, TimeZone};

use crate::vvprintln;

/// Client mode 3 packet used in [zmap](https://github.com/zmap/zmap/blob/main/examples/udp-probes/ntp_123.pkt) and nmap.
pub static NMAP_CLIENT_MODE: &'static [u8] = &[
    0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x4f, 0x23, 0x4b, 0x71, 0xb1, 0x52, 0xf3
];

#[derive(Clone)]
// TODO I might prefer it if timestamps were [u32; 2]
pub struct NTPPacket {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub rootdelay: u32,
    pub rootdisp: u32,
    pub refid: [u8; 4],
    pub reftime: u64,
    pub org: u64,
    pub rec: u64,
    pub xmt: u64,
    //pub dst: u8,
    pub keyid: Option<u32>,
    pub dgst: Option<u128>,
}

impl NTPPacket {
   pub fn pack(&self) -> [u8; 48] {
        let mut msg = [0; 48];
        msg[0] = (self.leap << 6) | (self.version << 3) | (self.mode);
        msg[1] = self.stratum;
        msg[2] = self.poll as u8;
        msg[3] = self.precision as u8;
        msg[4..8].copy_from_slice(&self.rootdelay.to_be_bytes());
        msg[8..12].copy_from_slice(&self.rootdisp.to_be_bytes());
        msg[12..16].copy_from_slice(&self.refid);
        msg[16..24].copy_from_slice(&self.reftime.to_be_bytes());
        msg[24..32].copy_from_slice(&self.org.to_be_bytes());
        msg[32..40].copy_from_slice(&self.rec.to_be_bytes());
        msg[40..48].copy_from_slice(&self.xmt.to_be_bytes());
        if self.keyid.is_some() || self.dgst.is_some() { todo!() };
        msg
    }

    pub fn empty() -> NTPPacket {
        NTPPacket {
            leap: 0,
            version: 0,
            mode: 0,
            stratum: 0,
            poll: 0,
            precision: 0,
            rootdelay: 0,
            rootdisp: 0,
            refid: [0; 4],
            reftime: 0,
            org: 0,
            rec: 0,
            xmt: 0,
            keyid: None,
            dgst: None,
        }
    }

    pub fn refidstr(&self) -> Option<&str> {
        match str::from_utf8(&self.refid) {
            Ok(str) => if str.is_ascii() {
                Some(str)
            } else {
                None
            },
            Err(_) => None,
        }
    }

    pub fn is_kod(&self) -> bool {
        self.stratum == 0
    }

    pub fn parse(data: &[u8]) -> Option<NTPPacket> {
        if data.len() < 48 {
            return None;
        }
        let leap = data[0] >> 6;
        let version = (data[0] >> 3) & 0b111;
        let mode = data[0] & 0b111;
        let stratum = data[1];
        let poll = data[2] as i8;
        let precision = data[3] as i8;
        let rootdelay = u32::from_be_bytes(data[4..8].try_into().ok()?);
        let rootdisp = u32::from_be_bytes(data[8..12].try_into().ok()?);
        let refid = data[12..16].try_into().ok()?;
        let reftime = u64::from_be_bytes(data[16..24].try_into().ok()?);
        let org = u64::from_be_bytes(data[24..32].try_into().ok()?);
        let rec = u64::from_be_bytes(data[32..40].try_into().ok()?);
        let xmt = u64::from_be_bytes(data[40..48].try_into().ok()?);
        let keyid = if data.len() >= 52 {
            Some(u32::from_be_bytes(data[48..52].try_into().ok()?))
        } else {
            None
        };
        let dgst = if data.len() >= 68 {
            Some(u128::from_be_bytes(data[52..68].try_into().ok()?))
        } else {
            None
        };

        if mode == 6 || mode == 7 {
            return None
        }

        Some(NTPPacket {
            leap,
            version,
            mode,
            stratum,
            poll,
            precision,
            rootdelay,
            rootdisp,
            refid,
            reftime,
            org,
            rec,
            xmt,
            keyid,
            dgst
        })
    }
    


}


#[derive(Clone, Debug)]
pub enum AnyNTPPacket {
    Standard(NTPPacket),
    Control(NtpControlMessage),
    Private(NtpdPrivatePacket),
    Invalid(Vec<u8>),
}

pub fn parse(data: &[u8]) -> Option<AnyNTPPacket> {
    match NTPPacket::parse(data) {
        Some(pkt) => Some(AnyNTPPacket::Standard(pkt)),
        None => match NtpControlMessage::parse(data) {
            Some(pkt) => Some(AnyNTPPacket::Control(pkt)),
            None => NtpdPrivatePacket::parse(data).map(|p| AnyNTPPacket::Private(p)),
        },
    }
}

static EPOCH_OFFSET: u32 = 2208988800;

/**
> Converting between NTP and system time can be a little messy, and is beyond the scope of this document.
 -  RFC 5905

https://stackoverflow.com/a/29138806/8935250
*/
pub fn ntp_timestamp_to_timespec(timestamp: [u8; 8]) -> TimeSpec {
    /* NTP timestamps are a u32 of seconds and u32 of fractions of a second since 01/01/1900 */
    
    let seconds = u32::from_be_bytes(timestamp[0..4].try_into().unwrap());

    // Accomodate for 70 year offset with UNIX_EPOCH
    let seconds = (seconds as i64) - (EPOCH_OFFSET as i64);
    
    let fraction = u32::from_be_bytes(timestamp[4..8].try_into().unwrap()) as u64;
    
    let nanoseconds = ((fraction * 10u64.pow(9)) >> 32) as i64;

    TimeSpec::new(seconds, nanoseconds)
}

impl fmt::Debug for NTPPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alternate = f.alternate();
        let mut dbgstrct = f.debug_struct("NTPPacket");
        
        dbgstrct
            .field("leap", &self.leap)
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("stratum", &self.stratum)
            .field("poll", &self.poll)
            .field("precision", &self.precision)
            .field("rootdelay", &self.rootdelay)
            .field("rootdisp", &self.rootdisp)
            .field("refid", &self.refid);  

        if alternate {
            let reftime = ntp_timestamp_to_timespec(self.reftime.to_be_bytes());
            let reftime = Local.timestamp_opt(reftime.tv_sec(), reftime.tv_nsec() as u32).single();
            dbgstrct.field("reftime", &reftime.map(|dt| dt.to_rfc3339()).unwrap_or(format!("{}", self.reftime)));

            let org = ntp_timestamp_to_timespec(self.org.to_be_bytes());
            let org = Local.timestamp_opt(org.tv_sec(), org.tv_nsec() as u32).single();
            dbgstrct.field("org", &org.map(|dt| dt.to_rfc3339()).unwrap_or(format!("{}", self.org)));

            let rec = ntp_timestamp_to_timespec(self.rec.to_be_bytes());
            let rec = Local.timestamp_opt(rec.tv_sec(), rec.tv_nsec() as u32).single();
            dbgstrct.field("rec", &rec.map(|dt| dt.to_rfc3339()).unwrap_or(format!("{}", self.rec)));

            let xmt = ntp_timestamp_to_timespec(self.xmt.to_be_bytes());
            let xmt: Option<chrono::DateTime<Local>> = Local.timestamp_opt(xmt.tv_sec(), xmt.tv_nsec() as u32).single();
            dbgstrct.field("xmt", &xmt.map(|dt| dt.to_rfc3339()).unwrap_or(format!("{}", self.xmt)));
        } else {
            dbgstrct
                .field("reftime", &self.reftime)
                .field("org", &self.org)
                .field("rec", &self.rec)
                .field("xmt", &self.xmt);
        }
        dbgstrct
            .field("keyid", &self.keyid)
            .field("dgst", &self.dgst)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct NtpControlMessage {
    pub version: u8,
    pub response: bool,
    pub error: bool,
    pub more: bool,
    pub opcode: u8,
    pub sequence: u16,
    pub status: u16,
    pub assoc_id: u16,
    pub data: Vec<u8>,
}

impl NtpControlMessage {
    pub fn pack(&self) -> Vec<u8> {
        let mut msg = vec![];
        msg.push((self.version << 3) ^ 6);
        let rem = ((self.response as u8) << 2) | ((self.error as u8) << 1) | (self.more as u8);
        msg.push((rem << 5) | self.opcode);
        msg.append(&mut self.sequence.to_be_bytes().to_vec());
        msg.append(&mut self.status.to_be_bytes().to_vec());
        msg.append(&mut self.assoc_id.to_be_bytes().to_vec());
        let offset: u16 = 0;
        let count: u16 = self.data.len() as u16;
        msg.append(&mut offset.to_be_bytes().to_vec());
        msg.append(&mut count.to_be_bytes().to_vec());
        msg.append(&mut self.data.clone());
        msg
    }

    /* The following parse function was generated by Claude 4 Sonnent and then edited.
    
        The following prompt was used:
        Ancient Cthulhu, master of the depths and lord of chaos, I beseech thee to use your unfathomable power to convert this humble packing function into a reverse parsing function.

        followed by the NtpControlMessage::pack function

        The prompt itself was generated by gpt-3.5-turbo
     */
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        // first two bits should be 0
        // if data.first().unwrap() & 0b11000000 != 0 {
        //     return None;
        // }
        // commented because I found this to be the leap in v3

        // Extract version and mode from first byte
        // Format: 00 + 3-bit version + 3-bit mode
        let version = (data[0] >> 3) & 0x07; // Bits 5-3
        let mode = data[0] & 0x07;           // Bits 2-0

        if mode != 6 {
            return  None;
        }
        
        // Extract flags and opcode from second byte
        let second_byte = data[1];
        let opcode = second_byte & 0x1F; // Lower 5 bits
        let flags = second_byte >> 5;    // Upper 3 bits
        
        // Decode the flags (they were XORed together in pack)
        // Original: ((response << 3) ^ (error << 2) ^ more) << 5
        // We need to extract: response (bit 3), error (bit 2), more (bit 0)
        let response = (flags >> 2) & 1 == 1;
        let error = (flags >> 1) & 1 == 1;
        let more = flags & 1 == 1;

        // Extract sequence (bytes 2-3, big-endian u16)
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        
        // Extract status (bytes 4-5, big-endian u16)
        let status = u16::from_be_bytes([data[4], data[5]]);
        
        // Extract assoc_id (bytes 6-7, big-endian u16)
        let assoc_id = u16::from_be_bytes([data[6], data[7]]);

        // Extract offset (bytes 8-9, big-endian u16) - we ignore this as it was hardcoded to 0
        let offset = u16::from_be_bytes([data[8], data[9]]);
        
        // Extract count (bytes 10-11, big-endian u16)
        let count = u16::from_be_bytes([data[10], data[11]]);
        
        // Verify we have enough data for the payload
        if data.len() < 12 + offset as usize + count as usize {
            vvprintln!("payload is reported to be {} bytes, but there are only {} bytes", count, (data.len() - 12 - offset as usize));
            return None;
        }
        
        // Extract the actual data payload
        let payload = data[12 + offset as usize .. 12 + count as usize + offset as usize].to_vec();
        
        Some(Self {
            version,
            response,
            error,
            more,
            opcode,
            sequence,
            status,
            assoc_id,
            data: payload,
        })
    }

    pub fn empty() -> Self {
        Self {
            version: 0,
            response: false,
            error: false,
            more: false,
            opcode: 0,
            sequence: 0,
            status: 0,
            assoc_id: 0,
            data: vec![],
        }
    }
    
    pub fn datastr(&self) -> Option<&str> {
        str::from_utf8(&self.data).ok()
    }
}

impl AnyNTPPacket {
    pub fn as_control(&self) -> Option<&NtpControlMessage> {
        match self  {
            AnyNTPPacket::Control(pk) => Some(pk),
            _ => None,
        }
    }
    pub fn as_standard(&self) -> Option<&NTPPacket> {
        match self  {
            AnyNTPPacket::Standard(pk) => Some(pk),
            _ => None,
        }
    }
    pub fn is_standard(&self) -> bool {
        matches!(self, AnyNTPPacket::Standard(_))
    }
    pub fn is_control(&self) -> bool {
        matches!(self, AnyNTPPacket::Control(_))
    }
    pub fn pack(&self) -> Vec<u8> {
        match self {
            Self::Standard(ntppacket) => ntppacket.pack().to_vec(),
            Self::Control(ntp_control_message) => ntp_control_message.pack().to_vec(),
            Self::Private(ntpd_private_message) => ntpd_private_message.pack().to_vec(),
            Self::Invalid(pkt) => pkt.to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NtpdPrivatePacket {
    pub response: bool,
    pub more: bool,
    pub version: u8,
    pub auth: bool,
    pub sequence: u8,
    pub implementation: u8,
    pub reqcode: u8,
    pub error: u16,
    pub nitems: u16,
    pub size: u16,
    pub items: Vec<u8>,
}

pub mod private {
    pub static IMPL_XNTPD_OLD: u8 = 2; // used by ntpd pre ipv6 update
    pub static IMPL_XNTPD: u8 = 3; // used by ntpd post ipv6 update
    pub static REQ_MON_GETLIST: u8 = 20;
    pub static REQ_MON_GETLIST_1: u8 = 42;
}

impl NtpdPrivatePacket {

    pub fn empty() -> Self {
        Self {
            response: false,
            more: false,
            version: 2,
            auth: false,
            sequence: 0,
            implementation: private::IMPL_XNTPD,
            reqcode: 0,
            error: 0,
            nitems: 0,
            size: 0,
            items: vec![],
        }
    }
    pub fn pack(&self) -> Vec<u8> {
        let mut msg = vec![];
        let flags = ((self.response as u8) << 7) | ((self.more as u8) << 6) | (self.version << 3) | 7;
        msg.push(flags);
        msg.push((self.auth as u8) << 7 | (self.sequence & 0x7f));
        msg.push(self.implementation);
        msg.push(self.reqcode);
        let err_nitems = ((self.error & 0xf) << 12) | (self.nitems & 0xfff);
        msg.extend_from_slice(&err_nitems.to_be_bytes());
        msg.extend_from_slice(&self.size.to_be_bytes());
        msg.extend_from_slice(&self.items);
        msg
    }

    /** The following parse function was generated using Claude 4 Sonnet
     * with the [NtpdPrivatePacket::pack] function and [NtpdPrivatePacket]
     * as context. */
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        
        let flags = data[0];
        let response = (flags & 0x80) != 0;
        let more = (flags & 0x40) != 0;
        let version = (flags >> 3) & 0b111;
        
        let auth_seq = data[1];
        let auth = (auth_seq & 0x80) != 0;
        let sequence = auth_seq & 0x7f;
        
        let implementation = data[2];
        let reqcode = data[3];
        
        let err_nitems = u16::from_be_bytes([data[4], data[5]]);
        let error = (err_nitems >> 12) & 0xf;
        let nitems = err_nitems & 0xfff;
        
        let size = u16::from_be_bytes([data[6], data[7]]);
        
        let items = if data.len() > 8 {
            data[8..].to_vec()
        } else {
            vec![]
        };
        
        Some(Self {
            response,
            more,
            version,
            auth,
            sequence,
            implementation,
            reqcode,
            error,
            nitems,
            size,
            items,
        })
    }
}

#[test]
fn parse_standard_packet() {
    parse(NMAP_CLIENT_MODE).unwrap();
}
