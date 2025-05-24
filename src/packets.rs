use core::array::TryFromSliceError;
use std::fmt;
use nix::sys::time::TimeSpec;
use chrono::{Local, TimeZone};

/// Client mode 3 packet used in [zmap](https://github.com/zmap/zmap/blob/main/examples/udp-probes/ntp_123.pkt) and nmap.
pub static STANDARD_CLIENT_MODE: &'static [u8] = &[
    0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x4f, 0x23, 0x4b, 0x71, 0xb1, 0x52, 0xf3
];

#[derive(Clone)]
// TODO I might prefer it if timestamps were [u32; 2]
pub struct NTPPacket {
    leap: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    poll: i8,
    precision: i8,
    rootdelay: u32,
    rootdisp: u32,
    refid: u32,
    reftime: u64,
    org: u64,
    rec: u64,
    xmt: u64,
    //dst: u8,
    keyid: Option<u32>,
    dgst: Option<u128>,
}

pub fn parse(data: &[u8]) -> Result<NTPPacket, TryFromSliceError> {
    let leap = data[0] >> 6;
    let version = (data[0] >> 3) & 0b111;
    let mode = data[0] & 0b111;
    let stratum = data[1];
    let poll = data[2] as i8;
    let precision = data[3] as i8;
    let rootdelay = u32::from_be_bytes(data[4..8].try_into()?);
    let rootdisp = u32::from_be_bytes(data[8..12].try_into()?);
    let refid = u32::from_be_bytes(data[12..16].try_into()?);
    let reftime = u64::from_be_bytes(data[16..24].try_into()?);
    let org = u64::from_be_bytes(data[24..32].try_into()?);
    let rec = u64::from_be_bytes(data[32..40].try_into()?);
    let xmt = u64::from_be_bytes(data[40..48].try_into()?);
    let keyid = if data.len() >= 52 {
        Some(u32::from_be_bytes(data[48..52].try_into()?))
    } else {
        None
    };
    let dgst = if data.len() >= 68 {
        Some(u128::from_be_bytes(data[52..68].try_into()?))
    } else {
        None
    };
    Ok(NTPPacket {
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

#[test]
fn parse_standard_packet() {
    parse(STANDARD_CLIENT_MODE).unwrap();
}
