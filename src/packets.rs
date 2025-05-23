use core::array::TryFromSliceError;

/// Client mode 3 packet used in [zmap](https://github.com/zmap/zmap/blob/main/examples/udp-probes/ntp_123.pkt) and nmap.
pub static STANDARD_CLIENT_MODE: &'static [u8] = &[
    0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x4f, 0x23, 0x4b, 0x71, 0xb1, 0x52, 0xf3
];

#[derive(Clone, Debug)]
pub struct NTPPacket {
    leap: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    poll: u8,
    precision: u8,
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
    let leap = (data[0] & 0b11000000) >> 6;
    let version = (data[0] & 0b00111000) >> 3;
    let mode = data[0] & 0b00000111;
    let stratum = data[1];
    let poll = data[2];
    let precision = data[3];
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

#[test]
fn parse_standard_packet() {
    parse(STANDARD_CLIENT_MODE).unwrap();
}
