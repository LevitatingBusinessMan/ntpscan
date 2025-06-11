use crate::scan::ScanResult;

pub fn save_result(res: ScanResult) {
    let mut versions_vec = res.versions.iter().filter_map(|(k,v)| v.map(|v| (*k,v))).collect::<Vec<(u8, u8)>>();
    versions_vec.sort_by_key(|(k,v)| *k);
    let versions_str = versions_vec.iter().map(|(k,v)| format!("{}->{}, ", k, v)).collect::<String>();

    if versions_vec.is_empty() {
        println!("{} offline", res.address);
    } else {
        println!("{} refid: {:?}, versions: {}, monlist: {}, variables: {} {}",
            res.address,
            res.refid,
            versions_str,
            res.monlist,
            res.variables.is_some(),
            if res.rate_kod { "(rate kod)" } else { "" },
        )
    }
}

impl ScanResult {
    pub fn csv_header() -> &'static str {
        "IpAddr,daemon,versions"
    }
    // pub fn csv(&self) -> String {
        
    // }
}
