use std::cell::LazyCell;
use std::fs::File;
use std::io::Write;

use crate::scan::RefId;
use crate::scan::ScanResult;
use crate::variables; 

pub fn save_result(res: ScanResult, csv_out: &mut File, variables_out: &mut File) {
    let mut versions_vec = res.versions.iter().filter_map(|(k,v)| v.map(|v| (*k,v))).collect::<Vec<(u8, u8)>>();
    versions_vec.sort_by_key(|(k,v)| *k);
    let versions_str = versions_vec.iter().map(|(k,v)| format!("{}->{}, ", k, v)).collect::<String>();

    if versions_vec.is_empty() && !res.monlist && res.variables.is_none() {
        println!("{} offline", res.address);
    } else {
        println!("{} refid: {:?}, versions: {}, monlist: {}, variables: {} {}",
            res.address,
            res.refid,
            versions_str,
            res.monlist,
            res.variables.is_some(),
            if res.rate_kod { "(rate kod)" } else { "" },
        );

        csv_out.write(res.csv().as_bytes()).expect("error writing to csv");

        // save variables
        if let Some(variables) = res.variables {
            variables_out.write(format!("{} {}\n", res.address, variables.trim_end()).as_bytes()).expect("error writing to variables out file");
        }

    }
}

impl ScanResult {
    pub fn csv_header() -> &'static str {
        "address,refid,v0,v1,v2,v3,v4,v5,v6,v7,monlist,variables\n"
    }

    pub fn csv(&self) -> String {
        let x = self.versions.get(&0).and_then(|x| *x);
        format!("{},{},{},{},{},{},{},{},{},{},{},{}\n",
            self.address,
            RefId::to_csv_str(&self.refid),
            self.versions.get(&0).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&1).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&2).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&3).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&4).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&5).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&6).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.versions.get(&7).and_then(|x| *x).map_or("".to_string(), |x| x.to_string()),
            self.monlist.to_string(),
            self.variables.is_some().to_string(),
        )
    }
}
