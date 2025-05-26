pub struct ScanResult {
    pub ip: String,
    /// what versions does it accept
    pub versions: Vec<u8>,
    pub daemon_guess: &'static str,
}

impl ScanResult {
    pub fn csv_header() -> &'static str {
        "IpAddr,daemon,versions"
    }
    pub fn csv(&self) -> String {
        let versions = self.versions.iter().map(|v| v.to_string()).collect::<Vec<String>>().join(",");
        format!("{},{},\"{}\"", self.ip, self.daemon_guess, versions)
    }
}
