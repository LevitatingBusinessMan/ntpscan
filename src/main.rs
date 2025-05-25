#![feature(file_buffered)]
use clap::Parser;
use nix::sys::socket::SockaddrIn;
use std::fs;
use std::io::BufRead;
use std::str::FromStr;

mod send;
mod socket;
mod args;
mod receive;
mod packets;
mod identify;

fn main() -> anyhow::Result<()> {
    let args = args::Args::parse();
    if args.verbose > 1 {
        println!("ntpscan was executed with the following arguments:\n{:?}", args);
    }

    let targets: Box<dyn Iterator<Item = String>> = if args.target.is_some() {
        Box::new(args.target.as_ref().unwrap().iter().map(|s| s.clone()))
    } else {
        let path = args.iplist.expect("Neither TARGET or iplist is set");
        let file = fs::File::open_buffered(path)?;
        Box::new(file.lines().map(|l| l.expect("malformed line")))
    };

    for target in targets {
        let ip = SockaddrIn::from_str(&format!("{target}:123"))?;
        identify::version_check(&ip, args.verbose)?;
    }

    Ok(())
}
