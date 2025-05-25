#![feature(file_buffered)]
use clap::Parser;
use nix::sys::socket::SockaddrIn;
use results::ScanResult;
use std::fs;
use std::io::BufRead;
use std::io::Write;
use std::str::FromStr;

mod send;
mod socket;
mod args;
mod receive;
mod packets;
mod identify;
mod results;

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

    let mut results = vec![];

    for target in targets {
        let addr = SockaddrIn::from_str(&format!("{target}:123"))?;
        let (vs, guess) = identify::version_check(&addr, args.verbose, 2)?;
        results.push(ScanResult {
            ip: addr.ip(),
            daemon_guess: guess,
            versions: vs,
        });
    }

    if let Some(path) = args.output_file {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)?;
        match args.output_format {
            args::OutputFormat::CSV => {
                file.write(ScanResult::csv_header().as_bytes())?;
                file.write(b"\n")?;
                for res in results {
                    file.write(res.csv().as_bytes())?;
                    file.write(b"\n")?;
                }
            },
            _ => todo!(),
        }
    }

    Ok(())
}
