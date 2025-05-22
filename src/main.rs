use clap::Parser;
use clap::ValueHint::*;

static HELP_TEMPLATE: &'static str = "\
{before-help}{name} {version}
{about}
by {author}

{usage-heading} {usage}

{all-args}{after-help}
";

#[derive(clap::Parser, Debug)]
#[command(version, author, long_about = None, help_template=HELP_TEMPLATE)]
/// Tool for scanning ntp servers
struct Args {
    /// Targets to scan
    #[arg(long, value_hint=FilePath)]
    #[clap(group = "input")]
    iplist: Option<String>,

    /// Blocklist
    #[arg(long, value_hint=FilePath)]
    blocklist: Option<String>,

    /// Bandwidth limit
    #[arg(long, short)]
    #[clap(group = "limit")]
    bandwidth: Option<String>,

    /// Packets per second
    #[arg(long, short)]
    #[clap(group = "limit")]
    rate: Option<u32>,

    /// Targets to scan
    #[arg(value_hint=Hostname)]
    #[clap(group = "input")]
    target: Option<Vec<String>>,
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args);
}
