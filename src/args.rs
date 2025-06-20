use clap::ValueEnum;
use clap::ValueHint::*;

pub static HELP_TEMPLATE: &'static str = "\
{before-help}{name} {version}
{about}
by {author}

{usage-heading} {usage}

{all-args}{after-help}
";

#[derive(clap::Parser, Debug)]
#[command(version, author, long_about = None, help_template=HELP_TEMPLATE)]
/// Tool for scanning ntp servers
pub struct Args {
    /// Targets to scan
    #[arg(long, value_hint=FilePath, group="input")]
    pub iplist: Option<String>,

    /// Blocklist (other than default) (disabled)
    #[arg(long, value_hint=FilePath)]
    pub blocklist: Option<String>,

    /// Targets to scan
    #[arg(value_hint=Hostname, group="input", required=true)]
    pub target: Option<Vec<String>>,

    /// Threads
    #[arg(long, short, default_value_t=2)]
    pub threads: u8,

    /// Targets per thread
    #[arg(long, default_value_t=1000)]
    pub targets_per_thread: usize,

    /// How often to retry sending a packet
    #[arg(long, short, default_value_t=1)]
    pub retries: u32,

    /// How long to wait for a reply (in ms)
    #[arg(long, short, default_value_t=1000)]
    pub poll: u32,

    /// Output format (disabled)
    #[arg(value_enum, long, short='f', default_value_t=OutputFormat::Plain)]
    pub output_format: OutputFormat,

    /// Output file
    #[arg(long, short, value_hint=FilePath)]
    pub output_file: Option<String>,

    /// Verbosity level
    #[arg(short, long, action=clap::ArgAction::Count)]
    pub verbose: u8,

    /// Do not send packets (disabled)
    #[arg(long, action=clap::ArgAction::SetTrue)]
    pub dry_run: bool,

    /// Interval in-between sent packets in secs
    #[arg(long)]
    pub spread: Option<u64>,

    // /// Attempt daemon identification
    #[arg(long="no-identify", action = clap::ArgAction::SetFalse)]
    pub identify: bool,

    /// Do not attempt daemon identification
    #[arg(long="identify", overrides_with = "identify")]
    pub _no_identify: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Plain,
    CSV,
    XML
}