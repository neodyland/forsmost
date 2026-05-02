use std::{ffi::OsString, iter::once, path::PathBuf};

use clap::{CommandFactory, Parser, error::ErrorKind};

const DEFAULT_CHUNK_SIZE_MB: u64 = 100;
const DEFAULT_CONFIG_FILE: &str = "foremost.conf";
const DEFAULT_OUTPUT_DIRECTORY: &str = "output";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum Command {
    Help,
    Run(Options),
    Version,
}

#[derive(Clone, Debug, Default)]
pub struct Modes {
    pub indirect_block: bool,
    pub quick: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub write_all: bool,
    pub write_audit_only: bool,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub block_size: u64,
    pub chunk_size_mb: u64,
    pub config_explicit: bool,
    pub config_file: PathBuf,
    pub input_files: Vec<PathBuf>,
    pub modes: Modes,
    pub output_directory: PathBuf,
    pub skip_blocks: u64,
    pub timestamp_output: bool,
    pub type_selectors: Vec<String>,
}

#[derive(Debug, Parser)]
#[command(
    name = "forsmost",
    version,
    about = "Recover files from an input stream or disk image by signature.",
    long_about = None
)]
struct CliArgs {
    #[arg(
        short = 'a',
        help = "Write every matching header when exact validation fails"
    )]
    write_all: bool,

    #[arg(
        short = 'b',
        value_name = "size",
        default_value_t = 512,
        help = "Set block size"
    )]
    block_size: u64,

    #[arg(short = 'c', value_name = "file", help = "Set configuration file")]
    config_file: Option<PathBuf>,

    #[arg(short = 'd', help = "Accept the foremost indirect block flag")]
    indirect_block: bool,

    #[arg(short = 'i', value_name = "file", help = "Specify input file")]
    input_file: Vec<PathBuf>,

    #[arg(
        short = 'k',
        value_name = "size_mb",
        default_value_t = DEFAULT_CHUNK_SIZE_MB,
        help = "Set chunk size in MB"
    )]
    chunk_size_mb: u64,

    #[arg(
        short = 'o',
        value_name = "dir",
        default_value = DEFAULT_OUTPUT_DIRECTORY,
        help = "Set output directory"
    )]
    output_directory: PathBuf,

    #[arg(short = 'q', help = "Quick mode, only check block boundaries")]
    quick: bool,

    #[arg(short = 'Q', help = "Quiet mode")]
    quiet: bool,

    #[arg(
        short = 's',
        value_name = "blocks",
        default_value_t = 0,
        help = "Skip blocks before scanning"
    )]
    skip_blocks: u64,

    #[arg(short = 'T', help = "Append a timestamp to the output directory name")]
    timestamp_output: bool,

    #[arg(
        short = 't',
        value_name = "type",
        value_delimiter = ',',
        help = "Specify file types, for example `-t jpg,pdf`"
    )]
    type_selectors: Vec<String>,

    #[arg(short = 'v', help = "Print verbose audit messages on stdout")]
    verbose: bool,

    #[arg(short = 'w', help = "Only write the audit file")]
    write_audit_only: bool,

    #[arg(value_name = "file")]
    files: Vec<PathBuf>,
}

impl Command {
    pub fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let args = once(OsString::from("forsmost")).chain(args);
        match CliArgs::try_parse_from(args) {
            Ok(args) => Ok(Self::Run(args.into_options())),
            Err(error) => match error.kind() {
                ErrorKind::DisplayHelp => Ok(Self::Help),
                ErrorKind::DisplayVersion => Ok(Self::Version),
                _ => Err(error.to_string()),
            },
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            block_size: 512,
            chunk_size_mb: DEFAULT_CHUNK_SIZE_MB,
            config_explicit: false,
            config_file: PathBuf::from(DEFAULT_CONFIG_FILE),
            input_files: Vec::new(),
            modes: Modes::default(),
            output_directory: PathBuf::from(DEFAULT_OUTPUT_DIRECTORY),
            skip_blocks: 0,
            timestamp_output: false,
            type_selectors: Vec::new(),
        }
    }
}

impl CliArgs {
    fn into_options(self) -> Options {
        let config_explicit = self.config_file.is_some();
        let mut input_files = self.input_file;
        input_files.extend(self.files);
        Options {
            block_size: self.block_size,
            chunk_size_mb: self.chunk_size_mb,
            config_explicit,
            config_file: self
                .config_file
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE)),
            input_files,
            modes: Modes {
                indirect_block: self.indirect_block,
                quick: self.quick,
                quiet: self.quiet,
                verbose: self.verbose,
                write_all: self.write_all,
                write_audit_only: self.write_audit_only,
            },
            output_directory: self.output_directory,
            skip_blocks: self.skip_blocks,
            timestamp_output: self.timestamp_output,
            type_selectors: self
                .type_selectors
                .into_iter()
                .map(|selector| selector.trim().to_owned())
                .filter(|selector| !selector.is_empty())
                .collect(),
        }
    }
}

#[must_use]
pub fn usage() -> String {
    CliArgs::command().render_help().to_string()
}

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
