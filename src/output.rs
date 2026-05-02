use std::{
    fs::{File, OpenOptions, create_dir_all, read_dir},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{cli::Options, spec::SearchSpec};

const AUDIT_FILE_NAME: &str = "audit.txt";
const DIVIDER: &str = "------------------------------------------------------------------";

#[derive(Debug)]
pub struct OutputWriter {
    audit_file: File,
    block_size: u64,
    files_written: u64,
    quiet: bool,
    root: PathBuf,
    verbose: bool,
    write_audit_only: bool,
}

impl OutputWriter {
    pub fn create(
        options: &Options,
        specs: &[SearchSpec],
        config_path: Option<&Path>,
    ) -> Result<Self, String> {
        let root = output_root(options);
        prepare_output_root(&root)?;

        if !options.modes.write_audit_only {
            for spec in specs {
                create_dir_all(root.join(spec.directory_name())).map_err(|error| {
                    format!(
                        "failed to create output subdirectory `{}`: {error}",
                        root.join(spec.directory_name()).display()
                    )
                })?;
            }
        }

        let audit_path = root.join(AUDIT_FILE_NAME);
        let audit_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&audit_path)
            .map_err(|error| {
                format!(
                    "failed to open audit file `{}`: {error}",
                    audit_path.display()
                )
            })?;
        let mut writer = Self {
            audit_file,
            block_size: options.block_size,
            files_written: 0,
            quiet: options.modes.quiet,
            root,
            verbose: options.modes.verbose,
            write_audit_only: options.modes.write_audit_only,
        };

        writer.write_header(options, config_path)?;
        Ok(writer)
    }

    pub fn audit(&mut self, message: &str) -> Result<(), String> {
        if self.verbose {
            println!("{message}");
        }
        writeln!(self.audit_file, "{message}")
            .map_err(|error| format!("failed to write audit file: {error}"))
    }

    pub fn audit_finish(&mut self, specs: &[SearchSpec]) -> Result<(), String> {
        self.audit("")?;
        self.audit(&format!("{} FILES EXTRACTED", self.files_written))?;
        for spec in specs {
            if spec.found != 0 {
                self.audit(&format!("{}:= {}", spec.suffix, spec.found))?;
            }
        }
        self.audit(DIVIDER)?;
        self.audit(&format!("forsmost finished at {}", timestamp_string()))
    }

    pub fn audit_layout(&mut self) -> Result<(), String> {
        self.audit(&format!(
            "Num\t Name (bs={})\t       Size\t File Offset\t Comment",
            self.block_size
        ))
    }

    pub fn audit_processing_start(
        &mut self,
        name: &str,
        total_bytes: Option<u64>,
    ) -> Result<(), String> {
        if !self.quiet {
            eprint!("Processing: {name}\n|");
        }
        self.audit(DIVIDER)?;
        self.audit(&format!("File: {name}"))?;
        match total_bytes {
            Some(bytes) => self.audit(&format!(
                "Length: {} ({bytes} bytes)",
                human_readable(bytes)
            ))?,
            None => self.audit("Length: Unknown")?,
        }
        self.audit(&format!("Start: {}", timestamp_string()))
    }

    pub fn audit_processing_finish(&mut self) -> Result<(), String> {
        if !self.quiet {
            eprintln!("|");
        }
        self.audit(&format!("Finish: {}", timestamp_string()))
    }

    pub fn mark_progress(&self) {
        if !self.quiet {
            eprint!("*");
        }
    }

    pub fn write_recovered(
        &mut self,
        suffix: &str,
        bytes: &[u8],
        offset: u64,
        comment: &str,
    ) -> Result<(), String> {
        let block = offset / self.block_size;
        let name = recovered_name(block, suffix, None);

        if self.write_audit_only {
            self.audit_recovered(&name, bytes.len(), offset, comment)?;
            self.files_written += 1;
            return Ok(());
        }

        let directory = self.root.join(directory_name(suffix));
        create_dir_all(&directory).map_err(|error| {
            format!(
                "failed to create output subdirectory `{}`: {error}",
                directory.display()
            )
        })?;
        let mut collision_index = None;
        let mut path = directory.join(&name);

        while path.exists() {
            let next = collision_index.map_or(1, |index| index + 1);
            collision_index = Some(next);
            path = directory.join(recovered_name(block, suffix, collision_index));
        }

        let mut file = File::create(&path).map_err(|error| {
            format!(
                "failed to create recovered file `{}`: {error}",
                path.display()
            )
        })?;
        file.write_all(bytes).map_err(|error| {
            format!(
                "failed to write recovered file `{}`: {error}",
                path.display()
            )
        })?;

        let audit_name = path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .unwrap_or(name.as_str());
        self.audit_recovered(audit_name, bytes.len(), offset, comment)?;
        self.files_written += 1;
        Ok(())
    }

    fn audit_recovered(
        &mut self,
        name: &str,
        len: usize,
        offset: u64,
        comment: &str,
    ) -> Result<(), String> {
        self.audit(&format!(
            "{}:\t{name} \t {:>10} \t {:>10} \t {comment}",
            self.files_written,
            human_readable(len as u64),
            offset
        ))
    }

    fn write_header(
        &mut self,
        options: &Options,
        config_path: Option<&Path>,
    ) -> Result<(), String> {
        self.audit(&format!("forsmost version {}", env!("CARGO_PKG_VERSION")))?;
        self.audit("Audit File")?;
        self.audit("")?;
        self.audit(&format!("forsmost started at {}", timestamp_string()))?;
        self.audit(&format!("Output directory: {}", self.root.display()))?;
        let config_display = config_path.map_or_else(
            || options.config_file.display().to_string(),
            |path| path.display().to_string(),
        );
        self.audit(&format!("Configuration file: {config_display}"))
    }
}

#[must_use]
pub fn human_readable(size: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];

    let mut value = size as f64;
    let mut unit = UNITS[0];
    for next_unit in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next_unit;
    }

    if unit == "B" {
        format!("{size} B")
    } else {
        format!("{value:.1} {unit}")
    }
}

#[must_use]
pub fn timestamp_string() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    seconds.to_string()
}

fn output_root(options: &Options) -> PathBuf {
    if options.timestamp_output {
        let mut root = options.output_directory.as_os_str().to_owned();
        root.push("_");
        root.push(timestamp_string());
        PathBuf::from(root)
    } else {
        options.output_directory.clone()
    }
}

fn prepare_output_root(path: &Path) -> Result<(), String> {
    if path.exists() {
        if !path.is_dir() {
            return Err(format!(
                "output path `{}` exists but is not a directory",
                path.display()
            ));
        }
        if read_dir(path)
            .map_err(|error| {
                format!(
                    "failed to inspect output directory `{}`: {error}",
                    path.display()
                )
            })?
            .next()
            .is_some()
        {
            return Err(format!(
                "output directory `{}` is not empty; specify another directory or use -T",
                path.display()
            ));
        }
        return Ok(());
    }

    create_dir_all(path).map_err(|error| {
        format!(
            "failed to create output directory `{}`: {error}",
            path.display()
        )
    })
}

fn recovered_name(block: u64, suffix: &str, collision_index: Option<u64>) -> String {
    let stem = collision_index.map_or_else(
        || format!("{block:08}"),
        |index| format!("{block:08}_{index}"),
    );

    if suffix.is_empty() {
        stem
    } else {
        format!("{stem}.{suffix}")
    }
}

const fn directory_name(suffix: &str) -> &str {
    if suffix.is_empty() { "none" } else { suffix }
}
