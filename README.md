# forsmost

[![Crates.io](https://img.shields.io/crates/v/forsmost.svg)](https://crates.io/crates/forsmost)
[![Documentation](https://docs.rs/forsmost/badge.svg)](https://docs.rs/forsmost)
[![CI](https://github.com/neodyland/forsmost/actions/workflows/ci.yml/badge.svg)](https://github.com/neodyland/forsmost/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`forsmost` is a Rust implementation of Foremost-style file carving. It scans an
input stream or disk image for configured file signatures, writes recovered
files into type-specific output directories, and records an `audit.txt` report.

The crate does not vendor or require the original Foremost source tree. Optional
compatibility tests can compare against an external Foremost executable when one
is provided by the developer.

## Installation

```bash
cargo install forsmost
```

## Usage

Recover JPEG files from an input image:

```bash
forsmost -t jpg -o output image.dd
```

Recover multiple built-in types:

```bash
forsmost -t jpg,pdf,zip image.dd
```

Use a custom signature configuration file:

```bash
forsmost -c foremost.conf -o output image.dd
```

Read from standard input:

```bash
cat image.dd | forsmost -t png -o output
```

Common options:

```text
-t <types>    Built-in file selectors, comma-separated
-c <file>     Configuration file, default is foremost.conf
-o <dir>      Output directory, default is output
-i <file>     Input file, default is stdin
-q            Quick mode, check only block boundaries
-Q            Quiet mode
-a            Write a header dump when validation cannot determine a file end
-w            Write only audit entries, not recovered files
-T            Append a timestamp to the output directory name
```

## Built-in selectors

The built-in selectors include common image, archive, office, executable, media,
and registry formats:

```text
avi, bmp, cpp, doc, docx, elf, exe, gif, gz, html, jpg, mov, mp4,
mpg, ole, pdf, png, ppt, pptx, rar, reg, rif, sxc, sxi, sxw, wav,
wmv, wpd, xls, xlsx, zip
```

Use `all` to enable the default Foremost-style selector set.

## Features

Default features:

```toml
default = ["gzip"]
```

Feature flags:

```text
gzip    Enables gzip stream validation and recovery through flate2.
```

Disable gzip support and the `flate2` dependency:

```bash
cargo install forsmost --no-default-features
```

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --no-default-features
cargo package --list
cargo publish --dry-run
```

The ignored `compare_foremost` tests require `FOREMOST_BIN` or
`FOREMOST_WSL_BIN` to point at an original Foremost executable.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
