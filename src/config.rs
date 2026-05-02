use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    str,
};

use crate::spec::{SearchMode, SearchSpec};

const NO_EXTENSION_SUFFIX: &str = "NONE";

#[derive(Debug)]
pub struct ConfigLoad {
    pub loaded_path: Option<PathBuf>,
    pub specs: Vec<SearchSpec>,
    pub wildcard: u8,
}

#[derive(Debug)]
struct ParsedLine {
    spec: Option<SearchSpec>,
    wildcard: u8,
}

pub fn load(path: &Path, explicit: bool) -> Result<ConfigLoad, String> {
    let mut wildcard = b'?';
    let Some(actual_path) = resolve_config_path(path, explicit)? else {
        return Ok(ConfigLoad {
            loaded_path: None,
            specs: Vec::new(),
            wildcard,
        });
    };

    let file = File::open(&actual_path)
        .map_err(|error| format!("failed to open config `{}`: {error}", actual_path.display()))?;
    let reader = BufReader::new(file);
    let mut specs = Vec::new();

    for (line_index, line) in reader.lines().enumerate() {
        let line_number = line_index + 1;
        let line = line.map_err(|error| {
            format!(
                "failed to read line {line_number} from config `{}`: {error}",
                actual_path.display()
            )
        })?;
        if let Some(parsed) = parse_line(&line, wildcard)
            .map_err(|message| format!("{}:{}: {message}", actual_path.display(), line_number))?
        {
            wildcard = parsed.wildcard;
            if let Some(spec) = parsed.spec {
                specs.push(spec);
            }
        }
    }

    Ok(ConfigLoad {
        loaded_path: Some(actual_path),
        specs,
        wildcard,
    })
}

fn decode_escapes(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }

        index += 1;
        let Some(&escaped) = bytes.get(index) else {
            decoded.push(b'\\');
            break;
        };

        match escaped {
            b'\\' => decoded.push(b'\\'),
            b'a' => decoded.push(0x07),
            b'n' => decoded.push(b'\n'),
            b'r' => decoded.push(b'\r'),
            b's' => decoded.push(b' '),
            b't' => decoded.push(b'\t'),
            b'v' => decoded.push(0x0b),
            b'x' => {
                let end = index + 3;
                let digits = bytes
                    .get(index + 1..end)
                    .ok_or_else(|| format!("incomplete hex escape in `{value}`"))?;
                decoded.push(parse_radix_escape(digits, 16, value)?);
                index += 2;
            }
            b'0'..=b'3' => {
                let end = index + 3;
                let digits = bytes
                    .get(index..end)
                    .ok_or_else(|| format!("incomplete octal escape in `{value}`"))?;
                decoded.push(parse_radix_escape(digits, 8, value)?);
                index += 2;
            }
            other => decoded.push(other),
        }

        index += 1;
    }

    Ok(decoded)
}

fn parse_line(line: &str, wildcard: u8) -> Result<Option<ParsedLine>, String> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let mut tokens = trimmed.split_whitespace();
    let Some(first) = tokens.next() else {
        return Ok(None);
    };

    if first.eq_ignore_ascii_case("wildcard") {
        let Some(value) = tokens.next() else {
            return Ok(None);
        };
        let decoded = decode_escapes(value)?;
        let new_wildcard = decoded
            .first()
            .copied()
            .ok_or_else(|| "wildcard must decode to at least one byte".to_owned())?;
        return Ok(Some(ParsedLine {
            spec: None,
            wildcard: new_wildcard,
        }));
    }

    let Some(case_token) = tokens.next() else {
        return Err("missing case-sensitivity column".to_owned());
    };
    let Some(size_token) = tokens.next() else {
        return Err("missing max-size column".to_owned());
    };
    let Some(header_token) = tokens.next() else {
        return Err("missing header column".to_owned());
    };

    let footer_token = tokens.next().unwrap_or_default();
    let mode_token = tokens.next().unwrap_or_default();
    let suffix = if first.eq_ignore_ascii_case(NO_EXTENSION_SUFFIX) {
        ""
    } else {
        first
    };
    let max_len = size_token
        .parse::<u64>()
        .map_err(|error| format!("invalid max-size `{size_token}`: {error}"))?;
    let case_sensitive =
        case_token.eq_ignore_ascii_case("y") || case_token.eq_ignore_ascii_case("yes");
    let search_mode = parse_search_mode(mode_token);
    let header = decode_escapes(header_token)?;
    let footer = decode_escapes(footer_token)?;

    Ok(Some(ParsedLine {
        spec: Some(SearchSpec::config(
            suffix,
            case_sensitive,
            max_len,
            header,
            footer,
            search_mode,
        )),
        wildcard,
    }))
}

fn parse_radix_escape(digits: &[u8], radix: u32, original: &str) -> Result<u8, String> {
    let text = str::from_utf8(digits)
        .map_err(|error| format!("invalid escape in `{original}`: {error}"))?;
    u8::from_str_radix(text, radix)
        .map_err(|error| format!("invalid escape `\\{text}` in `{original}`: {error}"))
}

const fn parse_search_mode(value: &str) -> SearchMode {
    if value.eq_ignore_ascii_case("REVERSE") {
        SearchMode::Reverse
    } else if value.eq_ignore_ascii_case("NEXT") {
        SearchMode::ForwardNext
    } else if value.eq_ignore_ascii_case("ASCII") {
        SearchMode::Ascii
    } else {
        SearchMode::Forward
    }
}

fn resolve_config_path(path: &Path, explicit: bool) -> Result<Option<PathBuf>, String> {
    if path.exists() {
        return Ok(Some(path.to_path_buf()));
    }

    if explicit {
        return Err(format!("config file `{}` does not exist", path.display()));
    }

    Ok(None)
}
