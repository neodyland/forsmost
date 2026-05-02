const KIBIBYTE: u64 = 1024;
const MEBIBYTE: u64 = 1024 * KIBIBYTE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Avi,
    Bmp,
    Config,
    Cpp,
    Doc,
    Docx,
    Elf,
    Exe,
    Gif,
    #[cfg(feature = "gzip")]
    Gzip,
    Html,
    Jpeg,
    Mov,
    Mp4,
    Mpeg,
    Ole,
    Pdf,
    Png,
    Ppt,
    Pptx,
    Rar,
    Reg,
    Riff,
    Sxc,
    Sxi,
    Sxw,
    Wav,
    Wmv,
    Wpd,
    Xls,
    Xlsx,
    Zip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchMode {
    Ascii,
    Forward,
    ForwardNext,
    Reverse,
}

#[derive(Clone, Debug)]
pub struct SearchSpec {
    pub case_sensitive: bool,
    pub footer: Vec<u8>,
    pub found: u64,
    pub header: Vec<u8>,
    pub kind: FileKind,
    pub markers: Vec<Vec<u8>>,
    pub max_len: u64,
    pub search_mode: SearchMode,
    pub suffix: String,
}

impl SearchSpec {
    #[must_use]
    pub fn config(
        suffix: &str,
        case_sensitive: bool,
        max_len: u64,
        header: Vec<u8>,
        footer: Vec<u8>,
        search_mode: SearchMode,
    ) -> Self {
        Self {
            case_sensitive,
            footer,
            found: 0,
            header,
            kind: FileKind::Config,
            markers: Vec::new(),
            max_len,
            search_mode,
            suffix: suffix.to_owned(),
        }
    }

    #[must_use]
    pub const fn directory_name(&self) -> &str {
        if self.suffix.is_empty() {
            "none"
        } else {
            self.suffix.as_str()
        }
    }
}

#[must_use]
pub fn builtins_for_selector(
    selector: &str,
    max_file_size: Option<u64>,
) -> Option<Vec<SearchSpec>> {
    let normalized = selector.to_ascii_lowercase();
    match normalized.as_str() {
        "all" => Some(all_builtins()),
        "avi" => Some(vec![builtin(
            FileKind::Avi,
            "avi",
            b"RIFF",
            b"INFO",
            max_file_size.unwrap_or(20 * MEBIBYTE),
            true,
        )]),
        "bmp" => Some(vec![builtin(
            FileKind::Bmp,
            "bmp",
            b"BM",
            b"",
            max_file_size.unwrap_or(2 * MEBIBYTE),
            true,
        )]),
        "cpp" => Some(vec![builtin_with_markers(
            FileKind::Cpp,
            "cpp",
            b"#include",
            b"char",
            max_file_size.unwrap_or(MEBIBYTE),
            true,
            &[b"int"],
        )]),
        "doc" => Some(vec![ole_family(
            FileKind::Doc,
            "doc",
            max_file_size.unwrap_or(20 * MEBIBYTE),
        )]),
        "docx" => Some(vec![zip_family(
            FileKind::Docx,
            "docx",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "elf" => Some(vec![builtin(
            FileKind::Elf,
            "elf",
            b"\x7fELF",
            b"",
            max_file_size.unwrap_or(MEBIBYTE),
            true,
        )]),
        "exe" => Some(vec![builtin(
            FileKind::Exe,
            "exe",
            b"MZ",
            b"",
            max_file_size.unwrap_or(MEBIBYTE),
            true,
        )]),
        "gif" => Some(vec![builtin_with_markers(
            FileKind::Gif,
            "gif",
            b"GIF8",
            b"\x00\x3b",
            max_file_size.unwrap_or(MEBIBYTE),
            true,
            &[b"\x00\x00\x3b"],
        )]),
        #[cfg(feature = "gzip")]
        "gzip" | "gz" => Some(vec![builtin(
            FileKind::Gzip,
            "gz",
            b"\x1f\x8b",
            b"\x00\x00\x00\x00",
            max_file_size.unwrap_or(100 * MEBIBYTE),
            true,
        )]),
        "html" | "htm" => Some(vec![builtin(
            FileKind::Html,
            "htm",
            b"<html",
            b"</html>",
            max_file_size.unwrap_or(MEBIBYTE),
            false,
        )]),
        "jpg" | "jpeg" => Some(vec![builtin(
            FileKind::Jpeg,
            "jpg",
            b"\xff\xd8\xff",
            b"\xff\xd9",
            max_file_size.unwrap_or(20 * MEBIBYTE),
            true,
        )]),
        "mov" => Some(vec![builtin(
            FileKind::Mov,
            "mov",
            b"moov",
            b"",
            max_file_size.unwrap_or(40 * MEBIBYTE),
            true,
        )]),
        "mp4" => Some(vec![builtin(
            FileKind::Mp4,
            "mp4",
            b"????ftyp",
            b"",
            max_file_size.unwrap_or(600 * MEBIBYTE),
            true,
        )]),
        "mpg" | "mpeg" => Some(vec![builtin_with_markers(
            FileKind::Mpeg,
            "mpg",
            b"\x00\x00\x01\xba",
            b"\x00\x00\x01\xb9",
            max_file_size.unwrap_or(50 * MEBIBYTE),
            true,
            &[b"\x00\x00\x01"],
        )]),
        "ole" | "office" => Some(vec![ole_family(
            FileKind::Ole,
            "ole",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "pdf" => Some(vec![builtin_with_markers(
            FileKind::Pdf,
            "pdf",
            b"%PDF-1.",
            b"%%EOF",
            max_file_size.unwrap_or(20 * MEBIBYTE),
            true,
            &[b"/L ", b"obj", b"/Linearized", b"/Length"],
        )]),
        "png" => Some(vec![builtin(
            FileKind::Png,
            "png",
            b"\x89PNG\r\n\x1a\n",
            b"IEND",
            max_file_size.unwrap_or(MEBIBYTE),
            true,
        )]),
        "ppt" => Some(vec![ole_family(
            FileKind::Ppt,
            "ppt",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "pptx" => Some(vec![zip_family(
            FileKind::Pptx,
            "pptx",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "rar" => Some(vec![builtin(
            FileKind::Rar,
            "rar",
            b"Rar!\x1a\x07\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            max_file_size.unwrap_or(100 * MEBIBYTE),
            true,
        )]),
        "reg" => Some(vec![builtin(
            FileKind::Reg,
            "reg",
            b"regf",
            b"",
            max_file_size.unwrap_or(2 * MEBIBYTE),
            true,
        )]),
        "rif" => Some(vec![builtin(
            FileKind::Riff,
            "rif",
            b"RIFF",
            b"INFO",
            max_file_size.unwrap_or(20 * MEBIBYTE),
            true,
        )]),
        "sxc" => Some(vec![zip_family(
            FileKind::Sxc,
            "sxc",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "sxi" => Some(vec![zip_family(
            FileKind::Sxi,
            "sxi",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "sxw" => Some(vec![zip_family(
            FileKind::Sxw,
            "sxw",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "vjpeg" => Some(vec![builtin(
            FileKind::Mov,
            "mov",
            b"pnot",
            b"",
            max_file_size.unwrap_or(40 * MEBIBYTE),
            true,
        )]),
        "wav" => Some(vec![builtin(
            FileKind::Wav,
            "wav",
            b"RIFF",
            b"INFO",
            max_file_size.unwrap_or(20 * MEBIBYTE),
            true,
        )]),
        "wmv" => Some(vec![builtin(
            FileKind::Wmv,
            "wmv",
            b"\x30\x26\xb2\x75\x8e\x66\xcf\x11",
            b"\xa1\xdc\xab\x8c\x47\xa9",
            max_file_size.unwrap_or(20 * MEBIBYTE),
            true,
        )]),
        "wpd" => Some(vec![builtin(
            FileKind::Wpd,
            "wpd",
            b"\xffWPC",
            b"",
            max_file_size.unwrap_or(MEBIBYTE),
            true,
        )]),
        "xls" => Some(vec![ole_family(
            FileKind::Xls,
            "xls",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "xlsx" => Some(vec![zip_family(
            FileKind::Xlsx,
            "xlsx",
            max_file_size.unwrap_or(10 * MEBIBYTE),
        )]),
        "zip" => Some(vec![zip_family(
            FileKind::Zip,
            "zip",
            max_file_size.unwrap_or(100 * MEBIBYTE),
        )]),
        _ => None,
    }
}

#[must_use]
pub fn default_all_builtins() -> Vec<SearchSpec> {
    all_builtins()
}

fn all_builtins() -> Vec<SearchSpec> {
    let mut specs = Vec::new();
    for selector in [
        "jpg", "gif", "bmp", "wmv", "mov", "mp4", "rif", "htm", "ole", "zip", "rar", "exe", "png",
        "mpg", "pdf",
    ] {
        if let Some(mut selected) = builtins_for_selector(selector, None) {
            specs.append(&mut selected);
        }
    }
    specs
}

fn builtin(
    kind: FileKind,
    suffix: &str,
    header: &[u8],
    footer: &[u8],
    max_len: u64,
    case_sensitive: bool,
) -> SearchSpec {
    builtin_with_markers(kind, suffix, header, footer, max_len, case_sensitive, &[])
}

fn builtin_with_markers(
    kind: FileKind,
    suffix: &str,
    header: &[u8],
    footer: &[u8],
    max_len: u64,
    case_sensitive: bool,
    markers: &[&[u8]],
) -> SearchSpec {
    SearchSpec {
        case_sensitive,
        footer: footer.to_vec(),
        found: 0,
        header: header.to_vec(),
        kind,
        markers: markers.iter().map(|marker| marker.to_vec()).collect(),
        max_len,
        search_mode: SearchMode::Forward,
        suffix: suffix.to_owned(),
    }
}

fn ole_family(kind: FileKind, suffix: &str, max_len: u64) -> SearchSpec {
    builtin(
        kind,
        suffix,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00",
        b"",
        max_len,
        true,
    )
}

fn zip_family(kind: FileKind, suffix: &str, max_len: u64) -> SearchSpec {
    builtin(kind, suffix, b"PK\x03\x04", b"PK\x05\x06", max_len, true)
}
