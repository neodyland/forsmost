use super::scan::{read_le_u16, read_le_u32, read_le_u64};
pub(super) const ASF_FILE_PROPERTIES_GUID: &[u8] =
    b"\xa1\xdc\xab\x8c\x47\xa9\xcf\x11\x8e\xe4\x00\xc0\x0c\x20\x53\x65";
pub(super) const ASF_FILE_SIZE_OFFSET: usize = 40;
pub(super) const ASF_HEADER_GUID: &[u8] =
    b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c";
pub(super) const BMP_SIZE_OFFSET: usize = 2;
pub(super) const BMP_DATA_OFFSET_OFFSET: usize = 10;
pub(super) const BMP_DATA_SIZE_OFFSET: usize = 34;
pub(super) const BMP_HEIGHT_OFFSET: usize = 22;
pub(super) const BMP_HEADER_LENGTH_OFFSET: usize = 14;
pub(super) const BMP_MIN_LEN: usize = 100;
pub(super) const BMP_VERTICAL_LIMIT: u32 = 2000;
pub(super) const BMP_WIDTH_OFFSET: usize = 18;
pub(super) const CFB_DIRECTORY_ENTRY_LEN: usize = 128;
pub(super) const CFB_DIRECTORY_SECTOR_LIMIT: usize = 300;
pub(super) const CFB_DIFAT_HEADER_ENTRIES: usize = 109;
pub(super) const CFB_DIFAT_OFFSET: usize = 76;
pub(super) const CFB_DIFAT_SECTOR: u32 = 0xffff_fffc;
pub(super) const CFB_END_OF_CHAIN: u32 = 0xffff_fffe;
pub(super) const CFB_FAT_SECTOR: u32 = 0xffff_fffd;
pub(super) const CFB_FREE_SECTOR: u32 = 0xffff_ffff;
pub(super) const CFB_HEADER_LEN: usize = 512;
pub(super) const CFB_MAX_EXTRA_DIFAT_SECTORS: u32 = 100;
pub(super) const CFB_MAX_FAT_SECTORS: u32 = 4096;
pub(super) const CFB_NO_STREAM: u32 = 0xffff_ffff;
pub(super) const CFB_ROOT: u8 = 5;
pub(super) const CFB_STREAM: u8 = 2;
pub(super) const CFB_VALID_BYTE_ORDER: u16 = 0xfffe;
pub(super) const ELF_32_HEADER_LEN: usize = 52;
pub(super) const ELF_32_PHDR_LEN: usize = 32;
pub(super) const ELF_32_SHDR_LEN: usize = 40;
pub(super) const ELF_64_HEADER_LEN: usize = 64;
pub(super) const ELF_64_PHDR_LEN: usize = 56;
pub(super) const ELF_64_SHDR_LEN: usize = 64;
pub(super) const ELF_CLASS_32: u8 = 1;
pub(super) const ELF_CLASS_64: u8 = 2;
pub(super) const ELF_DATA_BIG: u8 = 2;
pub(super) const ELF_DATA_LITTLE: u8 = 1;
pub(super) const ELF_HEADER_LEN_OFFSET_32: usize = 40;
pub(super) const ELF_HEADER_LEN_OFFSET_64: usize = 52;
pub(super) const ELF_MAGIC: &[u8] = b"\x7fELF";
pub(super) const ELF_PHDR_COUNT_OFFSET_32: usize = 44;
pub(super) const ELF_PHDR_COUNT_OFFSET_64: usize = 56;
pub(super) const ELF_PHDR_LEN_OFFSET_32: usize = 42;
pub(super) const ELF_PHDR_LEN_OFFSET_64: usize = 54;
pub(super) const ELF_PHDR_OFFSET_32: usize = 28;
pub(super) const ELF_PHDR_OFFSET_64: usize = 32;
pub(super) const ELF_SHDR_COUNT_OFFSET_32: usize = 48;
pub(super) const ELF_SHDR_COUNT_OFFSET_64: usize = 60;
pub(super) const ELF_SHDR_LEN_OFFSET_32: usize = 46;
pub(super) const ELF_SHDR_LEN_OFFSET_64: usize = 58;
pub(super) const ELF_SHDR_OFFSET_32: usize = 32;
pub(super) const ELF_SHDR_OFFSET_64: usize = 40;
pub(super) const ELF_VERSION: u8 = 1;
#[cfg(feature = "gzip")]
pub(super) const GZIP_HEADER_LEN: usize = 10;
#[cfg(feature = "gzip")]
pub(super) const GZIP_RESERVED_FLAGS: u8 = 0xe0;
pub(super) const GIF_HEADER_LEN: usize = 13;
pub(super) const HTML_ASCII_PROBE_LEN: usize = 16;
pub(super) const ISO_BMFF_MEDIA_BOXES: [&[u8; 4]; 3] = [b"mdat", b"moof", b"moov"];
pub(super) const ISO_BMFF_TOP_LEVEL_BOXES: [&[u8; 4]; 17] = [
    b"bloc", b"emsg", b"free", b"ftyp", b"mdat", b"meco", b"meta", b"mfra", b"moof", b"moov",
    b"pdin", b"prft", b"sidx", b"skip", b"ssix", b"styp", b"uuid",
];
pub(super) const JPEG_MIN_LEN: usize = 128;
pub(super) const KIBIBYTE: usize = 1024;
pub(super) const MEBIBYTE: usize = 1024 * KIBIBYTE;
pub(super) const MOV_REQUIRED_ATOMS: [&[u8; 4]; 8] = [
    b"free", b"mdat", b"wide", b"PICT", b"trak", b"moov", b"mp3\0", b"pnot",
];
pub(super) const MPEG_MARKER: &[u8] = b"\0\0\x01";
pub(super) const MPEG_MIN_LEN: usize = KIBIBYTE;
pub(super) const MPEG_SEARCH_WINDOW: usize = 2 * KIBIBYTE;
pub(super) const MP4_MIN_LEN: usize = KIBIBYTE;
pub(super) const PDF_MIN_PROBE_LEN: usize = 512;
pub(super) const PE_CHARACTERISTIC_DLL: u16 = 0x2000;
pub(super) const PE_CHARACTERISTIC_EXECUTABLE_IMAGE: u16 = 0x0002;
pub(super) const PE_CHARACTERISTIC_SYSTEM: u16 = 0x1000;
pub(super) const PE_CHARACTERISTICS_OFFSET: usize = 18;
pub(super) const PE_COFF_HEADER_LEN: usize = 20;
pub(super) const PE_MAX_LEN: usize = 4 * MEBIBYTE;
pub(super) const PE_MAX_OFFSET: usize = 1000;
pub(super) const PE_MIN_LEN: usize = 512;
pub(super) const PE_OFFSET_LOCATION: usize = 0x3c;
pub(super) const PE_SECTION_HEADER_LEN: usize = 40;
pub(super) const PE_SIGNATURE: &[u8] = b"PE\0\0";
pub(super) const PNG_CHUNK_OVERHEAD: usize = 12;
pub(super) const PNG_DIMENSION_LIMIT: u32 = 3000;
pub(super) const PNG_MIN_LEN: usize = 100;
pub(super) const PNG_SIGNATURE_LEN: usize = 8;
pub(super) const RAR_ENCRYPTED_SEARCH_LEN: usize = 50 * KIBIBYTE;
pub(super) const REG_SIZE_OFFSET: usize = 0x28;
pub(super) const WPD_DOCUMENT_AREA_OFFSET: usize = 4;
pub(super) const WPD_MIN_LEN: usize = 16;
pub(super) const ZIP_CONTENT_TYPES: &[u8] = b"[Content_Types].xml";
pub(super) const ZIP_CENTRAL_HEADER_LEN: usize = 46;
pub(super) const ZIP_CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
pub(super) const ZIP_EOCD_BASE_LEN: usize = 22;
pub(super) const ZIP_EOCD_COMMENT_OFFSET: usize = 20;
pub(super) const ZIP_EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
pub(super) const ZIP64_EOCD_LOCATOR_LEN: usize = 20;
pub(super) const ZIP64_EOCD_LOCATOR_SIGNATURE: &[u8] = b"PK\x06\x07";
pub(super) const ZIP64_EOCD_MIN_LEN: usize = 56;
pub(super) const ZIP64_EOCD_SIGNATURE: &[u8] = b"PK\x06\x06";
pub(super) const ZIP_LOCAL_HEADER_LEN: usize = 30;
pub(super) const ZIP_LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";

#[derive(Debug)]
pub struct Recovered<'a> {
    pub bytes: &'a [u8],
    pub comment: String,
    pub next_index: usize,
    pub suffix: String,
    pub write: bool,
}

#[derive(Debug)]
pub(super) struct MovScan {
    pub(super) end: usize,
    pub(super) write: bool,
}

#[derive(Debug)]
pub(super) struct PeDetails {
    pub(super) len: usize,
    pub(super) suffix: &'static str,
}

#[derive(Debug)]
pub(super) enum PdfLinearizedScan {
    Found(usize),
    Missing,
    NeedMore,
    Skip,
}

#[derive(Debug)]
pub(super) struct OleDetails {
    pub(super) len: usize,
    pub(super) suffix: String,
    pub(super) write: bool,
}

#[derive(Debug)]
pub(super) struct OleDirectoryEntry {
    pub(super) kind: u8,
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) start_sector: u32,
}

#[derive(Debug)]
pub(super) struct ZipClassification {
    pub(super) comment: Option<String>,
    pub(super) office_2007: bool,
    pub(super) office_2007_suffix: Option<&'static str>,
    pub(super) open_office: bool,
    pub(super) suffix: &'static str,
}

#[derive(Debug)]
pub(super) enum ZipScan {
    Search {
        classification: ZipClassification,
        search_start: usize,
    },
    SearchCentralDirectory {
        classification: ZipClassification,
        search_start: usize,
    },
    Skip(usize),
}

impl MovScan {
    pub(super) const fn skip(end: usize) -> Self {
        Self { end, write: false }
    }

    pub(super) const fn write(end: usize) -> Self {
        Self { end, write: true }
    }
}

impl OleDirectoryEntry {
    pub(super) fn parse(entry: &[u8]) -> Option<Self> {
        let kind = *entry.get(66)?;
        if kind == 0 {
            return None;
        }
        let name_len = read_le_u16(entry, 64)? as usize;
        if !(2..=64).contains(&name_len) {
            return None;
        }
        let name_bytes = entry.get(..name_len.saturating_sub(2))?;
        let mut units = Vec::with_capacity(name_bytes.len() / 2);
        for chunk in name_bytes.chunks_exact(2) {
            units.push(u16::from_le_bytes(chunk.try_into().ok()?));
        }
        let name = String::from_utf16_lossy(&units);
        let start_sector = read_le_u32(entry, 116)?;
        let size = read_le_u64(entry, 120).or_else(|| read_le_u32(entry, 120).map(u64::from))?;

        Some(Self {
            kind,
            name,
            size,
            start_sector,
        })
    }
}

impl ZipClassification {
    pub(super) const fn new() -> Self {
        Self {
            comment: None,
            office_2007: false,
            office_2007_suffix: None,
            open_office: false,
            suffix: "zip",
        }
    }
}
