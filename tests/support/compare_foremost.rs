use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::{create_dir_all, read, read_dir, read_to_string, remove_dir_all, write},
    iter::repeat_n,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

// Foremost 1.5.7 defines extract_reg but never dispatches REG from extract_file.
// OLE is covered separately because a 64-bit original build can keep a minimal
// WordDocument CFB as .ole while the Rust port classifies the same bytes as .doc.
pub const EXACT_SELECTORS: &str = "jpg,pdf,png,zip,exe,html,rar,wmv,mpg,mov,mp4";

#[derive(Debug)]
pub enum ForemostRunner {
    Native(OsString),
    Wsl { bin: String, cwd: String },
}

impl ForemostRunner {
    pub fn unique_root(&self, name: &str) -> PathBuf {
        match self {
            Self::Native(_) => env::temp_dir().join(unique_name(name)),
            Self::Wsl { .. } => env::current_dir()
                .unwrap()
                .join("target")
                .join(unique_name(name)),
        }
    }
}

pub fn append_at(buf: &mut Vec<u8>, offset: usize, data: &[u8]) {
    assert!(offset >= buf.len());
    buf.resize(offset, 0);
    buf.extend_from_slice(data);
}

pub fn append_cfb_dir_entry(
    buf: &mut [u8],
    index: usize,
    name: &str,
    kind: u8,
    start_sector: u32,
    size: u32,
) {
    let offset = 1024 + index * 128;
    write_cfb_dir_entry(buf, offset, name, kind, start_sector, u64::from(size));
}

pub fn write_cfb_dir_entry(
    buf: &mut [u8],
    offset: usize,
    name: &str,
    kind: u8,
    start_sector: u32,
    size: u64,
) {
    let mut utf16 = name.encode_utf16().collect::<Vec<_>>();
    utf16.push(0);
    for (unit_index, unit) in utf16.iter().enumerate() {
        let start = offset + unit_index * 2;
        buf[start..start + 2].copy_from_slice(&unit.to_le_bytes());
    }
    buf[offset + 64..offset + 66].copy_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
    buf[offset + 66] = kind;
    buf[offset + 68..offset + 72].copy_from_slice(&u32::MAX.to_le_bytes());
    buf[offset + 72..offset + 76].copy_from_slice(&u32::MAX.to_le_bytes());
    buf[offset + 76..offset + 80].copy_from_slice(&u32::MAX.to_le_bytes());
    buf[offset + 116..offset + 120].copy_from_slice(&start_sector.to_le_bytes());
    buf[offset + 120..offset + 128].copy_from_slice(&size.to_le_bytes());
}

pub fn append_jpeg_segment(buf: &mut Vec<u8>, marker: u8, data: &[u8]) {
    buf.extend_from_slice(&[0xff, marker]);
    buf.extend_from_slice(&((data.len() + 2) as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

pub fn append_png_chunk(buf: &mut Vec<u8>, chunk_type: [u8; 4], data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&chunk_type);
    buf.extend_from_slice(data);
    buf.extend_from_slice(&0u32.to_be_bytes());
}

pub fn append_zip_local(buf: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    append_zip_local_with_options(
        buf,
        name,
        data,
        0,
        data.len() as u32,
        data.len() as u32,
        &[],
    );
}

pub fn append_zip_local_with_options(
    buf: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    flags: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    extra: &[u8],
) {
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&compressed_size.to_le_bytes());
    buf.extend_from_slice(&uncompressed_size.to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(extra);
    buf.extend_from_slice(data);
}

pub fn audit_counts(path: &Path) -> BTreeMap<String, u64> {
    read_to_string(path.join("audit.txt"))
        .unwrap()
        .lines()
        .filter_map(|line| {
            let (suffix, count) = line.trim().split_once(":= ")?;
            Some((suffix.to_owned(), count.parse().unwrap()))
        })
        .collect()
}

pub fn audit_names(path: &Path) -> BTreeSet<String> {
    read_to_string(path.join("audit.txt"))
        .unwrap()
        .lines()
        .flat_map(str::split_whitespace)
        .filter(|token| looks_like_recovered_name(token))
        .map(ToOwned::to_owned)
        .collect()
}

pub fn collect_output_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let child_path = entry.path();
        if child_path.is_file() {
            continue;
        }
        let directory = entry.file_name().to_string_lossy().into_owned();
        for file_entry in read_dir(&child_path).unwrap() {
            let file_entry = file_entry.unwrap();
            let file_path = file_entry.path();
            if !file_path.is_file() {
                continue;
            }
            let file_name = file_entry.file_name().to_string_lossy().into_owned();
            files.insert(format!("{directory}/{file_name}"), read(file_path).unwrap());
        }
    }
    files
}

pub fn cfb_doc_sample() -> Vec<u8> {
    let mut buf = vec![0; 1536];
    buf[0..16].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\0\0\0\0\0\0\0\0");
    buf[24..26].copy_from_slice(&0x003eu16.to_le_bytes());
    buf[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
    buf[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    buf[30..32].copy_from_slice(&9u16.to_le_bytes());
    buf[32..34].copy_from_slice(&6u16.to_le_bytes());
    buf[44..48].copy_from_slice(&1u32.to_le_bytes());
    buf[48..52].copy_from_slice(&1u32.to_le_bytes());
    buf[56..60].copy_from_slice(&4096u32.to_le_bytes());
    buf[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    buf[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());
    for chunk in buf[512..1024].chunks_exact_mut(4) {
        chunk.copy_from_slice(&u32::MAX.to_le_bytes());
    }
    buf[512..516].copy_from_slice(&0xffff_fffdu32.to_le_bytes());
    buf[516..520].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
    append_cfb_dir_entry(&mut buf, 0, "Root Entry", 5, u32::MAX, 0);
    append_cfb_dir_entry(&mut buf, 1, "WordDocument", 2, u32::MAX, 0);
    buf
}

pub fn cfb_access_sample() -> Vec<u8> {
    let mut buf = cfb_doc_sample();
    append_cfb_dir_entry(&mut buf, 1, "AccessObjSiteData", 2, u32::MAX, 0);
    buf
}

pub fn cfb_4096_sector_doc_sample() -> Vec<u8> {
    const SECTOR_SIZE: usize = 4096;
    const END_OF_CHAIN: u32 = 0xffff_fffe;
    const FAT_SECTOR: u32 = 0xffff_fffd;
    const FREE_SECTOR: u32 = 0xffff_ffff;

    let sector_offset = |sector_id: u32| (sector_id as usize + 1) * SECTOR_SIZE;
    let mut buf = vec![0; sector_offset(1) + SECTOR_SIZE];
    buf[0..8].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    buf[24..26].copy_from_slice(&0x003eu16.to_le_bytes());
    buf[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
    buf[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    buf[30..32].copy_from_slice(&12u16.to_le_bytes());
    buf[32..34].copy_from_slice(&6u16.to_le_bytes());
    buf[44..48].copy_from_slice(&1u32.to_le_bytes());
    buf[48..52].copy_from_slice(&1u32.to_le_bytes());
    buf[56..60].copy_from_slice(&4096u32.to_le_bytes());
    buf[60..64].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
    buf[68..72].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
    for chunk in buf[76..512].chunks_exact_mut(4) {
        chunk.copy_from_slice(&FREE_SECTOR.to_le_bytes());
    }
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());

    let fat_offset = sector_offset(0);
    for chunk in buf[fat_offset..fat_offset + SECTOR_SIZE].chunks_exact_mut(4) {
        chunk.copy_from_slice(&FREE_SECTOR.to_le_bytes());
    }
    buf[fat_offset..fat_offset + 4].copy_from_slice(&FAT_SECTOR.to_le_bytes());
    buf[fat_offset + 4..fat_offset + 8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());

    let dir_offset = sector_offset(1);
    write_cfb_dir_entry(&mut buf, dir_offset, "Root Entry", 5, FREE_SECTOR, 0);
    write_cfb_dir_entry(
        &mut buf,
        dir_offset + 128,
        "WordDocument",
        2,
        FREE_SECTOR,
        0,
    );
    buf
}

pub fn bmp_sample(width: i32, height: i32) -> Vec<u8> {
    let size = 140usize;
    let data_offset = 54u32;
    let data_size = size as u32 - data_offset;
    let mut buf = vec![0; size];
    buf[0..2].copy_from_slice(b"BM");
    buf[2..6].copy_from_slice(&(size as u32).to_le_bytes());
    buf[10..14].copy_from_slice(&data_offset.to_le_bytes());
    buf[14..18].copy_from_slice(&40u32.to_le_bytes());
    buf[18..22].copy_from_slice(&width.to_le_bytes());
    buf[22..26].copy_from_slice(&height.to_le_bytes());
    buf[26..28].copy_from_slice(&1u16.to_le_bytes());
    buf[28..30].copy_from_slice(&24u16.to_le_bytes());
    buf[34..38].copy_from_slice(&data_size.to_le_bytes());
    buf[54..].fill(0x7f);
    buf
}

pub fn compare_payload_with_original(name: &str, selectors: &str, payload: Vec<u8>) {
    compare_payload(name, selectors, payload, true);
}

pub fn compare_payload_files_with_original(name: &str, selectors: &str, payload: Vec<u8>) {
    compare_payload(name, selectors, payload, false);
}

pub fn compare_payload(name: &str, selectors: &str, payload: Vec<u8>, compare_audit_counts: bool) {
    let Some(runner) = foremost_runner() else {
        eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
        return;
    };

    let root = runner.unique_root(name);
    create_dir_all(&root).unwrap();
    let input = root.join("input.bin");
    let rust_output = root.join("rust");
    let foremost_output = root.join("foremost");
    write(&input, payload).unwrap();

    run_forsmost(&input, &rust_output, selectors);
    run_original_foremost(&runner, &input, &foremost_output, selectors);

    let rust_files = collect_output_files(&rust_output);
    let foremost_files = collect_output_files(&foremost_output);
    assert_output_files_eq(&rust_files, &foremost_files);
    if compare_audit_counts {
        assert_eq!(audit_counts(&rust_output), audit_counts(&foremost_output));
    }
    assert_eq!(audit_names(&rust_output), audit_names(&foremost_output));

    remove_dir_all(root).unwrap();
}

pub fn assert_output_files_eq(
    rust_files: &BTreeMap<String, Vec<u8>>,
    foremost_files: &BTreeMap<String, Vec<u8>>,
) {
    if rust_files == foremost_files {
        return;
    }

    let extra_in_rust = rust_files
        .keys()
        .filter(|name| !foremost_files.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    let missing_from_rust = foremost_files
        .keys()
        .filter(|name| !rust_files.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    let byte_mismatches = rust_files
        .iter()
        .filter_map(|(name, bytes)| {
            foremost_files.get(name).and_then(|foremost_bytes| {
                (bytes != foremost_bytes).then(|| {
                    format!(
                        "{name}: rust {} bytes, foremost {} bytes",
                        bytes.len(),
                        foremost_bytes.len()
                    )
                })
            })
        })
        .collect::<Vec<_>>();

    panic!(
        "output file mismatch\nrust files: {:?}\nforemost files: {:?}\nextra in rust: {:?}\nmissing from rust: {:?}\nbyte mismatches: {:?}",
        output_file_summary(rust_files),
        output_file_summary(foremost_files),
        extra_in_rust,
        missing_from_rust,
        byte_mismatches
    );
}

pub fn eocd() -> Vec<u8> {
    let mut eocd = Vec::new();
    eocd.extend_from_slice(b"PK\x05\x06");
    eocd.extend_from_slice(&[0; 18]);
    eocd
}

pub fn exe_sample(characteristics: u16) -> Vec<u8> {
    let mut buf = vec![0; 1024];
    let pe_offset = 0x80usize;
    let section_table = pe_offset + 4 + 20 + 224;
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    buf[pe_offset + 6..pe_offset + 8].copy_from_slice(&1u16.to_le_bytes());
    buf[pe_offset + 20..pe_offset + 22].copy_from_slice(&224u16.to_le_bytes());
    buf[pe_offset + 22..pe_offset + 24].copy_from_slice(&characteristics.to_le_bytes());
    buf[section_table + 16..section_table + 20].copy_from_slice(&512u32.to_le_bytes());
    buf[section_table + 20..section_table + 24].copy_from_slice(&512u32.to_le_bytes());
    buf
}

pub fn foremost_runner() -> Option<ForemostRunner> {
    if let Ok(bin) = env::var("FOREMOST_WSL_BIN") {
        let cwd = env::var("FOREMOST_WSL_CWD").unwrap_or_else(|_| wsl_parent(&bin));
        return Some(ForemostRunner::Wsl { bin, cwd });
    }
    env::var_os("FOREMOST_BIN").map(ForemostRunner::Native)
}

pub fn generated_corpus() -> Vec<u8> {
    let samples: [(usize, Vec<u8>); 13] = [
        (17, jpeg_sample()),
        (307, pdf_sample()),
        (913, png_sample(20, 12)),
        (1301, zip_docx_sample()),
        (1909, exe_sample(0x2000)),
        (3011, b"<html><body>foremost compare</body></html>".to_vec()),
        (4099, registry_sample()),
        (4703, rar_sample()),
        (5401, wmv_sample()),
        (6007, mpeg_sample()),
        (7201, mov_sample()),
        (7601, mp4_sample()),
        (9101, cfb_doc_sample()),
    ];

    let mut buf = Vec::new();
    for (offset, sample) in samples {
        append_at(&mut buf, offset, &sample);
    }
    buf
}

pub fn jpeg_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\xff\xd8");
    append_jpeg_segment(&mut buf, 0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0");
    append_jpeg_segment(&mut buf, 0xdb, &[0; 65]);
    append_jpeg_segment(&mut buf, 0xc4, &[0; 31]);
    append_jpeg_segment(&mut buf, 0xda, &[0; 10]);
    buf.extend(repeat_n(0x55, 24));
    buf.extend_from_slice(b"\xff\xd9");
    buf
}

pub fn jpeg_app2_first_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\xff\xd8");
    append_jpeg_segment(&mut buf, 0xe2, b"ICC_PROFILE\0\x01\x01profile");
    append_jpeg_segment(&mut buf, 0xdb, &[0; 65]);
    append_jpeg_segment(&mut buf, 0xc4, &[0; 31]);
    append_jpeg_segment(&mut buf, 0xda, &[0; 10]);
    buf.extend(repeat_n(0x44, 24));
    buf.extend_from_slice(b"\xff\xd9");
    buf
}

pub fn gif_sample() -> Vec<u8> {
    let mut buf = b"GIF89a".to_vec();
    buf.extend_from_slice(&12u16.to_le_bytes());
    buf.extend_from_slice(&10u16.to_le_bytes());
    buf.extend_from_slice(&[0, 0, 0]);
    buf.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0]);
    buf.extend_from_slice(b"\0;");
    buf
}

pub fn looks_like_recovered_name(token: &str) -> bool {
    let Some((stem, suffix)) = token.split_once('.') else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
        && {
            let (block, collision) = stem
                .split_once('_')
                .map_or((stem, None), |(block, index)| (block, Some(index)));
            block.len() == 8
                && block.chars().all(|character| character.is_ascii_digit())
                && collision.is_none_or(|index| {
                    !index.is_empty() && index.chars().all(|character| character.is_ascii_digit())
                })
        }
}

pub fn output_file_summary(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, usize> {
    files
        .iter()
        .map(|(name, bytes)| (name.clone(), bytes.len()))
        .collect()
}

pub fn only_output_file(files: &BTreeMap<String, Vec<u8>>) -> (&str, &[u8]) {
    match files.iter().next() {
        Some((name, bytes)) if files.len() == 1 => (name.as_str(), bytes),
        _ => panic!(
            "expected exactly one output file: {:?}",
            output_file_summary(files)
        ),
    }
}

pub fn mpeg_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\0\0\x01\xba");
    buf.extend_from_slice(&[0x44; 8]);
    buf.extend_from_slice(b"\0\0\x01\xbb");
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(b"\0\0\x01\xe0");
    buf.extend_from_slice(&1000u16.to_be_bytes());
    buf.extend(repeat_n(0x55, 1000));
    buf.extend_from_slice(b"\0\0\x01\xb9");
    buf
}

pub fn pdf_sample() -> Vec<u8> {
    let mut buf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec();
    buf.resize(520, b' ');
    buf.extend_from_slice(b"%%EOF\nTAIL");
    buf
}

pub fn png_sample(width: u32, height: u32) -> Vec<u8> {
    let mut buf = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    append_png_chunk(&mut buf, *b"IHDR", &ihdr);
    append_png_chunk(&mut buf, *b"IDAT", &[0xaa; 50]);
    append_png_chunk(&mut buf, *b"IEND", &[]);
    buf
}

pub fn png_printable_non_alpha_chunk_sample() -> Vec<u8> {
    let mut buf = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&16u32.to_be_bytes());
    ihdr.extend_from_slice(&12u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    append_png_chunk(&mut buf, *b"IHDR", &ihdr);
    append_png_chunk(&mut buf, *b"ID1T", &[0xaa; 64]);
    append_png_chunk(&mut buf, *b"IEND", &[]);
    buf
}

pub fn rar_sample() -> Vec<u8> {
    let name = b"a.txt";
    let data = b"hello";
    let header_size = 32 + name.len();
    let mut buf = b"Rar!\x1a\x07\x00".to_vec();

    buf.extend_from_slice(&[0, 0, 0x73, 0, 0]);
    buf.extend_from_slice(&13u16.to_le_bytes());
    buf.extend_from_slice(&[0; 6]);

    buf.extend_from_slice(&[0, 0, 0x74, 0, 0]);
    buf.extend_from_slice(&(header_size as u16).to_le_bytes());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.push(2);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(20);
    buf.push(0x30);
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(data);

    buf.extend_from_slice(&[0, 0, 0x7b, 0, 0]);
    buf.extend_from_slice(&7u16.to_le_bytes());
    buf
}

pub fn rar_encrypted_header_sample() -> Vec<u8> {
    let mut buf = b"Rar!\x1a\x07\x00".to_vec();
    buf.extend_from_slice(&[0, 0, 0x73, 0, 0]);
    buf.extend_from_slice(&13u16.to_le_bytes());
    buf.extend_from_slice(&[0; 6]);
    buf.extend_from_slice(&[0x51; 24]);
    buf.extend_from_slice(&[0; 8]);
    buf
}

pub fn riff_avi_sample() -> Vec<u8> {
    let size = 64usize;
    let mut buf = vec![0; size];
    buf[0..4].copy_from_slice(b"RIFF");
    buf[4..8].copy_from_slice(&((size as u32) - 8).to_le_bytes());
    buf[8..12].copy_from_slice(b"AVI ");
    buf[12..16].copy_from_slice(b"LIST");
    buf[16..].fill(0x41);
    buf
}

pub fn zip_data_descriptor_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local_with_options(
        &mut buf,
        b"fakePK\x05\x06name.txt",
        b"",
        1 << 3,
        0,
        0,
        &[0x55; 80],
    );
    buf.extend_from_slice(&eocd());
    buf
}

pub fn zip_oversized_filename_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, &[b'a'; 101], b"data");
    buf.extend_from_slice(&eocd());
    buf
}

pub fn mov_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(b"moov");
    buf.extend_from_slice(b"abcd");
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(b"mdat");
    buf.extend_from_slice(b"efgh");
    buf
}

pub fn mov_invalid_then_valid_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(b"moov");
    buf.extend_from_slice(b"abcd");
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(b"zzzz");
    buf.extend_from_slice(b"efgh");
    buf.extend_from_slice(b"noise");
    buf.extend_from_slice(&mov_sample());
    buf
}

pub fn mp4_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&28u32.to_be_bytes());
    buf.extend_from_slice(b"ftyp");
    buf.extend_from_slice(b"isom\0\0\x02\0isomiso2mp41");
    buf.extend_from_slice(&600u32.to_be_bytes());
    buf.extend_from_slice(b"moov");
    buf.extend(repeat_n(0xaa, 592));
    buf.extend_from_slice(&600u32.to_be_bytes());
    buf.extend_from_slice(b"mdat");
    buf.extend(repeat_n(0xbb, 592));
    buf
}

pub fn path_to_wsl(path: &Path) -> String {
    let text = path.as_os_str().to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = text.chars().skip(2).collect::<String>();
        let rest = rest.trim_start_matches(['\\', '/']);
        format!("/mnt/{drive}/{}", rest.replace('\\', "/"))
    } else {
        text.replace('\\', "/")
    }
}

pub fn registry_sample() -> Vec<u8> {
    let mut buf = vec![0; 512];
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(b"regf");
    buf[0x28..0x2c].copy_from_slice(&len.to_le_bytes());
    buf
}

pub fn run_forsmost(input: &Path, output: &Path, selectors: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
        .args(["-Q", "-b", "1", "-t", selectors, "-o"])
        .arg(output)
        .arg(input)
        .status()
        .unwrap();
    assert!(status.success());
}

pub fn run_original_foremost(
    runner: &ForemostRunner,
    input: &Path,
    output: &Path,
    selectors: &str,
) {
    let mut command = match runner {
        ForemostRunner::Native(program) => Command::new(program),
        ForemostRunner::Wsl { bin, cwd } => {
            let mut command = Command::new("wsl");
            command.args(["--cd", cwd, "--", bin]);
            command
        }
    };

    command.args(["-Q", "-b", "1", "-t", selectors, "-o"]);
    match runner {
        ForemostRunner::Native(_) => {
            command.arg(output).arg(input);
        }
        ForemostRunner::Wsl { .. } => {
            command.arg(path_to_wsl(output)).arg(path_to_wsl(input));
        }
    }

    let status = command.status().unwrap();
    assert!(status.success());
}

pub fn unique_name(name: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    format!("forsmost-{name}-{nonce}")
}

pub fn wmv_sample() -> Vec<u8> {
    let mut buf = vec![0; 160];
    buf[0..16].copy_from_slice(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c");
    buf[16..24].copy_from_slice(&80u64.to_le_bytes());
    buf[24..28].copy_from_slice(&2u32.to_le_bytes());
    buf[28] = 1;
    buf[29] = 2;
    let file_properties = 30;
    buf[file_properties..file_properties + 16]
        .copy_from_slice(b"\xa1\xdc\xab\x8c\x47\xa9\xcf\x11\x8e\xe4\x00\xc0\x0c\x20\x53\x65");
    buf[file_properties + 16..file_properties + 24].copy_from_slice(&104u64.to_le_bytes());
    let len = buf.len() as u64;
    buf[file_properties + 40..file_properties + 48].copy_from_slice(&len.to_le_bytes());
    buf
}

pub fn zip_docx_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, b"[Content_Types].xml", b"");
    append_zip_local(&mut buf, b"word/document.xml", b"");
    buf.extend_from_slice(&eocd());
    buf
}

pub fn zip_docx_reordered_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, b"word/document.xml", b"");
    append_zip_local(&mut buf, b"[Content_Types].xml", b"");
    buf.extend_from_slice(&eocd());
    buf
}

pub fn wsl_parent(path: &str) -> String {
    path.rsplit_once('/').map_or_else(
        || ".".to_owned(),
        |(parent, _)| {
            if parent.is_empty() {
                "/".to_owned()
            } else {
                parent.to_owned()
            }
        },
    )
}
