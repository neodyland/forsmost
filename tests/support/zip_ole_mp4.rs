use std::{
    collections::BTreeMap,
    env::temp_dir,
    fs::{read, read_dir},
    iter::repeat_n,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub const CFB_DIFAT_SECTOR: u32 = 0xffff_fffc;
pub const CFB_END_OF_CHAIN: u32 = 0xffff_fffe;
pub const CFB_FAT_SECTOR: u32 = 0xffff_fffd;
pub const CFB_FREE_SECTOR: u32 = 0xffff_ffff;
pub const CFB_4K_SECTOR_SIZE: usize = 4096;
pub const CFB_SECTOR_SIZE: usize = 512;

pub struct Zip64EocdFields {
    central_directory_disk: u32,
    central_offset: u64,
    central_size: u64,
    disk_number: u32,
    entries_on_disk: u64,
    total_disks: u32,
    total_entries: u64,
}

pub fn cfb_sector_offset(sector_id: u32) -> usize {
    cfb_sector_offset_with_size(CFB_SECTOR_SIZE, sector_id)
}

pub fn cfb_sector_offset_with_size(sector_size: usize, sector_id: u32) -> usize {
    (sector_id as usize + 1) * sector_size
}

pub fn append_cfb_dir_entry(
    buf: &mut [u8],
    entry_index: usize,
    name: &str,
    kind: u8,
    start_sector: u32,
    size: u32,
) {
    let entry_offset = 1024 + entry_index * 128;
    write_cfb_dir_entry(buf, entry_offset, name, kind, start_sector, u64::from(size));
}

pub fn write_cfb_dir_entry(
    buf: &mut [u8],
    entry_offset: usize,
    name: &str,
    kind: u8,
    start_sector: u32,
    size: u64,
) {
    let entry = &mut buf[entry_offset..entry_offset + 128];
    let mut utf16: Vec<u16> = name.encode_utf16().collect();
    utf16.push(0);
    for (index, unit) in utf16.iter().enumerate() {
        let bytes = unit.to_le_bytes();
        entry[index * 2..index * 2 + 2].copy_from_slice(&bytes);
    }
    entry[64..66].copy_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
    entry[66] = kind;
    entry[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
    entry[72..76].copy_from_slice(&u32::MAX.to_le_bytes());
    entry[76..80].copy_from_slice(&u32::MAX.to_le_bytes());
    entry[116..120].copy_from_slice(&start_sector.to_le_bytes());
    entry[120..128].copy_from_slice(&size.to_le_bytes());
}

pub fn init_cfb_header(
    buf: &mut [u8],
    fat_sector_count: u32,
    directory_start: u32,
    mini_fat_start: u32,
    mini_fat_sector_count: u32,
    first_difat_sector: u32,
    difat_sector_count: u32,
) {
    buf[0..8].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    buf[24..26].copy_from_slice(&0x003eu16.to_le_bytes());
    buf[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
    buf[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    buf[30..32].copy_from_slice(&9u16.to_le_bytes());
    buf[32..34].copy_from_slice(&6u16.to_le_bytes());
    buf[44..48].copy_from_slice(&fat_sector_count.to_le_bytes());
    buf[48..52].copy_from_slice(&directory_start.to_le_bytes());
    buf[56..60].copy_from_slice(&4096u32.to_le_bytes());
    buf[60..64].copy_from_slice(&mini_fat_start.to_le_bytes());
    buf[64..68].copy_from_slice(&mini_fat_sector_count.to_le_bytes());
    buf[68..72].copy_from_slice(&first_difat_sector.to_le_bytes());
    buf[72..76].copy_from_slice(&difat_sector_count.to_le_bytes());
    for chunk in buf[76..512].chunks_exact_mut(4) {
        chunk.copy_from_slice(&CFB_FREE_SECTOR.to_le_bytes());
    }
}

pub fn fill_cfb_fat_sector(buf: &mut [u8], sector_id: u32) {
    fill_cfb_fat_sector_with_size(buf, CFB_SECTOR_SIZE, sector_id);
}

pub fn fill_cfb_fat_sector_with_size(buf: &mut [u8], sector_size: usize, sector_id: u32) {
    let offset = cfb_sector_offset_with_size(sector_size, sector_id);
    for chunk in buf[offset..offset + sector_size].chunks_exact_mut(4) {
        chunk.copy_from_slice(&CFB_FREE_SECTOR.to_le_bytes());
    }
}

pub fn write_cfb_fat_entry(buf: &mut [u8], fat_sector_ids: &[u32], sector_id: u32, next: u32) {
    let index = sector_id as usize;
    let fat_sector = fat_sector_ids[index / 128];
    let offset = cfb_sector_offset(fat_sector) + (index % 128) * 4;
    buf[offset..offset + 4].copy_from_slice(&next.to_le_bytes());
}

pub fn append_zip_local(buf: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    append_zip_local_with_options(buf, name, data, 0, data.len() as u32, data.len() as u32);
}

pub fn append_zip_local_with_options(
    buf: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    flags: u16,
    compressed_size: u32,
    uncompressed_size: u32,
) {
    append_zip_local_with_extra(
        buf,
        name,
        data,
        flags,
        compressed_size,
        uncompressed_size,
        &[],
    );
}

pub fn append_zip_local_with_extra(
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

pub fn append_zip_central_directory(
    buf: &mut Vec<u8>,
    name: &[u8],
    flags: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
) -> usize {
    append_zip_central_directory_with_extra(
        buf,
        name,
        flags,
        compressed_size,
        uncompressed_size,
        local_header_offset,
        &[],
    )
}

pub fn append_zip_central_directory_with_extra(
    buf: &mut Vec<u8>,
    name: &[u8],
    flags: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
    extra: &[u8],
) -> usize {
    let central_start = buf.len();
    buf.extend_from_slice(b"PK\x01\x02");
    buf.extend_from_slice(&20u16.to_le_bytes());
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
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&local_header_offset.to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(extra);
    buf.len() - central_start
}

pub fn append_zip_eocd(buf: &mut Vec<u8>, entries: u16, central_size: u32, central_offset: u32) {
    append_zip_eocd_with_fields(buf, 0, 0, entries, entries, central_size, central_offset);
}

pub fn append_zip_eocd_with_fields(
    buf: &mut Vec<u8>,
    disk_number: u16,
    central_directory_disk: u16,
    entries_on_disk: u16,
    total_entries: u16,
    central_size: u32,
    central_offset: u32,
) {
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&disk_number.to_le_bytes());
    buf.extend_from_slice(&central_directory_disk.to_le_bytes());
    buf.extend_from_slice(&entries_on_disk.to_le_bytes());
    buf.extend_from_slice(&total_entries.to_le_bytes());
    buf.extend_from_slice(&central_size.to_le_bytes());
    buf.extend_from_slice(&central_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
}

pub fn append_zip64_eocd_with_fields(buf: &mut Vec<u8>, fields: &Zip64EocdFields) {
    let zip64_offset = buf.len() as u64;
    buf.extend_from_slice(b"PK\x06\x06");
    buf.extend_from_slice(&44u64.to_le_bytes());
    buf.extend_from_slice(&45u16.to_le_bytes());
    buf.extend_from_slice(&45u16.to_le_bytes());
    buf.extend_from_slice(&fields.disk_number.to_le_bytes());
    buf.extend_from_slice(&fields.central_directory_disk.to_le_bytes());
    buf.extend_from_slice(&fields.entries_on_disk.to_le_bytes());
    buf.extend_from_slice(&fields.total_entries.to_le_bytes());
    buf.extend_from_slice(&fields.central_size.to_le_bytes());
    buf.extend_from_slice(&fields.central_offset.to_le_bytes());

    buf.extend_from_slice(b"PK\x06\x07");
    buf.extend_from_slice(&fields.disk_number.to_le_bytes());
    buf.extend_from_slice(&zip64_offset.to_le_bytes());
    buf.extend_from_slice(&fields.total_disks.to_le_bytes());

    append_zip_eocd_with_fields(
        buf,
        u16::try_from(fields.disk_number).unwrap_or(u16::MAX),
        u16::try_from(fields.central_directory_disk).unwrap_or(u16::MAX),
        u16::MAX,
        u16::MAX,
        u32::MAX,
        u32::MAX,
    );
}

pub fn zip64_size_extra(data_len: usize) -> Vec<u8> {
    let mut extra = Vec::new();
    extra.extend_from_slice(&0x0001u16.to_le_bytes());
    extra.extend_from_slice(&16u16.to_le_bytes());
    extra.extend_from_slice(&(data_len as u64).to_le_bytes());
    extra.extend_from_slice(&(data_len as u64).to_le_bytes());
    extra
}

pub fn append_zip64_local(buf: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    let extra = zip64_size_extra(data.len());
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&45u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(&extra);
    buf.extend_from_slice(data);
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

pub fn cfb_4096_sector_doc_sample() -> Vec<u8> {
    let mut buf = vec![0; cfb_sector_offset_with_size(CFB_4K_SECTOR_SIZE, 1) + CFB_4K_SECTOR_SIZE];
    init_cfb_header(&mut buf, 1, 1, CFB_END_OF_CHAIN, 0, CFB_END_OF_CHAIN, 0);
    buf[30..32].copy_from_slice(&12u16.to_le_bytes());
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());

    fill_cfb_fat_sector_with_size(&mut buf, CFB_4K_SECTOR_SIZE, 0);
    let fat_offset = cfb_sector_offset_with_size(CFB_4K_SECTOR_SIZE, 0);
    buf[fat_offset..fat_offset + 4].copy_from_slice(&CFB_FAT_SECTOR.to_le_bytes());
    buf[fat_offset + 4..fat_offset + 8].copy_from_slice(&CFB_END_OF_CHAIN.to_le_bytes());

    let dir_offset = cfb_sector_offset_with_size(CFB_4K_SECTOR_SIZE, 1);
    write_cfb_dir_entry(&mut buf, dir_offset, "Root Entry", 5, CFB_FREE_SECTOR, 0);
    write_cfb_dir_entry(
        &mut buf,
        dir_offset + 128,
        "WordDocument",
        2,
        CFB_FREE_SECTOR,
        0,
    );
    buf
}

pub fn cfb_difat_doc_sample() -> Vec<u8> {
    let fat_sector_ids = (0u32..109).chain([110]).collect::<Vec<_>>();
    let mut buf = vec![0; cfb_sector_offset(112) + CFB_SECTOR_SIZE];
    init_cfb_header(&mut buf, 110, 111, CFB_END_OF_CHAIN, 0, 109, 1);
    buf[56..60].copy_from_slice(&0u32.to_le_bytes());
    for (index, sector_id) in fat_sector_ids.iter().take(109).enumerate() {
        let offset = 76 + index * 4;
        buf[offset..offset + 4].copy_from_slice(&(*sector_id).to_le_bytes());
    }

    let difat_offset = cfb_sector_offset(109);
    for chunk in buf[difat_offset..difat_offset + CFB_SECTOR_SIZE].chunks_exact_mut(4) {
        chunk.copy_from_slice(&CFB_FREE_SECTOR.to_le_bytes());
    }
    buf[difat_offset..difat_offset + 4].copy_from_slice(&110u32.to_le_bytes());
    buf[difat_offset + 508..difat_offset + 512].copy_from_slice(&CFB_END_OF_CHAIN.to_le_bytes());

    for &sector_id in &fat_sector_ids {
        fill_cfb_fat_sector(&mut buf, sector_id);
    }
    for &sector_id in fat_sector_ids.iter().take(109) {
        write_cfb_fat_entry(&mut buf, &fat_sector_ids, sector_id, CFB_FAT_SECTOR);
    }
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 109, CFB_DIFAT_SECTOR);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 110, CFB_FAT_SECTOR);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 111, CFB_END_OF_CHAIN);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 112, CFB_END_OF_CHAIN);

    let dir_offset = cfb_sector_offset(111);
    write_cfb_dir_entry(&mut buf, dir_offset, "Root Entry", 5, CFB_FREE_SECTOR, 0);
    write_cfb_dir_entry(
        &mut buf,
        dir_offset + 128,
        "WordDocument",
        2,
        112,
        CFB_SECTOR_SIZE as u64,
    );
    let stream_offset = cfb_sector_offset(112);
    buf[stream_offset..stream_offset + CFB_SECTOR_SIZE].fill(0x51);
    buf
}

pub fn cfb_fragmented_stream_sample() -> Vec<u8> {
    let fat_sector_ids = [0u32];
    let stream_chain = [3u32, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut buf = vec![0; cfb_sector_offset(15) + CFB_SECTOR_SIZE];
    init_cfb_header(&mut buf, 1, 1, CFB_END_OF_CHAIN, 0, CFB_END_OF_CHAIN, 0);
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());
    fill_cfb_fat_sector(&mut buf, 0);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 0, CFB_FAT_SECTOR);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 1, CFB_END_OF_CHAIN);
    for pair in stream_chain.windows(2) {
        write_cfb_fat_entry(&mut buf, &fat_sector_ids, pair[0], pair[1]);
    }
    write_cfb_fat_entry(
        &mut buf,
        &fat_sector_ids,
        stream_chain[stream_chain.len() - 1],
        CFB_END_OF_CHAIN,
    );

    let dir_offset = cfb_sector_offset(1);
    write_cfb_dir_entry(&mut buf, dir_offset, "Root Entry", 5, CFB_FREE_SECTOR, 0);
    write_cfb_dir_entry(
        &mut buf,
        dir_offset + 128,
        "WordDocument",
        2,
        3,
        (stream_chain.len() * CFB_SECTOR_SIZE) as u64,
    );
    for (index, sector_id) in stream_chain.iter().enumerate() {
        let offset = cfb_sector_offset(*sector_id);
        buf[offset..offset + CFB_SECTOR_SIZE].fill(0x61 + index as u8);
    }
    buf
}

pub fn cfb_truncated_regular_stream_sample() -> Vec<u8> {
    let fat_sector_ids = [0u32];
    let mut buf = cfb_fragmented_stream_sample();
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 3, CFB_END_OF_CHAIN);
    buf
}

pub fn cfb_mini_stream_sample() -> Vec<u8> {
    let fat_sector_ids = [0u32];
    let mut buf = vec![0; cfb_sector_offset(8) + CFB_SECTOR_SIZE];
    init_cfb_header(&mut buf, 1, 1, 4, 1, CFB_END_OF_CHAIN, 0);
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());
    fill_cfb_fat_sector(&mut buf, 0);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 0, CFB_FAT_SECTOR);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 1, CFB_END_OF_CHAIN);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 4, CFB_END_OF_CHAIN);
    write_cfb_fat_entry(&mut buf, &fat_sector_ids, 8, CFB_END_OF_CHAIN);

    let mini_fat_offset = cfb_sector_offset(4);
    for chunk in buf[mini_fat_offset..mini_fat_offset + CFB_SECTOR_SIZE].chunks_exact_mut(4) {
        chunk.copy_from_slice(&CFB_FREE_SECTOR.to_le_bytes());
    }
    buf[mini_fat_offset..mini_fat_offset + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[mini_fat_offset + 4..mini_fat_offset + 8].copy_from_slice(&CFB_END_OF_CHAIN.to_le_bytes());

    let dir_offset = cfb_sector_offset(1);
    write_cfb_dir_entry(
        &mut buf,
        dir_offset,
        "Root Entry",
        5,
        8,
        CFB_SECTOR_SIZE as u64,
    );
    write_cfb_dir_entry(&mut buf, dir_offset + 128, "WordDocument", 2, 0, 128);
    let root_stream = cfb_sector_offset(8);
    buf[root_stream..root_stream + CFB_SECTOR_SIZE].fill(0x77);
    buf
}

pub fn cfb_truncated_mini_stream_sample() -> Vec<u8> {
    let mut buf = cfb_mini_stream_sample();
    let mini_fat_offset = cfb_sector_offset(4);
    buf[mini_fat_offset..mini_fat_offset + 4].copy_from_slice(&CFB_END_OF_CHAIN.to_le_bytes());
    buf[mini_fat_offset + 4..mini_fat_offset + 8].copy_from_slice(&CFB_FREE_SECTOR.to_le_bytes());
    buf
}

pub fn collect_output_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let child_path = entry.path();
        if !child_path.is_dir() {
            continue;
        }
        let directory = entry.file_name().to_string_lossy().into_owned();
        for file_entry in read_dir(&child_path).unwrap() {
            let file_entry = file_entry.unwrap();
            let file_path = file_entry.path();
            if file_path.is_file() {
                let file_name = file_entry.file_name().to_string_lossy().into_owned();
                files.insert(format!("{directory}/{file_name}"), read(file_path).unwrap());
            }
        }
    }
    files
}

pub fn assert_recovered_bytes(actual: &[u8], expected: &[u8]) {
    assert_eq!(actual.len(), expected.len());
    if let Some(index) = actual
        .iter()
        .zip(expected.iter())
        .position(|(actual, expected)| actual != expected)
    {
        panic!(
            "byte mismatch at {index}: actual={} expected={}",
            actual[index], expected[index]
        );
    }
}

pub fn eocd() -> Vec<u8> {
    let mut eocd = Vec::new();
    eocd.extend_from_slice(b"PK\x05\x06");
    eocd.extend_from_slice(&[0; 18]);
    eocd
}

pub fn invalid_cfb_header() -> Vec<u8> {
    let mut buf = vec![0; 512];
    buf[0..16].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\0\0\0\0\0\0\0\0");
    buf
}

pub fn append_mp4_box(buf: &mut Vec<u8>, box_type: [u8; 4], payload: &[u8]) {
    let size = 8 + payload.len();
    buf.extend_from_slice(&(size as u32).to_be_bytes());
    buf.extend_from_slice(&box_type);
    buf.extend_from_slice(payload);
}

pub fn fragmented_mp4_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_mp4_box(&mut buf, *b"ftyp", b"isom\0\0\x02\0isomiso6dash");
    append_mp4_box(&mut buf, *b"sidx", &[0x10; 32]);
    append_mp4_box(&mut buf, *b"moof", &[0x20; 96]);
    append_mp4_box(&mut buf, *b"mdat", &[0x30; 1024]);
    append_mp4_box(&mut buf, *b"mfra", &[0x40; 24]);
    buf
}

pub fn invalid_then_valid_mp4_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&8u32.to_be_bytes());
    buf.extend_from_slice(b"ftyp");
    buf.extend_from_slice(b"noise");
    buf.extend_from_slice(&fragmented_mp4_sample());
    buf
}

pub fn mp4_variable_ftyp_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&24u32.to_be_bytes());
    buf.extend_from_slice(b"ftyp");
    buf.extend_from_slice(b"isom\0\0\x02\0isomiso2");
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(b"moov");
    buf.extend_from_slice(b"abcd");
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(b"mdat");
    buf.extend(repeat_n(0xaa, 992));
    buf
}

pub fn mp4_large_size_uuid_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&24u32.to_be_bytes());
    buf.extend_from_slice(b"ftyp");
    buf.extend_from_slice(b"isom\0\0\x02\0isomiso2");
    buf.extend_from_slice(&24u32.to_be_bytes());
    buf.extend_from_slice(b"uuid");
    buf.extend_from_slice(&[0x11; 16]);
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(b"mdat");
    buf.extend_from_slice(&1024u64.to_be_bytes());
    buf.extend(repeat_n(0xaa, 1008));
    buf
}

pub fn mp4_with_unknown_printable_box_tail_sample() -> Vec<u8> {
    let mut buf = fragmented_mp4_sample();
    append_mp4_box(&mut buf, *b"zzzz", &[0x55; 32]);
    buf
}

pub fn openoffice_writer_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, b"mimetype", b"application/vnd.sun.xml.writer");
    append_zip_local(&mut buf, b"content.xml", &[b'a'; 32]);
    buf.extend_from_slice(&eocd());
    buf
}

pub fn plain_zip_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, b"file.txt", b"plain zip payload");
    buf.extend_from_slice(&eocd());
    buf
}

pub fn zip_with_central_directory_sample(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, name, data);
    let central_offset = buf.len();
    let central_size =
        append_zip_central_directory(&mut buf, name, 0, data.len() as u32, data.len() as u32, 0);
    append_zip_eocd(&mut buf, 1, central_size as u32, central_offset as u32);
    buf
}

pub fn run_forsmost(input: &Path, output: &Path, selector: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
        .args(["-Q", "-t", selector, "-o"])
        .arg(output)
        .arg(input)
        .status()
        .unwrap();
    assert!(status.success());
}

pub fn unique_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    temp_dir().join(format!("forsmost-{name}-{nonce}"))
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

pub fn zip_pptx_presentation_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip_local(&mut buf, b"[Content_Types].xml", b"");
    append_zip_local(&mut buf, b"ppt/presentation.xml", b"");
    buf.extend_from_slice(&eocd());
    buf
}

pub fn zip64_local_header_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    append_zip64_local(&mut buf, b"file.txt", &[0x5a; 32]);
    buf.extend_from_slice(&eocd());
    buf
}

pub fn zip64_eocd_sample() -> Vec<u8> {
    let name = b"zip64.txt";
    let data = &[0x64; 64];
    let mut buf = Vec::new();
    append_zip_local(&mut buf, name, data);
    let central_offset = buf.len();
    let central_size =
        append_zip_central_directory(&mut buf, name, 0, data.len() as u32, data.len() as u32, 0);
    append_zip64_eocd_with_fields(
        &mut buf,
        &Zip64EocdFields {
            central_directory_disk: 0,
            central_offset: central_offset as u64,
            central_size: central_size as u64,
            disk_number: 0,
            entries_on_disk: 1,
            total_disks: 1,
            total_entries: 1,
        },
    );
    buf
}

pub fn zip64_central_directory_size_sample() -> Vec<u8> {
    let name = b"central64.bin";
    let mut data = Vec::new();
    data.extend_from_slice(b"payload-before-");
    data.extend_from_slice(&eocd());
    data.extend_from_slice(b"-payload-after");

    let mut buf = Vec::new();
    append_zip_local_with_extra(&mut buf, name, &data, 0, u32::MAX, u32::MAX, &[]);
    let central_offset = buf.len();
    let central_extra = zip64_size_extra(data.len());
    let central_size = append_zip_central_directory_with_extra(
        &mut buf,
        name,
        0,
        u32::MAX,
        u32::MAX,
        0,
        &central_extra,
    );
    append_zip_eocd(&mut buf, 1, central_size as u32, central_offset as u32);
    buf
}

pub fn zip_data_descriptor_sample(data: &[u8]) -> Vec<u8> {
    let name = b"file.bin";
    let mut buf = Vec::new();
    append_zip_local_with_options(&mut buf, name, data, 1 << 3, 0, 0);
    let central_offset = buf.len();
    let central_size = append_zip_central_directory(
        &mut buf,
        name,
        1 << 3,
        data.len() as u32,
        data.len() as u32,
        0,
    );
    append_zip_eocd(&mut buf, 1, central_size as u32, central_offset as u32);
    buf
}

pub fn zip_data_descriptor_fake_eocd_payload_sample() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"payload-before-");
    data.extend_from_slice(&eocd());
    data.extend_from_slice(b"-payload-after");
    zip_data_descriptor_sample(&data)
}

pub fn zip_data_descriptor_fake_multidisk_eocd_payload_sample() -> Vec<u8> {
    let mut fake_eocd = Vec::new();
    append_zip_eocd_with_fields(&mut fake_eocd, 1, 1, 1, 1, 64, 4);

    let mut data = Vec::new();
    data.extend_from_slice(b"payload-before-");
    data.extend_from_slice(&fake_eocd);
    data.extend_from_slice(b"-payload-after");
    zip_data_descriptor_sample(&data)
}

pub fn zip_data_descriptor_fake_short_central_directory_sample() -> Vec<u8> {
    let name = b"file.bin";
    let mut buf = Vec::new();
    append_zip_local_with_options(&mut buf, name, &[], 1 << 3, 0, 0);
    let data_start = buf.len();
    buf.extend_from_slice(b"payload-before-");
    let fake_central_offset = buf.len();
    buf.extend_from_slice(b"PK\x01\x02");
    append_zip_eocd(&mut buf, 1, 4, fake_central_offset as u32);
    buf.extend_from_slice(b"-payload-after");
    let data_len = buf.len() - data_start;
    let central_offset = buf.len();
    let central_size =
        append_zip_central_directory(&mut buf, name, 1 << 3, data_len as u32, data_len as u32, 0);
    append_zip_eocd(&mut buf, 1, central_size as u32, central_offset as u32);
    buf
}

pub fn split_zip_then_valid_zip_sample() -> (Vec<u8>, Vec<u8>) {
    let split_name = b"split.txt";
    let split_data = b"incomplete split archive";
    let mut split = Vec::new();
    append_zip_local(&mut split, split_name, split_data);
    let split_central_offset = split.len();
    let split_central_size = append_zip_central_directory(
        &mut split,
        split_name,
        0,
        split_data.len() as u32,
        split_data.len() as u32,
        0,
    );
    append_zip_eocd_with_fields(
        &mut split,
        1,
        1,
        1,
        1,
        split_central_size as u32,
        split_central_offset as u32,
    );

    let valid = zip_with_central_directory_sample(b"valid.txt", &[0x41; 64]);
    let mut sample = split;
    sample.extend_from_slice(b"noise-before-valid-zip");
    sample.extend_from_slice(&valid);
    (sample, valid)
}

pub fn split_zip64_then_valid_zip_sample() -> (Vec<u8>, Vec<u8>) {
    let name = b"split64.txt";
    let data = &[0x73; 64];
    let mut split = Vec::new();
    append_zip_local(&mut split, name, data);
    let central_offset = split.len();
    let central_size =
        append_zip_central_directory(&mut split, name, 0, data.len() as u32, data.len() as u32, 0);
    append_zip64_eocd_with_fields(
        &mut split,
        &Zip64EocdFields {
            central_directory_disk: 1,
            central_offset: central_offset as u64,
            central_size: central_size as u64,
            disk_number: 1,
            entries_on_disk: 1,
            total_disks: 2,
            total_entries: 1,
        },
    );

    let valid = zip_with_central_directory_sample(b"valid64.txt", &[0x56; 64]);
    let mut sample = split;
    sample.extend_from_slice(b"noise-before-valid-zip64");
    sample.extend_from_slice(&valid);
    (sample, valid)
}
