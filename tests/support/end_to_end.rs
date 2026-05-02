use std::{
    env::temp_dir,
    iter::repeat_n,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn unique_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    temp_dir().join(format!("forsmost-{name}-{nonce}"))
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
    entry[120..124].copy_from_slice(&size.to_le_bytes());
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

pub fn append_at(buf: &mut Vec<u8>, offset: usize, data: &[u8]) {
    assert!(offset >= buf.len());
    buf.resize(offset, 0);
    buf.extend_from_slice(data);
}

pub fn assert_audit_has_offset(audit: &str, name: &str, offset: usize) {
    assert!(
        audit
            .lines()
            .any(|line| line.contains(name) && line.contains(&offset.to_string())),
        "audit did not contain {name} at offset {offset}:\n{audit}"
    );
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

pub fn bmp_sample_with_size(size: usize) -> Vec<u8> {
    let data_offset = 54u32;
    let data_size = size as u32 - data_offset;
    let mut buf = vec![0x7f; size];
    buf[0..2].copy_from_slice(b"BM");
    buf[2..6].copy_from_slice(&(size as u32).to_le_bytes());
    buf[10..14].copy_from_slice(&data_offset.to_le_bytes());
    buf[14..18].copy_from_slice(&40u32.to_le_bytes());
    buf[18..22].copy_from_slice(&16i32.to_le_bytes());
    buf[22..26].copy_from_slice(&12i32.to_le_bytes());
    buf[26..28].copy_from_slice(&1u16.to_le_bytes());
    buf[28..30].copy_from_slice(&24u16.to_le_bytes());
    buf[34..38].copy_from_slice(&data_size.to_le_bytes());
    buf
}

pub fn indirect_block(block_size: usize) -> Vec<u8> {
    let mut buf = vec![0; block_size];
    buf[0..4].copy_from_slice(&100u32.to_le_bytes());
    buf[4..8].copy_from_slice(&101u32.to_le_bytes());
    buf
}

pub fn insert_indirect_block(logical: &[u8], block_size: usize) -> Vec<u8> {
    let split = 12 * block_size;
    let mut physical = Vec::with_capacity(logical.len() + block_size);
    physical.extend_from_slice(&logical[..split]);
    physical.extend_from_slice(&indirect_block(block_size));
    physical.extend_from_slice(&logical[split..]);
    physical
}

pub fn eocd() -> Vec<u8> {
    let mut eocd = Vec::new();
    eocd.extend_from_slice(b"PK\x05\x06");
    eocd.extend_from_slice(&[0; 18]);
    eocd
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

pub fn mp4_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&28u32.to_be_bytes());
    buf.extend_from_slice(b"ftyp");
    buf.extend_from_slice(b"isom\0\0\x02\0isomiso2mp41");
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(b"moov");
    buf.extend_from_slice(b"abcd");
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(b"mdat");
    buf.extend(repeat_n(0xaa, 992));
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

pub fn riff_wav_sample() -> Vec<u8> {
    let size = 48usize;
    let mut buf = vec![0; size];
    buf[0..4].copy_from_slice(b"RIFF");
    buf[4..8].copy_from_slice(&((size as u32) - 8).to_le_bytes());
    buf[8..12].copy_from_slice(b"WAVE");
    buf[12..].fill(0x42);
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

pub fn registry_sample() -> Vec<u8> {
    let mut buf = vec![0; 512];
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(b"regf");
    buf[0x28..0x2c].copy_from_slice(&len.to_le_bytes());
    buf
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
