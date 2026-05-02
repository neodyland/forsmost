#[cfg(feature = "gzip")]
use std::io::{self, BufReader, Cursor};

#[cfg(feature = "gzip")]
use flate2::bufread::GzDecoder;

#[cfg(feature = "gzip")]
use super::types::{GZIP_HEADER_LEN, GZIP_RESERVED_FLAGS};
use super::{
    recover_zip::recover_zip,
    scan::{
        bmp_len, bounded_len, checked_recovery_len, elf_len, generic_footer_end, iso_bmff_len,
        mov_len, pdf_linearized_len, pe_details, read_be_u16, read_be_u32, read_le_u16,
        read_le_u32, read_le_u64, scan_ole, wpd_len,
    },
    types::{
        ASF_FILE_PROPERTIES_GUID, ASF_FILE_SIZE_OFFSET, ASF_HEADER_GUID, GIF_HEADER_LEN,
        HTML_ASCII_PROBE_LEN, JPEG_MIN_LEN, KIBIBYTE, MEBIBYTE, MP4_MIN_LEN, MPEG_MARKER,
        MPEG_MIN_LEN, MPEG_SEARCH_WINDOW, PDF_MIN_PROBE_LEN, PNG_CHUNK_OVERHEAD,
        PNG_DIMENSION_LIMIT, PNG_MIN_LEN, PNG_SIGNATURE_LEN, PdfLinearizedScan,
        RAR_ENCRYPTED_SEARCH_LEN, REG_SIZE_OFFSET, Recovered,
    },
};
use crate::{
    search::find_forward,
    spec::{FileKind, SearchMode, SearchSpec},
};

#[must_use]
pub fn recover<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    if window.len() < spec.header.len() {
        return None;
    }

    match spec.kind {
        FileKind::Bmp => recover_bmp(spec, window),
        FileKind::Cpp => recover_cpp(spec, window, wildcard),
        FileKind::Elf => recover_elf(spec, window),
        FileKind::Exe => recover_exe(spec, window),
        FileKind::Gif => recover_gif(spec, window, wildcard),
        #[cfg(feature = "gzip")]
        FileKind::Gzip => recover_gzip(spec, window),
        FileKind::Html => recover_html(spec, window, wildcard),
        FileKind::Jpeg => recover_jpeg(spec, window, wildcard),
        FileKind::Mov => recover_mov(spec, window),
        FileKind::Mpeg => recover_mpeg(spec, window, wildcard),
        FileKind::Mp4 => recover_mp4(spec, window),
        FileKind::Ole | FileKind::Doc | FileKind::Ppt | FileKind::Xls => recover_ole(spec, window),
        FileKind::Pdf => recover_pdf(spec, window, wildcard),
        FileKind::Png => recover_png(spec, window, wildcard),
        FileKind::Rar => recover_rar(spec, window, wildcard),
        // Foremost 1.5.7 has extract_reg, but extract_file never dispatches REG.
        FileKind::Reg => recover_reg(spec, window),
        FileKind::Riff | FileKind::Avi | FileKind::Wav => recover_riff(spec, window),
        FileKind::Wmv => recover_wmv(spec, window, wildcard),
        FileKind::Wpd => recover_wpd(spec, window),
        FileKind::Zip
        | FileKind::Sxw
        | FileKind::Sxc
        | FileKind::Sxi
        | FileKind::Docx
        | FileKind::Pptx
        | FileKind::Xlsx => recover_zip(spec, window, wildcard),
        FileKind::Config if spec.search_mode == SearchMode::Ascii => recover_ascii(spec, window),
        FileKind::Config => recover_generic(spec, window, wildcard),
    }
}

fn ascii_byte(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..=0x7e).contains(&byte)
}

fn c_source_byte(byte: u8) -> bool {
    byte == b'\n' || byte == b'\t' || (0x20..=0x7e).contains(&byte)
}

fn c_printable_byte(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn recover_bmp<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let requested_len = bmp_len(spec, window)?;
    let end = checked_recovery_len(spec, window, requested_len)?;
    if end == 0 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "BMP size"))
}

fn recover_ascii<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let mut end = spec.header.len();
    while end < window.len() && ascii_byte(window[end]) {
        end += 1;
    }

    let end = bounded_len(spec, window, end)?;
    Some(recovered(spec, window, end, "ASCII run"))
}

fn recover_generic<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    let end = generic_footer_end(spec, window, wildcard)?;
    let reason = if spec.footer.is_empty() {
        "maximum length"
    } else {
        "footer"
    };
    Some(recovered(spec, window, end, reason))
}

fn recover_cpp<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    let probe_end = window.len().min(20);
    if !window[..probe_end]
        .iter()
        .any(|byte| matches!(byte, b'"' | b'<'))
    {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let mut end = 0usize;
    while end < window.len() && c_source_byte(window[end]) {
        end += 1;
    }
    if end < 50 {
        return Some(skip_recovered(spec, window, end.max(spec.header.len())));
    }

    let end = bounded_len(spec, window, end)?;
    let source = &window[..end];
    let has_footer = find_forward(&spec.footer, source, 0, false, wildcard).is_some();
    let has_marker = spec
        .markers
        .iter()
        .any(|marker| find_forward(marker, source, 0, spec.case_sensitive, wildcard).is_some());
    if !has_footer && !has_marker {
        return Some(skip_recovered(spec, window, end));
    }

    Some(recovered(spec, window, end, "C source"))
}

fn recover_elf<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let end = elf_len(spec, window)?;
    if end == 0 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "ELF tables"))
}

fn recover_exe<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let details = pe_details(window)?;
    let end = bounded_len(spec, window, details.len)?;
    Some(recovered_with_suffix(
        spec,
        window,
        end,
        details.suffix,
        "PE section table",
    ))
}

fn recover_gif<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    if window.len() < GIF_HEADER_LEN {
        return None;
    }
    if window.get(4..6)? != b"9a" && window.get(4..6)? != b"7a" {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let end = generic_footer_end(spec, window, wildcard)?;
    Some(recovered(spec, window, end, "GIF footer"))
}

#[cfg(feature = "gzip")]
fn recover_gzip<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let header_end = gzip_header_end(window)?;
    if header_end == 0 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let search_limit = window.len().min(max_len);
    let end = gzip_member_len(&window[..search_limit])?;
    if end == 0 || end < header_end + 8 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "GZIP stream"))
}

#[cfg(feature = "gzip")]
fn gzip_header_end(window: &[u8]) -> Option<usize> {
    if window.len() < GZIP_HEADER_LEN {
        return None;
    }
    if window.get(..2) != Some(b"\x1f\x8b") || window.get(2) != Some(&8) {
        return Some(0);
    }
    let flags = *window.get(3)?;
    if flags & GZIP_RESERVED_FLAGS != 0 {
        return Some(0);
    }

    let mut offset = GZIP_HEADER_LEN;
    if flags & 0x04 != 0 {
        let extra_len = read_le_u16(window, offset)? as usize;
        offset = offset.checked_add(2)?.checked_add(extra_len)?;
        if offset > window.len() {
            return None;
        }
    }
    if flags & 0x08 != 0 {
        offset = gzip_zero_terminated_end(window, offset)?;
    }
    if flags & 0x10 != 0 {
        offset = gzip_zero_terminated_end(window, offset)?;
    }
    if flags & 0x02 != 0 {
        offset = offset.checked_add(2)?;
        if offset > window.len() {
            return None;
        }
    }
    Some(offset)
}

#[cfg(feature = "gzip")]
fn gzip_member_len(window: &[u8]) -> Option<usize> {
    let reader = BufReader::new(Cursor::new(window));
    let mut decoder = GzDecoder::new(reader);
    match io::copy(&mut decoder, &mut io::sink()) {
        Ok(_) => {
            let reader = decoder.get_ref();
            let position = usize::try_from(reader.get_ref().position()).ok()?;
            position.checked_sub(reader.buffer().len())
        }
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => None,
        Err(_) => Some(0),
    }
}

#[cfg(feature = "gzip")]
fn gzip_zero_terminated_end(window: &[u8], offset: usize) -> Option<usize> {
    let relative = window.get(offset..)?.iter().position(|&byte| byte == 0)?;
    offset.checked_add(relative)?.checked_add(1)
}

fn recover_html<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    let probe_start = spec.header.len();
    let probe_end = probe_start.checked_add(HTML_ASCII_PROBE_LEN)?;
    if probe_end > window.len() {
        return None;
    }
    if !window[probe_start..probe_end]
        .iter()
        .all(|&byte| byte == b'\n' || byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Some(skip_recovered(spec, window, probe_end));
    }

    let end = generic_footer_end(spec, window, wildcard)?;
    Some(recovered(spec, window, end, "HTML footer"))
}

fn recover_jpeg<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    if window.len() < JPEG_MIN_LEN {
        return None;
    }
    // Accept APP2-first streams too; Foremost only followed the APP0/JFIF path.
    let first_marker = window.get(3).copied()?;
    if !jpeg_segment_marker(first_marker) {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let mut offset = 2usize;
    let mut has_table = false;
    let mut has_huffman = false;

    while offset + 4 <= window.len().min(max_len) {
        if window[offset] != 0xff {
            break;
        }
        while matches!(window.get(offset + 1), Some(0xff)) {
            offset += 1;
        }

        let marker = *window.get(offset + 1)?;
        if marker == 0xd9 {
            break;
        }
        if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
            offset += 2;
            continue;
        }

        let segment_len = read_be_u16(window, offset + 2)? as usize;
        if segment_len < 2 {
            return Some(skip_recovered(spec, window, spec.header.len()));
        }

        if marker == 0xdb {
            has_table = true;
        } else if marker == 0xc4 {
            has_huffman = true;
        }

        let next_offset = offset.checked_add(2)?.checked_add(segment_len)?;
        if next_offset > window.len() {
            return if next_offset <= max_len {
                None
            } else {
                Some(skip_recovered(spec, window, spec.header.len()))
            };
        }
        offset = next_offset;

        if marker == 0xda {
            break;
        }
    }

    if !has_table || !has_huffman {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let search_limit = window.len().min(max_len);
    let footer_index = find_forward(
        &spec.footer,
        &window[..search_limit],
        offset,
        spec.case_sensitive,
        wildcard,
    )?;
    let end = bounded_len(spec, window, footer_index + spec.footer.len())?;
    Some(recovered(spec, window, end, "JPEG segments"))
}

const fn jpeg_segment_marker(marker: u8) -> bool {
    matches!(marker, 0xc0..=0xfe) && !matches!(marker, 0xd0..=0xd9 | 0x01)
}

fn recover_mpeg<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    if window.len() < 16 {
        return None;
    }
    if window[15] != 0xbb {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let limit = window.len().min(max_len);
    let mut search_start = 0usize;
    let mut end = None;

    while search_start < limit {
        let search_limit = limit.min(search_start.saturating_add(MPEG_SEARCH_WINDOW));
        let Some(mut marker_index) = find_forward(
            MPEG_MARKER,
            &window[..search_limit],
            search_start,
            spec.case_sensitive,
            wildcard,
        ) else {
            if search_start >= MEBIBYTE {
                end = Some(search_start);
                break;
            }
            return Some(skip_recovered(spec, window, spec.header.len()));
        };

        while marker_index + 6 <= limit {
            let stream_id = window[marker_index + 3];
            if !(0xbb..=0xef).contains(&stream_id) {
                break;
            }

            let packet_len = read_be_u16(window, marker_index + 4)? as usize;
            let next_index = marker_index.checked_add(packet_len)?.checked_add(6)?;
            if packet_len == 0 || next_index > window.len() {
                if packet_len <= 50 * KIBIBYTE && next_index <= max_len {
                    return None;
                }
                return Some(skip_recovered(spec, window, spec.header.len()));
            }
            marker_index = next_index;
        }

        let &stream_id = window.get(marker_index + 3)?;
        if stream_id == 0xb9 {
            end = Some(marker_index + spec.footer.len());
            break;
        }
        if stream_id != 0xba && stream_id != 0x00 {
            if search_start >= MEBIBYTE {
                end = Some(search_start);
                break;
            }
            return Some(skip_recovered(spec, window, spec.header.len()));
        }
        search_start = marker_index.saturating_add(3);
    }

    let end = end?;
    if end < MPEG_MIN_LEN {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    let end = bounded_len(spec, window, end)?;
    Some(recovered(spec, window, end, "MPEG packs"))
}

fn recover_mov<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let scan = mov_len(spec, window)?;
    if scan.write {
        Some(recovered(spec, window, scan.end, "MOV atoms"))
    } else {
        Some(skip_recovered(spec, window, scan.end))
    }
}

fn recover_mp4<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let end = iso_bmff_len(spec, window, true)?;
    if end < MP4_MIN_LEN {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "MP4 boxes"))
}

fn recover_ole<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let details = scan_ole(spec, window)?;
    if !details.write {
        return Some(skip_recovered(spec, window, details.len));
    }
    let mut recovered =
        recovered_with_suffix(spec, window, details.len, &details.suffix, "OLE CFB");
    if !zip_or_ole_suffix_matches(spec, &details.suffix) {
        recovered.write = false;
    }
    Some(recovered)
}

fn recover_pdf<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    if window.len() < PDF_MIN_PROBE_LEN {
        return None;
    }

    let obj_probe_end = window.len().min(spec.header.len() + 100);
    if find_forward(
        b"obj",
        &window[..obj_probe_end],
        spec.header.len(),
        spec.case_sensitive,
        wildcard,
    )
    .is_none()
    {
        return Some(skip_recovered(spec, window, spec.header.len() + 100));
    }

    match pdf_linearized_len(spec, window, wildcard) {
        PdfLinearizedScan::Found(end) => {
            return Some(recovered(spec, window, end, "PDF linearized"));
        }
        PdfLinearizedScan::NeedMore => return None,
        PdfLinearizedScan::Skip => return Some(skip_recovered(spec, window, spec.header.len())),
        PdfLinearizedScan::Missing => {}
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let search_limit = window.len().min(max_len);
    let footer_index = find_forward(
        &spec.footer,
        &window[..search_limit],
        spec.header.len(),
        spec.case_sensitive,
        wildcard,
    )?;
    let end = footer_index
        .saturating_add(spec.footer.len())
        .saturating_add(1)
        .min(window.len());
    Some(recovered(spec, window, end, "PDF EOF"))
}

fn recover_png<'a>(spec: &SearchSpec, window: &'a [u8], _wildcard: u8) -> Option<Recovered<'a>> {
    let max_len = usize::try_from(spec.max_len).ok()?;
    if window.len() < PNG_MIN_LEN {
        return None;
    }

    let ihdr_len = read_be_u32(window, PNG_SIGNATURE_LEN)?;
    if ihdr_len != 13 || window.get(12..16)? != b"IHDR" {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    let width = read_be_u32(window, 16)?;
    let height = read_be_u32(window, 20)?;
    if width == 0 || height == 0 || width > PNG_DIMENSION_LIMIT || height > PNG_DIMENSION_LIMIT {
        return Some(skip_recovered(spec, window, PNG_SIGNATURE_LEN));
    }

    let mut offset = PNG_SIGNATURE_LEN;
    loop {
        if offset + PNG_CHUNK_OVERHEAD > window.len() {
            return None;
        }
        if offset >= max_len {
            return Some(skip_recovered(spec, window, spec.header.len()));
        }

        let chunk_len = read_be_u32(window, offset)? as usize;
        let chunk_type = window.get(offset + 4..offset + 8)?;
        if chunk_len == 0 && chunk_type != b"IEND" {
            return Some(skip_recovered(spec, window, offset));
        }
        if !chunk_type
            .first()
            .is_some_and(|byte| c_printable_byte(*byte))
        {
            return Some(skip_recovered(spec, window, offset));
        }

        let next_offset = offset
            .checked_add(chunk_len)?
            .checked_add(PNG_CHUNK_OVERHEAD)?;
        if next_offset > window.len() {
            return if next_offset <= max_len {
                None
            } else {
                Some(skip_recovered(spec, window, spec.header.len()))
            };
        }
        if chunk_type == spec.footer.as_slice() {
            let end = bounded_len(spec, window, next_offset)?;
            return Some(recovered(spec, window, end, "PNG chunks"));
        }
        offset = next_offset;
    }
}

fn recover_rar<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    let max_len = usize::try_from(spec.max_len).ok()?;
    if window.len() < spec.header.len() + 7 {
        return None;
    }

    let marker_size = read_le_u16(window, 5)? as usize;
    if marker_size < spec.header.len() {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    let mut offset = marker_size;

    if offset + 7 > window.len() {
        return if offset + 7 <= max_len {
            None
        } else {
            Some(skip_recovered(spec, window, spec.header.len()))
        };
    }
    if window[offset + 2] != 0x73 {
        return Some(skip_recovered(spec, window, offset));
    }

    let archive_header_size = read_le_u16(window, offset + 5)? as usize;
    if archive_header_size < 7 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    offset = offset.checked_add(archive_header_size)?;

    if offset + 7 > window.len() {
        return if offset + 7 <= max_len {
            None
        } else {
            Some(skip_recovered(spec, window, spec.header.len()))
        };
    }

    if window[offset + 2] != 0x74
        && let Some(found) = window[offset..window.len().min(offset + 500)]
            .iter()
            .position(|&byte| byte == 0x74)
            .and_then(|relative| offset.checked_add(relative)?.checked_sub(2))
    {
        offset = found;
    }

    if archive_header_size == 13 && window.get(offset + 2) != Some(&0x74) {
        let search_limit = window
            .len()
            .min(offset.saturating_add(RAR_ENCRYPTED_SEARCH_LEN));
        let end = find_forward(
            &spec.footer,
            &window[..search_limit],
            offset,
            spec.case_sensitive,
            wildcard,
        )
        .unwrap_or(search_limit);
        let end = bounded_len(spec, window, end)?;
        return Some(recovered(spec, window, end, "RAR encrypted headers"));
    }

    let first_file_header = offset;
    while offset + 7 <= window.len() && window[offset + 2] == 0x74 {
        let header_size = read_le_u16(window, offset + 5)? as usize;
        let packed_size = read_le_u32(window, offset + 7)? as usize;
        let unpacked_size = read_le_u32(window, offset + 11)? as usize;
        if header_size < 7
            || header_size > window.len()
            || unpacked_size > max_len
            || packed_size > max_len
        {
            let search_limit = window
                .len()
                .min(offset.saturating_add(RAR_ENCRYPTED_SEARCH_LEN));
            let end = find_forward(
                &spec.footer,
                &window[..search_limit],
                offset,
                spec.case_sensitive,
                wildcard,
            )
            .unwrap_or(search_limit);
            let end = bounded_len(spec, window, end)?;
            return Some(recovered(spec, window, end, "RAR fallback"));
        }

        let next_offset = offset.checked_add(header_size)?.checked_add(packed_size)?;
        if next_offset > window.len() {
            return if next_offset <= max_len {
                None
            } else {
                Some(skip_recovered(spec, window, spec.header.len()))
            };
        }
        offset = next_offset;
    }

    if offset == first_file_header {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    if offset + 7 <= window.len() && window[offset + 2] == 0x7b {
        offset += 7;
    }
    let end = bounded_len(spec, window, offset)?;
    Some(recovered(spec, window, end, "RAR blocks"))
}

fn recover_reg<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    if window.len() < REG_SIZE_OFFSET + 4 {
        return None;
    }
    let size = read_le_u32(window, REG_SIZE_OFFSET)? as usize;
    let end = checked_recovery_len(spec, window, size)?;
    if end == 0 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "registry size"))
}

fn recover_riff<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    if window.len() < 16 {
        return None;
    }

    let riff_payload_size = read_le_u32(window, 4)? as usize;
    let suffix = if window.get(8..11) == Some(b"AVI") {
        if window.get(12..16) != Some(b"LIST") {
            return Some(skip_recovered(spec, window, spec.header.len()));
        }
        "avi"
    } else if window.get(8..12) == Some(b"WAVE") {
        "wav"
    } else {
        return Some(skip_recovered(spec, window, spec.header.len()));
    };

    let max_len = usize::try_from(spec.max_len).ok()?;
    // The chunk size field stores payload bytes, so add the 8-byte RIFF header here.
    let end = riff_payload_size.checked_add(8)?;
    if riff_payload_size < 4 || end > max_len {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    if end > window.len() {
        return None;
    }

    let mut recovered = recovered_with_suffix(spec, window, end, suffix, "RIFF chunk size");
    if !riff_suffix_matches(spec, suffix) {
        recovered.write = false;
    }
    Some(recovered)
}

fn recover_wmv<'a>(spec: &SearchSpec, window: &'a [u8], wildcard: u8) -> Option<Recovered<'a>> {
    if window.len() < 70 {
        return None;
    }
    if window.get(..ASF_HEADER_GUID.len())? != ASF_HEADER_GUID {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let header_size = read_le_u64(window, 16)? as usize;
    let header_objects = read_le_u32(window, 24)?;
    if header_size == 0 || header_objects == 0 || window.get(28) != Some(&1) {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let search_limit = window.len().min(max_len);
    let file_properties = find_forward(
        ASF_FILE_PROPERTIES_GUID,
        &window[..search_limit],
        30,
        spec.case_sensitive,
        wildcard,
    )
    .or_else(|| {
        find_forward(
            &spec.footer,
            &window[..search_limit],
            30,
            spec.case_sensitive,
            wildcard,
        )
    })?;
    let file_size = read_le_u64(window, file_properties + ASF_FILE_SIZE_OFFSET)? as usize;
    let end = checked_recovery_len(spec, window, file_size)?;
    if end == 0 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "ASF file size"))
}

fn recover_wpd<'a>(spec: &SearchSpec, window: &'a [u8]) -> Option<Recovered<'a>> {
    let end = wpd_len(spec, window)?;
    if end == 0 {
        return Some(skip_recovered(spec, window, spec.header.len()));
    }
    Some(recovered(spec, window, end, "WPD header"))
}

fn recovered<'a>(spec: &SearchSpec, window: &'a [u8], end: usize, comment: &str) -> Recovered<'a> {
    recovered_with_suffix(spec, window, end, &spec.suffix, comment)
}

pub(super) fn recovered_with_suffix<'a>(
    spec: &SearchSpec,
    window: &'a [u8],
    end: usize,
    suffix: &str,
    comment: &str,
) -> Recovered<'a> {
    let marker_note = if spec
        .markers
        .iter()
        .any(|marker| contains_marker(&window[..end], marker))
    {
        ", marker"
    } else {
        ""
    };

    Recovered {
        bytes: &window[..end],
        comment: format!("({comment}{marker_note})"),
        next_index: end.max(spec.header.len() + 1),
        suffix: suffix.to_owned(),
        write: true,
    }
}

pub(super) fn skip_recovered<'a>(
    spec: &SearchSpec,
    window: &'a [u8],
    next_index: usize,
) -> Recovered<'a> {
    Recovered {
        bytes: &window[..0],
        comment: "(skipped)".to_owned(),
        next_index: next_index.max(spec.header.len() + 1),
        suffix: spec.suffix.clone(),
        write: false,
    }
}

pub(super) fn zip_or_ole_suffix_matches(spec: &SearchSpec, suffix: &str) -> bool {
    matches!(spec.kind, FileKind::Zip | FileKind::Ole) || spec.suffix == suffix
}

fn riff_suffix_matches(spec: &SearchSpec, suffix: &str) -> bool {
    spec.kind == FileKind::Riff || spec.suffix == suffix
}

fn contains_marker(bytes: &[u8], marker: &[u8]) -> bool {
    !marker.is_empty()
        && marker.len() <= bytes.len()
        && bytes
            .windows(marker.len())
            .any(|candidate| candidate == marker)
}
