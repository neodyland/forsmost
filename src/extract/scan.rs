pub(super) use super::scan_ole::{scan_ole, scan_zip_local_headers};
use super::types::{
    BMP_DATA_OFFSET_OFFSET, BMP_DATA_SIZE_OFFSET, BMP_HEADER_LENGTH_OFFSET, BMP_HEIGHT_OFFSET,
    BMP_MIN_LEN, BMP_SIZE_OFFSET, BMP_VERTICAL_LIMIT, BMP_WIDTH_OFFSET, ELF_32_HEADER_LEN,
    ELF_32_PHDR_LEN, ELF_32_SHDR_LEN, ELF_64_HEADER_LEN, ELF_64_PHDR_LEN, ELF_64_SHDR_LEN,
    ELF_CLASS_32, ELF_CLASS_64, ELF_DATA_BIG, ELF_DATA_LITTLE, ELF_HEADER_LEN_OFFSET_32,
    ELF_HEADER_LEN_OFFSET_64, ELF_MAGIC, ELF_PHDR_COUNT_OFFSET_32, ELF_PHDR_COUNT_OFFSET_64,
    ELF_PHDR_LEN_OFFSET_32, ELF_PHDR_LEN_OFFSET_64, ELF_PHDR_OFFSET_32, ELF_PHDR_OFFSET_64,
    ELF_SHDR_COUNT_OFFSET_32, ELF_SHDR_COUNT_OFFSET_64, ELF_SHDR_LEN_OFFSET_32,
    ELF_SHDR_LEN_OFFSET_64, ELF_SHDR_OFFSET_32, ELF_SHDR_OFFSET_64, ELF_VERSION,
    ISO_BMFF_MEDIA_BOXES, ISO_BMFF_TOP_LEVEL_BOXES, MOV_REQUIRED_ATOMS, MovScan, PDF_MIN_PROBE_LEN,
    PE_CHARACTERISTIC_DLL, PE_CHARACTERISTIC_EXECUTABLE_IMAGE, PE_CHARACTERISTIC_SYSTEM,
    PE_CHARACTERISTICS_OFFSET, PE_COFF_HEADER_LEN, PE_MAX_LEN, PE_MAX_OFFSET, PE_MIN_LEN,
    PE_OFFSET_LOCATION, PE_SECTION_HEADER_LEN, PE_SIGNATURE, PdfLinearizedScan, PeDetails,
    WPD_DOCUMENT_AREA_OFFSET, WPD_MIN_LEN,
};
use crate::{
    search::{find_forward, find_reverse},
    spec::{SearchMode, SearchSpec},
};

#[derive(Clone, Copy, Debug)]
enum ByteOrder {
    Big,
    Little,
}

pub(super) fn bounded_len(spec: &SearchSpec, window: &[u8], requested_len: usize) -> Option<usize> {
    let max_len = usize::try_from(spec.max_len).ok()?;
    let len = requested_len.min(max_len).min(window.len());
    (len >= spec.header.len()).then_some(len)
}

pub(super) fn checked_recovery_len(
    spec: &SearchSpec,
    window: &[u8],
    requested_len: usize,
) -> Option<usize> {
    let max_len = usize::try_from(spec.max_len).ok()?;
    if requested_len < spec.header.len() || requested_len > max_len {
        return Some(0);
    }
    if requested_len > window.len() {
        return None;
    }
    Some(requested_len)
}

pub(super) fn bmp_len(spec: &SearchSpec, window: &[u8]) -> Option<usize> {
    if window.len() < BMP_MIN_LEN {
        return Some(0);
    }

    let size = read_le_u32(window, BMP_SIZE_OFFSET)? as usize;
    let max_len = usize::try_from(spec.max_len).ok()?;
    if size <= BMP_MIN_LEN || size > max_len {
        return Some(0);
    }

    let header_length = read_le_u32(window, BMP_HEADER_LENGTH_OFFSET)?;
    if header_length == 0 || header_length > 1000 {
        return Some(0);
    }

    // Negative BMP heights are valid top-down DIBs, even though Foremost rejects them.
    let width = i32::from_le_bytes(
        window
            .get(BMP_WIDTH_OFFSET..BMP_WIDTH_OFFSET + 4)?
            .try_into()
            .ok()?,
    );
    let height = i32::from_le_bytes(
        window
            .get(BMP_HEIGHT_OFFSET..BMP_HEIGHT_OFFSET + 4)?
            .try_into()
            .ok()?,
    );
    if width <= 0 || height == 0 || height == i32::MIN || height.unsigned_abs() > BMP_VERTICAL_LIMIT
    {
        return Some(0);
    }

    let _data_offset = read_le_u32(window, BMP_DATA_OFFSET_OFFSET)?;
    let _data_size = read_le_u32(window, BMP_DATA_SIZE_OFFSET)?;

    Some(size)
}

pub(super) fn generic_footer_end(spec: &SearchSpec, window: &[u8], wildcard: u8) -> Option<usize> {
    if spec.footer.is_empty() {
        return bounded_len(spec, window, window.len());
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let search_limit = window.len().min(max_len);
    let searchable = &window[..search_limit];
    let start = spec.header.len();
    let footer_index = match spec.search_mode {
        SearchMode::Ascii => return None,
        SearchMode::Forward | SearchMode::ForwardNext => find_forward(
            &spec.footer,
            searchable,
            start,
            spec.case_sensitive,
            wildcard,
        )?,
        SearchMode::Reverse => {
            find_reverse(&spec.footer, searchable, spec.case_sensitive, wildcard)?
        }
    };

    if spec.search_mode == SearchMode::ForwardNext {
        Some(footer_index)
    } else {
        Some(footer_index + spec.footer.len())
    }
}

pub(super) fn elf_len(spec: &SearchSpec, window: &[u8]) -> Option<usize> {
    if window.len() < ELF_32_HEADER_LEN {
        return None;
    }
    if window.get(..ELF_MAGIC.len()) != Some(ELF_MAGIC) {
        return Some(0);
    }

    let byte_order = match window.get(5).copied()? {
        ELF_DATA_LITTLE => ByteOrder::Little,
        ELF_DATA_BIG => ByteOrder::Big,
        _ => return Some(0),
    };
    if window.get(6).copied()? != ELF_VERSION {
        return Some(0);
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let class = window.get(4).copied()?;
    let (
        header_len,
        min_program_header_len,
        min_section_header_len,
        phoff_offset,
        shoff_offset,
        header_len_offset,
        phdr_len_offset,
        phdr_count_offset,
        shdr_len_offset,
        shdr_count_offset,
    ) = match class {
        ELF_CLASS_32 => (
            ELF_32_HEADER_LEN,
            ELF_32_PHDR_LEN,
            ELF_32_SHDR_LEN,
            ELF_PHDR_OFFSET_32,
            ELF_SHDR_OFFSET_32,
            ELF_HEADER_LEN_OFFSET_32,
            ELF_PHDR_LEN_OFFSET_32,
            ELF_PHDR_COUNT_OFFSET_32,
            ELF_SHDR_LEN_OFFSET_32,
            ELF_SHDR_COUNT_OFFSET_32,
        ),
        ELF_CLASS_64 => (
            ELF_64_HEADER_LEN,
            ELF_64_PHDR_LEN,
            ELF_64_SHDR_LEN,
            ELF_PHDR_OFFSET_64,
            ELF_SHDR_OFFSET_64,
            ELF_HEADER_LEN_OFFSET_64,
            ELF_PHDR_LEN_OFFSET_64,
            ELF_PHDR_COUNT_OFFSET_64,
            ELF_SHDR_LEN_OFFSET_64,
            ELF_SHDR_COUNT_OFFSET_64,
        ),
        _ => return Some(0),
    };

    if window.len() < header_len {
        return None;
    }
    if read_ordered_u16(window, header_len_offset, byte_order)? as usize != header_len {
        return Some(0);
    }

    let mut end = header_len;
    let phoff = read_elf_offset(window, phoff_offset, class, byte_order)?;
    let shoff = read_elf_offset(window, shoff_offset, class, byte_order)?;
    let phdr_len = read_ordered_u16(window, phdr_len_offset, byte_order)? as usize;
    let shdr_len = read_ordered_u16(window, shdr_len_offset, byte_order)? as usize;
    let phdr_count = read_ordered_u16(window, phdr_count_offset, byte_order)? as usize;
    let shdr_count = read_ordered_u16(window, shdr_count_offset, byte_order)? as usize;

    let ph_table_end = elf_table_len(phoff, phdr_len, phdr_count, min_program_header_len, max_len)?;
    if ph_table_end == usize::MAX {
        return Some(0);
    }
    if ph_table_end > window.len() {
        return None;
    }
    end = end.max(ph_table_end);
    for index in 0..phdr_count {
        let entry = phoff.checked_add(index.checked_mul(phdr_len)?)?;
        let (offset, size) = elf_program_file_range(window, entry, class, byte_order)?;
        if size == 0 {
            continue;
        }
        let segment_end = offset.checked_add(size)?;
        if segment_end > max_len {
            return Some(0);
        }
        if segment_end > window.len() {
            return None;
        }
        end = end.max(segment_end);
    }

    let sh_table_end = elf_table_len(shoff, shdr_len, shdr_count, min_section_header_len, max_len)?;
    if sh_table_end == usize::MAX {
        return Some(0);
    }
    if sh_table_end > window.len() {
        return None;
    }
    end = end.max(sh_table_end);
    for index in 0..shdr_count {
        let entry = shoff.checked_add(index.checked_mul(shdr_len)?)?;
        let (offset, size) = elf_section_file_range(window, entry, class, byte_order)?;
        if size == 0 {
            continue;
        }
        let section_end = offset.checked_add(size)?;
        if section_end > max_len {
            return Some(0);
        }
        if section_end > window.len() {
            return None;
        }
        end = end.max(section_end);
    }

    Some(end)
}

pub(super) fn iso_bmff_len(spec: &SearchSpec, window: &[u8], require_ftyp: bool) -> Option<usize> {
    let mut offset = 0usize;
    let mut saw_box = false;
    let mut saw_media_box = false;
    let max_len = usize::try_from(spec.max_len).ok()?;

    while offset + 8 <= window.len() {
        if offset >= max_len {
            break;
        }

        let size = read_be_u32(window, offset)? as usize;
        let atom_type = window.get(offset + 4..offset + 8)?;
        if require_ftyp && offset == 0 && atom_type != b"ftyp" {
            return None;
        }
        if !valid_iso_top_level_box(atom_type) {
            break;
        }

        let (box_len, min_box_len) = if size == 1 {
            let large_size = read_be_u64(window, offset + 8)?;
            (usize::try_from(large_size).ok()?, 16)
        } else if size == 0 {
            (window.len() - offset, 8)
        } else {
            (size, 8)
        };

        if box_len < min_box_len || box_len > max_len.saturating_sub(offset) {
            break;
        }
        let next_offset = offset.checked_add(box_len)?;
        if next_offset > window.len() {
            return None;
        }
        if atom_type == b"ftyp" && !valid_ftyp_box(window, offset, box_len) {
            return Some(0);
        }

        if ISO_BMFF_MEDIA_BOXES
            .iter()
            .any(|media_box| atom_type == media_box.as_slice())
        {
            saw_media_box = true;
        }

        if require_ftyp && matches!(atom_type, b"free" | b"skip" | b"wide") && offset == 0 {
            break;
        }

        saw_box = true;
        offset = next_offset;
        if size == 0 {
            break;
        }
    }

    if saw_box && (!require_ftyp || saw_media_box) {
        Some(offset)
    } else if require_ftyp {
        Some(0)
    } else {
        None
    }
}

pub(super) fn wpd_len(spec: &SearchSpec, window: &[u8]) -> Option<usize> {
    if window.len() < WPD_MIN_LEN {
        return None;
    }

    let max_len = usize::try_from(spec.max_len).ok()?;
    let document_area = read_le_u32(window, WPD_DOCUMENT_AREA_OFFSET)? as usize;
    if !(WPD_MIN_LEN..=max_len).contains(&document_area) {
        return Some(0);
    }
    if document_area > window.len() {
        return None;
    }

    let search_limit = window.len().min(max_len);
    if let Some(next_header) = find_forward(
        &spec.header,
        &window[..search_limit],
        document_area,
        spec.case_sensitive,
        0,
    ) {
        return Some(next_header);
    }
    Some(search_limit)
}

pub(super) fn mov_len(spec: &SearchSpec, window: &[u8]) -> Option<MovScan> {
    let max_len = usize::try_from(spec.max_len).ok()?;
    let mut offset = 0usize;
    let mut saw_mdat = false;

    loop {
        let atom_size = read_be_u32(window, offset)? as usize;
        if atom_size == 0 || atom_size > max_len {
            return Some(MovScan::skip(spec.header.len() + 4));
        }

        let next_offset = offset.checked_add(atom_size)?;
        if next_offset > window.len() {
            return if window.len() >= max_len {
                Some(MovScan::skip(spec.header.len() + 4))
            } else {
                None
            };
        }

        offset = next_offset;
        if window.len().saturating_sub(offset) < 8 {
            return if saw_mdat {
                Some(MovScan::write(offset))
            } else {
                Some(MovScan::skip(offset))
            };
        }

        let next_atom = window.get(offset + 4..offset + 8)?;
        if next_atom == b"mdat" {
            saw_mdat = true;
        }
        if !valid_mov_atom(next_atom) {
            return if saw_mdat {
                Some(MovScan::write(offset))
            } else {
                Some(MovScan::skip(offset))
            };
        }
    }
}

pub(super) fn pe_details(window: &[u8]) -> Option<PeDetails> {
    let pe_offset_bytes = window.get(PE_OFFSET_LOCATION..PE_OFFSET_LOCATION + 4)?;
    let pe_offset = u32::from_le_bytes(pe_offset_bytes.try_into().ok()?) as usize;
    if pe_offset == 0 || pe_offset > PE_MAX_OFFSET {
        return None;
    }
    if window.get(pe_offset..pe_offset + PE_SIGNATURE.len())? != PE_SIGNATURE {
        return None;
    }

    let coff_offset = pe_offset + PE_SIGNATURE.len();
    let section_count = u16::from_le_bytes(
        window
            .get(coff_offset + 2..coff_offset + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    let characteristics = read_le_u16(window, coff_offset + PE_CHARACTERISTICS_OFFSET)?;
    let suffix = if characteristics & PE_CHARACTERISTIC_DLL != 0 {
        "dll"
    } else if characteristics & (PE_CHARACTERISTIC_SYSTEM | PE_CHARACTERISTIC_EXECUTABLE_IMAGE) != 0
    {
        "exe"
    } else {
        return None;
    };

    let optional_header_size = u16::from_le_bytes(
        window
            .get(coff_offset + 16..coff_offset + 18)?
            .try_into()
            .ok()?,
    ) as usize;
    let section_table = coff_offset + PE_COFF_HEADER_LEN + optional_header_size;
    let section_headers_len = section_count.checked_mul(PE_SECTION_HEADER_LEN)?;
    if window.len() < section_table.checked_add(section_headers_len)? {
        return None;
    }
    let mut end = section_table + section_headers_len;

    for section_index in 0..section_count {
        let offset = section_table + section_index * PE_SECTION_HEADER_LEN;
        let raw_size =
            u32::from_le_bytes(window.get(offset + 16..offset + 20)?.try_into().ok()?) as usize;
        let raw_pointer =
            u32::from_le_bytes(window.get(offset + 20..offset + 24)?.try_into().ok()?) as usize;
        end = end.max(raw_pointer.saturating_add(raw_size));
    }

    if !(PE_MIN_LEN..=PE_MAX_LEN).contains(&end) {
        return None;
    }

    Some(PeDetails { len: end, suffix })
}

pub(super) fn pdf_linearized_len(
    spec: &SearchSpec,
    window: &[u8],
    wildcard: u8,
) -> PdfLinearizedScan {
    let Some(linearized_index) =
        find_forward(b"/Linearized", window, spec.header.len(), true, wildcard)
    else {
        return PdfLinearizedScan::Missing;
    };
    let search_end = window
        .len()
        .min(linearized_index.saturating_add(PDF_MIN_PROBE_LEN));
    let Some(size_marker) = find_forward(
        b"/L ",
        &window[..search_end],
        linearized_index,
        true,
        wildcard,
    ) else {
        return PdfLinearizedScan::Missing;
    };
    let size_start = size_marker + 3;
    let size_end = window.len().min(size_start + 8);
    let Some(size_bytes) = window.get(size_start..size_end) else {
        return PdfLinearizedScan::NeedMore;
    };
    let size_digits = size_bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .fold(0usize, |size, byte| {
            size.saturating_mul(10)
                .saturating_add(usize::from(byte - b'0'))
        });
    if size_digits == 0 {
        return PdfLinearizedScan::Skip;
    }

    let Some(size) = checked_recovery_len(spec, window, size_digits) else {
        return PdfLinearizedScan::NeedMore;
    };
    if size == 0 {
        return PdfLinearizedScan::Skip;
    }

    let footer_len = spec.footer.len();
    let probe_start = size.saturating_sub(footer_len + 10);
    let probe_end = window.len().min(size);
    let Some(footer_index) = find_forward(
        &spec.footer,
        &window[..probe_end],
        probe_start,
        spec.case_sensitive,
        wildcard,
    ) else {
        return PdfLinearizedScan::NeedMore;
    };
    PdfLinearizedScan::Found(
        footer_index
            .saturating_add(footer_len)
            .saturating_add(1)
            .min(window.len()),
    )
}

fn elf_program_file_range(
    window: &[u8],
    entry: usize,
    class: u8,
    byte_order: ByteOrder,
) -> Option<(usize, usize)> {
    let offset = if class == ELF_CLASS_64 {
        read_ordered_u64(window, entry + 8, byte_order)?
    } else {
        u64::from(read_ordered_u32(window, entry + 4, byte_order)?)
    };
    let size = if class == ELF_CLASS_64 {
        read_ordered_u64(window, entry + 32, byte_order)?
    } else {
        u64::from(read_ordered_u32(window, entry + 16, byte_order)?)
    };
    Some((usize::try_from(offset).ok()?, usize::try_from(size).ok()?))
}

fn elf_section_file_range(
    window: &[u8],
    entry: usize,
    class: u8,
    byte_order: ByteOrder,
) -> Option<(usize, usize)> {
    let offset = if class == ELF_CLASS_64 {
        read_ordered_u64(window, entry + 24, byte_order)?
    } else {
        u64::from(read_ordered_u32(window, entry + 16, byte_order)?)
    };
    let size = if class == ELF_CLASS_64 {
        read_ordered_u64(window, entry + 32, byte_order)?
    } else {
        u64::from(read_ordered_u32(window, entry + 20, byte_order)?)
    };
    Some((usize::try_from(offset).ok()?, usize::try_from(size).ok()?))
}

fn elf_table_len(
    offset: usize,
    entry_len: usize,
    count: usize,
    expected_entry_len: usize,
    max_len: usize,
) -> Option<usize> {
    if count == 0 {
        return Some(0);
    }
    if offset == 0 || entry_len < expected_entry_len {
        return Some(usize::MAX);
    }
    let len = entry_len.checked_mul(count)?;
    let end = offset.checked_add(len)?;
    if end > max_len {
        return Some(usize::MAX);
    }
    Some(end)
}

fn read_elf_offset(
    window: &[u8],
    offset: usize,
    class: u8,
    byte_order: ByteOrder,
) -> Option<usize> {
    let value = if class == ELF_CLASS_64 {
        read_ordered_u64(window, offset, byte_order)?
    } else {
        u64::from(read_ordered_u32(window, offset, byte_order)?)
    };
    usize::try_from(value).ok()
}

fn read_ordered_u16(window: &[u8], offset: usize, byte_order: ByteOrder) -> Option<u16> {
    match byte_order {
        ByteOrder::Big => read_be_u16(window, offset),
        ByteOrder::Little => read_le_u16(window, offset),
    }
}

fn read_ordered_u32(window: &[u8], offset: usize, byte_order: ByteOrder) -> Option<u32> {
    match byte_order {
        ByteOrder::Big => read_be_u32(window, offset),
        ByteOrder::Little => read_le_u32(window, offset),
    }
}

fn read_ordered_u64(window: &[u8], offset: usize, byte_order: ByteOrder) -> Option<u64> {
    match byte_order {
        ByteOrder::Big => read_be_u64(window, offset),
        ByteOrder::Little => read_le_u64(window, offset),
    }
}

pub(super) fn read_be_u16(window: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        window.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

pub(super) fn read_be_u32(window: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        window.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

pub(super) fn read_be_u64(window: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        window.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

pub(super) fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

pub(super) fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

pub(super) fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn valid_ftyp_box(window: &[u8], offset: usize, box_len: usize) -> bool {
    if box_len < 16 || !(box_len - 16).is_multiple_of(4) {
        return false;
    }
    let Some(payload) = window.get(offset + 8..offset + box_len) else {
        return false;
    };
    valid_iso_fourcc(&payload[..4]) && payload[8..].chunks_exact(4).all(valid_iso_fourcc)
}

fn valid_iso_fourcc(bytes: &[u8]) -> bool {
    bytes.len() == 4
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b' ' || *byte == b'_')
}

fn valid_iso_top_level_box(atom_type: &[u8]) -> bool {
    ISO_BMFF_TOP_LEVEL_BOXES
        .iter()
        .any(|valid| atom_type == valid.as_slice())
}

fn valid_mov_atom(atom_type: &[u8]) -> bool {
    if atom_type == b"mp3\0" {
        return true;
    }
    MOV_REQUIRED_ATOMS
        .iter()
        .any(|valid| atom_type == valid.as_slice())
}
