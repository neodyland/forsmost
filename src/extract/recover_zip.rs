use super::{
    recover::{recovered_with_suffix, skip_recovered, zip_or_ole_suffix_matches},
    scan::{bounded_len, read_le_u16, read_le_u32, read_le_u64, scan_zip_local_headers},
    types::{
        MEBIBYTE, Recovered, ZIP_CENTRAL_HEADER_LEN, ZIP_CENTRAL_SIGNATURE, ZIP_EOCD_BASE_LEN,
        ZIP_EOCD_COMMENT_OFFSET, ZIP_EOCD_SIGNATURE, ZIP64_EOCD_LOCATOR_LEN,
        ZIP64_EOCD_LOCATOR_SIGNATURE, ZIP64_EOCD_MIN_LEN, ZIP64_EOCD_SIGNATURE, ZipScan,
    },
};
use crate::{search::find_forward, spec::SearchSpec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZipEocdStrength {
    Strong,
    UnsupportedMultiDisk,
    Weak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZipEocdScan {
    Recover(usize),
    Skip(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ZipCentralDirectory {
    entries_on_disk: u64,
    expected_end: usize,
    offset: usize,
    single_disk: bool,
    size: usize,
    total_entries: u64,
}

pub(super) fn recover_zip<'a>(
    spec: &SearchSpec,
    window: &'a [u8],
    wildcard: u8,
) -> Option<Recovered<'a>> {
    let max_len = usize::try_from(spec.max_len).ok()?;
    let (search_start, classification, allow_weak_eocd) =
        match scan_zip_local_headers(spec, window, max_len)? {
            ZipScan::Search {
                classification,
                search_start,
            } => (search_start, classification, true),
            ZipScan::SearchCentralDirectory {
                classification,
                search_start,
            } => (search_start, classification, false),
            ZipScan::Skip(next_index) => return Some(skip_recovered(spec, window, next_index)),
        };
    let search_end = if classification.open_office {
        search_start.saturating_add(MEBIBYTE)
    } else {
        max_len
    };
    let search_limit = window.len().min(max_len).min(search_end);
    let footer_index = match find_zip_eocd(
        spec,
        window,
        search_start,
        search_limit,
        wildcard,
        allow_weak_eocd,
    )? {
        ZipEocdScan::Recover(index) => index,
        ZipEocdScan::Skip(next_index) => return Some(skip_recovered(spec, window, next_index)),
    };
    let end = bounded_len(spec, window, zip_eocd_end(window, footer_index)?)?;
    let mut recovered = recovered_with_suffix(spec, window, end, classification.suffix, "ZIP EOCD");
    if let Some(comment) = classification.comment {
        let base = recovered
            .comment
            .trim_start_matches('(')
            .trim_end_matches(')');
        recovered.comment = format!("({base}, {comment})");
    }
    if !zip_or_ole_suffix_matches(spec, &recovered.suffix) {
        recovered.write = false;
    }
    Some(recovered)
}

fn find_zip_eocd(
    spec: &SearchSpec,
    window: &[u8],
    search_start: usize,
    search_limit: usize,
    wildcard: u8,
    allow_weak: bool,
) -> Option<ZipEocdScan> {
    let mut offset = search_start;
    let mut weak_candidate = None;
    while offset < search_limit {
        let Some(candidate) = find_forward(
            &spec.footer,
            &window[..search_limit],
            offset,
            spec.case_sensitive,
            wildcard,
        ) else {
            break;
        };
        match zip_eocd_strength(window, candidate, search_limit) {
            Some(ZipEocdStrength::Strong) => return Some(ZipEocdScan::Recover(candidate)),
            Some(ZipEocdStrength::UnsupportedMultiDisk) => {
                return Some(ZipEocdScan::Skip(zip_eocd_end(window, candidate)?));
            }
            Some(ZipEocdStrength::Weak) if allow_weak && weak_candidate.is_none() => {
                weak_candidate = Some(candidate);
            }
            _ => {}
        }
        offset = candidate.checked_add(1)?;
    }
    weak_candidate.map(ZipEocdScan::Recover)
}

fn zip_eocd_end(window: &[u8], eocd_offset: usize) -> Option<usize> {
    let comment_length_offset = eocd_offset.checked_add(ZIP_EOCD_COMMENT_OFFSET)?;
    let comment_length = read_le_u16(window, comment_length_offset)? as usize;
    eocd_offset
        .checked_add(ZIP_EOCD_BASE_LEN)?
        .checked_add(comment_length)
}

fn zip_eocd_strength(
    window: &[u8],
    eocd_offset: usize,
    search_limit: usize,
) -> Option<ZipEocdStrength> {
    if window.get(eocd_offset..eocd_offset + ZIP_EOCD_SIGNATURE.len())? != ZIP_EOCD_SIGNATURE {
        return None;
    }
    let eocd_end = zip_eocd_end(window, eocd_offset)?;
    if eocd_end > search_limit || eocd_end > window.len() {
        return None;
    }

    let disk_number = read_le_u16(window, eocd_offset + 4)?;
    let central_directory_disk = read_le_u16(window, eocd_offset + 6)?;
    let entries_on_disk = read_le_u16(window, eocd_offset + 8)?;
    let total_entries = read_le_u16(window, eocd_offset + 10)?;
    let central_directory_size = read_le_u32(window, eocd_offset + 12)? as usize;
    let central_directory_offset = read_le_u32(window, eocd_offset + 16)? as usize;

    if entries_on_disk == 0
        && total_entries == 0
        && central_directory_size == 0
        && central_directory_offset == 0
    {
        return Some(ZipEocdStrength::Weak);
    }

    if entries_on_disk == u16::MAX
        || total_entries == u16::MAX
        || central_directory_size == u32::MAX as usize
        || central_directory_offset == u32::MAX as usize
    {
        return zip64_eocd_strength(window, eocd_offset, search_limit);
    }

    zip_central_directory_strength(
        window,
        ZipCentralDirectory {
            entries_on_disk: u64::from(entries_on_disk),
            expected_end: eocd_offset,
            offset: central_directory_offset,
            single_disk: disk_number == 0 && central_directory_disk == 0,
            size: central_directory_size,
            total_entries: u64::from(total_entries),
        },
    )
}

fn zip64_eocd_strength(
    window: &[u8],
    eocd_offset: usize,
    search_limit: usize,
) -> Option<ZipEocdStrength> {
    let locator_offset = eocd_offset.checked_sub(ZIP64_EOCD_LOCATOR_LEN)?;
    if window
        .get(locator_offset..locator_offset.checked_add(ZIP64_EOCD_LOCATOR_SIGNATURE.len())?)?
        != ZIP64_EOCD_LOCATOR_SIGNATURE
    {
        return None;
    }

    let locator_disk = read_le_u32(window, locator_offset + 4)?;
    let zip64_offset = usize::try_from(read_le_u64(window, locator_offset + 8)?).ok()?;
    let total_disks = read_le_u32(window, locator_offset + 16)?;

    if window.get(zip64_offset..zip64_offset.checked_add(ZIP64_EOCD_SIGNATURE.len())?)?
        != ZIP64_EOCD_SIGNATURE
    {
        return None;
    }

    let record_size = usize::try_from(read_le_u64(window, zip64_offset + 4)?).ok()?;
    let record_end = zip64_offset.checked_add(12)?.checked_add(record_size)?;
    if record_size < ZIP64_EOCD_MIN_LEN - 12
        || record_end != locator_offset
        || record_end > search_limit
        || record_end > window.len()
    {
        return None;
    }

    let disk_number = read_le_u32(window, zip64_offset + 16)?;
    let central_directory_disk = read_le_u32(window, zip64_offset + 20)?;
    let entries_on_disk = read_le_u64(window, zip64_offset + 24)?;
    let total_entries = read_le_u64(window, zip64_offset + 32)?;
    let central_directory_size = usize::try_from(read_le_u64(window, zip64_offset + 40)?).ok()?;
    let central_directory_offset = usize::try_from(read_le_u64(window, zip64_offset + 48)?).ok()?;

    zip_central_directory_strength(
        window,
        ZipCentralDirectory {
            entries_on_disk,
            expected_end: zip64_offset,
            offset: central_directory_offset,
            single_disk: locator_disk == 0
                && total_disks == 1
                && disk_number == 0
                && central_directory_disk == 0,
            size: central_directory_size,
            total_entries,
        },
    )
}

fn zip_central_directory_strength(
    window: &[u8],
    directory: ZipCentralDirectory,
) -> Option<ZipEocdStrength> {
    let plausible = zip_central_directory_well_formed(window, directory)?;

    if !directory.single_disk {
        return plausible.then_some(ZipEocdStrength::UnsupportedMultiDisk);
    }
    if directory.entries_on_disk != directory.total_entries || directory.total_entries == 0 {
        return None;
    }

    plausible.then_some(ZipEocdStrength::Strong)
}

fn zip_central_directory_well_formed(
    window: &[u8],
    directory: ZipCentralDirectory,
) -> Option<bool> {
    let end = directory.offset.checked_add(directory.size)?;
    let entry_count = usize::try_from(directory.total_entries).ok()?;
    if end != directory.expected_end
        || end > window.len()
        || directory.size < ZIP_CENTRAL_HEADER_LEN
        || entry_count == 0
    {
        return Some(false);
    }

    let mut offset = directory.offset;
    for _ in 0..entry_count {
        let header_end = offset.checked_add(ZIP_CENTRAL_HEADER_LEN)?;
        if header_end > end
            || window.get(offset..offset.checked_add(ZIP_CENTRAL_SIGNATURE.len())?)?
                != ZIP_CENTRAL_SIGNATURE
        {
            return Some(false);
        }

        let compressed_size = read_le_u32(window, offset + 20)?;
        let uncompressed_size = read_le_u32(window, offset + 24)?;
        let filename_len = read_le_u16(window, offset + 28)? as usize;
        let extra_len = read_le_u16(window, offset + 30)? as usize;
        let comment_len = read_le_u16(window, offset + 32)? as usize;
        let local_header_offset = read_le_u32(window, offset + 42)?;
        let extra_start = header_end.checked_add(filename_len)?;
        let extra_end = extra_start.checked_add(extra_len)?;
        let entry_end = extra_end.checked_add(comment_len)?;
        if entry_end > end {
            return Some(false);
        }

        let Some(local_header_offset) = zip_central_local_header_offset(
            compressed_size,
            uncompressed_size,
            local_header_offset,
            window.get(extra_start..extra_end)?,
        ) else {
            return Some(false);
        };
        if local_header_offset >= directory.offset {
            return Some(false);
        }

        offset = entry_end;
    }

    Some(offset == end)
}

fn zip_central_local_header_offset(
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
    extra: &[u8],
) -> Option<usize> {
    if compressed_size != u32::MAX
        && uncompressed_size != u32::MAX
        && local_header_offset != u32::MAX
    {
        return Some(local_header_offset as usize);
    }

    let mut offset = 0usize;
    while offset + 4 <= extra.len() {
        let field_id = read_le_u16(extra, offset)?;
        let field_len = read_le_u16(extra, offset + 2)? as usize;
        let data_start = offset + 4;
        let data_end = data_start.checked_add(field_len)?;
        if data_end > extra.len() {
            return None;
        }

        if field_id == 0x0001 {
            let mut zip64_offset = data_start;
            if uncompressed_size == u32::MAX {
                read_le_u64(extra, zip64_offset)?;
                zip64_offset = zip64_offset.checked_add(8)?;
            }
            if compressed_size == u32::MAX {
                read_le_u64(extra, zip64_offset)?;
                zip64_offset = zip64_offset.checked_add(8)?;
            }
            if local_header_offset == u32::MAX {
                return usize::try_from(read_le_u64(extra, zip64_offset)?).ok();
            }
            return Some(local_header_offset as usize);
        }
        offset = data_end;
    }

    None
}
