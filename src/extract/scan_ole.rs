use std::iter::from_fn;

use super::{
    scan::{read_le_u16, read_le_u32, read_le_u64},
    types::{
        CFB_DIFAT_HEADER_ENTRIES, CFB_DIFAT_OFFSET, CFB_DIFAT_SECTOR, CFB_DIRECTORY_ENTRY_LEN,
        CFB_DIRECTORY_SECTOR_LIMIT, CFB_END_OF_CHAIN, CFB_FAT_SECTOR, CFB_FREE_SECTOR,
        CFB_HEADER_LEN, CFB_MAX_EXTRA_DIFAT_SECTORS, CFB_MAX_FAT_SECTORS, CFB_NO_STREAM, CFB_ROOT,
        CFB_STREAM, CFB_VALID_BYTE_ORDER, OleDetails, OleDirectoryEntry, ZIP_CONTENT_TYPES,
        ZIP_LOCAL_HEADER_LEN, ZIP_LOCAL_SIGNATURE, ZipClassification, ZipScan,
    },
};
use crate::spec::SearchSpec;

#[derive(Debug)]
struct CfbDifat {
    difat_sector_ids: Vec<u32>,
    fat_sector_ids: Vec<u32>,
}

fn cfb_fat_entries(window: &[u8], sector_size: usize, fat_sector_ids: &[u32]) -> Option<Vec<u32>> {
    let mut entries = Vec::new();
    for &sector_id in fat_sector_ids {
        let sector = cfb_sector(window, sector_size, sector_id)?;
        for entry in sector.chunks_exact(4) {
            entries.push(u32::from_le_bytes(entry.try_into().ok()?));
        }
    }
    Some(entries)
}

fn cfb_fat_sector_ids(
    window: &[u8],
    sector_size: usize,
    fat_sectors: usize,
    first_difat_sector: u32,
    difat_sector_count: usize,
) -> Option<CfbDifat> {
    let mut fat_sector_ids = Vec::new();
    let mut difat_sector_ids = Vec::new();
    let header_entries =
        window.get(CFB_DIFAT_OFFSET..CFB_DIFAT_OFFSET + CFB_DIFAT_HEADER_ENTRIES * 4)?;
    for entry in header_entries.chunks_exact(4) {
        let sector_id = u32::from_le_bytes(entry.try_into().ok()?);
        if sector_id != CFB_FREE_SECTOR {
            fat_sector_ids.push(sector_id);
            if fat_sector_ids.len() == fat_sectors {
                break;
            }
        }
    }

    let difat_entries_per_sector = sector_size.checked_div(4)?.checked_sub(1)?;
    let mut current_difat_sector = first_difat_sector;
    for _ in 0..difat_sector_count {
        if fat_sector_ids.len() == fat_sectors {
            break;
        }
        if !cfb_regular_sector_id(current_difat_sector) {
            return None;
        }
        difat_sector_ids.push(current_difat_sector);
        let sector = cfb_sector(window, sector_size, current_difat_sector)?;
        for entry in sector
            .get(..difat_entries_per_sector.checked_mul(4)?)?
            .chunks_exact(4)
        {
            let sector_id = u32::from_le_bytes(entry.try_into().ok()?);
            if sector_id == CFB_FREE_SECTOR {
                continue;
            }
            if !cfb_regular_sector_id(sector_id) {
                return None;
            }
            fat_sector_ids.push(sector_id);
            if fat_sector_ids.len() == fat_sectors {
                break;
            }
        }
        current_difat_sector = read_le_u32(sector, difat_entries_per_sector * 4)?;
    }

    (fat_sector_ids.len() == fat_sectors).then_some(CfbDifat {
        difat_sector_ids,
        fat_sector_ids,
    })
}

fn cfb_sector(window: &[u8], sector_size: usize, sector_id: u32) -> Option<&[u8]> {
    if matches!(
        sector_id,
        CFB_DIFAT_SECTOR | CFB_END_OF_CHAIN | CFB_FAT_SECTOR | CFB_FREE_SECTOR
    ) {
        return None;
    }

    let sector_index = usize::try_from(sector_id).ok()?;
    let start = (sector_index + 1).checked_mul(sector_size)?;
    window.get(start..start + sector_size)
}

fn cfb_sector_offset(sector_size: usize, sector_id: u32) -> Option<usize> {
    let sector_index = usize::try_from(sector_id).ok()?;
    (sector_index + 1).checked_mul(sector_size)
}

const fn cfb_regular_sector_id(sector_id: u32) -> bool {
    !matches!(
        sector_id,
        CFB_DIFAT_SECTOR | CFB_END_OF_CHAIN | CFB_FAT_SECTOR | CFB_FREE_SECTOR
    )
}

fn cfb_stream_suffix(name: &str) -> Option<&'static str> {
    if name.contains("WordDocument") {
        Some("doc")
    } else if name.contains("Worksheet") || name.contains("Book") || name.contains("Workbook") {
        Some("xls")
    } else if name.contains("Power") {
        Some("ppt")
    } else if name.contains("Access") || name.contains("AccessObjSiteData") {
        // Foremost falls back to .ole for Access streams; use the real MDB suffix.
        Some("mdb")
    } else if name.contains("Visio") {
        Some("vis")
    } else if name.contains("Sfx") {
        Some("sdw")
    } else {
        None
    }
}

fn cfb_walk_chain(
    start_sector: u32,
    fat_entries: &[u32],
    max_entries: usize,
) -> impl Iterator<Item = u32> + '_ {
    let mut current = start_sector;
    let mut visited = 0usize;
    from_fn(move || {
        if visited >= max_entries || !cfb_regular_sector_id(current) {
            return None;
        }
        let sector = current;
        let next_index = usize::try_from(current).ok()?;
        current = fat_entries
            .get(next_index)
            .copied()
            .unwrap_or(CFB_END_OF_CHAIN);
        visited += 1;
        Some(sector)
    })
}

fn classify_zip_name(name: &[u8], state: &mut ZipClassification) {
    if state.suffix == "zip" {
        if name == b"content.xml" {
            state.open_office = true;
            state.suffix = "sx";
            state.comment = Some("OpenOffice Doc?".to_owned());
        } else if name.windows(6).any(|bytes| bytes == b".class")
            || name.windows(4).any(|bytes| bytes == b".jar")
            || name.windows(5).any(|bytes| bytes == b".java")
        {
            state.suffix = "jar";
        } else if name.starts_with(ZIP_CONTENT_TYPES) {
            state.office_2007 = true;
        } else if name.starts_with(b"ppt/slides") || name.starts_with(b"ppt/presentation.xml") {
            state.office_2007_suffix.get_or_insert("pptx");
        } else if name.starts_with(b"word/document.xml") {
            state.office_2007_suffix.get_or_insert("docx");
        } else if name.starts_with(b"xl/workbook.xml") {
            state.office_2007_suffix.get_or_insert("xlsx");
        }
        apply_zip_office_2007_suffix(state);
    }
}

fn apply_zip_office_2007_suffix(state: &mut ZipClassification) {
    // Foremost depends on local-entry order; keep both clues so either can appear first.
    if state.office_2007
        && state.suffix == "zip"
        && let Some(suffix) = state.office_2007_suffix
    {
        state.suffix = suffix;
    }
}

fn zip64_compressed_size(
    compressed_size: u32,
    uncompressed_size: u32,
    extra: &[u8],
) -> Option<usize> {
    if compressed_size != u32::MAX {
        return Some(compressed_size as usize);
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
                zip64_offset = zip64_offset.checked_add(8)?;
            }
            let compressed = read_le_u64(extra, zip64_offset)?;
            return usize::try_from(compressed).ok();
        }
        offset = data_end;
    }

    None
}

const fn round_up(value: usize, block_size: usize) -> Option<usize> {
    let remainder = value % block_size;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(block_size - remainder)
    }
}

fn cfb_chain_max_end(
    start_sector: u32,
    fat_entries: &[u32],
    sector_size: usize,
    max_entries: usize,
) -> Option<usize> {
    if max_entries == 0 {
        return Some(0);
    }

    let mut current = start_sector;
    let mut max_end = 0usize;
    let mut visited = Vec::new();

    for _ in 0..max_entries {
        if !cfb_regular_sector_id(current) || visited.contains(&current) {
            return None;
        }
        let sector_index = usize::try_from(current).ok()?;
        visited.push(current);
        let offset = cfb_sector_offset(sector_size, current)?;
        max_end = max_end.max(offset.checked_add(sector_size)?);
        current = *fat_entries.get(sector_index)?;
    }

    Some(max_end)
}

fn cfb_mini_fat_entries(
    window: &[u8],
    sector_size: usize,
    fat_entries: &[u32],
    mini_fat_start: u32,
    mini_fat_sector_count: usize,
) -> Option<Vec<u32>> {
    let mut entries = Vec::new();
    if mini_fat_sector_count == 0 {
        return Some(entries);
    }

    for sector_id in cfb_walk_chain(mini_fat_start, fat_entries, mini_fat_sector_count) {
        let sector = cfb_sector(window, sector_size, sector_id)?;
        for entry in sector.chunks_exact(4) {
            entries.push(u32::from_le_bytes(entry.try_into().ok()?));
        }
    }
    Some(entries)
}

fn cfb_mini_chain_max_end(
    start_sector: u32,
    mini_fat_entries: &[u32],
    mini_sector_size: usize,
    sector_count: usize,
) -> Option<usize> {
    let mut current = start_sector;
    let mut max_end = 0usize;
    let mut visited = Vec::new();

    for _ in 0..sector_count {
        if !cfb_regular_sector_id(current) || visited.contains(&current) {
            return None;
        }
        let sector_index = usize::try_from(current).ok()?;
        visited.push(current);
        max_end = max_end.max(sector_index.checked_add(1)?.checked_mul(mini_sector_size)?);
        current = *mini_fat_entries.get(sector_index)?;
    }

    Some(max_end)
}

fn cfb_dynamic_fat_limit(max_len: usize, sector_size: usize) -> Option<usize> {
    let entries_per_fat_sector = sector_size.checked_div(4)?;
    let sectors_in_file = max_len.div_ceil(sector_size);
    Some(
        sectors_in_file
            .div_ceil(entries_per_fat_sector)
            .saturating_add(4)
            .min(CFB_MAX_FAT_SECTORS as usize),
    )
}

pub(super) fn scan_ole(spec: &SearchSpec, window: &[u8]) -> Option<OleDetails> {
    if window.len() < CFB_HEADER_LEN {
        return None;
    }
    if !valid_ole_header(window) {
        return Some(OleDetails {
            len: CFB_HEADER_LEN,
            suffix: spec.suffix.clone(),
            write: false,
        });
    }

    let sector_shift = read_le_u16(window, 30)? as usize;
    let mini_sector_shift = read_le_u16(window, 32)? as usize;
    let sector_size = 1usize.checked_shl(u32::try_from(sector_shift).ok()?)?;
    let mini_sector_size = 1usize.checked_shl(u32::try_from(mini_sector_shift).ok()?)?;
    let fat_sector_count = read_le_u32(window, 44)? as usize;
    let directory_start = read_le_u32(window, 48)?;
    let mini_stream_cutoff = read_le_u32(window, 56)? as usize;
    let mini_fat_start = read_le_u32(window, 60)?;
    let mini_fat_sector_count = read_le_u32(window, 64)? as usize;
    let first_difat_sector = read_le_u32(window, 68)?;
    let difat_sector_count = read_le_u32(window, 72)? as usize;
    let max_len = usize::try_from(spec.max_len).ok()?;
    if fat_sector_count > cfb_dynamic_fat_limit(max_len, sector_size)? {
        return Some(OleDetails {
            len: CFB_HEADER_LEN,
            suffix: spec.suffix.clone(),
            write: false,
        });
    }

    let difat = cfb_fat_sector_ids(
        window,
        sector_size,
        fat_sector_count,
        first_difat_sector,
        difat_sector_count,
    )?;
    let fat_entries = cfb_fat_entries(window, sector_size, &difat.fat_sector_ids)?;
    let mini_fat_entries = cfb_mini_fat_entries(
        window,
        sector_size,
        &fat_entries,
        mini_fat_start,
        mini_fat_sector_count,
    )?;
    let mut max_sector_end = CFB_HEADER_LEN;
    for &sector_id in difat
        .fat_sector_ids
        .iter()
        .chain(difat.difat_sector_ids.iter())
    {
        if let Some(offset) = cfb_sector_offset(sector_size, sector_id) {
            max_sector_end = max_sector_end.max(offset.saturating_add(sector_size));
        }
    }

    let mut directory_entries = Vec::new();
    for sector_id in cfb_walk_chain(directory_start, &fat_entries, CFB_DIRECTORY_SECTOR_LIMIT) {
        let offset = cfb_sector_offset(sector_size, sector_id)?;
        max_sector_end = max_sector_end.max(offset.saturating_add(sector_size));
        let sector = cfb_sector(window, sector_size, sector_id)?;
        for entry in sector.chunks_exact(CFB_DIRECTORY_ENTRY_LEN) {
            let Some(directory_entry) = OleDirectoryEntry::parse(entry) else {
                continue;
            };
            if directory_entry.name.contains("Catalog") || directory_entry.name.starts_with('@') {
                return Some(OleDetails {
                    len: max_sector_end.min(window.len()),
                    suffix: spec.suffix.clone(),
                    write: false,
                });
            }
            directory_entries.push(directory_entry);
        }
    }

    if directory_entries.is_empty() {
        return Some(OleDetails {
            len: max_sector_end.min(window.len()),
            suffix: spec.suffix.clone(),
            write: false,
        });
    }

    let mut suffix = "ole".to_owned();
    let mut total_size = 1024usize;
    let root_mini_stream_len = directory_entries
        .iter()
        .find(|entry| entry.kind == CFB_ROOT)
        .and_then(|entry| usize::try_from(entry.size).ok())
        .unwrap_or(0);
    total_size = total_size.checked_add(round_up(
        directory_entries.len() * CFB_DIRECTORY_ENTRY_LEN,
        sector_size,
    )?)?;
    total_size = total_size.checked_add(fat_sector_count.checked_mul(sector_size)?)?;
    total_size = total_size.checked_add(difat.difat_sector_ids.len().checked_mul(sector_size)?)?;
    total_size = total_size.checked_add(mini_fat_sector_count.checked_mul(sector_size)?)?;

    if mini_fat_sector_count > 0 {
        max_sector_end = max_sector_end.max(cfb_chain_max_end(
            mini_fat_start,
            &fat_entries,
            sector_size,
            mini_fat_sector_count,
        )?);
    }

    for entry in &directory_entries {
        if entry.kind == CFB_ROOT {
            let stream_len = usize::try_from(entry.size).ok()?;
            if stream_len > 0 && entry.start_sector != CFB_NO_STREAM {
                let sector_count = round_up(stream_len, sector_size)? / sector_size;
                max_sector_end = max_sector_end.max(cfb_chain_max_end(
                    entry.start_sector,
                    &fat_entries,
                    sector_size,
                    sector_count,
                )?);
                total_size = total_size.checked_add(round_up(stream_len, sector_size)?)?;
            }
        } else if entry.kind == CFB_STREAM {
            if suffix == "ole"
                && let Some(detected) = cfb_stream_suffix(&entry.name)
            {
                detected.clone_into(&mut suffix);
            }

            let stream_len = usize::try_from(entry.size).ok()?;
            let allocation = if stream_len > mini_stream_cutoff {
                let sector_count = round_up(stream_len, sector_size)? / sector_size;
                if entry.start_sector == CFB_NO_STREAM {
                    return Some(OleDetails {
                        len: max_sector_end.min(window.len()),
                        suffix: spec.suffix.clone(),
                        write: false,
                    });
                }
                max_sector_end = max_sector_end.max(cfb_chain_max_end(
                    entry.start_sector,
                    &fat_entries,
                    sector_size,
                    sector_count,
                )?);
                round_up(stream_len, sector_size)?
            } else {
                if stream_len > 0
                    && (entry.start_sector == CFB_NO_STREAM || mini_fat_entries.is_empty())
                {
                    return Some(OleDetails {
                        len: max_sector_end.min(window.len()),
                        suffix: spec.suffix.clone(),
                        write: false,
                    });
                }
                if stream_len > 0 {
                    let sector_count = round_up(stream_len, mini_sector_size)? / mini_sector_size;
                    let mini_chain_end = cfb_mini_chain_max_end(
                        entry.start_sector,
                        &mini_fat_entries,
                        mini_sector_size,
                        sector_count,
                    );
                    if mini_chain_end.is_none_or(|end| end > root_mini_stream_len) {
                        return Some(OleDetails {
                            len: max_sector_end.min(window.len()),
                            suffix: spec.suffix.clone(),
                            write: false,
                        });
                    }
                }
                round_up(stream_len, mini_sector_size)?
            };
            total_size = total_size.checked_add(allocation)?;
        }
    }

    let required = total_size.max(max_sector_end);
    Some(OleDetails {
        len: required.min(window.len()).min(max_len),
        suffix,
        write: true,
    })
}

pub(super) fn scan_zip_local_headers(
    spec: &SearchSpec,
    window: &[u8],
    max_len: usize,
) -> Option<ZipScan> {
    if window.len() < 100 {
        return None;
    }

    let mut classification = ZipClassification::new();
    if window
        .get(ZIP_LOCAL_HEADER_LEN..ZIP_LOCAL_HEADER_LEN + b"mimetypeapplication/vnd.sun.xml.".len())
        == Some(b"mimetypeapplication/vnd.sun.xml.")
    {
        classification.open_office = true;
        if window.get(62..66) == Some(b"calc") {
            classification.suffix = "sxc";
        } else if window.get(62..69) == Some(b"impress") {
            classification.suffix = "sxi";
        } else if window.get(62..68) == Some(b"writer") {
            classification.suffix = "sxw";
        } else {
            classification.suffix = "sx";
            classification.comment = Some("OpenOffice Doc?".to_owned());
        }
    }

    let mut offset = 0usize;
    let mut search_start = spec.header.len();
    loop {
        if window.get(offset..offset + 4) != Some(ZIP_LOCAL_SIGNATURE) {
            break;
        }
        let flags = read_le_u16(window, offset + 6)?;
        let compressed_size = read_le_u32(window, offset + 18)?;
        let uncompressed_size = read_le_u32(window, offset + 22)?;
        let filename_len = read_le_u16(window, offset + 26)? as usize;
        let extra_len = read_le_u16(window, offset + 28)? as usize;

        if filename_len > 100 {
            return Some(ZipScan::Skip(spec.header.len()));
        }

        let name_start = offset + ZIP_LOCAL_HEADER_LEN;
        let name_end = name_start.checked_add(filename_len)?;
        let extra_end = name_end.checked_add(extra_len)?;
        if extra_end > window.len() {
            return None;
        }

        classify_zip_name(window.get(name_start..name_end)?, &mut classification);

        if flags & (1 << 3) != 0 && uncompressed_size == 0 && compressed_size == 0 {
            return Some(ZipScan::Search {
                classification,
                search_start: extra_end,
            });
        }

        let Some(compressed_size) = zip64_compressed_size(
            compressed_size,
            uncompressed_size,
            window.get(name_end..extra_end)?,
        ) else {
            return Some(ZipScan::SearchCentralDirectory {
                classification,
                search_start: extra_end,
            });
        };
        if compressed_size > max_len {
            return Some(ZipScan::Skip(spec.header.len()));
        }

        let data_end = extra_end.checked_add(compressed_size)?;
        if data_end > window.len() {
            return None;
        }
        search_start = data_end;
        offset = data_end;
    }

    Some(ZipScan::Search {
        classification,
        search_start,
    })
}

fn valid_ole_header(window: &[u8]) -> bool {
    read_le_u16(window, 28) == Some(CFB_VALID_BYTE_ORDER)
        // CFB sector shift 12 means 4096-byte sectors; Foremost hard-codes 512.
        && matches!(read_le_u16(window, 30), Some(9 | 12))
        && read_le_u16(window, 32) == Some(6)
        && read_le_u16(window, 34) == Some(0)
        && read_le_u32(window, 36) == Some(0)
        && read_le_u32(window, 40) == Some(0)
        && matches!(read_le_u32(window, 44), Some(1..=CFB_MAX_FAT_SECTORS))
        && matches!(
            read_le_u32(window, 72),
            Some(0..=CFB_MAX_EXTRA_DIFAT_SECTORS)
        )
}
