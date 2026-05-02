use std::{
    fmt::Write as _,
    fs::File,
    io::{Read, Seek, SeekFrom, stdin},
    path::Path,
};

use crate::{
    cli::Options,
    config,
    extract::{Recovered, recover},
    output::OutputWriter,
    search::{find_forward, find_quick},
    spec::{FileKind, SearchSpec, builtins_for_selector, default_all_builtins},
};

const BYTES_PER_MEBIBYTE: u64 = 1024 * 1024;
const INDIRECT_BLOCK_SIZES: [usize; 3] = [4096, 1024, 512];

#[derive(Debug)]
struct IndirectBlock {
    block_size: usize,
    bytes: Vec<u8>,
    offset: usize,
}

pub fn run(options: &Options) -> Result<(), String> {
    let config_load = config::load(&options.config_file, options.config_explicit)?;
    let wildcard = config_load.wildcard;
    let mut specs = selected_specs(options, config_load.specs)?;

    if specs.is_empty() {
        specs = default_all_builtins();
    }

    let mut output = OutputWriter::create(options, &specs, config_load.loaded_path.as_deref())?;
    output.audit_layout()?;

    if options.input_files.is_empty() {
        process_stdin(options, &mut specs, wildcard, &mut output)?;
    } else {
        for path in &options.input_files {
            process_file(path, options, &mut specs, wildcard, &mut output)?;
        }
    }

    output.audit_finish(&specs)
}

fn bridge_window(
    file: &mut File,
    absolute_offset: u64,
    max_len: u64,
) -> Result<Option<Vec<u8>>, String> {
    let saved_position = file
        .stream_position()
        .map_err(|error| format!("failed to read current input position: {error}"))?;
    file.seek(SeekFrom::Start(absolute_offset))
        .map_err(|error| format!("failed to seek input to {absolute_offset}: {error}"))?;

    let capacity = usize::try_from(max_len)
        .map_err(|error| format!("maximum file size is too large: {error}"))?;
    let mut buffer = vec![0; capacity];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|error| format!("failed to read bridge buffer: {error}"))?;
    buffer.truncate(bytes_read);

    file.seek(SeekFrom::Start(saved_position))
        .map_err(|error| format!("failed to restore input position: {error}"))?;
    Ok((!buffer.is_empty()).then_some(buffer))
}

fn bridge_read_len(options: &Options, spec: &SearchSpec) -> Result<u64, String> {
    if options.modes.indirect_block {
        spec.max_len
            .checked_add(INDIRECT_BLOCK_SIZES[0] as u64)
            .ok_or_else(|| "maximum file size plus indirect block is too large".to_owned())
    } else {
        Ok(spec.max_len)
    }
}

fn chunk_size(options: &Options) -> Result<usize, String> {
    let bytes = options
        .chunk_size_mb
        .checked_mul(BYTES_PER_MEBIBYTE)
        .ok_or_else(|| "chunk size is too large".to_owned())?;
    usize::try_from(bytes)
        .map_err(|error| format!("chunk size is not supported on this platform: {error}"))
}

fn process_file(
    path: &Path,
    options: &Options,
    specs: &mut [SearchSpec],
    wildcard: u8,
    output: &mut OutputWriter,
) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("failed to open input `{}`: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read metadata for `{}`: {error}", path.display()))?;
    let skip_bytes = options
        .skip_blocks
        .checked_mul(options.block_size)
        .ok_or_else(|| "skip offset is too large".to_owned())?;
    if skip_bytes != 0 {
        file.seek(SeekFrom::Start(skip_bytes)).map_err(|error| {
            format!(
                "failed to skip {skip_bytes} bytes in `{}`: {error}",
                path.display()
            )
        })?;
    }

    let name = path.display().to_string();
    output.audit_processing_start(&name, Some(metadata.len()))?;

    let mut offset = skip_bytes;
    let mut buffer = vec![0; chunk_size(options)?];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read input `{}`: {error}", path.display()))?;
        if bytes_read == 0 {
            break;
        }

        search_chunk(
            &buffer[..bytes_read],
            offset,
            Some(&mut file),
            options,
            specs,
            wildcard,
            output,
        )?;
        offset += bytes_read as u64;
        output.mark_progress();
    }

    output.audit_processing_finish()
}

fn process_stdin(
    options: &Options,
    specs: &mut [SearchSpec],
    wildcard: u8,
    output: &mut OutputWriter,
) -> Result<(), String> {
    let mut buffer = Vec::new();
    stdin()
        .read_to_end(&mut buffer)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    output.audit_processing_start("stdin", None)?;
    search_chunk(&buffer, 0, None, options, specs, wildcard, output)?;
    output.mark_progress();
    output.audit_processing_finish()
}

fn search_chunk(
    chunk: &[u8],
    chunk_offset: u64,
    mut file: Option<&mut File>,
    options: &Options,
    specs: &mut [SearchSpec],
    wildcard: u8,
    output: &mut OutputWriter,
) -> Result<(), String> {
    let block_size = usize::try_from(options.block_size)
        .map_err(|error| format!("block size is not supported: {error}"))?;

    for spec in specs {
        let mut search_start = 0usize;
        while search_start < chunk.len() {
            let Some(header_index) =
                find_header(spec, chunk, search_start, options, block_size, wildcard)
            else {
                break;
            };
            let Some(recovery_index) = recovery_start_index(spec, header_index) else {
                search_start = header_index.saturating_add(spec.header.len().saturating_add(1));
                continue;
            };
            let absolute_offset = chunk_offset + recovery_index as u64;
            let window = &chunk[recovery_index..];

            if options.modes.indirect_block
                && let Some(indirect) = remove_indirect_block(window)
                && let Some(mut recovered) = recover(spec, &indirect.bytes, wildcard)
            {
                apply_indirect_block_recovery(&mut recovered, &indirect, options.modes.verbose);
                write_recovered(spec, &recovered, absolute_offset, output)?;
                search_start = recovery_index.saturating_add(recovered.next_index);
                continue;
            }

            let recovered = recover(spec, window, wildcard);
            if let Some(recovered) = recovered {
                write_recovered(spec, &recovered, absolute_offset, output)?;
                search_start = recovery_index.saturating_add(recovered.next_index);
                continue;
            }

            if let Some(input) = file.as_deref_mut()
                && let Some(bridge) =
                    bridge_window(input, absolute_offset, bridge_read_len(options, spec)?)?
            {
                if options.modes.indirect_block
                    && let Some(indirect) = remove_indirect_block(&bridge)
                    && let Some(mut recovered) = recover(spec, &indirect.bytes, wildcard)
                {
                    apply_indirect_block_recovery(&mut recovered, &indirect, options.modes.verbose);
                    write_recovered(spec, &recovered, absolute_offset, output)?;
                    search_start = recovery_index.saturating_add(recovered.next_index);
                    continue;
                }

                if let Some(recovered) = recover(spec, &bridge, wildcard) {
                    write_recovered(spec, &recovered, absolute_offset, output)?;
                    search_start = recovery_index.saturating_add(recovered.next_index);
                    continue;
                }
            }

            if options.modes.write_all {
                let max_len = usize::try_from(spec.max_len).unwrap_or(window.len());
                let len = window.len().min(max_len);
                output.write_recovered(
                    &spec.suffix,
                    &window[..len],
                    absolute_offset,
                    "(Header dump)",
                )?;
                spec.found += 1;
            }

            search_start = header_index.saturating_add(spec.header.len().saturating_add(1));
        }
    }

    Ok(())
}

fn apply_indirect_block_recovery(
    recovered: &mut Recovered<'_>,
    indirect: &IndirectBlock,
    verbose: bool,
) {
    if recovered.next_index > indirect.offset {
        recovered.next_index = recovered.next_index.saturating_add(indirect.block_size);
    }
    if verbose {
        write!(recovered.comment, " (IND BLK bs:={})", indirect.block_size)
            .expect("writing to a String should not fail");
    }
}

fn find_header(
    spec: &SearchSpec,
    chunk: &[u8],
    start: usize,
    options: &Options,
    block_size: usize,
    wildcard: u8,
) -> Option<usize> {
    if options.modes.quick {
        find_quick(
            &spec.header,
            chunk,
            start,
            block_size,
            spec.case_sensitive,
            wildcard,
        )
    } else {
        find_forward(&spec.header, chunk, start, spec.case_sensitive, wildcard)
    }
}

fn recovery_start_index(spec: &SearchSpec, header_index: usize) -> Option<usize> {
    if spec.kind == FileKind::Mov {
        header_index.checked_sub(4)
    } else {
        Some(header_index)
    }
}

fn looks_like_indirect_block(window: &[u8], block_size: usize) -> bool {
    let Some(offset) = block_size.checked_mul(12) else {
        return false;
    };
    let Some(end) = offset.checked_add(block_size) else {
        return false;
    };
    if window.len() < end {
        return false;
    }

    let entries = block_size / 4;
    if entries < 2 {
        return false;
    }

    let numbers = entries - 1;
    let mut index = 0usize;
    while index < numbers {
        let Some(block) = read_le_u32_at(window, offset + index * 4) else {
            return false;
        };
        if block == 0 {
            break;
        }

        index += 1;
        let Some(next_block) = read_le_u32_at(window, offset + index * 4) else {
            return false;
        };
        if next_block == 0 {
            break;
        }
        if block.checked_add(1) != Some(next_block) {
            return false;
        }
    }

    if index == 0 {
        return false;
    }

    for zero_index in index + 1..numbers {
        if read_le_u32_at(window, offset + zero_index * 4) != Some(0) {
            return false;
        }
    }

    true
}

fn read_le_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn remove_indirect_block(window: &[u8]) -> Option<IndirectBlock> {
    for block_size in INDIRECT_BLOCK_SIZES {
        if !looks_like_indirect_block(window, block_size) {
            continue;
        }

        let offset = block_size.checked_mul(12)?;
        let end = offset.checked_add(block_size)?;
        if window.len() <= end {
            continue;
        }

        let mut bytes = Vec::with_capacity(window.len() - block_size);
        bytes.extend_from_slice(window.get(..offset)?);
        bytes.extend_from_slice(window.get(end..)?);
        return Some(IndirectBlock {
            block_size,
            bytes,
            offset,
        });
    }

    None
}

fn selected_specs(
    options: &Options,
    mut config_specs: Vec<SearchSpec>,
) -> Result<Vec<SearchSpec>, String> {
    let mut specs = Vec::new();

    for selector in &options.type_selectors {
        let Some(mut selected) = builtins_for_selector(selector, None) else {
            return Err(format!("unknown file type selector `{selector}`"));
        };
        specs.append(&mut selected);
    }

    specs.append(&mut config_specs);
    Ok(specs)
}

fn write_recovered(
    spec: &mut SearchSpec,
    recovered: &Recovered<'_>,
    absolute_offset: u64,
    output: &mut OutputWriter,
) -> Result<(), String> {
    if !recovered.write {
        return Ok(());
    }

    output.write_recovered(
        &recovered.suffix,
        recovered.bytes,
        absolute_offset,
        &recovered.comment,
    )?;
    spec.found += 1;
    Ok(())
}
