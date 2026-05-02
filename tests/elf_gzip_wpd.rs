#[cfg(test)]
mod tests {
    #[cfg(feature = "gzip")]
    use std::io::Write as _;
    use std::{
        collections::BTreeMap,
        env::temp_dir,
        fs::{create_dir_all, read, read_dir, remove_dir_all, write},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(feature = "gzip")]
    use flate2::{Compression, write::GzEncoder};

    fn collect_output_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
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

    fn elf64_sample() -> Vec<u8> {
        let mut buf = vec![0; 384];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        buf[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());

        let phdr = 64;
        let file_len = buf.len() as u64;
        buf[phdr..phdr + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[phdr + 4..phdr + 8].copy_from_slice(&5u32.to_le_bytes());
        buf[phdr + 32..phdr + 40].copy_from_slice(&file_len.to_le_bytes());
        buf[phdr + 40..phdr + 48].copy_from_slice(&file_len.to_le_bytes());
        buf[120..].fill(0x7f);
        buf
    }

    #[cfg(feature = "gzip")]
    fn gzip_sample() -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"gzip payload").unwrap();
        encoder.finish().unwrap()
    }

    fn run_forsmost(input: &Path, output: &Path, selector: &str) {
        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", selector, "-o"])
            .arg(output)
            .arg(input)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn unique_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        temp_dir().join(format!("forsmost-{name}-{nonce}"))
    }

    fn wpd_sample(byte: u8) -> Vec<u8> {
        let mut buf = vec![byte; 64];
        buf[0..4].copy_from_slice(b"\xffWPC");
        buf[4..8].copy_from_slice(&16u32.to_le_bytes());
        buf[8] = 1;
        buf[9] = 10;
        buf
    }

    #[test]
    fn recovers_elf_by_program_header_extent() {
        let root = unique_dir("elf");
        create_dir_all(&root).unwrap();
        let input = root.join("elf.bin");
        let output = root.join("out");
        let invalid = b"\x7fELF\x09\x01\x01\0invalid";
        let sample = elf64_sample();
        let mut payload = invalid.to_vec();
        payload.extend_from_slice(b"noise");
        payload.extend_from_slice(&sample);
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "elf");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &sample);
        assert!(files.keys().next().unwrap().starts_with("elf/"));
        remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn recovers_gzip_by_valid_member_end() {
        let root = unique_dir("gzip");
        create_dir_all(&root).unwrap();
        let input = root.join("gzip.bin");
        let output = root.join("out");
        let sample = gzip_sample();
        let mut payload = b"\x1f\x8b\x07invalid".to_vec();
        payload.extend_from_slice(b"noise");
        payload.extend_from_slice(&sample);
        payload.extend_from_slice(b"tail");
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "gzip");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &sample);
        assert!(files.keys().next().unwrap().starts_with("gz/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_wpd_with_next_header_boundary() {
        let root = unique_dir("wpd");
        create_dir_all(&root).unwrap();
        let input = root.join("wpd.bin");
        let output = root.join("out");
        let first = wpd_sample(0x41);
        let second = wpd_sample(0x42);
        let mut payload = first.clone();
        payload.extend_from_slice(&second);
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "wpd");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 2);
        let recovered = files.values().collect::<Vec<_>>();
        assert!(recovered.contains(&&first));
        assert!(recovered.contains(&&second));
        remove_dir_all(root).unwrap();
    }
}
