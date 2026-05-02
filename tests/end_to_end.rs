#[cfg(test)]
#[path = "support/end_to_end.rs"]
mod support;

#[cfg(test)]
mod tests {
    use std::{
        fs::{create_dir_all, read, read_to_string, remove_dir_all, write},
        process::Command,
    };

    use super::support::*;

    #[test]
    fn custom_config_decodes_escapes() {
        let root = unique_dir("config");
        create_dir_all(&root).unwrap();
        let input = root.join("image.bin");
        let config = root.join("foremost.conf");
        let output = root.join("out");
        write(&input, b"xxOS CCIzzENDtail").unwrap();
        write(&config, r"bin y 64 \x4f\123\sCCI END").unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-c"])
            .arg(&config)
            .args(["-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("bin").join("00000000.bin")).unwrap(),
            b"OS CCIzzEND"
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_cpp_after_include_sanity_check() {
        let root = unique_dir("cpp");
        create_dir_all(&root).unwrap();
        let input = root.join("source.bin");
        let output = root.join("out");
        let sample = b"#include <stdio.h>\nint main(void) { char c = 0; return c; }\n";
        write(&input, sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "cpp", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("cpp").join("00000000.cpp")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_bmp_after_c_sanity_checks() {
        let root = unique_dir("bmp");
        create_dir_all(&root).unwrap();
        let input = root.join("bmp.bin");
        let output = root.join("out");
        let invalid = bmp_sample(16, 3001);
        let valid = bmp_sample(16, 12);
        let mut payload = invalid;
        payload.extend_from_slice(b"noise");
        payload.extend_from_slice(&valid);
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "bmp", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("bmp").join("00000000.bmp")).unwrap(),
            valid
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_top_down_bmp() {
        let root = unique_dir("bmp-top-down");
        create_dir_all(&root).unwrap();
        let input = root.join("bmp.bin");
        let output = root.join("out");
        let sample = bmp_sample(16, -12);
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "bmp", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("bmp").join("00000000.bmp")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_bmp_with_indirect_block_detection() {
        let root = unique_dir("bmp-indirect");
        create_dir_all(&root).unwrap();
        let input = root.join("bmp.bin");
        let direct_output = root.join("direct");
        let indirect_output = root.join("indirect");
        let logical = bmp_sample_with_size(13 * 512);
        let physical = insert_indirect_block(&logical, 512);
        write(&input, physical).unwrap();

        let direct_status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "bmp", "-o"])
            .arg(&direct_output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(direct_status.success());
        assert_ne!(
            read(direct_output.join("bmp").join("00000000.bmp")).unwrap(),
            logical
        );

        let indirect_status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-d", "-t", "bmp", "-o"])
            .arg(&indirect_output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(indirect_status.success());
        assert_eq!(
            read(indirect_output.join("bmp").join("00000000.bmp")).unwrap(),
            logical
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_doc_from_ole_cfb_directory() {
        let root = unique_dir("ole");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let sample = cfb_doc_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "ole", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("doc").join("00000000.doc")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_access_cfb_directory_with_mdb_suffix() {
        let root = unique_dir("mdb");
        create_dir_all(&root).unwrap();
        let input = root.join("mdb.bin");
        let output = root.join("out");
        let sample = cfb_access_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "ole", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("mdb").join("00000000.mdb")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_dll_with_dll_suffix_from_exe_selector() {
        let root = unique_dir("exe");
        create_dir_all(&root).unwrap();
        let input = root.join("dll.bin");
        let output = root.join("out");
        let sample = exe_sample(0x2000);
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "exe", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("dll").join("00000000.dll")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_html_after_ascii_probe() {
        let root = unique_dir("html");
        create_dir_all(&root).unwrap();
        let input = root.join("html.bin");
        let output = root.join("out");
        let sample = b"<html><body>hello sample text</body></html>";
        let mut payload = b"<html\0not text</html>noise".to_vec();
        payload.extend_from_slice(sample);
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "html", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("htm").join("00000000.htm")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_jpeg_from_input_file() {
        let root = unique_dir("jpg");
        create_dir_all(&root).unwrap();
        let input = root.join("image.bin");
        let output = root.join("out");
        let sample = jpeg_sample();
        let mut payload = b"noise".to_vec();
        payload.extend_from_slice(&sample);
        payload.extend_from_slice(b"tail");
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "jpg", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("jpg").join("00000000.jpg")).unwrap(),
            sample
        );
        let audit = read_to_string(output.join("audit.txt")).unwrap();
        assert!(audit.contains("jpg:= 1"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_jpeg_with_app2_first_segment() {
        let root = unique_dir("jpg-app2");
        create_dir_all(&root).unwrap();
        let input = root.join("image.bin");
        let output = root.join("out");
        let sample = jpeg_app2_first_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "jpg", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("jpg").join("00000000.jpg")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_mov_from_moov_atom_start() {
        let root = unique_dir("mov");
        create_dir_all(&root).unwrap();
        let input = root.join("mov.bin");
        let output = root.join("out");
        let sample = mov_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "mov", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("mov").join("00000000.mov")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_mov_after_invalid_atom_probe() {
        let root = unique_dir("mov-invalid");
        create_dir_all(&root).unwrap();
        let input = root.join("mov.bin");
        let output = root.join("out");
        let payload = mov_invalid_then_valid_sample();
        let valid = mov_sample();
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "mov", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("mov").join("00000000.mov")).unwrap(),
            valid
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_corpus_preserves_offsets_sizes_and_counts() {
        let root = unique_dir("mixed");
        create_dir_all(&root).unwrap();
        let input = root.join("mixed.bin");
        let output = root.join("out");

        let jpg = jpeg_sample();
        let pdf = pdf_sample();
        let png = png_sample(20, 12);
        let zip = zip_docx_sample();
        let dll = exe_sample(0x2000);
        let html = b"<html><body>mixed corpus html</body></html>".to_vec();
        let cpp = b"#include <stdio.h>\nint main(void) { char c = 1; return c; }\n".to_vec();
        let reg = registry_sample();

        let cases: Vec<(&str, &str, usize, &Vec<u8>, usize)> = vec![
            ("jpg", "jpg", 17, &jpg, jpg.len()),
            ("pdf", "pdf", 307, &pdf, pdf.len() - 4),
            ("png", "png", 913, &png, png.len()),
            ("docx", "docx", 1301, &zip, zip.len()),
            ("dll", "dll", 1909, &dll, dll.len()),
            ("htm", "htm", 3011, &html, html.len()),
            ("cpp", "cpp", 3517, &cpp, cpp.len()),
            ("reg", "reg", 4099, &reg, reg.len()),
        ];

        let mut payload = Vec::new();
        for (_, _, offset, data, _) in &cases {
            append_at(&mut payload, *offset, data);
        }
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args([
                "-Q",
                "-b",
                "1",
                "-t",
                "jpg,pdf,png,zip,exe,html,cpp,reg",
                "-o",
            ])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        for (directory, suffix, offset, data, expected_len) in cases {
            let name = format!("{offset:08}.{suffix}");
            let recovered = read(output.join(directory).join(&name)).unwrap();
            assert_eq!(recovered, data[..expected_len]);
        }

        let audit = read_to_string(output.join("audit.txt")).unwrap();
        assert!(audit.contains("8 FILES EXTRACTED"));
        for count in [
            "jpg:= 1", "pdf:= 1", "png:= 1", "zip:= 1", "exe:= 1", "htm:= 1", "cpp:= 1", "reg:= 1",
        ] {
            assert!(
                audit.contains(count),
                "missing audit count {count}:\n{audit}"
            );
        }
        for (_, suffix, offset, _, _) in [
            ("jpg", "jpg", 17, &jpg, jpg.len()),
            ("pdf", "pdf", 307, &pdf, pdf.len() - 4),
            ("png", "png", 913, &png, png.len()),
            ("docx", "docx", 1301, &zip, zip.len()),
            ("dll", "dll", 1909, &dll, dll.len()),
            ("htm", "htm", 3011, &html, html.len()),
            ("cpp", "cpp", 3517, &cpp, cpp.len()),
            ("reg", "reg", 4099, &reg, reg.len()),
        ] {
            assert_audit_has_offset(&audit, &format!("{offset:08}.{suffix}"), offset);
        }
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_mpeg_by_walking_packs() {
        let root = unique_dir("mpg");
        create_dir_all(&root).unwrap();
        let input = root.join("mpeg.bin");
        let output = root.join("out");
        let sample = mpeg_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "mpg", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("mpg").join("00000000.mpg")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_riff_family_with_detected_suffixes() {
        let root = unique_dir("riff");
        create_dir_all(&root).unwrap();
        let input = root.join("riff.bin");
        let output = root.join("out");
        let avi = riff_avi_sample();
        let wav = riff_wav_sample();
        let mut payload = Vec::new();
        append_at(&mut payload, 17, &avi);
        append_at(&mut payload, 151, &wav);
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-b", "1", "-t", "rif", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(read(output.join("avi").join("00000017.avi")).unwrap(), avi);
        assert_eq!(read(output.join("wav").join("00000151.wav")).unwrap(), wav);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_mp4_by_walking_boxes() {
        let root = unique_dir("mp4");
        create_dir_all(&root).unwrap();
        let input = root.join("mp4.bin");
        let output = root.join("out");
        let sample = mp4_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "mp4", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("mp4").join("00000000.mp4")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_pdf_after_eof_marker() {
        let root = unique_dir("pdf");
        create_dir_all(&root).unwrap();
        let input = root.join("pdf.bin");
        let output = root.join("out");
        let sample = pdf_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "pdf", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("pdf").join("00000000.pdf")).unwrap(),
            sample[..sample.len() - 4]
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_png_by_validating_dimensions_and_chunks() {
        let root = unique_dir("png");
        create_dir_all(&root).unwrap();
        let input = root.join("png.bin");
        let output = root.join("out");
        let invalid = png_sample(4001, 10);
        let valid = png_sample(32, 24);
        let mut payload = invalid;
        payload.extend_from_slice(b"noise");
        payload.extend_from_slice(&valid);
        write(&input, payload).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "png", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("png").join("00000000.png")).unwrap(),
            valid
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_png_with_c_printable_chunk_heuristic() {
        let root = unique_dir("png-printable");
        create_dir_all(&root).unwrap();
        let input = root.join("png.bin");
        let output = root.join("out");
        let sample = png_printable_non_alpha_chunk_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "png", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("png").join("00000000.png")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_rar_by_block_headers() {
        let root = unique_dir("rar");
        create_dir_all(&root).unwrap();
        let input = root.join("rar.bin");
        let output = root.join("out");
        let sample = rar_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "rar", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("rar").join("00000000.rar")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_rar_encrypted_header_fallback() {
        let root = unique_dir("rar-encrypted");
        create_dir_all(&root).unwrap();
        let input = root.join("rar.bin");
        let output = root.join("out");
        let sample = rar_encrypted_header_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "rar", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("rar").join("00000000.rar")).unwrap(),
            sample[..sample.len() - 8]
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_registry_by_size_field() {
        let root = unique_dir("reg");
        create_dir_all(&root).unwrap();
        let input = root.join("reg.bin");
        let output = root.join("out");
        let sample = registry_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "reg", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("reg").join("00000000.reg")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_wmv_by_asf_file_properties_size() {
        let root = unique_dir("wmv");
        create_dir_all(&root).unwrap();
        let input = root.join("wmv.bin");
        let output = root.join("out");
        let sample = wmv_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "wmv", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("wmv").join("00000000.wmv")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip_family_into_detected_office_suffix() {
        let root = unique_dir("zip");
        create_dir_all(&root).unwrap();
        let input = root.join("docx.bin");
        let output = root.join("out");
        let sample = zip_docx_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "zip", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("docx").join("00000000.docx")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip_data_descriptor_after_filename_footer_bytes() {
        let root = unique_dir("zip-descriptor");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip_data_descriptor_sample();
        write(&input, &sample).unwrap();

        let status = Command::new(env!("CARGO_BIN_EXE_forsmost"))
            .args(["-Q", "-t", "zip", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }
}
