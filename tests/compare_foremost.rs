#[cfg(test)]
#[path = "support/compare_foremost.rs"]
mod support;

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs::{create_dir_all, remove_dir_all, write},
    };

    use super::support::*;

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_generated_corpus_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("corpus.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        write(&input, generated_corpus()).unwrap();

        run_forsmost(&input, &rust_output, EXACT_SELECTORS);
        run_original_foremost(&runner, &input, &foremost_output, EXACT_SELECTORS);

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        assert!(!rust_files.is_empty());
        assert_output_files_eq(&rust_files, &foremost_files);
        assert_eq!(audit_counts(&rust_output), audit_counts(&foremost_output));
        assert_eq!(audit_names(&rust_output), audit_names(&foremost_output));

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_bmp_and_gif_edges_with_original_foremost() {
        let mut payload = Vec::new();
        append_at(&mut payload, 11, &bmp_sample(16, 12));
        append_at(&mut payload, 211, &gif_sample());

        compare_payload_files_with_original("foremost-media-edges", "bmp,gif", payload);
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_bmp_top_down_gap_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-bmp-top-down-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("bmp.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = bmp_sample(16, -12);
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "bmp");
        run_original_foremost(&runner, &input, &foremost_output, "bmp");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        assert_eq!(rust_name, "bmp/00000000.bmp");
        assert_eq!(rust_bytes, sample.as_slice());
        assert!(
            foremost_files.is_empty(),
            "Foremost 1.5.7 unexpectedly recovered top-down BMP files: {:?}",
            output_file_summary(&foremost_files)
        );
        assert_eq!(
            audit_counts(&rust_output),
            BTreeMap::from([("bmp".to_owned(), 1)])
        );
        assert!(audit_counts(&foremost_output).is_empty());

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_jpeg_app2_first_marker_gap_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-jpeg-app2-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("jpg.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = jpeg_app2_first_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "jpg");
        run_original_foremost(&runner, &input, &foremost_output, "jpg");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        assert_eq!(rust_name, "jpg/00000000.jpg");
        assert_eq!(rust_bytes, sample);
        assert!(
            foremost_files.is_empty(),
            "Foremost 1.5.7 unexpectedly recovered APP2-first JPEG: {:?}",
            output_file_summary(&foremost_files)
        );
        assert_eq!(
            audit_counts(&rust_output),
            BTreeMap::from([("jpg".to_owned(), 1)])
        );

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_riff_chunk_size_bug_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-riff-size-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("riff.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = riff_avi_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "avi");
        run_original_foremost(&runner, &input, &foremost_output, "avi");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        let (foremost_name, foremost_bytes) = only_output_file(&foremost_files);
        assert_eq!(rust_name, "avi/00000000.avi");
        assert_eq!(rust_bytes, sample);
        assert_eq!(foremost_name, "avi/00000000.avi");
        assert_eq!(foremost_bytes, &sample[..sample.len() - 8]);
        assert_eq!(
            audit_counts(&rust_output),
            BTreeMap::from([("avi".to_owned(), 1)])
        );
        assert_eq!(
            audit_counts(&foremost_output),
            BTreeMap::from([("avi".to_owned(), 1)])
        );

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_png_printable_non_alpha_chunk_with_original_foremost() {
        let mut payload = Vec::new();
        append_at(&mut payload, 17, &png_printable_non_alpha_chunk_sample());

        compare_payload_with_original("foremost-png-edge", "png", payload);
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_ole_payload_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-ole-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        write(&input, cfb_doc_sample()).unwrap();

        run_forsmost(&input, &rust_output, "ole");
        run_original_foremost(&runner, &input, &foremost_output, "ole");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (_, rust_bytes) = only_output_file(&rust_files);
        let (_, foremost_bytes) = only_output_file(&foremost_files);
        assert_eq!(rust_bytes, foremost_bytes);
        assert_eq!(audit_counts(&rust_output), audit_counts(&foremost_output));

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_ole_access_suffix_typo_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-ole-access-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = cfb_access_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "ole");
        run_original_foremost(&runner, &input, &foremost_output, "ole");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        let (foremost_name, foremost_bytes) = only_output_file(&foremost_files);
        assert_eq!(rust_name, "mdb/00000000.mdb");
        assert_eq!(rust_bytes, sample.as_slice());
        assert_eq!(foremost_name, "mbd/00000000.mbd");
        assert_eq!(foremost_bytes, sample.as_slice());
        assert_eq!(audit_counts(&rust_output), audit_counts(&foremost_output));

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_ole_4096_sector_gap_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-ole-sector-4096-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = cfb_4096_sector_doc_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "ole");
        run_original_foremost(&runner, &input, &foremost_output, "ole");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        assert_eq!(rust_name, "doc/00000000.doc");
        assert_eq!(rust_bytes, sample.as_slice());
        assert!(
            foremost_files.is_empty(),
            "Foremost 1.5.7 unexpectedly recovered 4096-sector OLE files: {:?}",
            output_file_summary(&foremost_files)
        );
        assert_eq!(
            audit_counts(&rust_output),
            BTreeMap::from([("ole".to_owned(), 1)])
        );
        assert!(audit_counts(&foremost_output).is_empty());

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_zip_descriptor_and_invalid_name_with_original_foremost() {
        let mut payload = Vec::new();
        append_at(&mut payload, 7, &zip_data_descriptor_sample());
        append_at(&mut payload, 307, &zip_oversized_filename_sample());

        compare_payload_with_original("foremost-zip-edges", "zip", payload);
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_zip_office2007_entry_order_gap_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-zip-office-order-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("office.zip");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = zip_docx_reordered_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "zip");
        run_original_foremost(&runner, &input, &foremost_output, "zip");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        let (foremost_name, foremost_bytes) = only_output_file(&foremost_files);
        assert_eq!(rust_name, "docx/00000000.docx");
        assert_eq!(rust_bytes, sample.as_slice());
        assert_eq!(foremost_name, "zip/00000000.zip");
        assert_eq!(foremost_bytes, sample.as_slice());
        assert_eq!(audit_counts(&rust_output), audit_counts(&foremost_output));

        remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_rar_encrypted_header_with_original_foremost() {
        compare_payload_with_original("foremost-rar-edge", "rar", rar_encrypted_header_sample());
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_mov_invalid_atom_then_valid_with_original_foremost() {
        compare_payload_with_original("foremost-mov-edge", "mov", mov_invalid_then_valid_sample());
    }

    #[test]
    #[ignore = "requires FOREMOST_BIN or FOREMOST_WSL_BIN pointing to an original foremost executable"]
    fn compare_registry_dispatch_gap_with_original_foremost() {
        let Some(runner) = foremost_runner() else {
            eprintln!("set FOREMOST_BIN or FOREMOST_WSL_BIN to run this comparison");
            return;
        };

        let root = runner.unique_root("foremost-reg-compare");
        create_dir_all(&root).unwrap();
        let input = root.join("reg.bin");
        let rust_output = root.join("rust");
        let foremost_output = root.join("foremost");
        let sample = registry_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &rust_output, "reg");
        run_original_foremost(&runner, &input, &foremost_output, "reg");

        let rust_files = collect_output_files(&rust_output);
        let foremost_files = collect_output_files(&foremost_output);
        let (rust_name, rust_bytes) = only_output_file(&rust_files);
        assert_eq!(rust_name, "reg/00000000.reg");
        assert_eq!(rust_bytes, sample.as_slice());
        assert!(
            foremost_files.is_empty(),
            "Foremost 1.5.7 unexpectedly recovered registry files: {:?}",
            output_file_summary(&foremost_files)
        );
        assert_eq!(
            audit_counts(&rust_output),
            BTreeMap::from([("reg".to_owned(), 1)])
        );
        assert!(audit_counts(&foremost_output).is_empty());

        remove_dir_all(root).unwrap();
    }
}
