#[cfg(test)]
#[path = "support/zip_ole_mp4.rs"]
mod support;

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, read, remove_dir_all, write};

    use super::support::*;

    #[test]
    fn recovers_mp4_large_size_and_uuid_boxes() {
        let root = unique_dir("mp4-large-size");
        create_dir_all(&root).unwrap();
        let input = root.join("mp4.bin");
        let output = root.join("out");
        let sample = mp4_large_size_uuid_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "mp4");

        assert_eq!(
            read(output.join("mp4").join("00000000.mp4")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_fragmented_mp4_and_stops_before_unknown_box() {
        let root = unique_dir("mp4-fragmented");
        create_dir_all(&root).unwrap();
        let input = root.join("mp4.bin");
        let output = root.join("out");
        let sample = fragmented_mp4_sample();
        let payload = mp4_with_unknown_printable_box_tail_sample();
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "mp4");

        assert_eq!(
            read(output.join("mp4").join("00000000.mp4")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_invalid_mp4_ftyp_before_valid_mp4() {
        let root = unique_dir("mp4-invalid-ftyp");
        create_dir_all(&root).unwrap();
        let input = root.join("mp4.bin");
        let output = root.join("out");
        let sample = fragmented_mp4_sample();
        write(&input, invalid_then_valid_mp4_sample()).unwrap();

        run_forsmost(&input, &output, "mp4");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(files.values().next().unwrap(), &sample);
        assert!(files.keys().next().unwrap().starts_with("mp4/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_mp4_with_variable_ftyp_box_size() {
        let root = unique_dir("mp4-variable-ftyp");
        create_dir_all(&root).unwrap();
        let input = root.join("mp4.bin");
        let output = root.join("out");
        let sample = mp4_variable_ftyp_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "mp4");

        assert_eq!(
            read(output.join("mp4").join("00000000.mp4")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_openoffice_mimetype_for_typed_selector() {
        let root = unique_dir("sxw-selector");
        create_dir_all(&root).unwrap();
        let input = root.join("sxw.bin");
        let output = root.join("out");
        let sample = openoffice_writer_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "sxw");

        assert_eq!(
            read(output.join("sxw").join("00000000.sxw")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip64_local_header_size_from_extra() {
        let root = unique_dir("zip64");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip64_local_header_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "zip");

        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip64_eocd_locator() {
        let root = unique_dir("zip64-eocd");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip64_eocd_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "zip");

        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip64_central_directory_size_when_local_extra_missing() {
        let root = unique_dir("zip64-central-size");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip64_central_directory_size_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "zip");

        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip_data_descriptor_after_fake_payload_eocd() {
        let root = unique_dir("zip-fake-eocd");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip_data_descriptor_fake_eocd_payload_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "zip");

        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip_data_descriptor_after_fake_multidisk_eocd_payload() {
        let root = unique_dir("zip-fake-multidisk-eocd");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip_data_descriptor_fake_multidisk_eocd_payload_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "zip");

        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_zip_data_descriptor_after_fake_short_central_directory() {
        let root = unique_dir("zip-fake-short-central");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let sample = zip_data_descriptor_fake_short_central_directory_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "zip");

        assert_eq!(
            read(output.join("zip").join("00000000.zip")).unwrap(),
            sample
        );
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_split_zip_before_valid_zip() {
        let root = unique_dir("zip-split");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let (sample, valid) = split_zip_then_valid_zip_sample();
        write(&input, sample).unwrap();

        run_forsmost(&input, &output, "zip");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &valid);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_split_zip64_before_valid_zip() {
        let root = unique_dir("zip64-split");
        create_dir_all(&root).unwrap();
        let input = root.join("zip.bin");
        let output = root.join("out");
        let (sample, valid) = split_zip64_then_valid_zip_sample();
        write(&input, sample).unwrap();

        run_forsmost(&input, &output, "zip");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &valid);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_invalid_ole_header_before_valid_cfb() {
        let root = unique_dir("ole-invalid");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let valid = cfb_doc_sample();
        let mut payload = invalid_cfb_header();
        payload.extend_from_slice(b"noise");
        payload.extend_from_slice(&valid);
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "ole");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &valid);
        assert!(files.keys().next().unwrap().starts_with("doc/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_ole_with_difat_fat_sector_list() {
        let root = unique_dir("ole-difat");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let sample = cfb_difat_doc_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "ole");

        let recovered = read(output.join("doc").join("00000000.doc")).unwrap();
        assert_recovered_bytes(&recovered, &sample);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_ole_with_4096_byte_sector_size() {
        let root = unique_dir("ole-sector-4096");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let sample = cfb_4096_sector_doc_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "ole");

        let recovered = read(output.join("doc").join("00000000.doc")).unwrap();
        assert_recovered_bytes(&recovered, &sample);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_ole_fragmented_stream_chain() {
        let root = unique_dir("ole-fragmented");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let sample = cfb_fragmented_stream_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "ole");

        let recovered = read(output.join("doc").join("00000000.doc")).unwrap();
        assert_recovered_bytes(&recovered, &sample);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_truncated_ole_regular_stream_before_valid_cfb() {
        let root = unique_dir("ole-regular-stream-truncated");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let valid = cfb_fragmented_stream_sample();
        let mut payload = cfb_truncated_regular_stream_sample();
        payload.extend_from_slice(b"noise-before-valid-ole");
        payload.extend_from_slice(&valid);
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "ole");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_recovered_bytes(files.values().next().unwrap(), &valid);
        assert!(files.keys().next().unwrap().starts_with("doc/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_ole_mini_stream_root_chain() {
        let root = unique_dir("ole-mini-stream");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let sample = cfb_mini_stream_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "ole");

        let recovered = read(output.join("doc").join("00000000.doc")).unwrap();
        assert_recovered_bytes(&recovered, &sample);
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_truncated_ole_mini_stream_before_valid_cfb() {
        let root = unique_dir("ole-mini-stream-truncated");
        create_dir_all(&root).unwrap();
        let input = root.join("ole.bin");
        let output = root.join("out");
        let valid = cfb_mini_stream_sample();
        let mut payload = cfb_truncated_mini_stream_sample();
        payload.extend_from_slice(b"noise-before-valid-ole");
        payload.extend_from_slice(&valid);
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "ole");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_recovered_bytes(files.values().next().unwrap(), &valid);
        assert!(files.keys().next().unwrap().starts_with("doc/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn typed_zip_selector_requires_detected_office_family() {
        let root = unique_dir("docx-selector");
        create_dir_all(&root).unwrap();
        let input = root.join("docx.bin");
        let output = root.join("out");
        let plain = plain_zip_sample();
        let docx = zip_docx_sample();
        let mut payload = plain;
        payload.extend_from_slice(b"noise");
        payload.extend_from_slice(&docx);
        write(&input, payload).unwrap();

        run_forsmost(&input, &output, "docx");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &docx);
        assert!(files.keys().next().unwrap().starts_with("docx/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_docx_when_content_types_appears_after_document_entry() {
        let root = unique_dir("docx-reordered");
        create_dir_all(&root).unwrap();
        let input = root.join("docx.bin");
        let output = root.join("out");
        let sample = zip_docx_reordered_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "docx");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &sample);
        assert!(files.keys().next().unwrap().starts_with("docx/"));
        remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_pptx_from_presentation_part_without_slide_entry() {
        let root = unique_dir("pptx-presentation");
        create_dir_all(&root).unwrap();
        let input = root.join("pptx.bin");
        let output = root.join("out");
        let sample = zip_pptx_presentation_sample();
        write(&input, &sample).unwrap();

        run_forsmost(&input, &output, "pptx");

        let files = collect_output_files(&output);
        assert_eq!(files.len(), 1);
        assert_eq!(files.values().next().unwrap(), &sample);
        assert!(files.keys().next().unwrap().starts_with("pptx/"));
        remove_dir_all(root).unwrap();
    }
}
