//! Reproducible benchmark harness for ZARC (`.zarc`) v1.0.
//!
//! Run with:
//! `cargo run --release -p znf-zarc --example zarc_bench`

use std::time::Instant;
use znf_compression::Config as CompConfig;
use znf_core::Limits;
use znf_zarc::{inspect_archive, ReadOptions, WriteOptions, ZarcArchive, ZarcWriter};

fn make_workload() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    // 1. Source-code/text files (32 files x 16 KiB = 512 KiB)
    let sample_line =
        b"pub fn process_record(id: u64, payload: &[u8]) -> Result<usize, ZarcError> { Ok(payload.len()) }\n";
    for i in 0..32 {
        let mut buf = Vec::with_capacity(16 * 1024);
        while buf.len() < 16 * 1024 {
            buf.extend_from_slice(sample_line);
        }
        buf.truncate(16 * 1024);
        files.push((format!("src/module_{i:02}.rs"), buf));
    }
    // 2. Structured JSON/log files (16 files x 32 KiB = 512 KiB)
    let json_chunk =
        b"{\"timestamp\":1700000000,\"level\":\"INFO\",\"service\":\"znf-zarc\",\"status\":200}\n";
    for i in 0..16 {
        let mut buf = Vec::with_capacity(32 * 1024);
        while buf.len() < 32 * 1024 {
            buf.extend_from_slice(json_chunk);
        }
        buf.truncate(32 * 1024);
        files.push((format!("logs/events_{i:02}.jsonl"), buf));
    }
    // 3. Mixed binary asset data (8 files x 64 KiB = 512 KiB)
    for i in 0..8 {
        let mut buf = Vec::with_capacity(64 * 1024);
        for b in 0..(64 * 1024) {
            buf.push(((b * 31 + i * 17) & 0xFF) as u8);
        }
        files.push((format!("assets/blob_{i:02}.bin"), buf));
    }
    files
}

fn bench_mode(name: &str, comp: CompConfig, workload: &[(String, Vec<u8>)]) {
    let total_uncompressed: usize = workload.iter().map(|(_, d)| d.len()).sum();

    // Creation benchmark
    let t0 = Instant::now();
    let mut writer = ZarcWriter::new(WriteOptions {
        compression: comp,
        comment: Some("benchmark workload".into()),
        ..WriteOptions::default()
    });
    for (path, data) in workload {
        writer.add_bytes(path, data, 0o644, 1_700_000_000).unwrap();
    }
    let mut archive_bytes = Vec::with_capacity(total_uncompressed);
    writer.finish(&mut archive_bytes).unwrap();
    let create_dur = t0.elapsed();

    // Inspection / listing benchmark
    let t1 = Instant::now();
    let insp = inspect_archive(&archive_bytes, None, &Limits::default()).unwrap();
    let inspect_dur = t1.elapsed();
    assert_eq!(insp.entries.len(), workload.len());

    // Verification benchmark
    let t2 = Instant::now();
    let arch = ZarcArchive::open(&archive_bytes, ReadOptions::default()).unwrap();
    arch.verify_all().unwrap();
    let verify_dur = t2.elapsed();

    // Extraction (in-memory read_entry_bytes across all entries) benchmark
    let t3 = Instant::now();
    let mut extracted_bytes = 0usize;
    for entry in arch.entries() {
        let out = arch.read_entry_bytes(entry).unwrap();
        extracted_bytes += out.len();
    }
    let extract_dur = t3.elapsed();
    assert_eq!(extracted_bytes, total_uncompressed);

    let stats = arch.compression_stats();
    let mb = (total_uncompressed as f64) / (1024.0 * 1024.0);
    let create_mb_s = mb / create_dur.as_secs_f64();
    let verify_mb_s = mb / verify_dur.as_secs_f64();
    let extract_mb_s = mb / extract_dur.as_secs_f64();

    println!(
        "| {:<10} | {:>10} B | {:>10} B | {:>6.2}:1 | {:>8.1} MiB/s | {:>8.2} us | {:>8.1} MiB/s | {:>8.1} MiB/s |",
        name,
        total_uncompressed,
        archive_bytes.len(),
        stats.ratio(),
        create_mb_s,
        inspect_dur.as_secs_f64() * 1_000_000.0,
        verify_mb_s,
        extract_mb_s,
    );
}

fn main() {
    let workload = make_workload();
    println!("ZARC v1.0 Reproducible Benchmark Suite (56 files, 1.50 MiB mixed corpus)");
    println!(
        "| {:<10} | {:>12} | {:>12} | {:>8} | {:>14} | {:>11} | {:>14} | {:>14} |",
        "Mode",
        "Input Size",
        "Archive Size",
        "Ratio",
        "Create Speed",
        "List/Insp",
        "Verify Speed",
        "Extract Speed"
    );
    println!("|------------|--------------|--------------|----------|----------------|-------------|----------------|----------------|");
    bench_mode("Store", CompConfig::stored(), &workload);
    bench_mode("LZ4", CompConfig::lz4(), &workload);
    bench_mode("Zstd-1", CompConfig::zstd(1), &workload);
    bench_mode("Zstd-3", CompConfig::zstd(3), &workload);
    bench_mode("Zstd-9", CompConfig::zstd(9), &workload);
}
