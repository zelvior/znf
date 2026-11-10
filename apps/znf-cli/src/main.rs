//! `znf` — Command-line tool for ZNF Core containers and `.zarc` archives.
//!
//! Zero telemetry, zero network calls, deterministic binary output.
//! Diagnostic output never exposes secret keys, passwords, or sensitive metadata values.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};
use znf_compression::{Algorithm, Config as CompConfig};
use znf_core::{
    EncryptionKeySource, FormatId, ZnfCompression, ZnfMetadata, ZnfReader, ZnfValidator, ZnfWriter,
    CORE_SPEC_VERSION, HEADER_LEN,
};
use znf_zarc::{
    attempt_parity_repair, EntryKind, ReadOptions, WriteOptions, ZarcArchive, ZarcError,
    ZarcWriter, ZARC_SPEC_VERSION,
};

const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

fn build_cli() -> Command {
    Command::new("znf")
        .version(VERSION_STR)
        .about("Zelvior Native Format (ZNF) Core & ZARC (.zarc) CLI")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("inspect")
                .about("Inspect any ZNF container header, version, flags, compression, encryption, and integrity")
                .arg(
                    Arg::new("file")
                        .value_name("CONTAINER")
                        .required(true)
                        .help("Path to ZNF container (.znf, .zarc, etc.)"),
                ),
        )
        .subcommand(
            Command::new("validate")
                .about("Validate ZNF container structure, section boundaries, and pre-footer integrity")
                .arg(
                    Arg::new("file")
                        .value_name("CONTAINER")
                        .required(true)
                        .help("Path to ZNF container"),
                ),
        )
        .subcommand(
            Command::new("container")
                .about("Create, unpack, inspect, validate, and verify ZNF Core (.znf) containers")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("pack")
                        .about("Pack a file into a ZNF Core (.znf) container")
                        .arg(
                            Arg::new("input")
                                .short('i')
                                .long("input")
                                .value_name("FILE")
                                .required(true)
                                .help("Input payload file"),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_name("FILE.znf")
                                .required(true)
                                .help("Output .znf container path"),
                        )
                        .arg(
                            Arg::new("compression")
                                .short('c')
                                .long("compression")
                                .value_name("ALGO")
                                .default_value("zstd")
                                .help("Compression algorithm: zstd, lz4, or store"),
                        )
                        .arg(
                            Arg::new("level")
                                .short('l')
                                .long("level")
                                .value_name("1..22")
                                .default_value("3")
                                .help("Zstandard compression level (1..22)"),
                        )
                        .arg(
                            Arg::new("streaming")
                                .long("streaming")
                                .action(ArgAction::SetTrue)
                                .help("Use bounded-memory chunked streaming mode"),
                        )
                        .arg(
                            Arg::new("encrypt")
                                .short('e')
                                .long("encrypt")
                                .action(ArgAction::SetTrue)
                                .help("Encrypt payload with XChaCha20-Poly1305 + Argon2id"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read encryption password from environment variable"),
                        )
                        .arg(
                            Arg::new("comment")
                                .long("comment")
                                .value_name("TEXT")
                                .help("Optional UTF-8 comment"),
                        ),
                )
                .subcommand(
                    Command::new("unpack")
                        .about("Verify, decrypt, and unpack a ZNF Core (.znf) container to a file")
                        .arg(
                            Arg::new("input")
                                .short('i')
                                .long("input")
                                .value_name("FILE.znf")
                                .required(true)
                                .help("Input .znf container"),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_name("FILE")
                                .required(true)
                                .help("Output payload path"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read decryption password from environment variable"),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify header, metadata, payload, and container BLAKE3 integrity of a .znf container")
                        .arg(
                            Arg::new("file")
                                .value_name("FILE.znf")
                                .required(true)
                                .help("Path to .znf container"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read decryption password from environment variable"),
                        ),
                )
                .subcommand(
                    Command::new("inspect")
                        .about("Inspect a ZNF container without exposing keys or sensitive metadata")
                        .arg(
                            Arg::new("file")
                                .value_name("CONTAINER")
                                .required(true)
                                .help("Path to ZNF container"),
                        ),
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate ZNF container structure and boundaries")
                        .arg(
                            Arg::new("file")
                                .value_name("CONTAINER")
                                .required(true)
                                .help("Path to ZNF container"),
                        ),
                ),
        )
        .subcommand(
            Command::new("zarc")
                .about("Create, inspect, verify, and extract .zarc archives")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("create")
                        .about("Create a new .zarc archive from files or directories")
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_name("ARCHIVE.zarc")
                                .help("Output .zarc file path")
                                .required(true),
                        )
                        .arg(
                            Arg::new("compression")
                                .short('c')
                                .long("compression")
                                .value_name("ALGO")
                                .default_value("zstd")
                                .help("Compression algorithm: zstd, lz4, or store"),
                        )
                        .arg(
                            Arg::new("level")
                                .short('l')
                                .long("level")
                                .value_name("1..22")
                                .default_value("3")
                                .help("Zstandard compression level (1..22)"),
                        )
                        .arg(
                            Arg::new("encrypt")
                                .short('e')
                                .long("encrypt")
                                .action(ArgAction::SetTrue)
                                .help("Encrypt archive with XChaCha20-Poly1305 + Argon2id"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read encryption password from environment variable (non-interactive)"),
                        )
                        .arg(
                            Arg::new("parity")
                                .long("parity")
                                .action(ArgAction::SetTrue)
                                .help("Include XOR recovery parity stripe in archive footer"),
                        )
                        .arg(
                            Arg::new("comment")
                                .long("comment")
                                .value_name("TEXT")
                                .help("Optional UTF-8 comment stored in archive metadata"),
                        )
                        .arg(
                            Arg::new("inputs")
                                .value_name("PATH")
                                .num_args(1..)
                                .required(true)
                                .help("Input files or directories to archive"),
                        ),
                )
                .subcommand(
                    Command::new("list")
                        .about("List entries in a .zarc archive")
                        .arg(
                            Arg::new("archive")
                                .value_name("ARCHIVE.zarc")
                                .required(true)
                                .help("Path to .zarc archive"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read decryption password from environment variable"),
                        ),
                )
                .subcommand(
                    Command::new("extract")
                        .about("Safely extract a .zarc archive into a destination directory")
                        .arg(
                            Arg::new("archive")
                                .value_name("ARCHIVE.zarc")
                                .required(true)
                                .help("Path to .zarc archive"),
                        )
                        .arg(
                            Arg::new("dest")
                                .short('d')
                                .long("dest")
                                .value_name("DIR")
                                .default_value(".")
                                .help("Destination directory"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read decryption password from environment variable"),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify header, BLAKE3 hashes, AEAD tags, and optional parity")
                        .arg(
                            Arg::new("archive")
                                .value_name("ARCHIVE.zarc")
                                .required(true)
                                .help("Path to .zarc archive"),
                        )
                        .arg(
                            Arg::new("repair-out")
                                .long("repair-out")
                                .value_name("REPAIRED.zarc")
                                .help("Attempt single-block parity repair and write repaired archive"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read decryption password from environment variable"),
                        ),
                )
                .subcommand(
                    Command::new("info")
                        .about("Display detailed ZNF Core header and .zarc container metadata")
                        .arg(
                            Arg::new("archive")
                                .value_name("ARCHIVE.zarc")
                                .required(true)
                                .help("Path to .zarc archive"),
                        )
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("ENV_VAR")
                                .help("Read decryption password from environment variable"),
                        ),
                ),
        )
}

fn main() -> ExitCode {
    let matches = build_cli().get_matches();
    match run(&matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(matches: &ArgMatches) -> Result<(), String> {
    match matches.subcommand() {
        Some(("inspect", m)) => cmd_container_inspect(m),
        Some(("validate", m)) => cmd_container_validate(m),
        Some(("container", cm)) => match cm.subcommand() {
            Some(("pack", m)) => cmd_container_pack(m),
            Some(("unpack", m)) => cmd_container_unpack(m),
            Some(("verify", m)) => cmd_container_verify(m),
            Some(("inspect", m)) => cmd_container_inspect(m),
            Some(("validate", m)) => cmd_container_validate(m),
            _ => Err("unknown container subcommand".into()),
        },
        Some(("zarc", zarc_m)) => match zarc_m.subcommand() {
            Some(("create", m)) => cmd_create(m),
            Some(("list", m)) => cmd_list(m),
            Some(("extract", m)) => cmd_extract(m),
            Some(("verify", m)) => cmd_verify(m),
            Some(("info", m)) => cmd_info(m),
            _ => Err("unknown zarc subcommand".into()),
        },
        _ => Err("unknown subcommand".into()),
    }
}

fn resolve_password(
    m: &ArgMatches,
    need_prompt: bool,
    confirm: bool,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(env_name) = m.get_one::<String>("password-env") {
        let val = std::env::var(env_name)
            .map_err(|_| format!("environment variable '{env_name}' is not set"))?;
        if val.is_empty() {
            return Err(format!("environment variable '{env_name}' is empty"));
        }
        return Ok(Some(val.into_bytes()));
    }
    if need_prompt {
        let pw = rpassword::prompt_password("Enter archive password: ")
            .map_err(|e| format!("failed to read password from terminal: {e}"))?;
        if pw.is_empty() {
            return Err("password cannot be empty".into());
        }
        if confirm {
            let pw2 = rpassword::prompt_password("Confirm archive password: ")
                .map_err(|e| format!("failed to read password confirmation: {e}"))?;
            if pw != pw2 {
                return Err("passwords do not match".into());
            }
        }
        return Ok(Some(pw.into_bytes()));
    }
    Ok(None)
}

fn format_name(fid: FormatId) -> &'static str {
    match fid {
        FormatId::ZARC => "ZARC (.zarc)",
        FormatId::CORE => "ZNF Core (.znf)",
        _ => "Unknown/Vendor",
    }
}

fn cmd_container_inspect(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;
    let info = ZnfValidator::new().validate_structure(&raw).map_err(|e| {
        if e.is_unsupported() {
            format!("unsupported container feature/version: {e}")
        } else {
            format!("container validation failed: {e}")
        }
    })?;

    println!("ZNF Container Diagnostic Inspection");
    println!("  File:                {path} ({} bytes)", raw.len());
    println!(
        "  Format ID:           {:#010x} ({})",
        info.format_id.raw(),
        format_name(info.format_id)
    );
    println!(
        "  Format Version:      {}.{}",
        info.version.major, info.version.minor
    );
    println!(
        "  Feature Flags:       {:#018x} [compressed={}, encrypted={}, metadata={}, footer={}, streaming={}]",
        info.flags.bits(),
        info.flags.is_compressed(),
        info.flags.is_encrypted(),
        info.flags.has_metadata(),
        info.flags.has_footer(),
        info.flags.is_streaming()
    );
    println!("  Compression:         {:?}", info.compression);
    println!("  Encryption:          {:?}", info.encryption);
    println!("  Header Length:       {} bytes", info.header_len);
    println!("  Payload Offset:      {}", info.payload_offset);
    println!("  Stored Payload Len:  {} bytes", info.payload_len);
    if let Some(u_len) = info.uncompressed_len {
        println!("  Uncompressed Len:    {u_len} bytes");
    }
    println!(
        "  Metadata Attributes: {} (values redacted for privacy)",
        info.metadata_attribute_count
    );
    println!("  Metadata Extensions: {}", info.metadata_extension_count);
    if let Some(h) = info.metadata_blake3 {
        println!("  Metadata BLAKE3:     {}", h.to_hex());
    }
    if let Some(h) = info.payload_blake3 {
        println!("  Payload BLAKE3:      {}", h.to_hex());
    }
    if let Some(h) = info.container_blake3 {
        println!("  Container BLAKE3:    {}", h.to_hex());
    }
    Ok(())
}

fn cmd_container_validate(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;
    let info = ZnfValidator::new().validate_structure(&raw).map_err(|e| {
        if e.is_unsupported() {
            format!("unsupported container feature/version: {e}")
        } else {
            format!("validation failed: {e}")
        }
    })?;
    println!(
        "VALID: {} v{}.{} (compression={:?}, encrypted={}, payload={} bytes)",
        format_name(info.format_id),
        info.version.major,
        info.version.minor,
        info.compression,
        info.flags.is_encrypted(),
        info.payload_len
    );
    Ok(())
}

fn cmd_container_pack(m: &ArgMatches) -> Result<(), String> {
    let input_path = m.get_one::<String>("input").unwrap();
    let output_path = m.get_one::<String>("output").unwrap();
    let algo_str = m.get_one::<String>("compression").unwrap().as_str();
    let level: i32 = m
        .get_one::<String>("level")
        .unwrap()
        .parse()
        .map_err(|_| "invalid compression level (expected integer 1..22)".to_string())?;

    let compression = match algo_str {
        "zstd" => ZnfCompression::Zstd,
        "lz4" => ZnfCompression::Lz4,
        "store" | "none" => ZnfCompression::None,
        other => {
            return Err(format!(
                "unsupported compression '{other}' (expected zstd, lz4, or store)"
            ))
        }
    };

    let encrypt_flag = m.get_flag("encrypt") || m.contains_id("password-env");
    let password = resolve_password(m, encrypt_flag, true)?;

    let mut meta = ZnfMetadata::new();
    meta.comment = m.get_one::<String>("comment").cloned();

    let mut writer = ZnfWriter::new()
        .with_compression(compression)
        .with_zstd_level(level)
        .with_metadata(meta);

    if let Some(pw) = password {
        writer = writer.with_encryption(EncryptionKeySource::Password(pw));
    }

    let mut out_file = fs::File::create(output_path)
        .map_err(|e| format!("failed to create '{output_path}': {e}"))?;

    if m.get_flag("streaming") {
        let in_file = fs::File::open(input_path)
            .map_err(|e| format!("failed to open '{input_path}': {e}"))?;
        let n = writer
            .write_streaming(in_file, &mut out_file, None)
            .map_err(|e| e.to_string())?;
        println!("packed {n} bytes (streaming) -> {output_path}");
    } else {
        let payload =
            fs::read(input_path).map_err(|e| format!("failed to read '{input_path}': {e}"))?;
        writer
            .write_container(&payload, &mut out_file)
            .map_err(|e| e.to_string())?;
        println!("packed {} bytes -> {output_path}", payload.len());
    }
    Ok(())
}

fn cmd_container_unpack(m: &ArgMatches) -> Result<(), String> {
    let input_path = m.get_one::<String>("input").unwrap();
    let output_path = m.get_one::<String>("output").unwrap();
    let raw = fs::read(input_path).map_err(|e| format!("failed to read '{input_path}': {e}"))?;

    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    let password = resolve_password(m, hdr.flags().is_encrypted(), false)?;

    let mut reader = ZnfReader::new();
    if let Some(pw) = password {
        reader = reader.with_encryption_key(EncryptionKeySource::Password(pw));
    }
    let decoded = reader.read_container(&raw).map_err(|e| e.to_string())?;
    fs::write(output_path, &decoded.payload)
        .map_err(|e| format!("failed to write '{output_path}': {e}"))?;
    println!(
        "unpacked {} bytes -> {output_path} (BLAKE3={})",
        decoded.payload.len(),
        decoded.payload_blake3.to_hex()
    );
    Ok(())
}

fn cmd_container_verify(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;
    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    let password = resolve_password(m, hdr.flags().is_encrypted(), false)?;

    let mut reader = ZnfReader::new();
    if let Some(pw) = password {
        reader = reader.with_encryption_key(EncryptionKeySource::Password(pw));
    }
    let decoded = reader.read_container(&raw).map_err(|e| e.to_string())?;
    println!(
        "OK: verified container '{path}' ({} bytes, payload BLAKE3={})",
        decoded.payload.len(),
        decoded.payload_blake3.to_hex()
    );
    Ok(())
}

fn cmd_create(m: &ArgMatches) -> Result<(), String> {
    let output = PathBuf::from(m.get_one::<String>("output").unwrap());
    let algo_str = m.get_one::<String>("compression").unwrap().as_str();
    let level: i32 = m
        .get_one::<String>("level")
        .unwrap()
        .parse()
        .map_err(|_| "invalid compression level (expected integer 1..22)".to_string())?;

    let compression = match algo_str {
        "zstd" => CompConfig::zstd(level),
        "lz4" => CompConfig::lz4(),
        "store" | "none" => CompConfig::stored(),
        other => {
            return Err(format!(
                "unsupported compression '{other}' (expected zstd, lz4, or store)"
            ))
        }
    };

    let encrypt_flag = m.get_flag("encrypt") || m.contains_id("password-env");
    let password = resolve_password(m, encrypt_flag, true)?;
    let include_parity = m.get_flag("parity");
    let comment = m.get_one::<String>("comment").cloned();

    let opts = WriteOptions {
        compression,
        password,
        kdf_params: None,
        comment,
        include_parity,
        ..WriteOptions::default()
    };

    let mut writer = ZarcWriter::new(opts);
    let inputs: Vec<&String> = m.get_many::<String>("inputs").unwrap().collect();
    for raw_in in inputs {
        let p = Path::new(raw_in);
        if !p.exists() {
            return Err(format!("input path does not exist: {}", p.display()));
        }
        let base = p.parent().unwrap_or_else(|| Path::new(""));
        writer
            .add_path(base, p)
            .map_err(|e| format!("failed to add '{}': {e}", p.display()))?;
    }

    let mut file = fs::File::create(&output)
        .map_err(|e| format!("failed to create '{}': {e}", output.display()))?;
    writer
        .finish(&mut file)
        .map_err(|e| format!("failed to finalize archive: {e}"))?;
    println!("created {} (archive written)", output.display());
    Ok(())
}

fn open_archive_with_cli<'a>(raw: &'a [u8], m: &ArgMatches) -> Result<ZarcArchive<'a>, String> {
    let hdr = znf_core::Header::decode(raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    let need_pw = hdr.flags().is_encrypted();
    let password = resolve_password(m, need_pw, false)?;
    let opts = ReadOptions {
        password,
        ..ReadOptions::default()
    };
    ZarcArchive::open(raw, opts).map_err(|e: ZarcError| e.to_string())
}

fn cmd_list(m: &ArgMatches) -> Result<(), String> {
    let archive_path = m.get_one::<String>("archive").unwrap();
    let raw =
        fs::read(archive_path).map_err(|e| format!("failed to read '{archive_path}': {e}"))?;
    let arch = open_archive_with_cli(&raw, m)?;

    println!(
        "{:<5} {:<6} {:>12} {:>12}  PATH",
        "KIND", "ALGO", "ORIGINAL", "STORED"
    );
    for e in arch.entries() {
        let kind_str = match e.kind {
            EntryKind::File => "file",
            EntryKind::Directory => "dir",
        };
        let algo_str = match e.compression {
            Algorithm::None => "store",
            Algorithm::Zstd => "zstd",
            Algorithm::Lz4 => "lz4",
        };
        println!(
            "{:<5} {:<6} {:>12} {:>12}  {}",
            kind_str, algo_str, e.uncompressed_size, e.stored_size, e.path
        );
    }
    Ok(())
}

fn cmd_extract(m: &ArgMatches) -> Result<(), String> {
    let archive_path = m.get_one::<String>("archive").unwrap();
    let dest = Path::new(m.get_one::<String>("dest").unwrap());
    let raw =
        fs::read(archive_path).map_err(|e| format!("failed to read '{archive_path}': {e}"))?;
    let arch = open_archive_with_cli(&raw, m)?;
    let count = arch.extract_to(dest).map_err(|e| e.to_string())?;
    println!("extracted {count} entries to {}", dest.display());
    Ok(())
}

fn cmd_verify(m: &ArgMatches) -> Result<(), String> {
    let archive_path = m.get_one::<String>("archive").unwrap();
    let raw =
        fs::read(archive_path).map_err(|e| format!("failed to read '{archive_path}': {e}"))?;

    if let Some(repair_out) = m.get_one::<String>("repair-out") {
        match attempt_parity_repair(&raw, &znf_core::Limits::default()) {
            Ok(Some(repaired)) => {
                fs::write(repair_out, &repaired)
                    .map_err(|e| format!("failed to write repaired archive: {e}"))?;
                println!("repaired 1 corrupted block -> {repair_out}");
                let arch = open_archive_with_cli(&repaired, m)?;
                arch.verify_all().map_err(|e| e.to_string())?;
                println!("verification passed on repaired archive");
                return Ok(());
            }
            Ok(None) => {
                println!("parity check: 0 corrupted blocks");
            }
            Err(e) => return Err(format!("parity repair failed: {e}")),
        }
    }

    let arch = open_archive_with_cli(&raw, m)?;
    arch.verify_all().map_err(|e| e.to_string())?;
    println!(
        "OK: verified {} entries and container integrity ({archive_path})",
        arch.entries().len()
    );
    Ok(())
}

fn cmd_info(m: &ArgMatches) -> Result<(), String> {
    let archive_path = m.get_one::<String>("archive").unwrap();
    let raw =
        fs::read(archive_path).map_err(|e| format!("failed to read '{archive_path}': {e}"))?;
    let arch = open_archive_with_cli(&raw, m)?;
    let h = arch.header();

    let total_orig: u64 = arch.entries().iter().map(|e| e.uncompressed_size).sum();
    let total_stored: u64 = arch.entries().iter().map(|e| e.stored_size).sum();

    println!("ZNF Container Information");
    println!("  File size:         {} bytes", raw.len());
    println!(
        "  ZNF Core spec:     {}.{} (fixed header {} bytes)",
        CORE_SPEC_VERSION.0, CORE_SPEC_VERSION.1, HEADER_LEN
    );
    println!(
        "  Format ID:         {:#010x} (ZARC {}.{})",
        h.format_id().raw(),
        ZARC_SPEC_VERSION.0,
        ZARC_SPEC_VERSION.1
    );
    println!(
        "  Header version:    {}.{}",
        h.version().major,
        h.version().minor
    );
    println!(
        "  Flags:             {:#018x} (compressed={}, encrypted={}, metadata={}, footer={})",
        h.flags().bits(),
        h.flags().is_compressed(),
        h.flags().is_encrypted(),
        h.flags().has_metadata(),
        h.flags().has_footer()
    );
    println!("  Compression ID:    {:?}", h.compression());
    println!("  Encryption ID:     {:?}", h.encryption());
    println!("  Payload offset:    {}", h.payload_offset());
    println!("  Payload length:    {}", h.payload_len());
    println!("  Entry count:       {}", arch.entries().len());
    println!("  Uncompressed sum:  {total_orig} bytes");
    println!("  Stored sum:        {total_stored} bytes");
    if let Some(c) = arch.comment() {
        println!("  Comment:           {c}");
    }
    if let Some(b3) = arch.archive_blake3() {
        println!("  Archive BLAKE3:    {}", b3.to_hex());
    }
    if let Some(kdf) = arch.kdf_params() {
        println!(
            "  KDF (Argon2id):    m={} KiB, t={}, p={}",
            kdf.m_cost_kib, kdf.t_cost, kdf.p_cost
        );
    }
    println!(
        "  Parity stripe:     {}",
        if arch.parity_stripe().is_some() {
            "present"
        } else {
            "none"
        }
    );
    Ok(())
}
