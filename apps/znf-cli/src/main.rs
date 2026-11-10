//! `znf` — Command-line tool for ZNF Core containers and ZARC (`.zarc`) archives.
//!
//! Zero telemetry, zero network calls, deterministic binary output.
//! Passwords are read from interactive hidden terminal prompts (`rpassword`) or
//! `--password-env`, never from command-line arguments, and secrets are never logged.

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
use znf_img::{
    decode_image, encode_image, AlphaInfo, BitDepth, ChunkStrategy, ColorModel, ColorSpace,
    DecodeOptions, EncodeOptions, FilterType, Image, PixelFormat,
};
use znf_zarc::{
    add_paths_to_archive_file, attempt_parity_repair, inspect_archive,
    remove_entries_from_archive_file, ArchiveProgress, EntryKind, ExtractOptions, ReadOptions,
    WriteOptions, ZarcArchive, ZarcError, ZarcWriter, ZARC_SPEC_VERSION,
};

const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

fn common_password_arg() -> Arg {
    Arg::new("password-env")
        .long("password-env")
        .value_name("ENV_VAR")
        .help("Read encryption/decryption password from environment variable")
}

fn common_json_arg() -> Arg {
    Arg::new("json")
        .long("json")
        .action(ArgAction::SetTrue)
        .help("Emit machine-readable JSON output")
}

fn common_progress_arg() -> Arg {
    Arg::new("progress")
        .long("progress")
        .action(ArgAction::SetTrue)
        .help("Display per-entry progress to stderr")
}

fn zarc_create_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Create a new .zarc archive from files or directories")
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("ARCHIVE.zarc")
                .help("Output .zarc file path (if omitted, first positional argument is used)"),
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
        .arg(common_password_arg())
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
            Arg::new("overwrite")
                .short('f')
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("Allow overwriting an existing output .zarc file"),
        )
        .arg(common_progress_arg())
        .arg(common_json_arg())
        .arg(
            Arg::new("inputs")
                .value_name("PATH")
                .num_args(1..)
                .required(true)
                .help("Archive path (if -o not used) followed by input files/directories"),
        )
}

fn zarc_extract_command(name: &'static str) -> Command {
    Command::new(name)
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
                .visible_alias("output")
                .short_alias('o')
                .value_name("DIR")
                .default_value(".")
                .help("Destination directory"),
        )
        .arg(
            Arg::new("select")
                .long("select")
                .value_name("ENTRY_PATH")
                .num_args(1..)
                .action(ArgAction::Append)
                .help("Extract only the specified archive entry path(s) or directory subtree(s)"),
        )
        .arg(
            Arg::new("overwrite")
                .short('f')
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("Allow overwriting existing files in the destination directory"),
        )
        .arg(
            Arg::new("recover-intact")
                .long("recover-intact")
                .action(ArgAction::SetTrue)
                .help("Extract independently verified intact entries even if other entries are damaged"),
        )
        .arg(common_password_arg())
        .arg(common_progress_arg())
        .arg(common_json_arg())
}

fn zarc_list_command(name: &'static str) -> Command {
    Command::new(name)
        .about("List entries in a .zarc archive")
        .arg(
            Arg::new("archive")
                .value_name("ARCHIVE.zarc")
                .required(true)
                .help("Path to .zarc archive"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn zarc_verify_command(name: &'static str) -> Command {
    Command::new(name)
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
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn zarc_test_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Test every entry in a .zarc archive and report per-entry health")
        .arg(
            Arg::new("archive")
                .value_name("ARCHIVE.zarc")
                .required(true)
                .help("Path to .zarc archive"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn zarc_info_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Display detailed ZNF Core header and .zarc container metadata")
        .arg(
            Arg::new("archive")
                .value_name("ARCHIVE.zarc")
                .required(true)
                .help("Path to .zarc archive"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn zarc_add_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Add files or directories to an existing .zarc archive")
        .arg(
            Arg::new("archive")
                .value_name("ARCHIVE.zarc")
                .required(true)
                .help("Path to existing .zarc archive"),
        )
        .arg(
            Arg::new("inputs")
                .value_name("PATH")
                .num_args(1..)
                .required(true)
                .help("Files or directories to add"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn zarc_remove_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Remove entry path(s) from an existing .zarc archive")
        .arg(
            Arg::new("archive")
                .value_name("ARCHIVE.zarc")
                .required(true)
                .help("Path to existing .zarc archive"),
        )
        .arg(
            Arg::new("paths")
                .value_name("ENTRY_PATH")
                .num_args(1..)
                .required(true)
                .help("Canonical entry path(s) or directory subtree(s) to remove"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn image_encode_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Encode an image to .zimg (lossless)")
        .arg(
            Arg::new("input")
                .value_name("INPUT.png")
                .required(true)
                .help("Input image file (PNG or raw RGB/RGBA/gray)"),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT.zimg")
                .required(true)
                .help("Output .zimg file path"),
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
            Arg::new("filter")
                .short('f')
                .long("filter")
                .value_name("TYPE")
                .default_value("none")
                .help("Scanline filter: none, sub, up, average, paeth"),
        )
        .arg(
            Arg::new("encrypt")
                .short('e')
                .long("encrypt")
                .action(ArgAction::SetTrue)
                .help("Encrypt image payload with XChaCha20-Poly1305 + Argon2id"),
        )
        .arg(common_password_arg())
        .arg(
            Arg::new("overwrite")
                .short('o')
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("Allow overwriting existing output file"),
        )
        .arg(common_progress_arg())
        .arg(common_json_arg())
}

fn image_decode_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Decode a .zimg image to PNG or raw pixels")
        .arg(
            Arg::new("input")
                .value_name("INPUT.zimg")
                .required(true)
                .help("Input .zimg file path"),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT.png")
                .required(true)
                .help("Output decoded image file path"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn image_inspect_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Inspect a .zimg image without decoding pixels")
        .arg(
            Arg::new("file")
                .value_name("IMAGE.zimg")
                .required(true)
                .help("Path to .zimg image"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn image_verify_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Verify .zimg image integrity (BLAKE3 hashes, AEAD tags)")
        .arg(
            Arg::new("file")
                .value_name("IMAGE.zimg")
                .required(true)
                .help("Path to .zimg image"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn image_metadata_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Display or remove image metadata")
        .arg(
            Arg::new("file")
                .value_name("IMAGE.zimg")
                .required(true)
                .help("Path to .zimg image"),
        )
        .arg(
            Arg::new("remove")
                .long("remove")
                .action(ArgAction::SetTrue)
                .help("Remove/sanitize all metadata and write a new image"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT.zimg")
                .help("Output path (required with --remove)"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn image_info_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Display detailed .zimg image information")
        .arg(
            Arg::new("file")
                .value_name("IMAGE.zimg")
                .required(true)
                .help("Path to .zimg image"),
        )
        .arg(common_password_arg())
        .arg(common_json_arg())
}

fn image_optimize_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Re-encode a .zimg image with different compression/settings")
        .arg(
            Arg::new("input")
                .value_name("INPUT.zimg")
                .required(true)
                .help("Input .zimg file path"),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT.zimg")
                .required(true)
                .help("Output optimized .zimg file path"),
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
        .arg(common_password_arg())
        .arg(
            Arg::new("overwrite")
                .short('o')
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("Allow overwriting existing output file"),
        )
        .arg(common_json_arg())
}

fn build_cli() -> Command {
    Command::new("znf")
        .version(VERSION_STR)
        .about("Zelvior Native Format (ZNF) Core & ZARC (.zarc) CLI")
        .subcommand_required(true)
        .arg_required_else_help(true)
        // Top-level ergonomic commands (`znf create|extract|list|inspect|validate|verify|test|add|remove|info`)
        .subcommand(zarc_create_command("create"))
        .subcommand(zarc_extract_command("extract"))
        .subcommand(zarc_list_command("list"))
        .subcommand(zarc_verify_command("verify"))
        .subcommand(zarc_test_command("test"))
        .subcommand(zarc_add_command("add"))
        .subcommand(zarc_remove_command("remove"))
        .subcommand(zarc_info_command("info"))
        .subcommand(
            Command::new("inspect")
                .about("Inspect any ZNF or .zarc container without extracting files")
                .arg(
                    Arg::new("file")
                        .value_name("CONTAINER")
                        .required(true)
                        .help("Path to ZNF container (.zarc, .znf)"),
                )
                .arg(common_password_arg())
                .arg(common_json_arg()),
        )
        .subcommand(
            Command::new("validate")
                .about("Validate ZNF container structure, section boundaries, and pre-footer integrity")
                .arg(
                    Arg::new("file")
                        .value_name("CONTAINER")
                        .required(true)
                        .help("Path to ZNF container"),
                )
                .arg(common_json_arg()),
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
                        .arg(common_password_arg())
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
                        .arg(common_password_arg()),
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
                        .arg(common_password_arg()),
                )
                .subcommand(
                    Command::new("inspect")
                        .about("Inspect a ZNF container without exposing keys or sensitive metadata")
                        .arg(
                            Arg::new("file")
                                .value_name("CONTAINER")
                                .required(true)
                                .help("Path to ZNF container"),
                        )
                        .arg(common_password_arg())
                        .arg(common_json_arg()),
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate ZNF container structure and boundaries")
                        .arg(
                            Arg::new("file")
                                .value_name("CONTAINER")
                                .required(true)
                                .help("Path to ZNF container"),
                        )
                        .arg(common_json_arg()),
                ),
        )
        .subcommand(
            Command::new("image")
                .about("Encode, decode, inspect, verify, and optimize .zimg images")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(image_encode_command("encode"))
                .subcommand(image_decode_command("decode"))
                .subcommand(image_inspect_command("inspect"))
                .subcommand(image_verify_command("verify"))
                .subcommand(image_metadata_command("metadata"))
                .subcommand(image_info_command("info"))
                .subcommand(image_optimize_command("optimize")),
        )
        .subcommand(
            Command::new("zarc")
                .about("Create, inspect, verify, modify, and extract .zarc archives")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(zarc_create_command("create"))
                .subcommand(zarc_list_command("list"))
                .subcommand(zarc_extract_command("extract"))
                .subcommand(zarc_verify_command("verify"))
                .subcommand(zarc_test_command("test"))
                .subcommand(zarc_add_command("add"))
                .subcommand(zarc_remove_command("remove"))
                .subcommand(zarc_info_command("info"))
                .subcommand(
                    Command::new("inspect")
                        .about("Inspect a .zarc archive without extracting files")
                        .arg(
                            Arg::new("file")
                                .value_name("ARCHIVE.zarc")
                                .required(true)
                                .help("Path to .zarc archive"),
                        )
                        .arg(common_password_arg())
                        .arg(common_json_arg()),
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
        Some(("create", m)) => cmd_create(m),
        Some(("extract", m)) => cmd_extract(m),
        Some(("list", m)) => cmd_list(m),
        Some(("verify", m)) => cmd_verify(m),
        Some(("test", m)) => cmd_test(m),
        Some(("add", m)) => cmd_add(m),
        Some(("remove", m)) => cmd_remove(m),
        Some(("info", m)) => cmd_info(m),
        Some(("inspect", m)) => cmd_inspect_any(m),
        Some(("validate", m)) => cmd_container_validate(m),
        Some(("container", cm)) => match cm.subcommand() {
            Some(("pack", m)) => cmd_container_pack(m),
            Some(("unpack", m)) => cmd_container_unpack(m),
            Some(("verify", m)) => cmd_container_verify(m),
            Some(("inspect", m)) => cmd_inspect_any(m),
            Some(("validate", m)) => cmd_container_validate(m),
            _ => Err("unknown container subcommand".into()),
        },
        Some(("zarc", zarc_m)) => match zarc_m.subcommand() {
            Some(("create", m)) => cmd_create(m),
            Some(("list", m)) => cmd_list(m),
            Some(("extract", m)) => cmd_extract(m),
            Some(("verify", m)) => cmd_verify(m),
            Some(("test", m)) => cmd_test(m),
            Some(("add", m)) => cmd_add(m),
            Some(("remove", m)) => cmd_remove(m),
            Some(("info", m)) => cmd_info(m),
            Some(("inspect", m)) => cmd_inspect_any(m),
            _ => Err("unknown zarc subcommand".into()),
        },
        Some(("image", img_m)) => match img_m.subcommand() {
            Some(("encode", m)) => cmd_image_encode(m),
            Some(("decode", m)) => cmd_image_decode(m),
            Some(("inspect", m)) => cmd_image_inspect(m),
            Some(("verify", m)) => cmd_image_verify(m),
            Some(("metadata", m)) => cmd_image_metadata(m),
            Some(("info", m)) => cmd_image_info(m),
            Some(("optimize", m)) => cmd_image_optimize(m),
            _ => Err("unknown image subcommand".into()),
        },
        _ => Err("unknown subcommand".into()),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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

fn cmd_inspect_any(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;
    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| {
            if e.is_unsupported() {
                format!("unsupported container feature/version: {e}")
            } else {
                format!("container header validation failed: {e}")
            }
        })?;

    // If this is a ZARC archive, use the rich ZARC inspector (supports locked & unlocked).
    if hdr.format_id() == FormatId::ZARC {
        let pw = resolve_password(m, false, false)?;
        let insp =
            inspect_archive(&raw, pw, &znf_core::Limits::default()).map_err(|e| e.to_string())?;
        if m.get_flag("json") {
            let entries_count = insp.entries.len();
            let (u_bytes, s_bytes) = insp.stats.as_ref().map_or((0, 0), |st| {
                (st.total_uncompressed_bytes, st.total_stored_bytes)
            });
            println!(
                "{{\"format\":\"ZARC\",\"version\":\"{}.{}\",\"file_size\":{},\"encrypted\":{},\"index_locked\":{},\"compression\":\"{:?}\",\"entries\":{},\"uncompressed_bytes\":{},\"stored_bytes\":{},\"blake3_verified\":{}}}",
                insp.version.0,
                insp.version.1,
                insp.file_size,
                insp.flags.is_encrypted(),
                insp.index_locked,
                insp.header_compression,
                entries_count,
                u_bytes,
                s_bytes,
                insp.archive_blake3_verified
            );
            return Ok(());
        }
        println!("ZNF Container Diagnostic Inspection");
        println!("  File:                {path} ({} bytes)", insp.file_size);
        println!("  Format ID:           0x00000001 (ZARC (.zarc))");
        println!(
            "  Format Version:      {}.{}",
            insp.version.0, insp.version.1
        );
        println!(
            "  Feature Flags:       {:#018x} [compressed={}, encrypted={}, metadata={}, footer={}]",
            insp.flags.bits(),
            insp.flags.is_compressed(),
            insp.flags.is_encrypted(),
            insp.flags.has_metadata(),
            insp.flags.has_footer()
        );
        println!("  Compression:         {:?}", insp.header_compression);
        println!("  Encryption:          {:?}", insp.header_encryption);
        println!("  Payload Offset:      {}", insp.payload_offset);
        println!("  Stored Payload Len:  {} bytes", insp.payload_len);
        if let Some(b3) = insp.archive_blake3 {
            println!(
                "  Archive BLAKE3:      {} (verified={})",
                b3.to_hex(),
                insp.archive_blake3_verified
            );
        }
        println!(
            "  Parity Stripe:       {}",
            if insp.has_parity_stripe {
                "present"
            } else {
                "none"
            }
        );
        if insp.index_locked {
            println!("  Index Status:        ENCRYPTED (supply password to list entries)");
        } else if let Some(ref st) = insp.stats {
            println!(
                "  Entries:             {} ({} files, {} dirs; zstd={}, lz4={}, store={})",
                st.total_entries,
                st.file_count,
                st.dir_count,
                st.zstd_files,
                st.lz4_files,
                st.stored_files
            );
            println!(
                "  Uncompressed Sum:    {} bytes",
                st.total_uncompressed_bytes
            );
            println!("  Stored Sum:          {} bytes", st.total_stored_bytes);
            println!("  Compression Ratio:   {:.2}:1", st.ratio());
        }
        for w in &insp.warnings {
            println!("  Warning:             {w}");
        }
        return Ok(());
    }

    let info = ZnfValidator::new().validate_structure(&raw).map_err(|e| {
        if e.is_unsupported() {
            format!("unsupported container feature/version: {e}")
        } else {
            format!("container validation failed: {e}")
        }
    })?;

    if m.get_flag("json") {
        println!(
            "{{\"format\":\"{}\",\"version\":\"{}.{}\",\"compression\":\"{:?}\",\"encryption\":\"{:?}\",\"payload_len\":{}}}",
            json_escape(format_name(info.format_id)),
            info.version.major,
            info.version.minor,
            info.compression,
            info.encryption,
            info.payload_len
        );
        return Ok(());
    }

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
    if m.get_flag("json") {
        println!(
            "{{\"valid\":true,\"format\":\"{}\",\"version\":\"{}.{}\",\"payload_len\":{}}}",
            json_escape(format_name(info.format_id)),
            info.version.major,
            info.version.minor,
            info.payload_len
        );
    } else {
        println!(
            "VALID: {} v{}.{} (compression={:?}, encrypted={}, payload={} bytes)",
            format_name(info.format_id),
            info.version.major,
            info.version.minor,
            info.compression,
            info.flags.is_encrypted(),
            info.payload_len
        );
    }
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
    let raw_inputs: Vec<&String> = m.get_many::<String>("inputs").unwrap().collect();
    let (output, inputs): (PathBuf, &[&String]) =
        if let Some(out_flag) = m.get_one::<String>("output") {
            (PathBuf::from(out_flag), &raw_inputs[..])
        } else {
            if raw_inputs.len() < 2 {
                return Err(
                    "usage: znf create <ARCHIVE.zarc> <PATH>... (or pass -o <ARCHIVE.zarc>)".into(),
                );
            }
            (PathBuf::from(raw_inputs[0]), &raw_inputs[1..])
        };

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
    let overwrite = m.get_flag("overwrite");
    let comment = m.get_one::<String>("comment").cloned();

    let opts = WriteOptions {
        compression,
        password,
        kdf_params: None,
        comment,
        include_parity,
        overwrite,
        ..WriteOptions::default()
    };

    let mut writer = ZarcWriter::new(opts);
    for &raw_in in inputs {
        let p = Path::new(raw_in);
        if !p.exists() {
            return Err(format!("input path does not exist: {}", p.display()));
        }
        let base = p.parent().unwrap_or_else(|| Path::new(""));
        writer
            .add_path(base, p)
            .map_err(|e| format!("failed to add '{}': {e}", p.display()))?;
    }

    let show_progress = m.get_flag("progress");
    let mut progress_cb = |ev: ArchiveProgress| {
        if show_progress {
            eprintln!(
                "[{}/{}] {} ({} bytes processed)",
                ev.entry_index + 1,
                ev.total_entries,
                ev.current_path,
                ev.bytes_processed
            );
        }
    };

    writer
        .finish_to_path(&output, Some(&mut progress_cb), None)
        .map_err(|e| format!("failed to create archive: {e}"))?;

    if m.get_flag("json") {
        println!(
            "{{\"status\":\"created\",\"archive\":\"{}\"}}",
            json_escape(&output.display().to_string())
        );
    } else {
        println!("created {} (archive written)", output.display());
    }
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

    if m.get_flag("json") {
        print!("[");
        for (i, e) in arch.entries().iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            let kind_str = match e.kind {
                EntryKind::File => "file",
                EntryKind::Directory => "dir",
            };
            let algo_str = match e.compression {
                Algorithm::None => "store",
                Algorithm::Zstd => "zstd",
                Algorithm::Lz4 => "lz4",
            };
            print!(
                "{{\"path\":\"{}\",\"kind\":\"{}\",\"compression\":\"{}\",\"uncompressed_size\":{},\"stored_size\":{},\"blake3\":\"{}\"}}",
                json_escape(&e.path),
                kind_str,
                algo_str,
                e.uncompressed_size,
                e.stored_size,
                e.blake3_hash.to_hex()
            );
        }
        println!("]");
        return Ok(());
    }

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

    let selected_paths = m
        .get_many::<String>("select")
        .map(|vals| vals.cloned().collect::<Vec<String>>());
    let extract_opts = ExtractOptions {
        overwrite: m.get_flag("overwrite"),
        selected_paths,
        ..ExtractOptions::default()
    };

    if m.get_flag("recover-intact") {
        let report = arch
            .extract_verified_entries(dest, &extract_opts)
            .map_err(|e| e.to_string())?;
        if m.get_flag("json") {
            println!(
                "{{\"extracted\":{},\"failed\":{}}}",
                report.extracted_paths.len(),
                report.failed_entries.len()
            );
        } else {
            println!(
                "recovered {} verified entries to {} ({} damaged entries refused)",
                report.extracted_paths.len(),
                dest.display(),
                report.failed_entries.len()
            );
            for (p, err) in &report.failed_entries {
                eprintln!("  damaged: {p} ({err})");
            }
        }
        return Ok(());
    }

    let show_progress = m.get_flag("progress");
    let mut progress_cb = |ev: ArchiveProgress| {
        if show_progress {
            eprintln!(
                "[{}/{}] {} ({} bytes)",
                ev.entry_index + 1,
                ev.total_entries,
                ev.current_path,
                ev.bytes_processed
            );
        }
    };

    let count = arch
        .extract_with_options(dest, &extract_opts, Some(&mut progress_cb), None)
        .map_err(|e| e.to_string())?;

    if m.get_flag("json") {
        println!(
            "{{\"status\":\"extracted\",\"count\":{count},\"dest\":\"{}\"}}",
            json_escape(&dest.display().to_string())
        );
    } else {
        println!("extracted {count} entries to {}", dest.display());
    }
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
    if m.get_flag("json") {
        println!(
            "{{\"valid\":true,\"entries\":{},\"archive\":\"{}\"}}",
            arch.entries().len(),
            json_escape(archive_path)
        );
    } else {
        println!(
            "OK: verified {} entries and container integrity ({archive_path})",
            arch.entries().len()
        );
    }
    Ok(())
}

fn cmd_test(m: &ArgMatches) -> Result<(), String> {
    let archive_path = m.get_one::<String>("archive").unwrap();
    let raw =
        fs::read(archive_path).map_err(|e| format!("failed to read '{archive_path}': {e}"))?;
    let arch = open_archive_with_cli(&raw, m)?;
    let diagnoses = arch.diagnose_entries();
    let failed: Vec<_> = diagnoses.iter().filter(|d| !d.intact).collect();

    if m.get_flag("json") {
        println!(
            "{{\"total\":{},\"intact\":{},\"damaged\":{}}}",
            diagnoses.len(),
            diagnoses.len() - failed.len(),
            failed.len()
        );
    } else {
        for d in &diagnoses {
            if d.intact {
                println!("  OK      {}", d.path);
            } else {
                println!(
                    "  FAILED  {} ({})",
                    d.path,
                    d.error.as_deref().unwrap_or("corrupted")
                );
            }
        }
        println!(
            "test summary: {}/{} entries intact",
            diagnoses.len() - failed.len(),
            diagnoses.len()
        );
    }

    if !failed.is_empty() {
        return Err(format!(
            "{} entries failed integrity verification",
            failed.len()
        ));
    }
    Ok(())
}

fn cmd_add(m: &ArgMatches) -> Result<(), String> {
    let archive_path = Path::new(m.get_one::<String>("archive").unwrap());
    let raw = fs::read(archive_path)
        .map_err(|e| format!("failed to read '{}': {e}", archive_path.display()))?;
    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    let password = resolve_password(m, hdr.flags().is_encrypted(), false)?;

    let input_strings: Vec<&String> = m.get_many::<String>("inputs").unwrap().collect();
    let input_paths: Vec<&Path> = input_strings
        .iter()
        .map(|s| Path::new(s.as_str()))
        .collect();

    let total = add_paths_to_archive_file(archive_path, &input_paths, password)
        .map_err(|e| e.to_string())?;
    if m.get_flag("json") {
        println!("{{\"status\":\"updated\",\"total_entries\":{total}}}");
    } else {
        println!(
            "updated {} (total entries: {total})",
            archive_path.display()
        );
    }
    Ok(())
}

fn cmd_remove(m: &ArgMatches) -> Result<(), String> {
    let archive_path = Path::new(m.get_one::<String>("archive").unwrap());
    let raw = fs::read(archive_path)
        .map_err(|e| format!("failed to read '{}': {e}", archive_path.display()))?;
    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    let password = resolve_password(m, hdr.flags().is_encrypted(), false)?;

    let paths_to_remove: Vec<String> = m.get_many::<String>("paths").unwrap().cloned().collect();
    let removed = remove_entries_from_archive_file(archive_path, &paths_to_remove, password)
        .map_err(|e| e.to_string())?;

    if m.get_flag("json") {
        println!("{{\"status\":\"updated\",\"removed_entries\":{removed}}}");
    } else {
        println!("removed {removed} entries from {}", archive_path.display());
    }
    Ok(())
}

fn cmd_info(m: &ArgMatches) -> Result<(), String> {
    let archive_path = m.get_one::<String>("archive").unwrap();
    let raw =
        fs::read(archive_path).map_err(|e| format!("failed to read '{archive_path}': {e}"))?;
    let arch = open_archive_with_cli(&raw, m)?;
    let h = arch.header();
    let stats = arch.compression_stats();

    if m.get_flag("json") {
        println!(
            "{{\"file_size\":{},\"version\":\"{}.{}\",\"entries\":{},\"uncompressed_bytes\":{},\"stored_bytes\":{},\"ratio\":{:.4},\"encrypted\":{},\"parity\":{}}}",
            raw.len(),
            h.version().major,
            h.version().minor,
            stats.total_entries,
            stats.total_uncompressed_bytes,
            stats.total_stored_bytes,
            stats.ratio(),
            h.flags().is_encrypted(),
            arch.parity_stripe().is_some()
        );
        return Ok(());
    }

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
    println!(
        "  Entry count:       {} ({} files, {} dirs)",
        stats.total_entries, stats.file_count, stats.dir_count
    );
    println!(
        "  Uncompressed sum:  {} bytes",
        stats.total_uncompressed_bytes
    );
    println!("  Stored sum:        {} bytes", stats.total_stored_bytes);
    println!(
        "  Compression ratio: {:.2}:1 ({:.1}% saved)",
        stats.ratio(),
        stats.space_savings_percent()
    );
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

// ---------------------------------------------------------------------------
// ZIMG (.zimg) CLI command handlers
// ---------------------------------------------------------------------------

fn cmd_image_encode(m: &ArgMatches) -> Result<(), String> {
    let input_path = m.get_one::<String>("input").unwrap();
    let output_path = m.get_one::<String>("output").unwrap();

    let raw = fs::read(input_path).map_err(|e| format!("failed to read '{input_path}': {e}"))?;

    // Simple sidecar format: "width height color_model bit_depth" on first line
    // e.g. "1920 1080 rgb 8" or "800 600 gray 16"
    let meta_path = format!("{input_path}.meta");
    let meta_ok = std::path::Path::new(&meta_path).exists();
    let (width, height, pf) = if meta_ok {
        let meta_raw = fs::read_to_string(&meta_path)
            .map_err(|e| format!("failed to read '{meta_path}': {e}"))?;
        let parts: Vec<&str> = meta_raw.trim().split_whitespace().collect();
        if parts.len() < 4 {
            return Err(format!("invalid metadata sidecar '{meta_path}': expected 'width height color_model bit_depth'"));
        }
        let w: u32 = parts[0]
            .parse()
            .map_err(|_| format!("invalid width in '{meta_path}'"))?;
        let h: u32 = parts[1]
            .parse()
            .map_err(|_| format!("invalid height in '{meta_path}'"))?;
        let cm = match parts[2] {
            "rgb" => ColorModel::Rgb,
            "rgba" => ColorModel::Rgba,
            "gray" => ColorModel::Gray,
            "gray_alpha" => ColorModel::GrayAlpha,
            _ => ColorModel::Gray,
        };
        let bd: u32 = parts[3]
            .parse()
            .map_err(|_| format!("invalid bit_depth in '{meta_path}'"))?;
        let bd = match bd {
            8 => BitDepth::Bits8,
            16 => BitDepth::Bits16,
            _ => return Err(format!("unsupported bit depth {bd} in '{meta_path}'")),
        };
        let channel_count = cm.channel_count() as u8;
        let alpha = if cm == ColorModel::GrayAlpha || cm == ColorModel::Rgba {
            AlphaInfo::Present
        } else {
            AlphaInfo::None
        };
        let pf = PixelFormat {
            color_model: cm,
            bit_depth: bd,
            channel_count,
            alpha,
            color_space: ColorSpace::Srgb,
        };
        (w, h, pf)
    } else {
        (
            1,
            1,
            PixelFormat {
                color_model: ColorModel::Gray,
                bit_depth: BitDepth::Bits8,
                channel_count: 1,
                alpha: AlphaInfo::None,
                color_space: ColorSpace::Srgb,
            },
        )
    };

    let mut image = Image::new(width, height, pf).map_err(|e| e.to_string())?;
    if image.data.len() < raw.len() {
        return Err(format!(
            "input data {} bytes exceeds image capacity {} bytes",
            raw.len(),
            image.data.len()
        ));
    }
    image.data[..raw.len()].copy_from_slice(&raw);

    let algo_str = m.get_one::<String>("compression").unwrap().as_str();
    let level: i32 = m
        .get_one::<String>("level")
        .unwrap()
        .parse()
        .map_err(|_| "invalid compression level (expected integer 1..22)".to_string())?;
    let compression = match algo_str {
        "zstd" => znf_compression::Config::zstd(level),
        "lz4" => znf_compression::Config::lz4(),
        "store" | "none" => znf_compression::Config::stored(),
        other => {
            return Err(format!(
                "unsupported compression '{other}' (expected zstd, lz4, or store)"
            ))
        }
    };

    let filter_str = m.get_one::<String>("filter").unwrap().as_str();
    let filter = match filter_str {
        "none" => FilterType::None,
        "sub" => FilterType::Sub,
        "up" => FilterType::Up,
        "average" => FilterType::Average,
        "paeth" => FilterType::Paeth,
        other => {
            return Err(format!(
                "unsupported filter '{other}' (expected none, sub, up, average, paeth)"
            ))
        }
    };

    let encrypt_flag = m.get_flag("encrypt") || m.contains_id("password-env");
    let password = resolve_password(m, encrypt_flag, true)?;
    let overwrite = m.get_flag("overwrite");
    let show_progress = m.get_flag("progress");

    let output = std::path::Path::new(output_path);
    if output.exists() && !overwrite {
        return Err(format!(
            "output file already exists (pass --overwrite to replace): {}",
            output.display()
        ));
    }

    let kdf_params = if password.is_some() {
        Some(
            znf_crypto::KdfParams::new_default()
                .map_err(|e| format!("KDF parameter generation failed: {e}"))?,
        )
    } else {
        None
    };
    let opts = EncodeOptions {
        compression,
        filter,
        password,
        kdf_params,
        chunk_strategy: ChunkStrategy::default(),
        include_integrity: true,
    };

    let encoded = encode_image(&image, &opts).map_err(|e| e.to_string())?;

    if show_progress {
        eprintln!(
            "encoded {}x{} {} -> {} bytes ({} stored)",
            image.width,
            image.height,
            image.pixel_format.color_model,
            encoded.bytes.len(),
            encoded.info.stored_len
        );
    }

    fs::write(output, &encoded.bytes)
        .map_err(|e| format!("failed to write '{output_path}': {e}"))?;

    if m.get_flag("json") {
        println!(
            "{{\"status\":\"encoded\",\"format\":\"ZIMG\",\"version\":\"{}.{}\",\"width\":{},\"height\":{},\"uncompressed_bytes\":{},\"stored_bytes\":{},\"encrypted\":{}}}",
            znf_img::ZIMG_SPEC_VERSION.0, znf_img::ZIMG_SPEC_VERSION.1,
            image.width, image.height,
            encoded.info.uncompressed_len, encoded.info.stored_len,
            encoded.info.encrypted
        );
    } else {
        println!(
            "encoded {} ({} bytes stored)",
            output.display(),
            encoded.info.stored_len
        );
    }
    Ok(())
}

fn cmd_image_decode(m: &ArgMatches) -> Result<(), String> {
    let input_path = m.get_one::<String>("input").unwrap();
    let output_path = m.get_one::<String>("output").unwrap();
    let raw = fs::read(input_path).map_err(|e| format!("failed to read '{input_path}': {e}"))?;

    let password = resolve_password(m, false, false)?;
    let opts = DecodeOptions {
        password,
        ..DecodeOptions::default()
    };

    let decoded = decode_image(&raw, &opts).map_err(|e| e.to_string())?;

    fs::write(output_path, &decoded.image.data)
        .map_err(|e| format!("failed to write '{output_path}': {e}"))?;

    let meta_path = format!("{output_path}.meta");
    let cm_str = match decoded.image.pixel_format.color_model {
        ColorModel::Gray => "gray",
        ColorModel::GrayAlpha => "gray_alpha",
        ColorModel::Rgb => "rgb",
        ColorModel::Rgba => "rgba",
    };
    let meta_content = format!(
        "{} {} {} {}",
        decoded.image.width,
        decoded.image.height,
        cm_str,
        decoded.image.pixel_format.bit_depth as u32
    );
    fs::write(&meta_path, meta_content)
        .map_err(|e| format!("failed to write metadata sidecar '{meta_path}': {e}"))?;

    if m.get_flag("json") {
        println!(
            "{{\"status\":\"decoded\",\"format\":\"ZIMG\",\"width\":{},\"height\":{},\"bytes\":{},\"encrypted\":{},\"integrity_verified\":{}}}",
            decoded.image.width, decoded.image.height, decoded.image.data.len(),
            decoded.encrypted, decoded.integrity_verified
        );
    } else {
        println!(
            "decoded {}x{} -> {} ({} bytes)",
            decoded.image.width,
            decoded.image.height,
            output_path,
            decoded.image.data.len()
        );
    }
    Ok(())
}

fn cmd_image_inspect(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;

    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    if hdr.format_id() != FormatId::ZIMG {
        return Err(format!(
            "not a ZIMG image (format id {:#010x})",
            hdr.format_id().raw()
        ));
    }
    let password = resolve_password(m, hdr.flags().is_encrypted(), false)?;

    let opts = DecodeOptions {
        password,
        verify_integrity: false,
        ..DecodeOptions::default()
    };
    let decoded = decode_image(&raw, &opts).map_err(|e| e.to_string())?;

    if m.get_flag("json") {
        println!(
            "{{\"format\":\"ZIMG\",\"version\":\"{}.{}\",\"width\":{},\"height\":{},\"color_model\":\"{:?}\",\"bit_depth\":{},\"channels\":{},\"color_space\":\"{:?}\",\"encrypted\":{},\"integrity_verified\":{},\"file_size\":{}}}",
            znf_img::ZIMG_SPEC_VERSION.0, znf_img::ZIMG_SPEC_VERSION.1,
            decoded.image.width, decoded.image.height,
            decoded.image.pixel_format.color_model,
            decoded.image.pixel_format.bit_depth as u32,
            decoded.image.pixel_format.channel_count,
            decoded.image.pixel_format.color_space,
            decoded.encrypted, decoded.integrity_verified,
            raw.len()
        );
    } else {
        println!("ZIMG Image Inspection");
        println!("  File:            {path} ({} bytes)", raw.len());
        println!(
            "  Format:          ZIMG v{}.{}",
            znf_img::ZIMG_SPEC_VERSION.0,
            znf_img::ZIMG_SPEC_VERSION.1
        );
        println!(
            "  Dimensions:      {} x {}",
            decoded.image.width, decoded.image.height
        );
        println!(
            "  Color model:     {:?} ({} channels, {:?}-bit, alpha={:?})",
            decoded.image.pixel_format.color_model,
            decoded.image.pixel_format.channel_count,
            decoded.image.pixel_format.bit_depth,
            decoded.image.pixel_format.alpha
        );
        println!(
            "  Color space:     {:?}",
            decoded.image.pixel_format.color_space
        );
        println!("  Encrypted:       {}", decoded.encrypted);
        println!("  Integrity:       {}", decoded.integrity_verified);
        if !decoded.metadata.title.as_deref().unwrap_or("").is_empty() {
            println!(
                "  Title:           {}",
                decoded.metadata.title.as_deref().unwrap_or("")
            );
        }
        if !decoded
            .metadata
            .description
            .as_deref()
            .unwrap_or("")
            .is_empty()
        {
            println!(
                "  Description:     {}",
                decoded.metadata.description.as_deref().unwrap_or("")
            );
        }
        if !decoded.metadata.creator.as_deref().unwrap_or("").is_empty() {
            println!(
                "  Creator:         {}",
                decoded.metadata.creator.as_deref().unwrap_or("")
            );
        }
    }
    Ok(())
}

fn cmd_image_verify(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;

    let password = resolve_password(m, false, false)?;
    let opts = DecodeOptions {
        password,
        verify_integrity: true,
        ..DecodeOptions::default()
    };

    let decoded = decode_image(&raw, &opts).map_err(|e| e.to_string())?;

    if m.get_flag("json") {
        println!(
            "{{\"valid\":true,\"encrypted\":{},\"integrity_verified\":{},\"pixels_verified\":{}}}",
            decoded.encrypted,
            decoded.integrity_verified,
            decoded.image.total_pixels()
        );
    } else {
        println!("OK: verified '{}'", path);
        println!(
            "  Pixels:          {} x {} = {}",
            decoded.image.width,
            decoded.image.height,
            decoded.image.total_pixels()
        );
        println!("  Encrypted:       {}", decoded.encrypted);
        println!("  Integrity:       {}", decoded.integrity_verified);
    }
    Ok(())
}

fn cmd_image_metadata(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;

    let password = resolve_password(m, false, false)?;
    let opts = DecodeOptions {
        password,
        verify_integrity: false,
        ..DecodeOptions::default()
    };

    let decoded = decode_image(&raw, &opts).map_err(|e| e.to_string())?;

    if m.get_flag("remove") {
        let output_path = m
            .get_one::<String>("output")
            .ok_or_else(|| "--output is required with --remove".to_string())?;
        let overwrite = m.get_flag("overwrite");
        let output = std::path::Path::new(output_path);
        if output.exists() && !overwrite {
            return Err(format!(
                "output file already exists (pass --overwrite to replace): {}",
                output.display()
            ));
        }

        let kdf_params = if password.is_some() {
            Some(
                znf_crypto::KdfParams::new_default()
                    .map_err(|e| format!("KDF parameter generation failed: {e}"))?,
            )
        } else {
            None
        };
        let opts2 = EncodeOptions {
            compression: znf_compression::Config::zstd(3),
            filter: FilterType::None,
            password,
            kdf_params,
            chunk_strategy: ChunkStrategy::default(),
            include_integrity: true,
        };
        let encoded = encode_image(&decoded.image, &opts2).map_err(|e| e.to_string())?;
        fs::write(output, &encoded.bytes)
            .map_err(|e| format!("failed to write '{output_path}': {e}"))?;
        if m.get_flag("json") {
            println!(
                "{{\"status\":\"metadata_removed\",\"output\":\"{}\"}}",
                json_escape(output_path)
            );
        } else {
            println!("metadata removed -> {}", output.display());
        }
    } else {
        if m.get_flag("json") {
            println!(
                "{{\"title\":{},\"description\":{},\"creator\":{},\"created\":{},\"software\":{},\"copyright\":{},\"custom_entries\":{}}}",
                json_escape_option(&decoded.metadata.title),
                json_escape_option(&decoded.metadata.description),
                json_escape_option(&decoded.metadata.creator),
                json_escape_option(&decoded.metadata.created),
                json_escape_option(&decoded.metadata.software),
                json_escape_option(&decoded.metadata.copyright),
                decoded.metadata.custom.len()
            );
        } else {
            println!("Image Metadata");
            if let Some(t) = &decoded.metadata.title {
                println!("  Title:       {t}");
            }
            if let Some(d) = &decoded.metadata.description {
                println!("  Description: {d}");
            }
            if let Some(c) = &decoded.metadata.creator {
                println!("  Creator:     {c}");
            }
            if let Some(c) = &decoded.metadata.created {
                println!("  Created:     {c}");
            }
            if let Some(s) = &decoded.metadata.software {
                println!("  Software:    {s}");
            }
            if let Some(c) = &decoded.metadata.copyright {
                println!("  Copyright:   {c}");
            }
            if !decoded.metadata.custom.is_empty() {
                println!("  Custom ({} entries):", decoded.metadata.custom.len());
                for (k, v) in &decoded.metadata.custom {
                    println!("    {k}: {v}");
                }
            }
        }
    }
    Ok(())
}

fn json_escape_option(s: &Option<String>) -> String {
    match s {
        Some(v) => format!("\"{}\"", json_escape(v)),
        None => "null".to_string(),
    }
}

fn cmd_image_info(m: &ArgMatches) -> Result<(), String> {
    let path = m.get_one::<String>("file").unwrap();
    let raw = fs::read(path).map_err(|e| format!("failed to read '{path}': {e}"))?;

    let hdr = znf_core::Header::decode(&raw, &znf_core::Limits::default(), Some(raw.len() as u64))
        .map_err(|e| e.to_string())?;
    if hdr.format_id() != FormatId::ZIMG {
        return Err(format!(
            "not a ZIMG image (format id {:#010x})",
            hdr.format_id().raw()
        ));
    }
    let password = resolve_password(m, hdr.flags().is_encrypted(), false)?;

    let opts = DecodeOptions {
        password,
        verify_integrity: true,
        ..DecodeOptions::default()
    };
    let decoded = decode_image(&raw, &opts).map_err(|e| e.to_string())?;

    if m.get_flag("json") {
        println!(
            "{{\"format\":\"ZIMG\",\"version\":\"{}.{}\",\"file_size\":{},\"width\":{},\"height\":{},\"total_pixels\":{},\"color_model\":\"{:?}\",\"bit_depth\":{},\"channels\":{},\"color_space\":\"{:?}\",\"encrypted\":{},\"integrity_verified\":{}}}",
            znf_img::ZIMG_SPEC_VERSION.0, znf_img::ZIMG_SPEC_VERSION.1,
            raw.len(),
            decoded.image.width, decoded.image.height, decoded.image.total_pixels(),
            decoded.image.pixel_format.color_model,
            decoded.image.pixel_format.bit_depth as u32,
            decoded.image.pixel_format.channel_count,
            decoded.image.pixel_format.color_space,
            decoded.encrypted, decoded.integrity_verified
        );
    } else {
        println!("ZIMG Image Information");
        println!("  File:            {path} ({} bytes)", raw.len());
        println!(
            "  Format:          ZIMG v{}.{}",
            znf_img::ZIMG_SPEC_VERSION.0,
            znf_img::ZIMG_SPEC_VERSION.1
        );
        println!(
            "  Dimensions:      {} x {}",
            decoded.image.width, decoded.image.height
        );
        println!("  Total pixels:    {}", decoded.image.total_pixels());
        println!(
            "  Color model:     {:?} ({} channels)",
            decoded.image.pixel_format.color_model, decoded.image.pixel_format.channel_count
        );
        println!(
            "  Bit depth:       {:?}-bit per sample",
            decoded.image.pixel_format.bit_depth
        );
        println!("  Alpha:           {:?}", decoded.image.pixel_format.alpha);
        println!(
            "  Color space:     {:?}",
            decoded.image.pixel_format.color_space
        );
        println!("  Row stride:      {} bytes", decoded.image.stride);
        println!("  Data bytes:      {}", decoded.image.data.len());
        println!("  Encrypted:       {}", decoded.encrypted);
        println!("  Integrity:       {}", decoded.integrity_verified);
    }
    Ok(())
}

fn cmd_image_optimize(m: &ArgMatches) -> Result<(), String> {
    let input_path = m.get_one::<String>("input").unwrap();
    let output_path = m.get_one::<String>("output").unwrap();
    let raw = fs::read(input_path).map_err(|e| format!("failed to read '{input_path}': {e}"))?;

    let password = resolve_password(m, false, false)?;
    let opts = DecodeOptions {
        password,
        verify_integrity: true,
        ..DecodeOptions::default()
    };
    let decoded = decode_image(&raw, &opts).map_err(|e| e.to_string())?;

    if !decoded.integrity_verified {
        return Err("source image failed integrity verification; refusing to optimize".into());
    }

    let algo_str = m.get_one::<String>("compression").unwrap().as_str();
    let level: i32 = m
        .get_one::<String>("level")
        .unwrap()
        .parse()
        .map_err(|_| "invalid compression level (expected integer 1..22)".to_string())?;
    let compression = match algo_str {
        "zstd" => znf_compression::Config::zstd(level),
        "lz4" => znf_compression::Config::lz4(),
        "store" | "none" => znf_compression::Config::stored(),
        other => {
            return Err(format!(
                "unsupported compression '{other}' (expected zstd, lz4, or store)"
            ))
        }
    };

    let overwrite = m.get_flag("overwrite");
    let output = std::path::Path::new(output_path);
    if output.exists() && !overwrite {
        return Err(format!(
            "output file already exists (pass --overwrite to replace): {}",
            output.display()
        ));
    }

    let kdf_params = if password.is_some() {
        Some(
            znf_crypto::KdfParams::new_default()
                .map_err(|e| format!("KDF parameter generation failed: {e}"))?,
        )
    } else {
        None
    };
    let opts2 = EncodeOptions {
        compression,
        filter: FilterType::None,
        password,
        kdf_params,
        chunk_strategy: ChunkStrategy::default(),
        include_integrity: true,
    };
    let encoded = encode_image(&decoded.image, &opts2).map_err(|e| e.to_string())?;

    fs::write(output, &encoded.bytes)
        .map_err(|e| format!("failed to write '{output_path}': {e}"))?;

    if m.get_flag("json") {
        println!(
            "{{\"status\":\"optimized\",\"input_bytes\":{},\"output_bytes\":{},\"stored_bytes\":{},\"ratio\":{:.4}}}",
            raw.len(), encoded.bytes.len(), encoded.info.stored_len,
            raw.len() as f64 / encoded.bytes.len() as f64
        );
    } else {
        println!(
            "optimized {} -> {} ({} bytes stored)",
            input_path,
            output.display(),
            encoded.info.stored_len
        );
    }
    Ok(())
}
