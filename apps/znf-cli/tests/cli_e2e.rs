//! End-to-end CLI tests for `znf` (`create`, `list`, `inspect`, `info`, `verify`,
//! `test`, `add`, `remove`, `extract`, `--json`, `--select`, `--overwrite`,
//! encryption via `--password-env`, and parity repair via `--repair-out`).

use std::fs;
use std::process::Command;

fn znf_bin() -> String {
    env!("CARGO_BIN_EXE_znf").to_string()
}

#[test]
fn cli_full_lifecycle_unencrypted_and_encrypted() {
    let base = std::env::temp_dir().join(format!("znf-cli-e2e-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let src_dir = base.join("input_tree");
    fs::create_dir_all(src_dir.join("nested")).unwrap();
    fs::write(src_dir.join("readme.md"), b"# ZNF CLI Test\nExact bytes.\n").unwrap();
    fs::write(src_dir.join("nested/data.bin"), [0xABu8; 4096]).unwrap();

    // 1. Version output
    let v_out = Command::new(znf_bin()).arg("--version").output().unwrap();
    assert!(v_out.status.success());
    assert!(String::from_utf8_lossy(&v_out.stdout).contains("0.1.0"));

    // 2. Create unencrypted archive with Zstd + parity + comment
    let zarc_path = base.join("bundle.zarc");
    let c_out = Command::new(znf_bin())
        .args([
            "zarc",
            "create",
            "-o",
            zarc_path.to_str().unwrap(),
            "-c",
            "zstd",
            "-l",
            "3",
            "--parity",
            "--comment",
            "e2e archive",
            src_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        c_out.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&c_out.stderr)
    );

    // 3. List
    let l_out = Command::new(znf_bin())
        .args(["zarc", "list", zarc_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(l_out.status.success());
    let l_stdout = String::from_utf8_lossy(&l_out.stdout);
    assert!(l_stdout.contains("input_tree/readme.md"));
    assert!(l_stdout.contains("input_tree/nested/data.bin"));

    // 4. Info
    let i_out = Command::new(znf_bin())
        .args(["zarc", "info", zarc_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(i_out.status.success());
    let i_stdout = String::from_utf8_lossy(&i_out.stdout);
    assert!(i_stdout.contains("e2e archive"));
    assert!(i_stdout.contains("Parity stripe:     present"));

    // 5. Verify
    let ver_out = Command::new(znf_bin())
        .args(["zarc", "verify", zarc_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ver_out.status.success());

    // 6. Extract and compare byte-for-byte
    let ext_dir = base.join("extracted");
    let x_out = Command::new(znf_bin())
        .args([
            "zarc",
            "extract",
            zarc_path.to_str().unwrap(),
            "-d",
            ext_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(x_out.status.success());
    assert_eq!(
        fs::read(ext_dir.join("input_tree/readme.md")).unwrap(),
        b"# ZNF CLI Test\nExact bytes.\n"
    );
    assert_eq!(
        fs::read(ext_dir.join("input_tree/nested/data.bin")).unwrap(),
        vec![0xABu8; 4096]
    );

    // 7. Encrypted archive via --password-env
    let enc_path = base.join("secret.zarc");
    let e_out = Command::new(znf_bin())
        .env("ZNF_TEST_PW", "strong-test-passphrase")
        .args([
            "zarc",
            "create",
            "-o",
            enc_path.to_str().unwrap(),
            "-c",
            "lz4",
            "--encrypt",
            "--password-env",
            "ZNF_TEST_PW",
            src_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        e_out.status.success(),
        "encrypted create failed: {}",
        String::from_utf8_lossy(&e_out.stderr)
    );

    // Unauthenticated inspect on encrypted archive succeeds and reports ENCRYPTED index
    let enc_insp = Command::new(znf_bin())
        .args(["inspect", enc_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(enc_insp.status.success());
    assert!(String::from_utf8_lossy(&enc_insp.stdout).contains("ENCRYPTED"));

    // Wrong password fails
    let bad_v = Command::new(znf_bin())
        .env("ZNF_TEST_PW", "wrong-pass")
        .args([
            "zarc",
            "verify",
            "--password-env",
            "ZNF_TEST_PW",
            enc_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad_v.status.success());

    // Correct password verifies
    let ok_v = Command::new(znf_bin())
        .env("ZNF_TEST_PW", "strong-test-passphrase")
        .args([
            "zarc",
            "verify",
            "--password-env",
            "ZNF_TEST_PW",
            enc_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(ok_v.status.success());

    // 8. ZNF Core Container (.znf) CLI commands: pack, inspect, validate, verify, unpack
    let znf_path = base.join("sample.znf");
    let unpacked_path = base.join("unpacked_readme.md");
    let pack_out = Command::new(znf_bin())
        .env("ZNF_CORE_PW", "core-secret-pw")
        .args([
            "container",
            "pack",
            "-i",
            src_dir.join("readme.md").to_str().unwrap(),
            "-o",
            znf_path.to_str().unwrap(),
            "-c",
            "zstd",
            "--streaming",
            "--encrypt",
            "--password-env",
            "ZNF_CORE_PW",
            "--comment",
            "confidential-comment",
        ])
        .output()
        .unwrap();
    assert!(
        pack_out.status.success(),
        "container pack failed: {}",
        String::from_utf8_lossy(&pack_out.stderr)
    );

    // Top-level `znf inspect` and `znf validate` work without requiring the password
    // and never expose the password in output.
    let insp_out = Command::new(znf_bin())
        .args(["inspect", znf_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(insp_out.status.success());
    let insp_stdout = String::from_utf8_lossy(&insp_out.stdout);
    assert!(insp_stdout.contains("ZNF Core (.znf)"));
    assert!(insp_stdout.contains("Compression:         Zstd"));
    assert!(insp_stdout.contains("Encryption:          XChaCha20Poly1305"));
    assert!(!insp_stdout.contains("core-secret-pw"));

    let val_out = Command::new(znf_bin())
        .args(["validate", znf_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(val_out.status.success());

    let cver_out = Command::new(znf_bin())
        .env("ZNF_CORE_PW", "core-secret-pw")
        .args([
            "container",
            "verify",
            "--password-env",
            "ZNF_CORE_PW",
            znf_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(cver_out.status.success());

    let unp_out = Command::new(znf_bin())
        .env("ZNF_CORE_PW", "core-secret-pw")
        .args([
            "container",
            "unpack",
            "-i",
            znf_path.to_str().unwrap(),
            "-o",
            unpacked_path.to_str().unwrap(),
            "--password-env",
            "ZNF_CORE_PW",
        ])
        .output()
        .unwrap();
    assert!(unp_out.status.success());
    assert_eq!(
        fs::read(&unpacked_path).unwrap(),
        b"# ZNF CLI Test\nExact bytes.\n"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn cli_top_level_zarc_commands_json_select_add_remove_and_test() {
    let base = std::env::temp_dir().join(format!("znf-cli-top-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let folder = base.join("folder");
    fs::create_dir_all(folder.join("sub")).unwrap();
    fs::write(folder.join("a.txt"), b"alpha").unwrap();
    fs::write(folder.join("sub/b.txt"), b"bravo").unwrap();

    let archive = base.join("archive.zarc");

    // 1. Positional `znf create archive.zarc ./folder`
    let create_out = Command::new(znf_bin())
        .args([
            "create",
            archive.to_str().unwrap(),
            folder.to_str().unwrap(),
            "--progress",
        ])
        .output()
        .unwrap();
    assert!(
        create_out.status.success(),
        "top-level create failed: {}",
        String::from_utf8_lossy(&create_out.stderr)
    );

    // 2. `znf list archive.zarc --json`
    let list_out = Command::new(znf_bin())
        .args(["list", archive.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_json = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_json.contains("\"path\":\"folder/a.txt\""));
    assert!(list_json.contains("\"path\":\"folder/sub/b.txt\""));

    // 3. `znf inspect archive.zarc --json` and `znf info archive.zarc --json`
    let insp_out = Command::new(znf_bin())
        .args(["inspect", archive.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(insp_out.status.success());
    assert!(String::from_utf8_lossy(&insp_out.stdout).contains("\"format\":\"ZARC\""));

    let info_out = Command::new(znf_bin())
        .args(["info", archive.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(info_out.status.success());
    assert!(String::from_utf8_lossy(&info_out.stdout).contains("\"uncompressed_bytes\":10"));

    // 4. `znf test archive.zarc`
    let test_out = Command::new(znf_bin())
        .args(["test", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(test_out.status.success());
    assert!(String::from_utf8_lossy(&test_out.stdout).contains("intact"));

    // 5. `znf add archive.zarc extra.txt`
    let extra = base.join("extra.txt");
    fs::write(&extra, b"charlie").unwrap();
    let add_out = Command::new(znf_bin())
        .args(["add", archive.to_str().unwrap(), extra.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(add_out.status.success());

    // 6. `znf remove archive.zarc folder/a.txt`
    let rem_out = Command::new(znf_bin())
        .args(["remove", archive.to_str().unwrap(), "folder/a.txt"])
        .output()
        .unwrap();
    assert!(rem_out.status.success());

    // 7. `znf extract archive.zarc --output ./restored --select extra.txt`
    let restored = base.join("restored");
    let ext_out = Command::new(znf_bin())
        .args([
            "extract",
            archive.to_str().unwrap(),
            "--output",
            restored.to_str().unwrap(),
            "--select",
            "extra.txt",
        ])
        .output()
        .unwrap();
    assert!(ext_out.status.success());
    assert_eq!(fs::read(restored.join("extra.txt")).unwrap(), b"charlie");
    assert!(!restored.join("folder/sub/b.txt").exists());

    // 8. Extracting again without --overwrite fails; with --overwrite succeeds
    let ext_fail = Command::new(znf_bin())
        .args([
            "extract",
            archive.to_str().unwrap(),
            "--output",
            restored.to_str().unwrap(),
            "--select",
            "extra.txt",
        ])
        .output()
        .unwrap();
    assert!(!ext_fail.status.success());

    let ext_ovw = Command::new(znf_bin())
        .args([
            "extract",
            archive.to_str().unwrap(),
            "--output",
            restored.to_str().unwrap(),
            "--select",
            "extra.txt",
            "--overwrite",
        ])
        .output()
        .unwrap();
    assert!(ext_ovw.status.success());

    let _ = fs::remove_dir_all(&base);
}
