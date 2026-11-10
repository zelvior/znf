//! Cross-platform path sanitization and traversal prevention.
//!
//! Archive extraction is a high-risk surface: untrusted archives often
//! include `..`, leading `/`, Windows drive letters (`C:`), backslashes,
//! NUL bytes, or reserved device names (`CON`, `NUL`, `COM1`) to escape
//! the destination directory.
//!
//! Every archive path in ZARC is canonicalized to forward-slash UTF-8
//! (`a/b/c.txt`) and validated by [`sanitize_relative_path`] before
//! storing OR extracting.

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Maximum UTF-8 byte length of an archive entry path.
pub const MAX_PATH_LEN: usize = 4096;

/// Errors when validating or normalizing an archive entry path.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Path is empty.
    #[error("archive entry path cannot be empty")]
    Empty,

    /// Path exceeds [`MAX_PATH_LEN`].
    #[error("path length {0} exceeds maximum {MAX_PATH_LEN}")]
    TooLong(usize),

    /// Path contains a NUL byte or control character.
    #[error("path contains forbidden control or NUL byte")]
    ControlOrNul,

    /// Path is absolute or starts with a root/drive prefix.
    #[error("absolute or rooted path is forbidden: {0}")]
    Absolute(String),

    /// Path contains `..` (parent directory traversal).
    #[error("parent directory traversal ('..') is forbidden: {0}")]
    ParentTraversal(String),

    /// Path component is a Windows reserved device name.
    #[error("reserved device name in path: {0}")]
    ReservedDeviceName(String),

    /// Path is not valid UTF-8.
    #[error("path is not valid UTF-8")]
    InvalidUtf8,
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate and normalize an archive entry path string to canonical
/// forward-slash relative form (`dir/subdir/file.txt`).
///
/// Rejects:
/// - Empty paths or paths that reduce to `.`
/// - Paths longer than [`MAX_PATH_LEN`]
/// - NUL bytes or ASCII control characters (`< 0x20` or `0x7F`)
/// - Leading `/` or `\`, or Windows drive prefixes (`C:`, `\\server\share`)
/// - Any `..` component
/// - Backslashes used as traversal (`..\`) — backslashes are rejected outright
///   in wire format; use [`normalize_fs_path`] when adding local OS paths.
/// - Windows reserved device names (`CON`, `NUL`, `COM1`, etc., even with extensions)
///
/// # Errors
///
/// Returns [`PathError`] if the path violates any security rule.
pub fn validate_archive_path(raw: &str) -> Result<String, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }
    if raw.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong(raw.len()));
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(PathError::ControlOrNul);
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(PathError::Absolute(raw.to_string()));
    }
    if raw.contains('\\') {
        return Err(PathError::Absolute(format!(
            "backslash forbidden in canonical archive path: {raw}"
        )));
    }
    // Check Windows drive prefix like "C:" on the first segment.
    if raw.len() >= 2 && raw.as_bytes()[1] == b':' {
        return Err(PathError::Absolute(raw.to_string()));
    }

    let mut clean_parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(PathError::ParentTraversal(raw.to_string()));
        }
        if part.contains(':') {
            return Err(PathError::Absolute(raw.to_string()));
        }
        // Windows trailing dot/space or reserved device names.
        let stem = part.split('.').next().unwrap_or(part);
        if WINDOWS_RESERVED
            .iter()
            .any(|&r| stem.eq_ignore_ascii_case(r))
        {
            return Err(PathError::ReservedDeviceName(part.to_string()));
        }
        clean_parts.push(part);
    }

    if clean_parts.is_empty() {
        return Err(PathError::Empty);
    }
    Ok(clean_parts.join("/"))
}

/// Convert a local filesystem relative path into a canonical ZARC archive path.
///
/// Leading `./` is stripped; platform separators are converted to `/`;
/// parent (`..`) and root components are rejected.
///
/// # Errors
///
/// Returns [`PathError`] if the path is not valid UTF-8 or violates safety rules.
pub fn normalize_fs_path(path: &Path) -> Result<String, PathError> {
    let mut parts = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => continue,
            Component::Normal(os) => {
                let s = os.to_str().ok_or(PathError::InvalidUtf8)?;
                parts.push(s);
            }
            Component::ParentDir => {
                return Err(PathError::ParentTraversal(path.display().to_string()))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PathError::Absolute(path.display().to_string()))
            }
        }
    }
    let joined = parts.join("/");
    validate_archive_path(&joined)
}

/// Resolve a validated archive entry path safely under `dest_dir`.
///
/// Guarantees that the returned path is strictly inside `dest_dir` by
/// validating every component through [`validate_archive_path`] and
/// joining only normal components.
///
/// # Errors
///
/// Returns [`PathError`] if `archive_path` is unsafe.
pub fn safe_join(dest_dir: &Path, archive_path: &str) -> Result<PathBuf, PathError> {
    let canonical = validate_archive_path(archive_path)?;
    let mut out = dest_dir.to_path_buf();
    for segment in canonical.split('/') {
        out.push(segment);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_relative_paths() {
        assert_eq!(validate_archive_path("src/lib.rs").unwrap(), "src/lib.rs");
        assert_eq!(validate_archive_path("a/./b//c.txt").unwrap(), "a/b/c.txt");
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/../../b",
            "a/../..",
            "/etc/passwd",
            "\\Windows\\System32",
            "a\\..\\b",
            "C:/Windows/System32",
            "C:foo",
            "dir/CON.txt",
            "aux",
            "lpt1.log",
            "bad\0name",
        ] {
            assert!(
                validate_archive_path(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }
}
