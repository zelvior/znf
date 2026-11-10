//! Cross-platform path sanitization, depth bounds, and traversal prevention.
//!
//! Archive extraction is a high-risk surface: untrusted archives may include
//! `..`, leading `/`, Windows drive letters (`C:`), UNC paths (`\\server\share`
//! or `//server/share`), backslashes, NUL bytes, control characters, excessive
//! directory depth, or Windows reserved device names (`CON`, `NUL`, `COM1`).
//!
//! Every archive path in ZARC is validated by [`validate_archive_path`] before
//! storing or extracting. Valid filenames preserve their exact case and Unicode
//! characters without silent alteration.

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Maximum UTF-8 byte length of an archive entry path.
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum UTF-8 byte length of a single filename / path component.
pub const MAX_COMPONENT_LEN: usize = 255;

/// Default maximum directory nesting depth.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Errors when validating or normalizing an archive entry path.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Path is empty.
    #[error("archive entry path cannot be empty")]
    Empty,

    /// Path exceeds [`MAX_PATH_LEN`].
    #[error("path length {0} exceeds maximum {MAX_PATH_LEN}")]
    TooLong(usize),

    /// A single path component exceeds [`MAX_COMPONENT_LEN`].
    #[error("path component length {0} exceeds maximum {MAX_COMPONENT_LEN}")]
    ComponentTooLong(usize),

    /// Directory depth exceeds maximum allowed depth.
    #[error("path directory depth {depth} exceeds maximum {max}")]
    ExcessiveDepth {
        /// Depth of the path.
        depth: usize,
        /// Configured maximum depth.
        max: usize,
    },

    /// Path contains a NUL byte or ASCII control character.
    #[error("path contains forbidden control or NUL byte")]
    ControlOrNul,

    /// Path is absolute or starts with a root/drive prefix.
    #[error("absolute or rooted path is forbidden: {0}")]
    Absolute(String),

    /// Path is a Windows UNC or network share path (`\\server\share` or `//server/share`).
    #[error("UNC or network path is forbidden: {0}")]
    UncPath(String),

    /// Path contains `..` (parent directory traversal).
    #[error("parent directory traversal ('..') is forbidden: {0}")]
    ParentTraversal(String),

    /// Path component is a Windows reserved device name or ends with a forbidden dot/space.
    #[error("reserved device name or invalid Windows component in path: {0}")]
    ReservedDeviceName(String),

    /// Path is not valid UTF-8.
    #[error("path is not valid UTF-8")]
    InvalidUtf8,
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate and normalize an archive entry path with an explicit maximum directory depth.
///
/// Preserves exact case and Unicode codepoints of all valid components.
///
/// # Errors
///
/// Returns [`PathError`] if the path violates any security or length invariant.
pub fn validate_archive_path_with_depth(raw: &str, max_depth: usize) -> Result<String, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }
    if raw.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong(raw.len()));
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(PathError::ControlOrNul);
    }
    if raw.starts_with("//") || raw.starts_with("\\\\") {
        return Err(PathError::UncPath(raw.to_string()));
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(PathError::Absolute(raw.to_string()));
    }
    if raw.contains('\\') {
        return Err(PathError::Absolute(format!(
            "backslash separator forbidden in canonical archive path: {raw}"
        )));
    }
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
        if part.len() > MAX_COMPONENT_LEN {
            return Err(PathError::ComponentTooLong(part.len()));
        }
        if part.contains(':') {
            return Err(PathError::Absolute(raw.to_string()));
        }
        // Windows forbids components ending in a space or dot.
        if part.ends_with(' ') || part.ends_with('.') {
            return Err(PathError::ReservedDeviceName(part.to_string()));
        }
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
    if clean_parts.len() > max_depth {
        return Err(PathError::ExcessiveDepth {
            depth: clean_parts.len(),
            max: max_depth,
        });
    }
    Ok(clean_parts.join("/"))
}

/// Validate and normalize an archive entry path using [`DEFAULT_MAX_DEPTH`].
///
/// # Errors
///
/// Returns [`PathError`] if the path is unsafe or invalid.
pub fn validate_archive_path(raw: &str) -> Result<String, PathError> {
    validate_archive_path_with_depth(raw, DEFAULT_MAX_DEPTH)
}

/// Convert a local filesystem relative path into a canonical ZARC archive path.
///
/// Leading `./` is stripped; platform separators are converted to `/`;
/// parent (`..`), root, and prefix components are rejected.
///
/// # Errors
///
/// Returns [`PathError`] if the path is not valid UTF-8 or violates safety rules.
pub fn normalize_fs_path(path: &Path) -> Result<String, PathError> {
    let s_lossy = path.to_string_lossy();
    if s_lossy.starts_with("\\\\") || s_lossy.starts_with("//") {
        return Err(PathError::UncPath(s_lossy.into_owned()));
    }
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
/// # Errors
///
/// Returns [`PathError`] if `archive_path` is unsafe or exceeds `max_depth`.
pub fn safe_join_with_depth(
    dest_dir: &Path,
    archive_path: &str,
    max_depth: usize,
) -> Result<PathBuf, PathError> {
    let canonical = validate_archive_path_with_depth(archive_path, max_depth)?;
    let mut out = dest_dir.to_path_buf();
    for segment in canonical.split('/') {
        out.push(segment);
    }
    Ok(out)
}

/// Resolve a validated archive entry path safely under `dest_dir` with [`DEFAULT_MAX_DEPTH`].
///
/// # Errors
///
/// Returns [`PathError`] if `archive_path` is unsafe.
pub fn safe_join(dest_dir: &Path, archive_path: &str) -> Result<PathBuf, PathError> {
    safe_join_with_depth(dest_dir, archive_path, DEFAULT_MAX_DEPTH)
}

/// Produce a case-folded key for detecting case-insensitive path collisions
/// across platforms like Windows and macOS.
#[must_use]
pub fn case_fold_path(canonical_path: &str) -> String {
    canonical_path.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_and_unicode_relative_paths() {
        assert_eq!(validate_archive_path("src/lib.rs").unwrap(), "src/lib.rs");
        assert_eq!(
            validate_archive_path("docs/اردو/日本語/🚀.txt").unwrap(),
            "docs/اردو/日本語/🚀.txt"
        );
        // Case is preserved exactly.
        assert_eq!(
            validate_archive_path("Src/MyFile.TXT").unwrap(),
            "Src/MyFile.TXT"
        );
    }

    #[test]
    fn rejects_traversal_unc_and_absolute_paths() {
        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/../../b",
            "a/../..",
            "/etc/passwd",
            "//server/share/file.txt",
            "\\\\server\\share\\file.txt",
            "\\Windows\\System32",
            "a\\..\\b",
            "C:/Windows/System32",
            "C:foo",
            "dir/CON.txt",
            "aux",
            "lpt1.log",
            "trailingdot.",
            "trailingspace ",
            "bad\0name",
        ] {
            assert!(
                validate_archive_path(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_excessive_depth_and_long_components() {
        let deep = (0..70)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            validate_archive_path(&deep),
            Err(PathError::ExcessiveDepth { .. })
        ));

        let long_comp = "a".repeat(256);
        assert!(matches!(
            validate_archive_path(&long_comp),
            Err(PathError::ComponentTooLong(256))
        ));
    }
}
