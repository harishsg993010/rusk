//! npm tarball extraction.
//!
//! Handles extracting npm package tarballs (.tgz) into the appropriate
//! node_modules directory, stripping the "package/" prefix that npm
//! tarballs use.

use flate2::read::GzDecoder;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::Archive;

/// Extract an npm tarball into the target directory.
///
/// npm tarballs are gzip-compressed tar archives containing a single
/// top-level directory (usually "package/"). This function decompresses,
/// iterates entries, strips that prefix, and writes each file into
/// `target_dir` so that `package/index.js` becomes `<target_dir>/index.js`.
pub fn extract_npm_tarball(
    tarball_data: &[u8],
    target_dir: &Path,
) -> io::Result<ExtractResult> {
    std::fs::create_dir_all(target_dir)?;

    tracing::debug!(
        target = %target_dir.display(),
        size = tarball_data.len(),
        "extracting npm tarball"
    );

    let gz = GzDecoder::new(tarball_data);
    let mut archive = Archive::new(gz);

    let mut files_extracted: usize = 0;
    let mut total_size: u64 = 0;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?.into_owned();

        // Strip the top-level directory prefix (usually "package/").
        // npm tarballs always have one top-level dir; we strip the first
        // component regardless of its name.
        let stripped = strip_first_component(&entry_path);
        let stripped = match stripped {
            Some(p) if !p.as_os_str().is_empty() => p,
            // Skip directory entries that consist solely of the prefix itself
            _ => continue,
        };

        let dest = target_dir.join(&stripped);

        // Ensure we never write outside the target directory (zip-slip protection).
        // We can't canonicalize dest yet because it doesn't exist; check that
        // the joined path starts with the target after normalization.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        {
            let dest_normalized = normalize_path(&dest);
            let target_normalized = normalize_path(target_dir);
            if !dest_normalized.starts_with(&target_normalized) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "tarball entry escapes target directory: {}",
                        entry_path.display()
                    ),
                ));
            }
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            std::fs::create_dir_all(&dest)?;
        } else if entry_type.is_file() || entry_type.is_hard_link() || entry_type == tar::EntryType::Regular {
            // Read entry data and write it out.
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            let size = data.len() as u64;
            std::fs::write(&dest, &data)?;

            // Restore file permissions on Unix-like systems.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mode) = entry.header().mode() {
                    let permissions = std::fs::Permissions::from_mode(mode);
                    let _ = std::fs::set_permissions(&dest, permissions);
                }
            }

            files_extracted += 1;
            total_size += size;
        } else if entry_type.is_symlink() {
            // npm tarballs should not contain symlinks for security reasons,
            // but if they do, we skip them.
            tracing::warn!(
                path = %entry_path.display(),
                "skipping symlink in npm tarball"
            );
        }
        // Other entry types (block devices, etc.) are silently skipped.
    }

    tracing::debug!(
        files = files_extracted,
        total_bytes = total_size,
        "tarball extraction complete"
    );

    Ok(ExtractResult {
        target_dir: target_dir.to_path_buf(),
        files_extracted,
        total_size,
    })
}

/// Strip the first path component (the top-level directory in the tarball).
fn strip_first_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    // Skip the first component.
    components.next()?;
    let remainder: PathBuf = components.collect();
    if remainder.as_os_str().is_empty() {
        None
    } else {
        Some(remainder)
    }
}

/// Normalize a path by resolving `.` and `..` without requiring the path to exist.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => {
                result.push(other.as_os_str());
            }
        }
    }
    result
}

/// Result of a tarball extraction.
#[derive(Clone, Debug)]
pub struct ExtractResult {
    /// Directory where files were extracted.
    pub target_dir: PathBuf,
    /// Number of files extracted.
    pub files_extracted: usize,
    /// Total size of extracted files.
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_first_component_works() {
        let p = Path::new("package/lib/index.js");
        let stripped = strip_first_component(p).unwrap();
        assert_eq!(stripped, Path::new("lib/index.js"));
    }

    #[test]
    fn strip_first_component_single() {
        let p = Path::new("package");
        assert!(strip_first_component(p).is_none());
    }

    #[test]
    fn strip_first_component_file_at_root() {
        let p = Path::new("package/README.md");
        let stripped = strip_first_component(p).unwrap();
        assert_eq!(stripped, Path::new("README.md"));
    }

    #[test]
    fn extract_real_tgz() {
        // Build a minimal .tgz in memory and verify extraction.
        let tgz_data = build_test_tgz();
        let tmp = tempfile::tempdir().unwrap();
        let result = extract_npm_tarball(&tgz_data, tmp.path()).unwrap();
        assert!(result.files_extracted > 0);

        // Verify a file was extracted.
        let index = tmp.path().join("index.js");
        assert!(index.exists());
        let contents = std::fs::read_to_string(&index).unwrap();
        assert_eq!(contents, "module.exports = 42;\n");
    }

    /// Helper: Build a minimal .tgz with a "package/" prefix.
    fn build_test_tgz() -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut encoder);

            // Add package/index.js
            let content = b"module.exports = 42;\n";
            let mut header = tar::Header::new_gnu();
            header.set_path("package/index.js").unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();

            // Add package/package.json
            let pkg_json = br#"{"name":"test","version":"1.0.0"}"#;
            let mut header2 = tar::Header::new_gnu();
            header2.set_path("package/package.json").unwrap();
            header2.set_size(pkg_json.len() as u64);
            header2.set_mode(0o644);
            header2.set_cksum();
            builder.append(&header2, &pkg_json[..]).unwrap();

            builder.finish().unwrap();
        }
        encoder.finish().unwrap()
    }
}
