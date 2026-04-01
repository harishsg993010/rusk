//! Binary lockfile support.
//!
//! Provides an optional compact binary encoding of the lockfile for
//! faster reads in large projects. The canonical format remains TOML
//! but this binary format can be used as a cache.

use rusk_core::Sha256Digest;
use std::io::{self, Read, Write};
use std::path::Path;

/// Magic bytes identifying a rusk binary lockfile.
const MAGIC: &[u8; 4] = b"RSLK";
/// Current binary lockfile format version.
const FORMAT_VERSION: u32 = 1;

/// Header of a binary lockfile.
#[derive(Clone, Debug)]
pub struct BinaryLockfileHeader {
    pub format_version: u32,
    pub package_count: u32,
    pub content_hash: Sha256Digest,
}

/// Write a binary lockfile cache alongside the TOML lockfile.
pub fn write_binary_cache(
    lockfile_path: &Path,
    content_hash: Sha256Digest,
    package_count: u32,
    serialized_data: &[u8],
) -> io::Result<()> {
    let cache_path = lockfile_path.with_extension("lock.bin");
    let mut file = std::fs::File::create(&cache_path)?;

    file.write_all(MAGIC)?;
    file.write_all(&FORMAT_VERSION.to_le_bytes())?;
    file.write_all(&package_count.to_le_bytes())?;
    file.write_all(&content_hash.0)?;
    file.write_all(serialized_data)?;

    Ok(())
}

/// Try to read a binary lockfile cache. Returns None if missing or invalid.
pub fn read_binary_cache(lockfile_path: &Path) -> io::Result<Option<(BinaryLockfileHeader, Vec<u8>)>> {
    let cache_path = lockfile_path.with_extension("lock.bin");
    if !cache_path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(&cache_path)?;
    if data.len() < 4 + 4 + 4 + 32 {
        return Ok(None); // Too small to be valid
    }

    // Verify magic bytes
    if &data[..4] != MAGIC {
        return Ok(None);
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Ok(None);
    }

    let package_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let hash_bytes: [u8; 32] = data[12..44].try_into().unwrap();
    let content_hash = Sha256Digest(hash_bytes);

    let header = BinaryLockfileHeader {
        format_version: version,
        package_count,
        content_hash,
    };

    let payload = data[44..].to_vec();
    Ok(Some((header, payload)))
}

/// Invalidate the binary cache by deleting it.
pub fn invalidate_binary_cache(lockfile_path: &Path) -> io::Result<()> {
    let cache_path = lockfile_path.with_extension("lock.bin");
    if cache_path.exists() {
        std::fs::remove_file(&cache_path)?;
    }
    Ok(())
}
