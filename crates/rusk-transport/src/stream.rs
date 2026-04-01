//! Streaming hash reader for SHA-256 verification during download.
//!
//! Wraps any `Read` source and computes a SHA-256 digest as bytes flow
//! through, allowing verification without buffering the entire payload.

use rusk_core::Sha256Digest;
use sha2::{Digest, Sha256};
use std::io::{self, Read};

/// A reader wrapper that computes SHA-256 as data passes through.
///
/// Usage:
/// ```no_run
/// use rusk_transport::StreamingHashReader;
/// let data = b"hello world";
/// let mut reader = StreamingHashReader::new(&data[..]);
/// let content = reader.read_all().unwrap();
/// let digest = reader.finalize();
/// ```
pub struct StreamingHashReader<R: Read> {
    inner: R,
    hasher: Sha256,
    bytes_read: u64,
}

impl<R: Read> StreamingHashReader<R> {
    /// Wrap a reader with SHA-256 hashing.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_read: 0,
        }
    }

    /// Consume the reader and return the computed SHA-256 digest.
    ///
    /// This must be called after all data has been read; it finalizes
    /// the hash computation.
    pub fn finalize(self) -> Sha256Digest {
        let hash = self.hasher.finalize();
        Sha256Digest(hash.into())
    }

    /// Total number of bytes that have passed through this reader.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Read all remaining bytes into a Vec, updating the hash as we go.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = self.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok(buf)
    }

    /// Read exactly `len` bytes, updating the hash.
    pub fn read_exact_hashed(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;
        self.hasher.update(&buf);
        self.bytes_read += len as u64;
        Ok(buf)
    }
}

impl<R: Read> Read for StreamingHashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.bytes_read += n as u64;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_hash_matches_direct_hash() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let expected = Sha256Digest::compute(data);

        let mut reader = StreamingHashReader::new(&data[..]);
        let read_data = reader.read_all().unwrap();
        let digest = reader.finalize();

        assert_eq!(read_data, data);
        assert_eq!(digest, expected);
    }

    #[test]
    fn empty_input_yields_empty_hash() {
        let data: &[u8] = b"";
        let expected = Sha256Digest::compute(data);

        let mut reader = StreamingHashReader::new(data);
        let _ = reader.read_all().unwrap();
        let digest = reader.finalize();

        assert_eq!(digest, expected);
    }

    #[test]
    fn bytes_read_tracks_correctly() {
        let data = b"hello world";
        let mut reader = StreamingHashReader::new(&data[..]);
        let _ = reader.read_all().unwrap();
        assert_eq!(reader.bytes_read(), data.len() as u64);
    }
}
