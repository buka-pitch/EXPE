use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use expe_core::{ArtifactBytes, ArtifactReader, ExpeError, Hashes, Limits, Result};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const CHUNK: usize = 64 * 1024;

/// Read-only file reader. Refuses non-regular files, follows no symlinks at the
/// metadata layer and hashes while reading so the file is never walked twice.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileReader;

impl ArtifactReader for FileReader {
    fn read(&self, path: &Path, limits: &Limits) -> Result<ArtifactBytes> {
        let metadata = std::fs::symlink_metadata(path).map_err(|source| ExpeError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        if metadata.file_type().is_symlink() {
            return Err(ExpeError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "symbolic links are refused; pass the target path explicitly",
                ),
            });
        }

        if !metadata.is_file() {
            return Err(ExpeError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a regular file (directories, devices and FIFOs are refused)",
                ),
            });
        }

        if metadata.len() > limits.max_file_size {
            return Err(ExpeError::LimitExceeded(format!(
                "{} is {} bytes; maximum accepted size is {} bytes",
                path.display(),
                metadata.len(),
                limits.max_file_size
            )));
        }

        let mut file = File::open(path).map_err(|source| ExpeError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let mut bytes =
            Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0).min(1 << 26));
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut chunk = vec![0_u8; CHUNK];

        loop {
            let read = file.read(&mut chunk).map_err(|source| ExpeError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            if read == 0 {
                break;
            }
            if bytes.len().saturating_add(read)
                > usize::try_from(limits.max_file_size).unwrap_or(usize::MAX)
            {
                return Err(ExpeError::LimitExceeded(format!(
                    "{} grew past the {} byte cap while reading",
                    path.display(),
                    limits.max_file_size
                )));
            }
            let slice = &chunk[..read];
            md5.update(slice);
            sha1.update(slice);
            sha256.update(slice);
            bytes.extend_from_slice(slice);
        }

        let hashes = Hashes {
            md5: super::hashing::hex_digest(md5),
            sha1: super::hashing::hex_digest(sha1),
            sha256: super::hashing::hex_digest(sha256),
            imphash: None,
        };

        Ok(ArtifactBytes {
            bytes: Arc::from(bytes),
            hashes,
        })
    }
}

/// Helper used by callers that already hold bytes (TUI retry, tests, stdin).
pub fn bytes_from_vec(bytes: Vec<u8>, hashes: Hashes) -> ArtifactBytes {
    ArtifactBytes {
        bytes: Arc::from(bytes),
        hashes,
    }
}

/// Resolve a path without accidentally traversing a symlink for batch scans.
pub fn ensure_regular_file(path: &Path) -> Result<PathBuf> {
    let meta = std::fs::symlink_metadata(path).map_err(|source| ExpeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.file_type().is_symlink() {
        return Err(ExpeError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "symlinks are skipped by default",
            ),
        });
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_directories() {
        let dir = tempfile::tempdir().unwrap();
        let error = FileReader.read(dir.path(), &Limits::default()).unwrap_err();
        assert!(error.to_string().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.bin");
        std::fs::write(&target, b"MZ").unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = FileReader.read(&link, &Limits::default()).unwrap_err();
        assert!(error.to_string().contains("symbolic links"));
    }
}
