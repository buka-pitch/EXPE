use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use expe_core::{ExpeError, Result};

/// Deterministically expand files and directories. Symlinks are never followed,
/// non-regular files are skipped, and results are sorted for reproducible output.
pub fn discover_files(paths: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for path in paths {
        collect(path, recursive, &mut files)?;
    }
    Ok(files.into_iter().collect())
}

fn collect(path: &Path, recursive: bool, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ExpeError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        out.insert(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    if !recursive {
        // Non-recursive directory scan still accepts direct children.
        let entries = std::fs::read_dir(path).map_err(|source| ExpeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| ExpeError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let child = entry.path();
            let child_meta = std::fs::symlink_metadata(&child).map_err(|source| ExpeError::Io {
                path: child.clone(),
                source,
            })?;
            if child_meta.is_file() && !child_meta.file_type().is_symlink() {
                out.insert(child);
            }
        }
        return Ok(());
    }

    let entries = std::fs::read_dir(path).map_err(|source| ExpeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ExpeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        collect(&entry.path(), true, out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn discovers_recursively_and_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(dir.path().join("a.bin"), b"a").unwrap();
        fs::write(nested.join("b.bin"), b"b").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("a.bin"), dir.path().join("link.bin")).unwrap();

        let files = discover_files(&[dir.path().to_path_buf()], true).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.bin", "b.bin"]);
    }
}
