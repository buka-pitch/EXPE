use expe_core::Hashes;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[must_use]
pub fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[must_use]
pub fn hex_digest<D: Digest>(digest: D) -> String {
    hex_bytes(&digest.finalize())
}

#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> Hashes {
    Hashes {
        md5: hex_bytes(&Md5::digest(bytes)),
        sha1: hex_bytes(&Sha1::digest(bytes)),
        sha256: hex_bytes(&Sha256::digest(bytes)),
        imphash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hashes_are_well_known() {
        let hashes = hash_bytes(b"");
        assert_eq!(hashes.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hashes.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hashes.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_abc() {
        let hashes = hash_bytes(b"abc");
        assert_eq!(hashes.sha256.len(), 64);
        assert_eq!(hashes.imphash, None);
    }
}
