#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used, dead_code)]

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

pub fn vectors_dir() -> PathBuf {
    let mut path = workspace_root();
    path.push("tests");
    path.push("vectors");
    path.push("format-v1");
    path
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = {
        let mut p = vectors_dir();
        p.push(name);
        p
    };
    fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} not found at {}: {e}", path.display()))
}

pub fn fixture_string(name: &str) -> String {
    let path = {
        let mut p = vectors_dir();
        p.push(name);
        p
    };
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {name} not found at {}: {e}", path.display()))
}

pub fn manifest_json() -> serde_json::Value {
    let text = fixture_string("manifest.json");
    serde_json::from_str(&text).expect("manifest.json is valid JSON")
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

pub fn mutate_byte(data: &mut [u8]) {
    if !data.is_empty() {
        data[0] = data[0].wrapping_add(1);
    }
}

/// Create a temporary directory that is automatically cleaned up on drop.
pub struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    pub fn new(prefix: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("{}-{}", prefix, std::process::id()));
        fs::create_dir_all(&path).expect("create temp repo dir");
        TempRepo { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_fixture_checksum() {
        let manifest = manifest_json();
        let fixtures = manifest["fixtures"].as_array().expect("fixtures array");
        assert!(!fixtures.is_empty(), "at least one fixture");

        for entry in fixtures {
            let filename = entry["filename"].as_str().expect("filename");
            let expected = entry["sha256"].as_str().expect("sha256").to_lowercase();
            let data = fixture_bytes(filename);
            let actual = sha256_hex(&data);
            assert_eq!(actual, expected, "SHA-256 mismatch for {filename}");
        }
    }

    #[test]
    fn temp_repo_creates_and_cleans_up() {
        let repo = TempRepo::new("test-eternal");
        assert!(repo.path().exists());
        let p = repo.path().to_owned();
        drop(repo);
        assert!(!p.exists());
    }
}
