/// 计算 blake3 哈希
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// 验证 blake3 哈希
pub fn verify_blake3(data: &[u8], expected: &[u8]) -> bool {
    let hash = blake3_hash(data);
    hash.as_slice() == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_roundtrip() {
        let data = b"hello pcm";
        let hash = blake3_hash(data);
        assert!(verify_blake3(data, &hash));
        assert!(!verify_blake3(b"wrong data", &hash));
    }
}
