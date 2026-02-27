//! 证书二进制序列化（wire format）
//!
//! 格式：
//! ```text
//! [4B magic "PCMC"] [2B version=1] [2B flags=0]
//! [32B policy_hash] [32B graph_hash] [32B request_hash]
//! [4B num_steps]
//! 每个 step:
//!   [4B rule_index] [4B num_premises] [4B × num_premises premise_indices...]
//!   [4B predicate_len] [predicate_len bytes predicate]
//!   [4B num_args]
//!   每个 arg: [4B arg_len] [arg_len bytes arg]
//! ```

use crate::generator::{CertStep, CertificateData, SerializedAtom};
use pcm_common::error::PcmError;

/// 魔数
const MAGIC: &[u8; 4] = b"PCMC";
/// 当前版本
const VERSION: u16 = 1;

// ──────────────────────────────────────────────
// 序列化
// ──────────────────────────────────────────────

/// 将证书序列化为紧凑二进制格式
pub fn serialize_certificate(cert: &CertificateData) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags

    // Hashes
    buf.extend_from_slice(&cert.policy_hash);
    buf.extend_from_slice(&cert.graph_hash);
    buf.extend_from_slice(&cert.request_hash);

    // Steps
    buf.extend_from_slice(&(cert.steps.len() as u32).to_le_bytes());
    for step in &cert.steps {
        write_step(&mut buf, step);
    }

    buf
}

fn write_step(buf: &mut Vec<u8>, step: &CertStep) {
    buf.extend_from_slice(&step.rule_index.to_le_bytes());
    buf.extend_from_slice(&(step.premise_indices.len() as u32).to_le_bytes());
    for &pidx in &step.premise_indices {
        buf.extend_from_slice(&pidx.to_le_bytes());
    }
    write_serialized_atom(buf, &step.conclusion);
}

fn write_serialized_atom(buf: &mut Vec<u8>, atom: &SerializedAtom) {
    let pred_bytes = atom.predicate.as_bytes();
    buf.extend_from_slice(&(pred_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(pred_bytes);

    buf.extend_from_slice(&(atom.args.len() as u32).to_le_bytes());
    for arg in &atom.args {
        let arg_bytes = arg.as_bytes();
        buf.extend_from_slice(&(arg_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(arg_bytes);
    }
}

// ──────────────────────────────────────────────
// 反序列化
// ──────────────────────────────────────────────

/// 从二进制反序列化证书
pub fn deserialize_certificate(data: &[u8]) -> Result<CertificateData, PcmError> {
    let mut cursor = Cursor::new(data);

    // Magic
    let magic = cursor.read_bytes(4)?;
    if magic != MAGIC {
        return Err(PcmError::CertVerification(format!(
            "invalid magic: expected PCMC, got {:?}",
            magic
        )));
    }

    // Version
    let version = cursor.read_u16()?;
    if version != VERSION {
        return Err(PcmError::CertVerification(format!(
            "unsupported version: {}",
            version
        )));
    }

    // Flags (reserved)
    let _flags = cursor.read_u16()?;

    // Hashes
    let policy_hash = cursor.read_hash()?;
    let graph_hash = cursor.read_hash()?;
    let request_hash = cursor.read_hash()?;

    // Steps
    let num_steps = cursor.read_u32()? as usize;
    let mut steps = Vec::with_capacity(num_steps);
    for _ in 0..num_steps {
        steps.push(read_step(&mut cursor)?);
    }

    if cursor.pos != cursor.data.len() {
        return Err(PcmError::CertVerification(format!(
            "trailing data: {} bytes remaining",
            cursor.data.len() - cursor.pos
        )));
    }

    Ok(CertificateData {
        steps,
        policy_hash,
        graph_hash,
        request_hash,
    })
}

fn read_step(cursor: &mut Cursor) -> Result<CertStep, PcmError> {
    let rule_index = cursor.read_u32()?;
    let num_premises = cursor.read_u32()? as usize;
    let mut premise_indices = Vec::with_capacity(num_premises);
    for _ in 0..num_premises {
        premise_indices.push(cursor.read_u32()?);
    }
    let conclusion = read_serialized_atom(cursor)?;
    Ok(CertStep {
        rule_index,
        premise_indices,
        conclusion,
    })
}

fn read_serialized_atom(cursor: &mut Cursor) -> Result<SerializedAtom, PcmError> {
    let predicate = cursor.read_string()?;
    let num_args = cursor.read_u32()? as usize;
    let mut args = Vec::with_capacity(num_args);
    for _ in 0..num_args {
        args.push(cursor.read_string()?);
    }
    Ok(SerializedAtom { predicate, args })
}

// ──────────────────────────────────────────────
// 简单游标
// ──────────────────────────────────────────────

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], PcmError> {
        if self.remaining() < n {
            return Err(PcmError::CertVerification(format!(
                "unexpected EOF: need {} bytes, have {}",
                n,
                self.remaining()
            )));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, PcmError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, PcmError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], PcmError> {
        let bytes = self.read_bytes(32)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(bytes);
        Ok(hash)
    }

    fn read_string(&mut self) -> Result<String, PcmError> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| {
            PcmError::CertVerification(format!("invalid UTF-8 string: {}", e))
        })
    }
}

// ──────────────────────────────────────────────
// 测试
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> CertificateData {
        CertificateData {
            steps: vec![
                CertStep {
                    rule_index: 0,
                    premise_indices: vec![],
                    conclusion: SerializedAtom {
                        predicate: "has_role".to_string(),
                        args: vec!["alice".to_string(), "admin".to_string()],
                    },
                },
                CertStep {
                    rule_index: 1,
                    premise_indices: vec![0, 1],
                    conclusion: SerializedAtom {
                        predicate: "action".to_string(),
                        args: vec![
                            "r1".to_string(),
                            "tool_call".to_string(),
                            "alice".to_string(),
                            "db".to_string(),
                        ],
                    },
                },
            ],
            policy_hash: [0xAA; 32],
            graph_hash: [0xBB; 32],
            request_hash: [0xCC; 32],
        }
    }

    #[test]
    fn test_serialize_roundtrip() {
        let cert = sample_cert();
        let bytes = serialize_certificate(&cert);
        let restored = deserialize_certificate(&bytes).unwrap();
        assert_eq!(cert, restored);
    }

    #[test]
    fn test_serialize_magic_header() {
        let cert = sample_cert();
        let bytes = serialize_certificate(&cert);
        assert_eq!(&bytes[0..4], b"PCMC");
    }

    #[test]
    fn test_serialize_empty_cert() {
        let cert = CertificateData {
            steps: vec![],
            policy_hash: [1u8; 32],
            graph_hash: [2u8; 32],
            request_hash: [3u8; 32],
        };
        let bytes = serialize_certificate(&cert);
        let restored = deserialize_certificate(&bytes).unwrap();
        assert_eq!(cert, restored);
    }

    #[test]
    fn test_deserialize_invalid_magic() {
        let mut bytes = serialize_certificate(&sample_cert());
        bytes[0] = b'X';
        let result = deserialize_certificate(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_truncated() {
        let bytes = serialize_certificate(&sample_cert());
        let result = deserialize_certificate(&bytes[..10]);
        assert!(result.is_err());
    }
}
