//! PostgreSQL-backed audit log storage with Ed25519 signature chain.
//!
//! Each audit record is linked to the previous one via a hash chain,
//! and every link is signed with Ed25519 for tamper detection.

use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, QueryBuilder, Row};
use tokio::sync::Mutex;
use uuid::Uuid;

use pcm_common::hash::blake3_hash;
use pcm_common::proto::pcm_v1::{self, AuditRecord, Decision, Request as PcmRequest};

// ============================================================
// Query filter
// ============================================================

/// Filter criteria for [`AuditStore::query_logs`].
#[derive(Debug, Default)]
pub struct QueryFilter {
    pub principal: Option<String>,
    pub action_type: Option<i32>,
    pub verdict: Option<i32>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

// ============================================================
// Helpers
// ============================================================

/// Convert a `prost_types::Timestamp` to `chrono::DateTime<Utc>`.
fn ts_to_chrono(ts: &prost_types::Timestamp) -> DateTime<Utc> {
    DateTime::from_timestamp(ts.seconds, ts.nanos.max(0) as u32).unwrap_or_else(Utc::now)
}

/// Convert a `chrono::DateTime<Utc>` to `prost_types::Timestamp`.
fn chrono_to_ts(dt: &DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// Reconstruct an [`AuditRecord`] proto from a database row.
fn row_to_audit_record(row: &PgRow) -> AuditRecord {
    let record_id: String = row.get("record_id");
    let request_data: Vec<u8> = row.get("request_data");
    let decision_data: Vec<u8> = row.get("decision_data");
    let prev_hash: Option<Vec<u8>> = row.get("prev_hash");
    let record_hash: Vec<u8> = row.get("record_hash");
    let signature: Vec<u8> = row.get("signature");
    let logged_at: DateTime<Utc> = row.get("logged_at");

    let request = PcmRequest::decode(request_data.as_slice()).ok();
    let decision = Decision::decode(decision_data.as_slice()).ok();

    AuditRecord {
        record_id,
        request,
        decision,
        previous_record_hash: prev_hash.unwrap_or_default(),
        record_hash,
        signature,
        recorded_at: Some(chrono_to_ts(&logged_at)),
    }
}

// ============================================================
// AuditStore
// ============================================================

/// Audit log store backed by PostgreSQL with an Ed25519 signature chain.
pub struct AuditStore {
    pool: PgPool,
    signing_key: SigningKey,
    /// Hash of the most-recently-written record (signature chain head).
    last_hash: Arc<Mutex<Option<Vec<u8>>>>,
}

impl AuditStore {
    /// Create a new `AuditStore`, recovering the chain head from the database.
    pub async fn new(pool: PgPool, signing_key: SigningKey) -> Result<Self> {
        let last_hash: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT record_hash FROM audit_records ORDER BY logged_at DESC LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .context("failed to recover last audit hash")?;

        tracing::info!(
            chain_head = last_hash.as_ref().map(|h| hex::encode(h)),
            "audit store initialised"
        );

        Ok(Self {
            pool,
            signing_key,
            last_hash: Arc::new(Mutex::new(last_hash)),
        })
    }

    /// Return a reference to the underlying connection pool (useful for tests).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Return the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    // ----------------------------------------------------------------
    // log_decision
    // ----------------------------------------------------------------

    /// Persist a decision and extend the signature chain.
    ///
    /// Returns `(record_id, record_hash)`.
    pub async fn log_decision(
        &self,
        request: &PcmRequest,
        decision: &Decision,
    ) -> Result<(String, Vec<u8>)> {
        let record_id = Uuid::new_v4().to_string();

        // Extract fields for indexing columns
        let decided_at: DateTime<Utc> = decision
            .decided_at
            .as_ref()
            .map(ts_to_chrono)
            .unwrap_or_else(Utc::now);

        let verdict = decision.verdict;
        let policy_hash = decision.policy_version_hash.as_bytes().to_vec();
        let graph_hash: Option<Vec<u8>> = if decision.graph_snapshot_hash.is_empty() {
            None
        } else {
            Some(decision.graph_snapshot_hash.clone())
        };

        // Serialize evidence (Certificate or Witness) for storage
        let certificate: Option<Vec<u8>> = match &decision.evidence {
            Some(pcm_v1::decision::Evidence::Certificate(cert)) => Some(cert.encode_to_vec()),
            Some(pcm_v1::decision::Evidence::Witness(w)) => Some(w.encode_to_vec()),
            None => None,
        };

        // Full serialised protos for lossless reconstruction
        let request_data = request.encode_to_vec();
        let decision_data = decision.encode_to_vec();

        // record_hash = blake3(request_id || verdict || policy_hash || timestamp)
        let record_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(request.request_id.as_bytes());
            buf.extend_from_slice(&verdict.to_le_bytes());
            buf.extend_from_slice(&policy_hash);
            buf.extend_from_slice(decided_at.to_rfc3339().as_bytes());
            blake3_hash(&buf).to_vec()
        };

        // ---- Signature chain (serialised access) ----
        let mut lock = self.last_hash.lock().await;
        let prev_hash = lock.clone();

        // sign_data = blake3(record_hash || prev_hash_or_zeros)
        let signature_bytes = {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&record_hash);
            match &prev_hash {
                Some(h) => buf.extend_from_slice(h),
                None => buf.extend_from_slice(&[0u8; 32]),
            }
            let digest = blake3_hash(&buf);
            self.signing_key.sign(&digest).to_bytes().to_vec()
        };

        // Persist
        sqlx::query(
            r#"INSERT INTO audit_records (
                record_id, request_id, principal, action_type, target,
                verdict, policy_hash, graph_hash, certificate,
                request_data, decision_data,
                record_hash, prev_hash, signature,
                decided_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11,
                $12, $13, $14,
                $15
            )"#,
        )
        .bind(&record_id)
        .bind(&request.request_id)
        .bind(&request.principal)
        .bind(request.action_type)
        .bind(&request.target)
        .bind(verdict)
        .bind(&policy_hash)
        .bind(&graph_hash)
        .bind(&certificate)
        .bind(&request_data)
        .bind(&decision_data)
        .bind(&record_hash)
        .bind(&prev_hash)
        .bind(&signature_bytes)
        .bind(decided_at)
        .execute(&self.pool)
        .await
        .context("failed to insert audit record")?;

        // Advance chain head
        *lock = Some(record_hash.clone());

        Ok((record_id, record_hash))
    }

    // ----------------------------------------------------------------
    // query_logs
    // ----------------------------------------------------------------

    /// Query audit records with filtering and cursor-based pagination.
    ///
    /// Returns `(records, next_page_token)`.
    pub async fn query_logs(
        &self,
        filter: QueryFilter,
        limit: u32,
        page_token: Option<&str>,
    ) -> Result<(Vec<AuditRecord>, Option<String>)> {
        let limit = if limit == 0 { 50 } else { limit.min(1000) };

        let mut qb: QueryBuilder<'_, sqlx::Postgres> = QueryBuilder::new(
            "SELECT record_id, request_data, decision_data, prev_hash, \
             record_hash, signature, logged_at \
             FROM audit_records WHERE 1=1",
        );

        if let Some(ref principal) = filter.principal {
            qb.push(" AND principal = ");
            qb.push_bind(principal.clone());
        }
        if let Some(action_type) = filter.action_type {
            qb.push(" AND action_type = ");
            qb.push_bind(action_type);
        }
        if let Some(verdict) = filter.verdict {
            qb.push(" AND verdict = ");
            qb.push_bind(verdict);
        }
        if let Some(ref start_time) = filter.start_time {
            qb.push(" AND decided_at >= ");
            qb.push_bind(*start_time);
        }
        if let Some(ref end_time) = filter.end_time {
            qb.push(" AND decided_at <= ");
            qb.push_bind(*end_time);
        }

        // Cursor-based pagination: page_token is the RFC3339 logged_at of the
        // last record from the previous page.
        if let Some(token) = page_token {
            if let Ok(cursor) = token.parse::<DateTime<Utc>>() {
                qb.push(" AND logged_at < ");
                qb.push_bind(cursor);
            }
        }

        qb.push(" ORDER BY logged_at DESC LIMIT ");
        // Fetch one extra to determine whether there is a next page.
        qb.push_bind((limit + 1) as i64);

        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .context("query_logs failed")?;

        let has_more = rows.len() > limit as usize;
        let rows = if has_more {
            &rows[..limit as usize]
        } else {
            &rows[..]
        };

        let records: Vec<AuditRecord> = rows.iter().map(row_to_audit_record).collect();

        let next_page_token = if has_more {
            records.last().map(|r| {
                r.recorded_at
                    .as_ref()
                    .map(|ts| {
                        DateTime::from_timestamp(ts.seconds, ts.nanos.max(0) as u32)
                            .unwrap_or_else(Utc::now)
                            .to_rfc3339()
                    })
                    .unwrap_or_default()
            })
        } else {
            None
        };

        Ok((records, next_page_token))
    }

    // ----------------------------------------------------------------
    // export_logs
    // ----------------------------------------------------------------

    /// Export all audit records in a time range, ordered chronologically.
    pub async fn export_logs(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT record_id, request_data, decision_data, prev_hash, \
             record_hash, signature, logged_at \
             FROM audit_records \
             WHERE decided_at >= $1 AND decided_at <= $2 \
             ORDER BY logged_at ASC",
        )
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .context("export_logs failed")?;

        Ok(rows.iter().map(row_to_audit_record).collect())
    }

    // ----------------------------------------------------------------
    // verify_chain
    // ----------------------------------------------------------------

    /// Walk the signature chain between two record IDs and verify every link.
    ///
    /// Returns `(valid, records_verified, first_invalid_id)`.
    pub async fn verify_chain(
        &self,
        start_id: &str,
        end_id: &str,
    ) -> Result<(bool, u64, Option<String>)> {
        // Fetch all records between start and end (inclusive), ordered by
        // logged_at so the chain can be walked in order.
        let rows = sqlx::query(
            "SELECT record_id, request_id, verdict, policy_hash, \
                    decided_at, record_hash, prev_hash, signature \
             FROM audit_records \
             WHERE logged_at >= (SELECT logged_at FROM audit_records WHERE record_id = $1) \
               AND logged_at <= (SELECT logged_at FROM audit_records WHERE record_id = $2) \
             ORDER BY logged_at ASC",
        )
        .bind(start_id)
        .bind(end_id)
        .fetch_all(&self.pool)
        .await
        .context("verify_chain: failed to fetch records")?;

        if rows.is_empty() {
            return Ok((true, 0, None));
        }

        let vk = self.verifying_key();
        let mut verified: u64 = 0;

        for (i, row) in rows.iter().enumerate() {
            let record_id: String = row.get("record_id");
            let request_id: String = row.get("request_id");
            let verdict: i32 = row.get("verdict");
            let policy_hash: Vec<u8> = row.get("policy_hash");
            let decided_at: DateTime<Utc> = row.get("decided_at");
            let stored_hash: Vec<u8> = row.get("record_hash");
            let prev_hash: Option<Vec<u8>> = row.get("prev_hash");
            let sig_bytes: Vec<u8> = row.get("signature");

            // 1. Recompute record_hash
            let expected_hash = {
                let mut buf = Vec::new();
                buf.extend_from_slice(request_id.as_bytes());
                buf.extend_from_slice(&verdict.to_le_bytes());
                buf.extend_from_slice(&policy_hash);
                buf.extend_from_slice(decided_at.to_rfc3339().as_bytes());
                blake3_hash(&buf).to_vec()
            };

            if stored_hash != expected_hash {
                return Ok((false, verified, Some(record_id)));
            }

            // 2. Verify hash chain linkage
            if i > 0 {
                let prev_stored: Vec<u8> = rows[i - 1].get("record_hash");
                match &prev_hash {
                    Some(ph) if *ph == prev_stored => {}
                    _ => return Ok((false, verified, Some(record_id))),
                }
            }

            // 3. Verify signature
            let digest = {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&stored_hash);
                match &prev_hash {
                    Some(h) => buf.extend_from_slice(h),
                    None => buf.extend_from_slice(&[0u8; 32]),
                }
                blake3_hash(&buf)
            };

            let sig = Signature::from_bytes(
                sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid signature length"))?,
            );

            if vk.verify(&digest, &sig).is_err() {
                return Ok((false, verified, Some(record_id)));
            }

            verified += 1;
        }

        Ok((true, verified, None))
    }
}

// ============================================================
// Hex helper  (avoids pulling in the `hex` crate)
// ============================================================

mod hex {
    /// Encode bytes as a lower-case hex string.
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for b in data {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Decode a hex string into bytes.  Returns `Err` on invalid input.
    #[allow(dead_code)]
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex at {i}: {e}"))
            })
            .collect()
    }
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// Verify the record-hash computation is deterministic.
    #[test]
    fn test_record_hash_deterministic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"req-1");
        buf.extend_from_slice(&1i32.to_le_bytes()); // ALLOW
        buf.extend_from_slice(b"policy-hash");
        buf.extend_from_slice(b"2025-01-01T00:00:00+00:00");
        let h1 = blake3_hash(&buf);
        let h2 = blake3_hash(&buf);
        assert_eq!(h1, h2);
    }

    /// Verify that the signature chain scheme produces valid signatures.
    #[test]
    fn test_signature_chain_single() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = signing_key.verifying_key();

        let record_hash = blake3_hash(b"test-content");
        let prev_hash = [0u8; 32]; // genesis

        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&record_hash);
        buf.extend_from_slice(&prev_hash);
        let digest = blake3_hash(&buf);

        let sig = signing_key.sign(&digest);
        assert!(vk.verify(&digest, &sig).is_ok());
    }

    /// Walk a 3-link chain and verify every link.
    #[test]
    fn test_signature_chain_three_records() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = signing_key.verifying_key();

        let mut prev = [0u8; 32]; // genesis
        let mut chain: Vec<([u8; 32], ed25519_dalek::Signature)> = Vec::new();

        for i in 0..3 {
            let content = format!("record-{i}");
            let record_hash = blake3_hash(content.as_bytes());

            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&record_hash);
            buf.extend_from_slice(&prev);
            let digest = blake3_hash(&buf);
            let sig = signing_key.sign(&digest);
            chain.push((record_hash, sig));
            prev = record_hash;
        }

        // Verify all links
        let mut prev = [0u8; 32];
        for (hash, sig) in &chain {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(hash);
            buf.extend_from_slice(&prev);
            let digest = blake3_hash(&buf);
            assert!(vk.verify(&digest, sig).is_ok());
            prev = *hash;
        }
    }

    /// Tampering with a record hash breaks verification.
    #[test]
    fn test_signature_chain_tamper_detection() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = signing_key.verifying_key();

        let record_hash = blake3_hash(b"original-content");
        let prev_hash = [0u8; 32];

        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&record_hash);
        buf.extend_from_slice(&prev_hash);
        let digest = blake3_hash(&buf);
        let sig = signing_key.sign(&digest);

        // Original verifies
        assert!(vk.verify(&digest, &sig).is_ok());

        // Tampered record hash does NOT verify
        let tampered_hash = blake3_hash(b"tampered-content");
        let mut buf2 = Vec::with_capacity(64);
        buf2.extend_from_slice(&tampered_hash);
        buf2.extend_from_slice(&prev_hash);
        let tampered_digest = blake3_hash(&buf2);
        assert!(vk.verify(&tampered_digest, &sig).is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello";
        let encoded = hex::encode(data);
        assert_eq!(encoded, "68656c6c6f");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_chrono_timestamp_roundtrip() {
        let now = Utc::now();
        let ts = chrono_to_ts(&now);
        let back = ts_to_chrono(&ts);
        // Sub-nanosecond precision may differ, but second-level should match
        assert_eq!(now.timestamp(), back.timestamp());
    }
}
