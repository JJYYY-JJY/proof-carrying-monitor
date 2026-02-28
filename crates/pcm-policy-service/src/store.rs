//! PostgreSQL-backed policy storage layer.
//!
//! Provides CRUD operations for policies and their versions, with
//! content-hash deduplication and monotonic version activation.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use pcm_common::hash::blake3_hash;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

// ============================================================
// Data types
// ============================================================

/// A single policy version record as stored in the database.
#[derive(Debug, Clone)]
pub struct PolicyVersionRecord {
    pub policy_id: String,
    pub version: String,
    pub content_hash: Vec<u8>,
    pub source_dsl: String,
    pub compiled_json: Option<serde_json::Value>,
    pub author: String,
    pub commit_sha: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Error types specific to the policy store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("policy not found: {0}")]
    NotFound(String),
    #[error("version downgrade rejected: active={active}, requested={requested}")]
    VersionDowngrade { active: String, requested: String },
    #[error("compilation failed: {0}")]
    CompilationFailed(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

// ============================================================
// Row mapping helper
// ============================================================

fn row_to_record(row: &PgRow) -> PolicyVersionRecord {
    PolicyVersionRecord {
        policy_id: row.get("policy_id"),
        version: row.get("version"),
        content_hash: row.get("content_hash"),
        source_dsl: row.get("source_dsl"),
        compiled_json: row.get("compiled_json"),
        author: row.get("author"),
        commit_sha: row.get("commit_sha"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
    }
}

// ============================================================
// PolicyStore
// ============================================================

/// PostgreSQL-backed store for policy management.
pub struct PolicyStore {
    pool: PgPool,
}

impl PolicyStore {
    /// Create a new `PolicyStore` wrapping the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ----------------------------------------------------------------
    // Create
    // ----------------------------------------------------------------

    /// Create a new policy version.
    ///
    /// - Generates a UUID v4 `policy_id` for each new policy.
    /// - Auto-increments the minor version number.
    /// - Deduplicates by `content_hash`: if the same content already
    ///   exists, returns the existing record.
    /// - Compiles the DSL and stores the compiled JSON.
    pub async fn create_policy(
        &self,
        source_dsl: &str,
        author: &str,
        commit_sha: &str,
    ) -> Result<PolicyVersionRecord> {
        // 1. Compute content hash
        let hash = blake3_hash(source_dsl.as_bytes());
        let hash_bytes = hash.to_vec();

        // 2. Check for existing version with same content hash (global dedup)
        if let Some(existing) = self.find_by_content_hash(&hash_bytes).await? {
            return Ok(existing);
        }

        // 3. Compile the policy DSL
        let ast = pcm_policy_dsl::parse_policy(source_dsl)
            .map_err(|e| StoreError::CompilationFailed(e.to_string()))?;

        // Use a placeholder version during compilation; the real version
        // is determined below.
        let compile_result = pcm_policy_dsl::compile(&ast, "0.0.0")
            .map_err(|e| StoreError::CompilationFailed(e.to_string()))?;

        let compiled_json = serde_json::to_value(&compile_result.policy)
            .context("failed to serialize compiled policy")?;

        // 4. Generate policy_id (UUID v4)
        let policy_id = uuid::Uuid::new_v4().to_string();

        // 5. Ensure the parent policy row exists
        self.ensure_policy_row(&policy_id).await?;

        // 6. Determine next version
        let next_version = self.next_version(&policy_id).await?;

        // 7. Insert the version row
        let row = sqlx::query(
            r#"
            INSERT INTO policy_versions
                (policy_id, version, content_hash, source_dsl, compiled_json, author, commit_sha)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                policy_id, version, content_hash, source_dsl,
                compiled_json, author, commit_sha, is_active, created_at
            "#,
        )
        .bind(&policy_id)
        .bind(&next_version)
        .bind(&hash_bytes)
        .bind(source_dsl)
        .bind(&compiled_json)
        .bind(author)
        .bind(commit_sha)
        .fetch_one(&self.pool)
        .await
        .context("insert policy_version")?;

        Ok(row_to_record(&row))
    }

    // ----------------------------------------------------------------
    // Read
    // ----------------------------------------------------------------

    /// Get a specific policy version.
    ///
    /// If `version` is `None`, returns the latest version.
    pub async fn get_policy(
        &self,
        policy_id: &str,
        version: Option<&str>,
    ) -> Result<Option<PolicyVersionRecord>> {
        let row = match version {
            Some(v) => {
                sqlx::query(
                    r#"
                    SELECT policy_id, version, content_hash, source_dsl,
                           compiled_json, author, commit_sha, is_active, created_at
                    FROM policy_versions
                    WHERE policy_id = $1 AND version = $2
                    "#,
                )
                .bind(policy_id)
                .bind(v)
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    r#"
                    SELECT policy_id, version, content_hash, source_dsl,
                           compiled_json, author, commit_sha, is_active, created_at
                    FROM policy_versions
                    WHERE policy_id = $1
                    ORDER BY created_at DESC
                    LIMIT 1
                    "#,
                )
                .bind(policy_id)
                .fetch_optional(&self.pool)
                .await?
            }
        };

        Ok(row.as_ref().map(row_to_record))
    }

    /// Get the currently active version for a policy.
    pub async fn get_active_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<PolicyVersionRecord>> {
        let row = sqlx::query(
            r#"
            SELECT policy_id, version, content_hash, source_dsl,
                   compiled_json, author, commit_sha, is_active, created_at
            FROM policy_versions
            WHERE policy_id = $1 AND is_active = TRUE
            "#,
        )
        .bind(policy_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_record))
    }

    // ----------------------------------------------------------------
    // List
    // ----------------------------------------------------------------

    /// List policy versions with cursor-based pagination.
    ///
    /// Returns `(versions, next_page_token)`.  The page token is the
    /// RFC 3339 timestamp of the last record.
    pub async fn list_versions(
        &self,
        policy_id: &str,
        limit: u32,
        page_token: Option<&str>,
    ) -> Result<(Vec<PolicyVersionRecord>, Option<String>)> {
        let effective_limit = limit.clamp(1, 100) as i64;

        let rows = if let Some(token) = page_token {
            let cursor: DateTime<Utc> = token
                .parse()
                .context("invalid page_token (expected RFC 3339 timestamp)")?;

            sqlx::query(
                r#"
                SELECT policy_id, version, content_hash, source_dsl,
                       compiled_json, author, commit_sha, is_active, created_at
                FROM policy_versions
                WHERE policy_id = $1 AND created_at < $2
                ORDER BY created_at DESC
                LIMIT $3
                "#,
            )
            .bind(policy_id)
            .bind(cursor)
            .bind(effective_limit + 1)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT policy_id, version, content_hash, source_dsl,
                       compiled_json, author, commit_sha, is_active, created_at
                FROM policy_versions
                WHERE policy_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(policy_id)
            .bind(effective_limit + 1)
            .fetch_all(&self.pool)
            .await?
        };

        let has_next = rows.len() as i64 > effective_limit;
        let records: Vec<PolicyVersionRecord> = rows
            .iter()
            .take(effective_limit as usize)
            .map(row_to_record)
            .collect();

        let next_token = if has_next {
            records.last().map(|r| r.created_at.to_rfc3339())
        } else {
            None
        };

        Ok((records, next_token))
    }

    // ----------------------------------------------------------------
    // Activate
    // ----------------------------------------------------------------

    /// Activate a specific version of a policy.
    ///
    /// Enforces **monotonic version activation**: a version older than
    /// the currently active one cannot be activated (version downgrade
    /// protection per design doc T4 threat mitigation).
    ///
    /// Returns `true` if the version was activated, `false` if it was
    /// already active.
    pub async fn activate_policy(
        &self,
        policy_id: &str,
        version: &str,
    ) -> Result<bool> {
        // 1. Check that the requested version exists
        let target = self
            .get_policy(policy_id, Some(version))
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("{policy_id}@{version}")))?;

        if target.is_active {
            return Ok(false); // already active
        }

        // 2. Check monotonic constraint against current active version
        if let Some(active) = self.get_active_policy(policy_id).await?
            && compare_versions(&active.version, version) == std::cmp::Ordering::Greater
        {
            bail!(StoreError::VersionDowngrade {
                active: active.version.clone(),
                requested: version.to_string(),
            });
        }

        // 3. Deactivate all other versions and activate the target
        let mut tx = self.pool.begin().await?;

        sqlx::query("UPDATE policy_versions SET is_active = FALSE WHERE policy_id = $1")
            .bind(policy_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE policy_versions SET is_active = TRUE WHERE policy_id = $1 AND version = $2",
        )
        .bind(policy_id)
        .bind(version)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    // ----------------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------------

    /// Ensure the `policies` parent row exists.
    async fn ensure_policy_row(&self, policy_id: &str) -> Result<()> {
        sqlx::query("INSERT INTO policies (policy_id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(policy_id)
            .execute(&self.pool)
            .await
            .context("ensure policy row")?;
        Ok(())
    }

    /// Determine the next semver-style version string for a given policy.
    ///
    /// If no versions exist yet the first version is `"0.1.0"`.
    /// Otherwise the minor component is incremented: `"0.3.0"` → `"0.4.0"`.
    async fn next_version(&self, policy_id: &str) -> Result<String> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT version
            FROM policy_versions
            WHERE policy_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(policy_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            Some((v,)) => increment_minor(&v),
            None => "0.1.0".to_string(),
        })
    }

    /// Find an existing version record by content hash (across all policies).
    async fn find_by_content_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<PolicyVersionRecord>> {
        let row = sqlx::query(
            r#"
            SELECT policy_id, version, content_hash, source_dsl,
                   compiled_json, author, commit_sha, is_active, created_at
            FROM policy_versions
            WHERE content_hash = $1
            LIMIT 1
            "#,
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_record))
    }
}

// ============================================================
// Proto conversion
// ============================================================

impl PolicyVersionRecord {
    /// Convert to the protobuf `PolicyVersion` message.
    pub fn to_proto(&self) -> pcm_common::proto::pcm_v1::PolicyVersion {
        use prost_types::Timestamp;

        pcm_common::proto::pcm_v1::PolicyVersion {
            policy_id: self.policy_id.clone(),
            version: self.version.clone(),
            content_hash: self.content_hash.clone(),
            source_dsl: self.source_dsl.clone(),
            compiled: self.compiled_json.as_ref().map(|json| {
                let bytes = serde_json::to_vec(json).unwrap_or_default();
                let content_hash = blake3_hash(&bytes).to_vec();
                pcm_common::proto::pcm_v1::CompiledPolicy {
                    content: bytes,
                    content_hash,
                    version: self.version.clone(),
                }
            }),
            created_at: Some(Timestamp {
                seconds: self.created_at.timestamp(),
                nanos: self.created_at.timestamp_subsec_nanos() as i32,
            }),
            author: self.author.clone(),
            commit_sha: self.commit_sha.clone(),
        }
    }
}

// ============================================================
// Version helpers
// ============================================================

/// Increment the minor component of a semver-like version string.
///
/// `"0.3.0"` → `"0.4.0"`.  Falls back to appending `.1` if parsing fails.
pub(crate) fn increment_minor(version: &str) -> String {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() == 3
        && let Ok(minor) = parts[1].parse::<u64>()
    {
        return format!("{}.{}.{}", parts[0], minor + 1, parts[2]);
    }
    // Fallback: just append
    format!("{version}.1")
}

/// Compare two semver-like version strings by their numeric components.
pub(crate) fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .filter_map(|p| p.parse::<u64>().ok())
            .collect()
    };
    parse(a).cmp(&parse(b))
}

// ============================================================
// Unit tests (pure logic — no database required)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- version helpers ----

    #[test]
    fn test_increment_minor() {
        assert_eq!(increment_minor("0.1.0"), "0.2.0");
        assert_eq!(increment_minor("0.9.0"), "0.10.0");
        assert_eq!(increment_minor("1.0.0"), "1.1.0");
        assert_eq!(increment_minor("2.42.1"), "2.43.1");
    }

    #[test]
    fn test_increment_minor_fallback() {
        assert_eq!(increment_minor("v1"), "v1.1");
    }

    #[test]
    fn test_compare_versions() {
        use std::cmp::Ordering;

        assert_eq!(compare_versions("0.1.0", "0.2.0"), Ordering::Less);
        assert_eq!(compare_versions("0.2.0", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_versions("0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.0", "0.9.0"), Ordering::Greater);
        assert_eq!(compare_versions("0.10.0", "0.9.0"), Ordering::Greater);
    }

    // ---- content hash ----

    #[test]
    fn test_content_hash_deterministic() {
        let dsl = "deny(X, Y, Z, W) :- action(X, Y, Z, W).";
        let h1 = blake3_hash(dsl.as_bytes());
        let h2 = blake3_hash(dsl.as_bytes());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_different_inputs() {
        let h1 = blake3_hash(b"policy A");
        let h2 = blake3_hash(b"policy B");
        assert_ne!(h1, h2);
    }

    // ---- proto conversion ----

    #[test]
    fn test_policy_version_record_to_proto() {
        let record = PolicyVersionRecord {
            policy_id: "test-id".to_string(),
            version: "0.1.0".to_string(),
            content_hash: vec![1, 2, 3],
            source_dsl: "deny(A,B,C,D) :- action(A,B,C,D).".to_string(),
            compiled_json: Some(serde_json::json!({"rules": []})),
            author: "alice".to_string(),
            commit_sha: "abc123".to_string(),
            is_active: false,
            created_at: Utc::now(),
        };

        let proto = record.to_proto();
        assert_eq!(proto.policy_id, "test-id");
        assert_eq!(proto.version, "0.1.0");
        assert_eq!(proto.content_hash, vec![1, 2, 3]);
        assert_eq!(proto.author, "alice");
        assert_eq!(proto.commit_sha, "abc123");
        assert!(proto.compiled.is_some());
        assert!(proto.created_at.is_some());
    }

    #[test]
    fn test_policy_version_record_to_proto_no_compiled() {
        let record = PolicyVersionRecord {
            policy_id: "test-id".to_string(),
            version: "0.1.0".to_string(),
            content_hash: vec![],
            source_dsl: String::new(),
            compiled_json: None,
            author: String::new(),
            commit_sha: String::new(),
            is_active: true,
            created_at: Utc::now(),
        };

        let proto = record.to_proto();
        assert!(proto.compiled.is_none());
    }

    // ---- mock-based store logic tests ----

    /// Helper: simulate the version increment logic that `create_policy` uses.
    fn simulate_create_versions(existing_versions: &[&str]) -> String {
        match existing_versions.last() {
            Some(v) => increment_minor(v),
            None => "0.1.0".to_string(),
        }
    }

    #[test]
    fn test_version_auto_increment_simulation() {
        assert_eq!(simulate_create_versions(&[]), "0.1.0");
        assert_eq!(simulate_create_versions(&["0.1.0"]), "0.2.0");
        assert_eq!(simulate_create_versions(&["0.1.0", "0.2.0"]), "0.3.0");
    }

    /// Simulate the dedup check: returns `true` if the hash already exists.
    fn simulate_dedup_check(existing_hashes: &[Vec<u8>], new_hash: &[u8]) -> bool {
        existing_hashes.iter().any(|h| h.as_slice() == new_hash)
    }

    #[test]
    fn test_content_hash_dedup_simulation() {
        let dsl = "deny(X,Y,Z,W) :- action(X,Y,Z,W).";
        let hash = blake3_hash(dsl.as_bytes()).to_vec();

        // No existing hashes → no dedup
        assert!(!simulate_dedup_check(&[], &hash));

        // Same hash exists → dedup triggers
        assert!(simulate_dedup_check(&[hash.clone()], &hash));

        // Different hash → no dedup
        let other_hash = blake3_hash(b"other policy").to_vec();
        assert!(!simulate_dedup_check(&[other_hash], &hash));
    }

    /// Simulate activate policy monotonic check.
    fn simulate_activate_check(
        active_version: Option<&str>,
        requested: &str,
    ) -> Result<(), String> {
        if let Some(active) = active_version {
            if compare_versions(active, requested) == std::cmp::Ordering::Greater {
                return Err(format!(
                    "version downgrade rejected: active={active}, requested={requested}"
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn test_activate_allows_upgrade() {
        assert!(simulate_activate_check(None, "0.1.0").is_ok());
        assert!(simulate_activate_check(Some("0.1.0"), "0.2.0").is_ok());
        assert!(simulate_activate_check(Some("0.1.0"), "0.1.0").is_ok());
        assert!(simulate_activate_check(Some("0.1.0"), "1.0.0").is_ok());
    }

    #[test]
    fn test_activate_rejects_downgrade() {
        assert!(simulate_activate_check(Some("0.2.0"), "0.1.0").is_err());
        assert!(simulate_activate_check(Some("1.0.0"), "0.9.0").is_err());
    }

    #[test]
    fn test_activate_rejects_downgrade_message() {
        let err = simulate_activate_check(Some("0.5.0"), "0.3.0").unwrap_err();
        assert!(err.contains("0.5.0"));
        assert!(err.contains("0.3.0"));
    }

    // ---- query for non-existing policy ----

    #[test]
    fn test_nonexistent_policy_simulation() {
        // Simulating that a lookup in an empty store returns None
        let store: Vec<PolicyVersionRecord> = vec![];
        let result = store.iter().find(|r| r.policy_id == "nonexistent");
        assert!(result.is_none());
    }

    // ---- compilation ----

    #[test]
    fn test_compile_valid_policy() {
        let dsl = r#"deny(Req, "blocked") :- action(Req, HttpOut, P, _)."#;
        let ast = pcm_policy_dsl::parse_policy(dsl).expect("parse should succeed");
        let result = pcm_policy_dsl::compile(&ast, "0.1.0").expect("compile should succeed");
        assert!(result.policy.decidable);
        assert!(!result.policy.rules.is_empty());

        // Verify JSON serialization works
        let json = serde_json::to_value(&result.policy).expect("serialize should succeed");
        assert!(json.is_object());
    }

    #[test]
    fn test_compile_invalid_policy_fails() {
        let dsl = "this is not valid policy DSL !!!";
        let result = pcm_policy_dsl::parse_policy(dsl);
        assert!(result.is_err());
    }
}
