#!/bin/bash
# PCM 数据库初始化脚本（遗留 / CI 兼容）
# 由 PostgreSQL Docker entrypoint 在首次启动后执行
#
# 主 Schema 已由 01-init.sql (init-db.sql) 在 POSTGRES_DB 中创建。
# 此脚本为 CI (docker-compose.test.yml) 保留向后兼容：
#   - 如果 POSTGRES_DB 为旧的 pcm_policies，则额外创建 pcm_audit 数据库并初始化两套 schema。
#   - 如果 POSTGRES_DB 为 pcm（新统一模式），则仅确保 schema 存在（幂等）。
set -euo pipefail

echo "=== PCM: init-db.sh running (POSTGRES_DB=$POSTGRES_DB) ==="

if [ "$POSTGRES_DB" = "pcm_policies" ]; then
  # ---- 旧版双数据库模式（CI 兼容） ----
  echo "=== PCM: Legacy mode — creating pcm_audit database ==="

  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
      SELECT 'CREATE DATABASE pcm_audit'
      WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'pcm_audit')\gexec
EOSQL

  echo "=== PCM: Initializing pcm_policies schema ==="

  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "pcm_policies" <<-'EOSQL'
      CREATE TABLE IF NOT EXISTS policies (
          policy_id   TEXT PRIMARY KEY,
          created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS policy_versions (
          id            SERIAL PRIMARY KEY,
          policy_id     TEXT NOT NULL REFERENCES policies(policy_id),
          version       TEXT NOT NULL,
          content_hash  BYTEA NOT NULL,
          source_dsl    TEXT NOT NULL,
          compiled_json JSONB,
          author        TEXT NOT NULL DEFAULT '',
          commit_sha    TEXT NOT NULL DEFAULT '',
          is_active     BOOLEAN NOT NULL DEFAULT FALSE,
          created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(policy_id, version),
          UNIQUE(policy_id, content_hash)
      );

      CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_id
          ON policy_versions(policy_id);

      CREATE INDEX IF NOT EXISTS idx_policy_versions_active
          ON policy_versions(policy_id, is_active)
          WHERE is_active = TRUE;
EOSQL

  echo "=== PCM: Initializing pcm_audit schema ==="

  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "pcm_audit" <<-'EOSQL'
      CREATE TABLE IF NOT EXISTS audit_records (
          record_id       TEXT PRIMARY KEY,
          request_id      TEXT NOT NULL,
          principal       TEXT NOT NULL,
          action_type     INTEGER NOT NULL,
          target          TEXT NOT NULL,
          verdict         INTEGER NOT NULL,
          policy_hash     BYTEA NOT NULL,
          graph_hash      BYTEA,
          certificate     BYTEA,
          request_data    BYTEA NOT NULL,
          decision_data   BYTEA NOT NULL,
          record_hash     BYTEA NOT NULL,
          prev_hash       BYTEA,
          signature       BYTEA NOT NULL,
          decided_at      TIMESTAMPTZ NOT NULL,
          logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_audit_principal
          ON audit_records(principal);

      CREATE INDEX IF NOT EXISTS idx_audit_action
          ON audit_records(action_type);

      CREATE INDEX IF NOT EXISTS idx_audit_verdict
          ON audit_records(verdict);

      CREATE INDEX IF NOT EXISTS idx_audit_time
          ON audit_records(decided_at);
EOSQL

else
  # ---- 新版统一数据库模式 ----
  echo "=== PCM: Unified mode — schema already applied by 01-init.sql ==="
fi

echo "=== PCM: init-db.sh completed ==="
EOSQL

echo "=== PCM: Database initialization complete ==="
