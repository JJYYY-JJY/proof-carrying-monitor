#!/bin/bash
# PCM 数据库初始化脚本
# 由 PostgreSQL Docker entrypoint 在首次启动时执行
# POSTGRES_DB (pcm_policies) 已由 entrypoint 自动创建
set -euo pipefail

echo "=== PCM: Creating additional databases ==="

# 创建 pcm_audit 数据库（如果不存在）
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
    SELECT 'CREATE DATABASE pcm_audit'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'pcm_audit')\gexec
EOSQL

echo "=== PCM: Initializing pcm_policies schema ==="

# 在 pcm_policies 数据库中创建策略表
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

# 在 pcm_audit 数据库中创建审计表
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "pcm_audit" <<-'EOSQL'
    CREATE TABLE IF NOT EXISTS audit_records (
        id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        request_id          VARCHAR(255) NOT NULL,
        request_data        JSONB NOT NULL,
        verdict             VARCHAR(10) NOT NULL CHECK (verdict IN ('ALLOW', 'DENY', 'ERROR')),
        policy_version_hash BYTEA NOT NULL,
        graph_snapshot_hash BYTEA,
        certificate_data    BYTEA,
        witness_data        BYTEA,
        previous_hash       BYTEA,
        record_hash         BYTEA NOT NULL,
        signature           BYTEA NOT NULL,
        recorded_at         TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_audit_request_id
        ON audit_records(request_id);

    CREATE INDEX IF NOT EXISTS idx_audit_recorded_at
        ON audit_records(recorded_at);

    CREATE INDEX IF NOT EXISTS idx_audit_verdict
        ON audit_records(verdict);
EOSQL

echo "=== PCM: Database initialization complete ==="
