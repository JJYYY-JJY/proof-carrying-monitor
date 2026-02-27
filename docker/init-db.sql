-- PCM 数据库初始化脚本

-- 策略数据库
CREATE DATABASE pcm_policies;
CREATE DATABASE pcm_audit;

-- 策略表
\c pcm_policies;

CREATE TABLE IF NOT EXISTS policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       VARCHAR(255) NOT NULL,
    version         VARCHAR(50) NOT NULL,
    content_hash    BYTEA NOT NULL,
    source_dsl      TEXT NOT NULL,
    compiled_data   BYTEA,
    is_active       BOOLEAN DEFAULT FALSE,
    decidable       BOOLEAN DEFAULT TRUE,
    author          VARCHAR(255),
    commit_sha      VARCHAR(40),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(policy_id, version)
);

CREATE INDEX idx_policy_versions_active ON policy_versions(policy_id, is_active)
    WHERE is_active = TRUE;

CREATE INDEX idx_policy_versions_hash ON policy_versions(content_hash);

-- 审计数据库
\c pcm_audit;

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
) PARTITION BY RANGE (recorded_at);

-- 按月分区（最近 3 个月）
CREATE TABLE audit_records_current PARTITION OF audit_records
    FOR VALUES FROM (CURRENT_DATE - INTERVAL '1 month') TO (CURRENT_DATE + INTERVAL '2 months');

CREATE INDEX idx_audit_request_id ON audit_records(request_id);
CREATE INDEX idx_audit_recorded_at ON audit_records(recorded_at);
CREATE INDEX idx_audit_verdict ON audit_records(verdict);
