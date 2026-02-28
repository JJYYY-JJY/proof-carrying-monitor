-- PCM 数据库初始化脚本
-- 由 PostgreSQL Docker entrypoint 在首次启动时执行
-- 在统一的 pcm 数据库中创建所有表

-- ============================================================
-- 策略表
-- ============================================================

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

-- ============================================================
-- 审计日志表
-- ============================================================

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
