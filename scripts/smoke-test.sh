#!/bin/bash
# PCM 冒烟测试脚本
# 用法: ./scripts/smoke-test.sh
# 前置条件: docker compose up --build -d 且服务已就绪；需安装 grpcurl
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}$1${NC}"; }

# 检查 grpcurl 是否可用
if ! command -v grpcurl &> /dev/null; then
    echo "grpcurl 未安装。请从 https://github.com/fullstorydev/grpcurl/releases 安装。"
    exit 1
fi

GATEWAY="localhost:50051"
AUDIT="localhost:50054"
PROTO_DIR="proto"

echo "========================================="
echo "  PCM Smoke Test"
echo "========================================="
echo ""

# ──────────────────────────────────────────────
# 1. 健康检查 — MonitorService/Health
# ──────────────────────────────────────────────
info "[1/4] Health check — MonitorService/Health ..."

HEALTH=$(grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto pcm/v1/services.proto \
    "$GATEWAY" pcm.v1.MonitorService/Health 2>&1) \
    && pass "Health check OK" \
    || fail "Health check failed: $HEALTH"
echo "$HEALTH"
echo ""

# ──────────────────────────────────────────────
# 2. 评估一个 Allow 请求
# ──────────────────────────────────────────────
info "[2/4] Evaluate allow request (http_allowed user) ..."

ALLOW_RESP=$(grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto pcm/v1/services.proto \
    -d '{
      "request": {
        "request_id": "smoke-allow-001",
        "action_type": 2,
        "principal": "http_allowed_user",
        "target": "https://api.example.com"
      }
    }' \
    "$GATEWAY" pcm.v1.MonitorService/Evaluate 2>&1) \
    && pass "Evaluate (allow) OK" \
    || fail "Evaluate (allow) failed: $ALLOW_RESP"
echo "$ALLOW_RESP"
echo ""

# ──────────────────────────────────────────────
# 3. 评估一个 Deny 请求
# ──────────────────────────────────────────────
info "[3/4] Evaluate deny request (unauthorized user) ..."

DENY_RESP=$(grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto pcm/v1/services.proto \
    -d '{
      "request": {
        "request_id": "smoke-deny-002",
        "action_type": 2,
        "principal": "unauthorized_user",
        "target": "https://api.example.com"
      }
    }' \
    "$GATEWAY" pcm.v1.MonitorService/Evaluate 2>&1) \
    && pass "Evaluate (deny) OK" \
    || fail "Evaluate (deny) failed: $DENY_RESP"
echo "$DENY_RESP"
echo ""

# ──────────────────────────────────────────────
# 4. 查询审计日志
# ──────────────────────────────────────────────
info "[4/4] Query audit logs — AuditService/QueryLogs ..."

AUDIT_RESP=$(grpcurl -plaintext \
    -import-path "$PROTO_DIR" \
    -proto pcm/v1/services.proto \
    -d '{"limit": 10}' \
    "$AUDIT" pcm.v1.AuditService/QueryLogs 2>&1) \
    && pass "QueryLogs OK" \
    || fail "QueryLogs failed: $AUDIT_RESP"
echo "$AUDIT_RESP"
echo ""

echo "========================================="
echo -e "${GREEN}  Smoke Test PASSED${NC}"
echo "========================================="
