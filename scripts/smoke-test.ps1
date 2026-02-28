# PCM 冒烟测试脚本 (PowerShell)
# 用法: .\scripts\smoke-test.ps1
# 前置条件: docker compose up --build -d 且服务已就绪；需安装 grpcurl
$ErrorActionPreference = "Stop"

$GATEWAY = "localhost:50051"
$AUDIT   = "localhost:50054"
$PROTO   = "proto"

# 检查 grpcurl
if (-not (Get-Command grpcurl -ErrorAction SilentlyContinue)) {
    Write-Error "grpcurl 未安装。请从 https://github.com/fullstorydev/grpcurl/releases 安装。"
    exit 1
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  PCM Smoke Test" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Health check
Write-Host "[1/4] Health check — MonitorService/Health ..." -ForegroundColor Yellow
$health = grpcurl -plaintext -import-path $PROTO -proto pcm/v1/services.proto $GATEWAY pcm.v1.MonitorService/Health 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "Health check failed: $health"; exit 1 }
Write-Host "OK" -ForegroundColor Green
Write-Host $health
Write-Host ""

# 2. Evaluate allow
Write-Host "[2/4] Evaluate allow request ..." -ForegroundColor Yellow
$allowBody = '{"request":{"request_id":"smoke-allow-001","action_type":2,"principal":"http_allowed_user","target":"https://api.example.com"}}'
$allow = grpcurl -plaintext -import-path $PROTO -proto pcm/v1/services.proto -d $allowBody $GATEWAY pcm.v1.MonitorService/Evaluate 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "Evaluate (allow) failed: $allow"; exit 1 }
Write-Host "OK" -ForegroundColor Green
Write-Host $allow
Write-Host ""

# 3. Evaluate deny
Write-Host "[3/4] Evaluate deny request ..." -ForegroundColor Yellow
$denyBody = '{"request":{"request_id":"smoke-deny-002","action_type":2,"principal":"unauthorized_user","target":"https://api.example.com"}}'
$deny = grpcurl -plaintext -import-path $PROTO -proto pcm/v1/services.proto -d $denyBody $GATEWAY pcm.v1.MonitorService/Evaluate 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "Evaluate (deny) failed: $deny"; exit 1 }
Write-Host "OK" -ForegroundColor Green
Write-Host $deny
Write-Host ""

# 4. Query audit logs
Write-Host "[4/4] Query audit logs — AuditService/QueryLogs ..." -ForegroundColor Yellow
$audit = grpcurl -plaintext -import-path $PROTO -proto pcm/v1/services.proto -d '{"limit":10}' $AUDIT pcm.v1.AuditService/QueryLogs 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "QueryLogs failed: $audit"; exit 1 }
Write-Host "OK" -ForegroundColor Green
Write-Host $audit
Write-Host ""

Write-Host "=========================================" -ForegroundColor Green
Write-Host "  Smoke Test PASSED" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
