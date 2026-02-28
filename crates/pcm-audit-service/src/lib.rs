//! PCM Audit Service — 审计日志服务
//!
//! 基于 PostgreSQL 的审计记录存储，支持 Ed25519 签名链、
//! 决策记录写入、查询过滤与分页、时间范围导出以及签名链验证。
//!
//! gRPC AuditService 暴露 LogDecision、QueryLogs、ExportLogs、VerifyChain。

pub mod service;
pub mod store;
