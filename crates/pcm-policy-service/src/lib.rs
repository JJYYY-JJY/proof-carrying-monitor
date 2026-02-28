//! PCM Policy Service — 策略管理服务
//!
//! 基于 PostgreSQL 的策略存储层，支持策略版本 CRUD、
//! 按 content_hash 去重以及版本列表分页查询。
//! gRPC PolicyService 暴露 CreatePolicy、GetPolicy、
//! ListPolicyVersions、CompilePolicy、ValidatePolicy、ActivatePolicy。

pub mod service;
pub mod store;
