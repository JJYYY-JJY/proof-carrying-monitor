//! PCM Datalog Engine — 朴素自底向上不动点评估器
//!
//! 对编译后的策略规则在给定事实集上进行不动点求值，
//! 并追踪推导路径以支持证书生成。

pub mod engine;
pub mod facts;

pub use engine::DatalogEngine;
