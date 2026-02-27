//! MonitorService gRPC 实现

use std::time::Instant;

/// Monitor 服务实现
pub struct MonitorServiceImpl {
    // TODO: 持有策略引擎、图客户端、证书生成器等
}

impl MonitorServiceImpl {
    pub fn new() -> Self {
        Self {}
    }

    /// 评估单个请求
    pub async fn evaluate(
        &self,
        _request_id: &str,
        _action_type: &str,
        _principal: &str,
        _target: &str,
        _dry_run: bool,
    ) -> EvaluateResult {
        let start = Instant::now();

        // TODO: 完整实现流程
        // 1. 更新图
        // 2. 评估策略
        // 3. 生成证书/反例
        // 4. 自验证证书
        // 5. 记录审计

        let duration_us = start.elapsed().as_micros() as u64;

        EvaluateResult {
            verdict: Verdict::Allow,
            duration_us,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Verdict {
    Allow,
    Deny,
    Error,
}

#[derive(Debug)]
pub struct EvaluateResult {
    pub verdict: Verdict,
    pub duration_us: u64,
}
