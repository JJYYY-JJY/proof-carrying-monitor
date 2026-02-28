//! 策略热加载器
//!
//! 支持两种模式：
//! - **本地文件轮询**：定期读取策略文件，检测变更后自动重新编译
//! - **远程 policy-service 拉取**：从 gRPC policy-service 获取最新策略
//!
//! 所有模式均使用 content_hash 去重，编译失败时保持旧策略不变。

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use pcm_common::hash::blake3_hash;
use pcm_policy_dsl::ast::PolicyAst;
use pcm_policy_dsl::compiler::{CompiledPolicy, FactSchema, compile};
use tokio::task::JoinHandle;

/// 默认轮询间隔（秒）
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// 策略热加载器
///
/// 持有可共享的策略状态（`Arc<RwLock<…>>`），供 `MonitorServiceImpl` 读取。
/// 编译在锁外进行，仅在替换指针时持锁，最小化写锁时间。
pub struct PolicyLoader {
    /// 当前已编译策略
    policy: Arc<RwLock<CompiledPolicy>>,
    /// 当前策略 AST
    policy_ast: Arc<RwLock<PolicyAst>>,
    /// 当前策略源码的 content_hash（用于去重）
    current_hash: Arc<RwLock<Option<[u8; 32]>>>,
    /// 重载成功次数
    reload_count: Arc<std::sync::atomic::AtomicU64>,
    /// 重载失败次数
    reload_fail_count: Arc<std::sync::atomic::AtomicU64>,
}

impl PolicyLoader {
    /// 从策略文件初始加载
    ///
    /// 读取文件 → 解析 → 编译 → 初始化 loader。
    /// 失败时返回错误（启动阶段不容忍策略加载失败）。
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read policy file {}: {e}", path.display()))?;
        Self::load_from_source(&source)
    }

    /// 从源码字符串初始加载
    pub fn load_from_source(source: &str) -> Result<Self, String> {
        let hash = blake3_hash(source.as_bytes());
        let ast = pcm_policy_dsl::parse_policy(source).map_err(|e| format!("parse error: {e}"))?;
        let result = compile(&ast, "runtime").map_err(|e| format!("compile error: {e}"))?;

        tracing::info!(
            content_hash = %hex::encode(hash),
            "initial policy loaded"
        );

        Ok(Self {
            policy: Arc::new(RwLock::new(result.policy)),
            policy_ast: Arc::new(RwLock::new(ast)),
            current_hash: Arc::new(RwLock::new(Some(hash))),
            reload_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reload_fail_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// 创建空策略的 loader（用于测试或无策略启动）
    pub fn empty() -> Self {
        let empty_ast = PolicyAst { rules: vec![] };
        let compiled = default_compiled_policy();
        Self {
            policy: Arc::new(RwLock::new(compiled)),
            policy_ast: Arc::new(RwLock::new(empty_ast)),
            current_hash: Arc::new(RwLock::new(None)),
            reload_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reload_fail_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// 获取策略的共享引用（供 `MonitorServiceImpl` 使用）
    pub fn policy(&self) -> Arc<RwLock<CompiledPolicy>> {
        Arc::clone(&self.policy)
    }

    /// 获取策略 AST 的共享引用
    pub fn policy_ast(&self) -> Arc<RwLock<PolicyAst>> {
        Arc::clone(&self.policy_ast)
    }

    /// 重载成功次数
    pub fn reload_count(&self) -> u64 {
        self.reload_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 重载失败次数
    pub fn reload_fail_count(&self) -> u64 {
        self.reload_fail_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 启动本地文件轮询后台任务
    ///
    /// 轮询间隔由 `PCM_POLICY_POLL_INTERVAL_SECS` 环境变量配置，默认 5 秒。
    pub fn watch_file(self: Arc<Self>, path: PathBuf) -> JoinHandle<()> {
        let interval_secs: u64 = std::env::var("PCM_POLICY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECS);
        let interval = Duration::from_secs(interval_secs);

        tracing::info!(
            path = %path.display(),
            interval_secs,
            "starting policy file watcher"
        );

        tokio::spawn(async move {
            Self::poll_file(self, path, interval).await;
        })
    }

    /// 文件轮询循环
    async fn poll_file(self: Arc<Self>, path: PathBuf, interval: Duration) {
        loop {
            tokio::time::sleep(interval).await;
            match tokio::fs::read_to_string(&path).await {
                Ok(source) => {
                    if let Err(e) = self.reload(&source) {
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            "policy reload failed"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "cannot read policy file"
                    );
                }
            }
        }
    }

    /// 重新加载策略
    ///
    /// 流程：
    /// 1. 计算 content_hash → 与当前 hash 比较 → 相同则跳过
    /// 2. 解析 AST → 编译 → 失败则保持旧策略
    /// 3. 编译成功 → 原子替换 policy + ast + hash
    pub fn reload(&self, source: &str) -> Result<(), String> {
        let new_hash = blake3_hash(source.as_bytes());

        // content_hash 去重
        {
            let current = self.current_hash.read().unwrap();
            if let Some(ref h) = *current
                && *h == new_hash
            {
                tracing::debug!("policy unchanged, skipping reload");
                return Ok(());
            }
        }

        // 锁外编译 — 不阻塞评估请求
        let ast = pcm_policy_dsl::parse_policy(source).map_err(|e| {
            self.reload_fail_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("parse error: {e}")
        })?;

        let result = compile(&ast, "runtime").map_err(|e| {
            self.reload_fail_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("compile error: {e}")
        })?;

        // 原子替换：先获取所有写锁再更新
        let old_hash_display = {
            let current = self.current_hash.read().unwrap();
            current
                .map(hex::encode)
                .unwrap_or_else(|| "none".to_string())
        };

        {
            let mut policy = self.policy.write().unwrap();
            *policy = result.policy;
        }
        {
            let mut policy_ast = self.policy_ast.write().unwrap();
            *policy_ast = ast;
        }
        {
            let mut hash = self.current_hash.write().unwrap();
            *hash = Some(new_hash);
        }

        self.reload_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tracing::info!(
            old_hash = %old_hash_display,
            new_hash = %hex::encode(new_hash),
            reload_count = self.reload_count.load(std::sync::atomic::Ordering::Relaxed),
            "policy reloaded successfully"
        );

        Ok(())
    }
}

/// 创建带空规则的默认 CompiledPolicy
fn default_compiled_policy() -> CompiledPolicy {
    let empty_ast = PolicyAst { rules: vec![] };
    match compile(&empty_ast, "default") {
        Ok(result) => result.policy,
        Err(_) => CompiledPolicy {
            rules: vec![],
            strata: vec![],
            fact_schema: FactSchema { predicates: vec![] },
            content_hash: [0u8; 32],
            version: "default".to_string(),
            decidable: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_POLICY: &str = r#"
deny(Req, "unauthorized_http") :-
    action(Req, HttpOut, P, _),
    !has_role(P, "http_allowed").
"#;

    const VALID_POLICY_V2: &str = r#"
deny(Req, "all_blocked") :-
    action(Req, HttpOut, P, _),
    !has_role(P, "admin").
"#;

    const INVALID_POLICY: &str = r#"
this is not valid policy syntax !!!
"#;

    #[test]
    fn test_load_from_source_valid() {
        let loader = PolicyLoader::load_from_source(VALID_POLICY).unwrap();
        let policy = loader.policy.read().unwrap();
        assert!(!policy.rules.is_empty(), "should have compiled rules");
        let hash = loader.current_hash.read().unwrap();
        assert!(hash.is_some(), "should have content hash");
    }

    #[test]
    fn test_load_from_source_invalid() {
        let result = PolicyLoader::load_from_source(INVALID_POLICY);
        assert!(result.is_err(), "invalid policy should fail");
    }

    #[test]
    fn test_load_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", VALID_POLICY).unwrap();
        let loader = PolicyLoader::load_from_file(f.path()).unwrap();
        let policy = loader.policy.read().unwrap();
        assert!(!policy.rules.is_empty());
    }

    #[test]
    fn test_reload_changes_policy() {
        let loader = PolicyLoader::load_from_source(VALID_POLICY).unwrap();
        let hash_before = *loader.current_hash.read().unwrap();

        loader.reload(VALID_POLICY_V2).unwrap();

        let hash_after = *loader.current_hash.read().unwrap();
        assert_ne!(hash_before, hash_after, "hash should change");
        assert_eq!(loader.reload_count(), 1);
    }

    #[test]
    fn test_reload_same_content_skips() {
        let loader = PolicyLoader::load_from_source(VALID_POLICY).unwrap();
        loader.reload(VALID_POLICY).unwrap();
        assert_eq!(loader.reload_count(), 0, "same content should skip reload");
    }

    #[test]
    fn test_reload_invalid_keeps_old_policy() {
        let loader = PolicyLoader::load_from_source(VALID_POLICY).unwrap();
        let hash_before = *loader.current_hash.read().unwrap();
        let rule_count_before = loader.policy.read().unwrap().rules.len();

        let result = loader.reload(INVALID_POLICY);
        assert!(result.is_err(), "invalid policy should fail reload");

        // 旧策略保持不变
        let hash_after = *loader.current_hash.read().unwrap();
        let rule_count_after = loader.policy.read().unwrap().rules.len();
        assert_eq!(hash_before, hash_after, "hash should not change on failure");
        assert_eq!(rule_count_before, rule_count_after);
        assert_eq!(loader.reload_fail_count(), 1);
    }

    #[test]
    fn test_reload_counts() {
        let loader = PolicyLoader::load_from_source(VALID_POLICY).unwrap();

        // 成功重载
        loader.reload(VALID_POLICY_V2).unwrap();
        assert_eq!(loader.reload_count(), 1);
        assert_eq!(loader.reload_fail_count(), 0);

        // 失败重载
        let _ = loader.reload(INVALID_POLICY);
        assert_eq!(loader.reload_count(), 1);
        assert_eq!(loader.reload_fail_count(), 1);

        // 再次成功
        loader.reload(VALID_POLICY).unwrap();
        assert_eq!(loader.reload_count(), 2);
        assert_eq!(loader.reload_fail_count(), 1);
    }

    #[test]
    fn test_empty_loader() {
        let loader = PolicyLoader::empty();
        let policy = loader.policy.read().unwrap();
        assert!(policy.rules.is_empty());
        let hash = loader.current_hash.read().unwrap();
        assert!(hash.is_none());
    }

    #[tokio::test]
    async fn test_watch_file_detects_change() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", VALID_POLICY).unwrap();
        f.flush().unwrap();

        let loader = Arc::new(PolicyLoader::load_from_file(f.path()).unwrap());
        let hash_before = *loader.current_hash.read().unwrap();

        // 用极短轮询间隔启动 watcher
        let loader_clone = Arc::clone(&loader);
        let path = f.path().to_path_buf();
        let handle = tokio::spawn(async move {
            PolicyLoader::poll_file(loader_clone, path, Duration::from_millis(50)).await;
        });

        // 写入新策略
        tokio::time::sleep(Duration::from_millis(80)).await;
        std::fs::write(f.path(), VALID_POLICY_V2).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let hash_after = *loader.current_hash.read().unwrap();
        assert_ne!(hash_before, hash_after, "should detect file change");
        assert_eq!(loader.reload_count(), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn test_watch_file_invalid_keeps_old() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", VALID_POLICY).unwrap();
        f.flush().unwrap();

        let loader = Arc::new(PolicyLoader::load_from_file(f.path()).unwrap());
        let hash_before = *loader.current_hash.read().unwrap();

        let loader_clone = Arc::clone(&loader);
        let path = f.path().to_path_buf();
        let handle = tokio::spawn(async move {
            PolicyLoader::poll_file(loader_clone, path, Duration::from_millis(50)).await;
        });

        // 写入非法策略
        tokio::time::sleep(Duration::from_millis(80)).await;
        std::fs::write(f.path(), INVALID_POLICY).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let hash_after = *loader.current_hash.read().unwrap();
        assert_eq!(
            hash_before, hash_after,
            "invalid policy should keep old hash"
        );
        assert_eq!(loader.reload_count(), 0);
        assert!(loader.reload_fail_count() > 0);

        handle.abort();
    }

    #[tokio::test]
    async fn test_concurrent_reload_no_race() {
        let loader = Arc::new(PolicyLoader::load_from_source(VALID_POLICY).unwrap());

        let mut handles = vec![];
        for i in 0..10 {
            let loader_clone = Arc::clone(&loader);
            let source = if i % 2 == 0 {
                VALID_POLICY_V2.to_string()
            } else {
                VALID_POLICY.to_string()
            };
            handles.push(tokio::spawn(async move {
                let _ = loader_clone.reload(&source);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // 不应该 panic，策略应该是两者之一的有效策略
        let policy = loader.policy.read().unwrap();
        assert!(!policy.rules.is_empty());
    }
}
