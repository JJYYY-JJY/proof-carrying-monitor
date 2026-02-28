//! PCM CLI — 策略编译、证书验证、diff 分析、审计查询

mod audit_cmd;
mod diff_cmd;
mod verify_cmd;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pcm", about = "Proof-Carrying Monitor CLI", version)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable verbose logging (debug level)
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 编译策略 DSL
    Compile {
        /// 策略文件路径
        #[arg(short, long)]
        file: String,
        /// 输出编译产物路径
        #[arg(short, long)]
        output: Option<String>,
    },
    /// 离线验证证书
    Verify {
        /// 证书文件路径（二进制或 JSON）
        #[arg(short, long)]
        cert: String,
        /// 策略文件路径（.pcm）
        #[arg(short, long)]
        policy: String,
        /// 请求数据文件（JSON）
        #[arg(short, long)]
        request: Option<String>,
        /// 输出格式：text / json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// 策略 diff 分析
    Diff {
        /// 旧策略文件路径
        #[arg(long)]
        old: String,
        /// 新策略文件路径
        #[arg(long)]
        new: String,
        /// 输出报告路径（JSON）
        #[arg(short, long)]
        output: Option<String>,
        /// 输出格式：text / json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// 查询审计日志
    Audit {
        /// 查询过滤条件（principal=xxx, verdict=allow, etc.）
        #[arg(short, long)]
        query: Option<String>,
        /// 审计服务地址
        #[arg(long, default_value = "http://localhost:50054")]
        endpoint: String,
        /// 最大返回条数
        #[arg(long, default_value = "20")]
        limit: u32,
        /// 输出格式：text / json
        #[arg(long, default_value = "text")]
        format: String,
        /// 验证签名链完整性
        #[arg(long)]
        verify_chain: bool,
    },
    /// 验证策略 DSL 语法
    Validate {
        /// 策略文件路径
        #[arg(short, long)]
        file: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let env_filter = if cli.verbose { "pcm=debug" } else { "pcm=info" };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Compile { file, output } => {
            tracing::info!(%file, ?output, "compiling policy");
            let source = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("failed to read policy file '{}': {}", file, e))?;
            let ast = pcm_policy_dsl::parser::parse_policy(&source)
                .map_err(|e| anyhow::anyhow!("parse error: {}", e))?;
            let result = pcm_policy_dsl::compiler::compile(&ast, "0.1.0")
                .map_err(|e| anyhow::anyhow!("compile error: {}", e))?;
            let out_path = output.unwrap_or_else(|| format!("{}.compiled.json", file));
            let json = serde_json::to_string_pretty(&result.policy)?;
            std::fs::write(&out_path, &json)
                .map_err(|e| anyhow::anyhow!("failed to write output '{}': {}", out_path, e))?;
            println!("Compiled policy written to {}", out_path);
            Ok(())
        }
        Commands::Verify {
            cert,
            policy,
            request,
            format,
        } => verify_cmd::run(cert, policy, request, format),
        Commands::Diff {
            old,
            new,
            output,
            format,
        } => diff_cmd::run(old, new, output, format),
        Commands::Audit {
            query,
            endpoint,
            limit,
            format,
            verify_chain,
        } => audit_cmd::run(query, endpoint, limit, format, verify_chain),
        Commands::Validate { file } => {
            let source = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("failed to read file '{}': {}", file, e))?;
            match pcm_policy_dsl::parser::parse_policy(&source) {
                Ok(_) => {
                    println!("Policy is valid");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Policy validation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
