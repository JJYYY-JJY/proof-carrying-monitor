//! PCM CLI — 策略编译、证书验证、diff 分析、审计查询

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pcm", about = "Proof-Carrying Monitor CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 编译策略 DSL
    Compile {
        /// 策略文件路径
        #[arg(short, long)]
        file: String,
        /// 输出编译产物路径
        #[arg(short, long)]
        output: Option<String>,
    },
    /// 验证证书
    Verify {
        /// 证书文件路径
        #[arg(short, long)]
        cert: String,
    },
    /// 策略 diff 分析
    Diff {
        /// 旧策略版本
        #[arg(long)]
        old: String,
        /// 新策略版本
        #[arg(long)]
        new: String,
        /// 输出报告路径
        #[arg(short, long)]
        output: Option<String>,
    },
    /// 查询审计日志
    Audit {
        /// 查询过滤条件
        #[arg(short, long)]
        query: Option<String>,
    },
    /// 验证策略 DSL 语法
    Validate {
        /// 策略文件路径
        #[arg(short, long)]
        file: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pcm=info")
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { file, output } => {
            tracing::info!(%file, ?output, "compiling policy");
            let source = std::fs::read_to_string(&file)?;
            let ast = pcm_policy_dsl::parser::parse_policy(&source)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let result = pcm_policy_dsl::compiler::compile(&ast, "0.1.0")
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let out_path = output.unwrap_or_else(|| format!("{}.compiled.json", file));
            let json = serde_json::to_string_pretty(&result.policy)?;
            std::fs::write(&out_path, json)?;
            println!("Compiled policy written to {}", out_path);
            Ok(())
        }
        Commands::Verify { cert } => {
            tracing::info!(%cert, "verifying certificate");
            let cert_bytes = std::fs::read(&cert)?;
            let result = pcm_cert_checker_ffi::verify_certificate(
                &cert_bytes, b"TODO", b"TODO", b"TODO",
            );
            if result.valid {
                println!("Certificate VALID");
            } else {
                println!("Certificate INVALID: {}", result.error.unwrap_or_default());
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::Diff { old, new, output } => {
            tracing::info!(%old, %new, ?output, "analyzing policy diff");
            // TODO: 调用 diff-analyzer 服务
            println!("Diff analysis: TODO");
            Ok(())
        }
        Commands::Audit { query } => {
            tracing::info!(?query, "querying audit logs");
            // TODO: 调用 audit-log-service
            println!("Audit query: TODO");
            Ok(())
        }
        Commands::Validate { file } => {
            let source = std::fs::read_to_string(&file)?;
            match pcm_policy_dsl::parser::parse_policy(&source) {
                Ok(_) => println!("Policy is valid"),
                Err(e) => {
                    println!("Policy validation failed: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}
