//! PCM Common — 共享类型与工具函数
//!
//! 包含 protobuf 生成的类型、通用错误、blake3 哈希工具等。

pub mod error;
pub mod hash;

/// Protobuf 生成的类型和服务定义
pub mod proto {
    pub mod pcm_v1 {
        tonic::include_proto!("pcm.v1");
    }
}

/// PCM 通用错误类型
pub use error::PcmError;
