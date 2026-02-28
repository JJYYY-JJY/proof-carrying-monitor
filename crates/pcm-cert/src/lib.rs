//! PCM Cert — 证书生成、序列化与签名
//!
//! 根据 Datalog 评估的推导追踪生成可验证的证书（Certificate）或反例（Witness）。

pub mod generator;
pub mod serialize;

pub use generator::{
    CertStep, CertificateData, SerializedAtom, ViolationPath, WitnessData, generate_all_witnesses,
    generate_certificate, generate_witness,
};
pub use serialize::{deserialize_certificate, serialize_certificate};
