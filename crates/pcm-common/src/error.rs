use thiserror::Error;

#[derive(Error, Debug)]
pub enum PcmError {
    #[error("policy compilation error: {0}")]
    PolicyCompilation(String),

    #[error("policy validation error: {0}")]
    PolicyValidation(String),

    #[error("certificate verification failed: {0}")]
    CertVerification(String),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("evaluation timeout after {0}ms")]
    EvaluationTimeout(u64),

    #[error("internal error: {0}")]
    Internal(String),
}
