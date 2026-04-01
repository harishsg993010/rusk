pub mod attestation;
pub mod bundle;
pub mod normalize;
pub mod risk;
pub mod verify;
pub mod slsa;
pub mod npm;

pub use attestation::{DsseEnvelope, DsseSignature, InTotoStatement, parse_attestation};
pub use bundle::VerifiedProvenance;
pub use normalize::{
    NormalizedProvenance, ProvBuildConfig, ProvMaterial, ProvMetadata, ProvenanceBuilder,
    ProvenanceSource, ProvenanceSubject,
};
pub use risk::{RiskFlag, compute_risk_flags};
pub use verify::ProvenanceVerifyResult;
pub use slsa::{SlsaPredicate, SlsaLevel, assess_slsa_level};

#[cfg(test)]
mod adversarial_tests;
