pub mod cache;
pub mod identity;
pub mod verifier;
pub mod keyless;
pub mod static_key;
pub mod certificate;

pub use cache::SignatureCache;
pub use identity::{extract_signer_identity, IdentityMatcher};
pub use verifier::{
    ArtifactSignature, SignatureAlgorithm, SignatureVerifier, SignerProof, VerifiedSignature,
};
pub use static_key::{StaticKey, StaticKeyRegistry};
pub use certificate::{CertificateInfo, parse_certificate_info, parse_certificate_der, validate_chain_link};
pub use keyless::{KeylessConfig, verify_keyless_signature, extract_oidc_identity};
