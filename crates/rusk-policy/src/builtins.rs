//! Built-in policy functions.
//!
//! Provides built-in functions available in policy expressions, such as
//! `is_prerelease()`, `days_since_publish()`, `has_provenance()`, etc.

use crate::context::PolicyContext;

/// Evaluate a built-in function by name.
pub fn evaluate_builtin(name: &str, ctx: &PolicyContext) -> Result<bool, BuiltinError> {
    match name {
        "is_prerelease" => Ok(ctx.artifact.version.is_prerelease()),
        "has_provenance" => Ok(ctx.artifact.provenance_verified),
        "has_signature" => Ok(ctx.artifact.signature_verified),
        "is_internal" => {
            Ok(ctx.artifact.trust_class == rusk_core::TrustClass::LocalDev)
        }
        "is_direct" => Ok(ctx.graph.depth == 0),
        "is_dev" => Ok(ctx.graph.is_dev_dependency),
        other => Err(BuiltinError::UnknownFunction(other.to_string())),
    }
}

/// Error from built-in function evaluation.
#[derive(Debug, thiserror::Error)]
pub enum BuiltinError {
    #[error("unknown built-in function: {0}")]
    UnknownFunction(String),
    #[error("wrong argument type for {function}: expected {expected}")]
    TypeError {
        function: String,
        expected: String,
    },
}

/// List all available built-in function names.
pub fn builtin_names() -> &'static [&'static str] {
    &[
        "is_prerelease",
        "has_provenance",
        "has_signature",
        "is_internal",
        "is_direct",
        "is_dev",
    ]
}
