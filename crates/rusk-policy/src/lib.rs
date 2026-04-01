//! Policy engine with DSL for rusk.
//!
//! Provides a declarative policy language for controlling which artifacts
//! are allowed, denied, quarantined, or require approval during installation.
//!
//! # Architecture
//!
//! 1. **AST** (`ast`) - User-facing policy file format (JSON/TOML serializable)
//! 2. **IR** (`ir`) - Compiled intermediate representation with pre-compiled patterns
//! 3. **Context** (`context`) - Runtime evaluation context (artifact info, graph, install mode)
//! 4. **Evaluator** (`evaluator`) - Evaluates compiled policies against contexts
//! 5. **Cache** (`cache`) - Thread-safe verdict caching with DashMap
//! 6. **Explain** (`explain`) - Detailed evaluation trace for debugging

pub mod ast;
pub mod parser;
pub mod cache;
pub mod context;
pub mod evaluator;
pub mod explain;
pub mod ir;
pub mod builtins;

pub use ast::{Action, DefaultAction, Expr, PolicyFile, Rule};
pub use parser::{load_policy_file, parse_policy_json};
pub use cache::{PolicyCacheKey, PolicyVerdictCache};
pub use context::{ArtifactInfo, GraphContext, InstallMode, PolicyContext};
pub use evaluator::PolicyEvaluator;
pub use explain::EvalTrace;
pub use ir::{CompiledExpr, CompiledPolicy, CompiledRule, CompileError};
pub use builtins::evaluate_builtin;

#[cfg(test)]
mod adversarial_tests;
