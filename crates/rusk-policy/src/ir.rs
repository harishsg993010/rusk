//! Compiled intermediate representation for policy evaluation.
//!
//! The IR is optimized for fast evaluation: glob patterns are pre-compiled,
//! sets are stored as HashSets, and expressions are flattened where possible.

use crate::ast::{Action, DefaultAction, Expr, PolicyFile, Rule};
use std::collections::HashSet;

/// A compiled policy ready for evaluation.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    /// Policy name for diagnostics.
    pub name: String,
    /// Policy version.
    pub version: String,
    /// Compiled rules in priority order (lowest priority number first).
    pub rules: Vec<CompiledRule>,
    /// Default action when no rules match.
    pub default_action: DefaultAction,
}

/// A compiled rule with pre-processed condition.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    /// Rule name for diagnostics.
    pub name: String,
    /// Compiled condition expression.
    pub condition: CompiledExpr,
    /// Action to take when condition is true.
    pub action: Action,
    /// Priority (lower = higher priority).
    pub priority: u32,
}

/// Compiled expression optimized for evaluation.
#[derive(Clone, Debug)]
pub enum CompiledExpr {
    /// Constant boolean.
    Const(bool),
    /// Variable lookup from context by dotted path.
    VarLookup(String),
    /// Equality comparison.
    Eq(Box<CompiledExpr>, Box<CompiledExpr>),
    /// Logical AND (short-circuiting).
    And(Vec<CompiledExpr>),
    /// Logical OR (short-circuiting).
    Or(Vec<CompiledExpr>),
    /// Logical NOT.
    Not(Box<CompiledExpr>),
    /// Set membership test with pre-built HashSet.
    InSet {
        value: Box<CompiledExpr>,
        set: HashSet<String>,
    },
    /// Pre-compiled glob pattern match.
    GlobMatch {
        value: Box<CompiledExpr>,
        pattern: glob::Pattern,
    },
    /// String literal.
    StringLit(String),
}

/// Errors that can occur during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        source: glob::PatternError,
    },
    #[error("empty policy: no rules and default action is deny")]
    EmptyDenyPolicy,
}

impl CompiledPolicy {
    /// Compile a policy AST into the optimized IR.
    pub fn compile(policy: &PolicyFile) -> Result<Self, CompileError> {
        let mut rules: Vec<CompiledRule> = policy
            .rules
            .iter()
            .map(|r| CompiledRule::compile(r))
            .collect::<Result<_, _>>()?;

        // Sort rules by priority (lowest number = highest priority).
        rules.sort_by_key(|r| r.priority);

        Ok(Self {
            name: policy.name.clone(),
            version: policy.version.clone(),
            rules,
            default_action: policy.default_action.clone(),
        })
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl CompiledRule {
    /// Compile a single rule.
    fn compile(rule: &Rule) -> Result<Self, CompileError> {
        Ok(Self {
            name: rule.name.clone(),
            condition: CompiledExpr::compile(&rule.condition)?,
            action: rule.action.clone(),
            priority: rule.priority,
        })
    }
}

impl CompiledExpr {
    /// Compile an AST expression into the IR.
    pub fn compile(expr: &Expr) -> Result<Self, CompileError> {
        match expr {
            Expr::Const { value } => Ok(CompiledExpr::Const(*value)),

            Expr::Var { name } => Ok(CompiledExpr::VarLookup(name.clone())),

            Expr::StringLit { value } => Ok(CompiledExpr::StringLit(value.clone())),

            Expr::Eq { left, right } => Ok(CompiledExpr::Eq(
                Box::new(CompiledExpr::compile(left)?),
                Box::new(CompiledExpr::compile(right)?),
            )),

            Expr::Neq { left, right } => Ok(CompiledExpr::Not(Box::new(CompiledExpr::Eq(
                Box::new(CompiledExpr::compile(left)?),
                Box::new(CompiledExpr::compile(right)?),
            )))),

            Expr::And { exprs } => {
                let compiled: Vec<CompiledExpr> = exprs
                    .iter()
                    .map(CompiledExpr::compile)
                    .collect::<Result<_, _>>()?;
                // Flatten nested ANDs.
                let flattened = flatten_and(compiled);
                Ok(CompiledExpr::And(flattened))
            }

            Expr::Or { exprs } => {
                let compiled: Vec<CompiledExpr> = exprs
                    .iter()
                    .map(CompiledExpr::compile)
                    .collect::<Result<_, _>>()?;
                // Flatten nested ORs.
                let flattened = flatten_or(compiled);
                Ok(CompiledExpr::Or(flattened))
            }

            Expr::Not { expr } => Ok(CompiledExpr::Not(Box::new(CompiledExpr::compile(expr)?))),

            Expr::InSet { value, set } => Ok(CompiledExpr::InSet {
                value: Box::new(CompiledExpr::compile(value)?),
                set: set.iter().cloned().collect(),
            }),

            Expr::GlobMatch { value, pattern } => {
                let compiled_pattern =
                    glob::Pattern::new(pattern).map_err(|e| CompileError::InvalidGlob {
                        pattern: pattern.clone(),
                        source: e,
                    })?;
                Ok(CompiledExpr::GlobMatch {
                    value: Box::new(CompiledExpr::compile(value)?),
                    pattern: compiled_pattern,
                })
            }
        }
    }
}

/// Flatten nested AND expressions into a single list.
fn flatten_and(exprs: Vec<CompiledExpr>) -> Vec<CompiledExpr> {
    let mut result = Vec::new();
    for expr in exprs {
        match expr {
            CompiledExpr::And(inner) => result.extend(flatten_and(inner)),
            other => result.push(other),
        }
    }
    result
}

/// Flatten nested OR expressions into a single list.
fn flatten_or(exprs: Vec<CompiledExpr>) -> Vec<CompiledExpr> {
    let mut result = Vec::new();
    for expr in exprs {
        match expr {
            CompiledExpr::Or(inner) => result.extend(flatten_or(inner)),
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    #[test]
    fn compile_simple_policy() {
        let policy = PolicyFile {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            default_action: DefaultAction::Deny,
            rules: vec![Rule {
                name: "allow-signed".to_string(),
                description: None,
                condition: Expr::Var {
                    name: "signature.verified".to_string(),
                },
                action: Action::Allow,
                priority: 10,
            }],
        };
        let compiled = CompiledPolicy::compile(&policy).unwrap();
        assert_eq!(compiled.rule_count(), 1);
        assert_eq!(compiled.rules[0].name, "allow-signed");
    }

    #[test]
    fn compile_glob_pattern() {
        let expr = Expr::GlobMatch {
            value: Box::new(Expr::Var {
                name: "package.name".to_string(),
            }),
            pattern: "@myorg/*".to_string(),
        };
        let compiled = CompiledExpr::compile(&expr).unwrap();
        match compiled {
            CompiledExpr::GlobMatch { pattern, .. } => {
                assert!(pattern.matches("@myorg/foo"));
                assert!(!pattern.matches("@other/bar"));
            }
            _ => panic!("expected GlobMatch"),
        }
    }

    #[test]
    fn rules_sorted_by_priority() {
        let policy = PolicyFile {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            default_action: DefaultAction::Deny,
            rules: vec![
                Rule {
                    name: "low-priority".to_string(),
                    description: None,
                    condition: Expr::Const { value: true },
                    action: Action::Allow,
                    priority: 200,
                },
                Rule {
                    name: "high-priority".to_string(),
                    description: None,
                    condition: Expr::Const { value: true },
                    action: Action::Deny {
                        reason: "blocked".to_string(),
                    },
                    priority: 1,
                },
            ],
        };
        let compiled = CompiledPolicy::compile(&policy).unwrap();
        assert_eq!(compiled.rules[0].name, "high-priority");
        assert_eq!(compiled.rules[1].name, "low-priority");
    }
}
