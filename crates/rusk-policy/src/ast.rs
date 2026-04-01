//! Policy DSL abstract syntax tree.
//!
//! Represents the user-facing policy file format before compilation to IR.

use serde::{Deserialize, Serialize};

/// A complete policy file containing metadata and rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyFile {
    /// Human-readable policy name.
    pub name: String,
    /// Semantic version of this policy file.
    pub version: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// The default action when no rules match.
    #[serde(default)]
    pub default_action: DefaultAction,
    /// Ordered list of policy rules (first match wins).
    pub rules: Vec<Rule>,
}

/// A single policy rule with a condition and an action.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    /// Human-readable rule name for diagnostics.
    pub name: String,
    /// Optional description of what this rule does.
    #[serde(default)]
    pub description: Option<String>,
    /// The condition that must hold for this rule to fire.
    pub condition: Expr,
    /// The action to take when the condition holds.
    pub action: Action,
    /// Priority (lower number = higher priority). Default 100.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 {
    100
}

/// Expression AST for policy conditions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Expr {
    /// Boolean literal.
    Const { value: bool },
    /// Variable lookup from the policy context.
    Var { name: String },
    /// String equality comparison.
    Eq {
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Not-equal comparison.
    Neq {
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Logical AND of sub-expressions.
    And { exprs: Vec<Expr> },
    /// Logical OR of sub-expressions.
    Or { exprs: Vec<Expr> },
    /// Logical NOT.
    Not { expr: Box<Expr> },
    /// Membership test: value in a set of strings.
    InSet {
        value: Box<Expr>,
        set: Vec<String>,
    },
    /// Glob pattern match against a string value.
    GlobMatch {
        value: Box<Expr>,
        pattern: String,
    },
    /// String literal for use in comparisons.
    StringLit { value: String },
}

/// Action to take when a rule matches.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Allow the artifact.
    Allow,
    /// Deny the artifact with a reason.
    Deny { reason: String },
    /// Require explicit approval.
    RequireApproval { reason: String },
    /// Place the artifact under quarantine for a duration.
    Quarantine {
        reason: String,
        /// Duration in hours.
        duration_hours: u64,
    },
    /// Allow but emit warnings.
    Warn { warnings: Vec<String> },
}

/// Default action when no rules match.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
    Deny,
    Warn,
}

impl Default for DefaultAction {
    fn default() -> Self {
        DefaultAction::Deny
    }
}

impl PolicyFile {
    /// Create a minimal policy that allows everything.
    pub fn allow_all(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: Some("Allow-all policy".to_string()),
            default_action: DefaultAction::Allow,
            rules: Vec::new(),
        }
    }

    /// Create a minimal policy that denies everything.
    pub fn deny_all(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: Some("Deny-all policy".to_string()),
            default_action: DefaultAction::Deny,
            rules: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_policy_json() {
        let policy = PolicyFile {
            name: "test-policy".to_string(),
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
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: PolicyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test-policy");
        assert_eq!(parsed.rules.len(), 1);
    }

    #[test]
    fn complex_expression() {
        let expr = Expr::And {
            exprs: vec![
                Expr::Var {
                    name: "signature.verified".to_string(),
                },
                Expr::Or {
                    exprs: vec![
                        Expr::InSet {
                            value: Box::new(Expr::Var {
                                name: "package.ecosystem".to_string(),
                            }),
                            set: vec!["js".to_string(), "python".to_string()],
                        },
                        Expr::GlobMatch {
                            value: Box::new(Expr::Var {
                                name: "package.name".to_string(),
                            }),
                            pattern: "@myorg/*".to_string(),
                        },
                    ],
                },
            ],
        };
        let json = serde_json::to_string(&expr).unwrap();
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        match parsed {
            Expr::And { exprs } => assert_eq!(exprs.len(), 2),
            _ => panic!("expected And"),
        }
    }
}
