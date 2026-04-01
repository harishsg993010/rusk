//! Policy expression evaluator.
//!
//! Evaluates compiled IR expressions against a PolicyContext,
//! producing a verdict with an explanation trace.

use crate::ast::{Action, DefaultAction};
use crate::context::PolicyContext;
use crate::explain::{EvalTrace, TraceNode};
use crate::ir::{CompiledExpr, CompiledPolicy};
use rusk_core::trust::PolicyVerdict;
use tracing::{debug, instrument, warn};

/// Evaluates compiled policies against artifact contexts.
pub struct PolicyEvaluator {
    /// The compiled policy to evaluate.
    policy: CompiledPolicy,
}

/// Result of evaluating a single expression to a string or boolean.
#[derive(Clone, Debug)]
enum EvalResult {
    Bool(bool),
    Str(String),
}

impl EvalResult {
    fn as_bool(&self) -> bool {
        match self {
            EvalResult::Bool(b) => *b,
            // Non-empty strings are truthy, "true" is true, everything else is false.
            EvalResult::Str(s) => s == "true",
        }
    }

    fn as_str(&self) -> String {
        match self {
            EvalResult::Bool(b) => b.to_string(),
            EvalResult::Str(s) => s.clone(),
        }
    }
}

impl PolicyEvaluator {
    /// Create an evaluator for the given compiled policy.
    pub fn new(policy: CompiledPolicy) -> Self {
        Self { policy }
    }

    /// Evaluate the policy against a context, returning a verdict and explanation trace.
    #[instrument(skip(self, ctx), fields(policy = %self.policy.name))]
    pub fn evaluate(&self, ctx: &PolicyContext) -> (PolicyVerdict, EvalTrace) {
        let mut trace = EvalTrace::new(self.policy.name.clone());
        let mut matched_rules = Vec::new();

        for rule in &self.policy.rules {
            let (result, node) = self.eval_expr(&rule.condition, ctx);
            trace.add_rule_trace(rule.name.clone(), node, result.as_bool());

            if result.as_bool() {
                debug!(rule = %rule.name, "policy rule matched");
                matched_rules.push(rule.name.clone());

                let verdict = action_to_verdict(&rule.action, &matched_rules);
                trace.set_verdict(format!("{:?}", verdict));
                return (verdict, trace);
            }
        }

        // No rules matched: apply default action.
        debug!(policy = %self.policy.name, "no rules matched, applying default action");
        let verdict = match &self.policy.default_action {
            DefaultAction::Allow => PolicyVerdict::Allow { matched_rules },
            DefaultAction::Deny => PolicyVerdict::Deny {
                reason: format!("no policy rules matched in '{}'", self.policy.name),
                matched_rules,
            },
            DefaultAction::Warn => PolicyVerdict::Warn {
                warnings: vec![format!(
                    "no policy rules matched in '{}', allowing by default",
                    self.policy.name
                )],
            },
        };
        trace.set_verdict(format!("{:?}", verdict));
        (verdict, trace)
    }

    /// Evaluate a compiled expression, returning the result and a trace node.
    fn eval_expr(&self, expr: &CompiledExpr, ctx: &PolicyContext) -> (EvalResult, TraceNode) {
        match expr {
            CompiledExpr::Const(val) => {
                let node = TraceNode::leaf(format!("const({val})"), format!("{val}"));
                (EvalResult::Bool(*val), node)
            }

            CompiledExpr::VarLookup(path) => {
                let value = ctx.lookup(path).unwrap_or_default();
                let node = TraceNode::leaf(format!("var({path})"), value.clone());
                (EvalResult::Str(value), node)
            }

            CompiledExpr::StringLit(s) => {
                let node = TraceNode::leaf(format!("string(\"{s}\")"), s.clone());
                (EvalResult::Str(s.clone()), node)
            }

            CompiledExpr::Eq(left, right) => {
                let (left_val, left_trace) = self.eval_expr(left, ctx);
                let (right_val, right_trace) = self.eval_expr(right, ctx);
                let result = left_val.as_str() == right_val.as_str();
                let node = TraceNode::binary(
                    "eq",
                    left_trace,
                    right_trace,
                    result.to_string(),
                );
                (EvalResult::Bool(result), node)
            }

            CompiledExpr::And(exprs) => {
                let mut children = Vec::new();
                for sub_expr in exprs {
                    let (val, trace) = self.eval_expr(sub_expr, ctx);
                    children.push(trace);
                    if !val.as_bool() {
                        // Short-circuit: false AND anything = false.
                        let node = TraceNode::nary("and", children, "false".to_string());
                        return (EvalResult::Bool(false), node);
                    }
                }
                let node = TraceNode::nary("and", children, "true".to_string());
                (EvalResult::Bool(true), node)
            }

            CompiledExpr::Or(exprs) => {
                let mut children = Vec::new();
                for sub_expr in exprs {
                    let (val, trace) = self.eval_expr(sub_expr, ctx);
                    children.push(trace);
                    if val.as_bool() {
                        // Short-circuit: true OR anything = true.
                        let node = TraceNode::nary("or", children, "true".to_string());
                        return (EvalResult::Bool(true), node);
                    }
                }
                let node = TraceNode::nary("or", children, "false".to_string());
                (EvalResult::Bool(false), node)
            }

            CompiledExpr::Not(inner) => {
                let (val, inner_trace) = self.eval_expr(inner, ctx);
                let result = !val.as_bool();
                let node = TraceNode::unary("not", inner_trace, result.to_string());
                (EvalResult::Bool(result), node)
            }

            CompiledExpr::InSet { value, set } => {
                let (val, val_trace) = self.eval_expr(value, ctx);
                let str_val = val.as_str();
                let result = set.contains(&str_val);
                let node = TraceNode::with_detail(
                    format!("in_set({:?})", set),
                    vec![val_trace],
                    result.to_string(),
                    format!("\"{}\" in {:?} => {}", str_val, set, result),
                );
                (EvalResult::Bool(result), node)
            }

            CompiledExpr::GlobMatch { value, pattern } => {
                let (val, val_trace) = self.eval_expr(value, ctx);
                let str_val = val.as_str();
                let result = pattern.matches(&str_val);
                let node = TraceNode::with_detail(
                    format!("glob_match(\"{}\")", pattern.as_str()),
                    vec![val_trace],
                    result.to_string(),
                    format!(
                        "\"{}\" matches \"{}\" => {}",
                        str_val,
                        pattern.as_str(),
                        result
                    ),
                );
                (EvalResult::Bool(result), node)
            }
        }
    }
}

/// Convert a rule action into a policy verdict.
fn action_to_verdict(action: &Action, matched_rules: &[String]) -> PolicyVerdict {
    match action {
        Action::Allow => PolicyVerdict::Allow {
            matched_rules: matched_rules.to_vec(),
        },
        Action::Deny { reason } => PolicyVerdict::Deny {
            reason: reason.clone(),
            matched_rules: matched_rules.to_vec(),
        },
        Action::RequireApproval { reason } => PolicyVerdict::RequireApproval {
            reason: reason.clone(),
        },
        Action::Quarantine {
            reason,
            duration_hours,
        } => PolicyVerdict::Quarantine {
            reason: reason.clone(),
            duration: chrono::Duration::hours(*duration_hours as i64),
        },
        Action::Warn { warnings } => PolicyVerdict::Warn {
            warnings: warnings.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;
    use crate::context::*;
    use crate::ir::CompiledPolicy;
    use rusk_core::*;
    use std::collections::HashMap;

    fn make_context(signed: bool, ecosystem: Ecosystem) -> PolicyContext {
        PolicyContext {
            artifact: ArtifactInfo {
                package_id: PackageId::js("test-pkg"),
                version: Version::Semver(semver::Version::new(1, 0, 0)),
                ecosystem,
                digest: Sha256Digest::zero(),
                signature_verified: signed,
                signer: if signed {
                    Some("user@example.com".to_string())
                } else {
                    None
                },
                provenance_verified: false,
                source_repo: None,
                trust_class: if signed {
                    TrustClass::TrustedRelease
                } else {
                    TrustClass::Unverified
                },
                in_transparency_log: false,
                yanked: false,
                age_hours: 24,
            },
            graph: GraphContext::default(),
            install_mode: InstallMode::Interactive,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn evaluate_allow_signed() {
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
        let evaluator = PolicyEvaluator::new(compiled);

        // Signed artifact should be allowed.
        let ctx = make_context(true, Ecosystem::Js);
        let (verdict, _trace) = evaluator.evaluate(&ctx);
        assert!(matches!(verdict, PolicyVerdict::Allow { .. }));

        // Unsigned artifact should be denied by default.
        let ctx = make_context(false, Ecosystem::Js);
        let (verdict, _trace) = evaluator.evaluate(&ctx);
        assert!(matches!(verdict, PolicyVerdict::Deny { .. }));
    }

    #[test]
    fn evaluate_ecosystem_filter() {
        let policy = PolicyFile {
            name: "js-only".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            default_action: DefaultAction::Deny,
            rules: vec![Rule {
                name: "allow-js".to_string(),
                description: None,
                condition: Expr::Eq {
                    left: Box::new(Expr::Var {
                        name: "package.ecosystem".to_string(),
                    }),
                    right: Box::new(Expr::StringLit {
                        value: "js".to_string(),
                    }),
                },
                action: Action::Allow,
                priority: 10,
            }],
        };
        let compiled = CompiledPolicy::compile(&policy).unwrap();
        let evaluator = PolicyEvaluator::new(compiled);

        let js_ctx = make_context(false, Ecosystem::Js);
        let (verdict, _) = evaluator.evaluate(&js_ctx);
        assert!(matches!(verdict, PolicyVerdict::Allow { .. }));

        let py_ctx = make_context(false, Ecosystem::Python);
        let (verdict, _) = evaluator.evaluate(&py_ctx);
        assert!(matches!(verdict, PolicyVerdict::Deny { .. }));
    }

    #[test]
    fn default_allow_when_no_rules_match() {
        let policy = PolicyFile::allow_all("permissive");
        let compiled = CompiledPolicy::compile(&policy).unwrap();
        let evaluator = PolicyEvaluator::new(compiled);
        let ctx = make_context(false, Ecosystem::Js);
        let (verdict, _) = evaluator.evaluate(&ctx);
        assert!(matches!(verdict, PolicyVerdict::Allow { .. }));
    }
}
