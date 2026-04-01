//! Explanation trace types for policy evaluation.
//!
//! Provides detailed traces of how each rule was evaluated, which variables
//! were consulted, and why the final verdict was reached. Useful for
//! debugging policies and presenting to users.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Complete evaluation trace for a policy run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalTrace {
    /// Name of the policy that was evaluated.
    pub policy_name: String,
    /// Traces for each rule evaluated (in evaluation order).
    pub rule_traces: Vec<RuleTrace>,
    /// The final verdict description.
    pub verdict: Option<String>,
}

/// Trace of a single rule evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleTrace {
    /// Name of the rule.
    pub rule_name: String,
    /// Whether the rule condition evaluated to true.
    pub matched: bool,
    /// Trace of the condition expression evaluation.
    pub condition_trace: TraceNode,
}

/// A node in the expression evaluation trace tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceNode {
    /// Description of the operation (e.g., "var(package.name)", "and", "glob_match").
    pub operation: String,
    /// The computed result as a string.
    pub result: String,
    /// Child trace nodes.
    pub children: Vec<TraceNode>,
    /// Optional detail message for complex operations.
    pub detail: Option<String>,
}

impl EvalTrace {
    /// Create a new empty trace for a policy.
    pub fn new(policy_name: String) -> Self {
        Self {
            policy_name,
            rule_traces: Vec::new(),
            verdict: None,
        }
    }

    /// Add a rule evaluation trace.
    pub fn add_rule_trace(&mut self, rule_name: String, condition_trace: TraceNode, matched: bool) {
        self.rule_traces.push(RuleTrace {
            rule_name,
            matched,
            condition_trace,
        });
    }

    /// Set the final verdict description.
    pub fn set_verdict(&mut self, verdict: String) {
        self.verdict = Some(verdict);
    }

    /// Get the names of all rules that were evaluated.
    pub fn evaluated_rules(&self) -> Vec<&str> {
        self.rule_traces.iter().map(|r| r.rule_name.as_str()).collect()
    }

    /// Get the names of rules that matched.
    pub fn matched_rules(&self) -> Vec<&str> {
        self.rule_traces
            .iter()
            .filter(|r| r.matched)
            .map(|r| r.rule_name.as_str())
            .collect()
    }

    /// Format the trace as a human-readable explanation.
    pub fn explain(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Policy: {}\n", self.policy_name));
        out.push_str(&format!(
            "Rules evaluated: {}\n",
            self.rule_traces.len()
        ));

        for rule_trace in &self.rule_traces {
            let status = if rule_trace.matched {
                "MATCHED"
            } else {
                "no match"
            };
            out.push_str(&format!(
                "\n  Rule '{}': {}\n",
                rule_trace.rule_name, status
            ));
            format_trace_node(&rule_trace.condition_trace, &mut out, 4);
        }

        if let Some(verdict) = &self.verdict {
            out.push_str(&format!("\nVerdict: {}\n", verdict));
        }
        out
    }
}

impl TraceNode {
    /// Create a leaf node (no children).
    pub fn leaf(operation: String, result: String) -> Self {
        Self {
            operation,
            result,
            children: Vec::new(),
            detail: None,
        }
    }

    /// Create a unary node (one child).
    pub fn unary(operation: &str, child: TraceNode, result: String) -> Self {
        Self {
            operation: operation.to_string(),
            result,
            children: vec![child],
            detail: None,
        }
    }

    /// Create a binary node (two children).
    pub fn binary(operation: &str, left: TraceNode, right: TraceNode, result: String) -> Self {
        Self {
            operation: operation.to_string(),
            result,
            children: vec![left, right],
            detail: None,
        }
    }

    /// Create an n-ary node (multiple children).
    pub fn nary(operation: &str, children: Vec<TraceNode>, result: String) -> Self {
        Self {
            operation: operation.to_string(),
            result,
            children,
            detail: None,
        }
    }

    /// Create a node with an extra detail message.
    pub fn with_detail(
        operation: String,
        children: Vec<TraceNode>,
        result: String,
        detail: String,
    ) -> Self {
        Self {
            operation,
            result,
            children,
            detail: Some(detail),
        }
    }
}

/// Recursively format a trace node tree into a string with indentation.
fn format_trace_node(node: &TraceNode, out: &mut String, indent: usize) {
    let pad: String = " ".repeat(indent);
    out.push_str(&format!("{}{} => {}\n", pad, node.operation, node.result));
    if let Some(detail) = &node.detail {
        out.push_str(&format!("{}  ({})\n", pad, detail));
    }
    for child in &node.children {
        format_trace_node(child, out, indent + 2);
    }
}

impl fmt::Display for EvalTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.explain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_explain_format() {
        let mut trace = EvalTrace::new("test-policy".to_string());
        trace.add_rule_trace(
            "allow-signed".to_string(),
            TraceNode::leaf("var(signature.verified)".to_string(), "true".to_string()),
            true,
        );
        trace.set_verdict("Allow".to_string());

        let explanation = trace.explain();
        assert!(explanation.contains("test-policy"));
        assert!(explanation.contains("allow-signed"));
        assert!(explanation.contains("MATCHED"));
        assert!(explanation.contains("Verdict: Allow"));
    }

    #[test]
    fn matched_rules_filters_correctly() {
        let mut trace = EvalTrace::new("test".to_string());
        trace.add_rule_trace(
            "rule-a".to_string(),
            TraceNode::leaf("const".to_string(), "false".to_string()),
            false,
        );
        trace.add_rule_trace(
            "rule-b".to_string(),
            TraceNode::leaf("const".to_string(), "true".to_string()),
            true,
        );

        assert_eq!(trace.matched_rules(), vec!["rule-b"]);
        assert_eq!(trace.evaluated_rules(), vec!["rule-a", "rule-b"]);
    }

    #[test]
    fn nested_trace_formatting() {
        let node = TraceNode::nary(
            "and",
            vec![
                TraceNode::leaf("var(a)".to_string(), "true".to_string()),
                TraceNode::with_detail(
                    "glob_match(\"@org/*\")".to_string(),
                    vec![TraceNode::leaf("var(name)".to_string(), "@org/foo".to_string())],
                    "true".to_string(),
                    "\"@org/foo\" matches \"@org/*\" => true".to_string(),
                ),
            ],
            "true".to_string(),
        );

        let mut out = String::new();
        format_trace_node(&node, &mut out, 0);
        assert!(out.contains("and => true"));
        assert!(out.contains("var(a) => true"));
        assert!(out.contains("glob_match"));
    }
}
