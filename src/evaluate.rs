//! Evaluate a rule against one normalized event, with Wazuh 5.0 semantics.
//!
//! This is the fast, offline half of the test suite. It models how the Wazuh
//! 5.0 detection path (Content Manager logtest and Security Analytics
//! detectors, which share one compiler and percolator) evaluates a rule:
//!
//! * string comparison is case-sensitive (the Sigma spec says insensitive);
//! * `|re` is an unanchored search;
//! * a multi-valued field matches when any element matches;
//! * a missing field never matches, except `|exists: false` and `null`.
//!
//! The parity suite runs every fixture through a real rc2 indexer and compares
//! results, so a divergence from Wazuh fails CI.

use std::net::IpAddr;

use serde_json::Value;

use crate::sigma::{Cmp, Expr, Item, Pattern, Rule};

pub fn matches(rule: &Rule, event: &Value) -> bool {
    eval(&rule.condition, rule, event)
}

fn eval(expr: &Expr, rule: &Rule, event: &Value) -> bool {
    match expr {
        Expr::And(es) => es.iter().all(|e| eval(e, rule, event)),
        Expr::Or(es) => es.iter().any(|e| eval(e, rule, event)),
        Expr::Not(e) => !eval(e, rule, event),
        Expr::Sel(name) => rule.selections[name]
            .iter()
            .any(|items| items.iter().all(|i| item_matches(i, event))),
    }
}

fn item_matches(item: &Item, event: &Value) -> bool {
    let values = field_values(event, &item.field);
    let hit = |p: &Pattern| pattern_matches(p, &values);
    if item.all {
        item.patterns.iter().all(hit)
    } else {
        item.patterns.iter().any(hit)
    }
}

/// Leaf values of a dotted field, from a flat key or nested objects, with
/// arrays flattened and nulls dropped.
pub fn field_values<'a>(event: &'a Value, field: &str) -> Vec<&'a Value> {
    let mut nodes: Vec<&Value> = match event.get(field) {
        Some(v) => vec![v],
        None => {
            let mut nodes = vec![event];
            for part in field.split('.') {
                nodes = flatten(nodes)
                    .into_iter()
                    .filter_map(|n| n.get(part))
                    .collect();
            }
            nodes
        }
    };
    nodes = flatten(nodes);
    nodes.retain(|v| !v.is_null());
    nodes
}

fn flatten(values: Vec<&Value>) -> Vec<&Value> {
    let mut out = Vec::new();
    for v in values {
        match v {
            Value::Array(a) => out.extend(flatten(a.iter().collect())),
            v => out.push(v),
        }
    }
    out
}

fn pattern_matches(p: &Pattern, values: &[&Value]) -> bool {
    match p {
        Pattern::Exists(want) => !values.is_empty() == *want,
        Pattern::Null => values.is_empty(),
        p => values.iter().any(|v| value_matches(p, v)),
    }
}

fn value_matches(p: &Pattern, v: &Value) -> bool {
    match p {
        Pattern::Str(re) => as_text(v).is_some_and(|s| re.is_match(&s)),
        Pattern::Re(re) => v.as_str().is_some_and(|s| re.is_match(s)),
        Pattern::Num(n) => as_number(v) == Some(*n),
        Pattern::Bool(b) => v.as_bool() == Some(*b),
        Pattern::Cidr(net) => v
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .is_some_and(|ip| net.contains(&ip)),
        Pattern::Cmp(op, n) => as_number(v).is_some_and(|x| match op {
            Cmp::Lt => x < *n,
            Cmp::Lte => x <= *n,
            Cmp::Gt => x > *n,
            Cmp::Gte => x >= *n,
        }),
        Pattern::Exists(_) | Pattern::Null => unreachable!("handled per field"),
    }
}

/// Keyword fields index numbers and booleans by their string form.
fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}
