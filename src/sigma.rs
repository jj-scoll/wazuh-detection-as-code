//! Sigma rule model: the subset of Sigma this repository authors, compiled with
//! Wazuh 5.0 matching semantics.
//!
//! Supported: field selections (map = AND, list of maps = OR), value lists
//! (OR, or AND with `|all`), wildcards and `\` escapes, the modifiers
//! `contains`, `startswith`, `endswith`, `all`, `re` (with `i`/`m`/`s`), `cidr`,
//! `exists`, `gt`, `gte`, `lt`, `lte`, and conditions built from `and`, `or`,
//! `not`, parentheses, `1 of`/`all of` with patterns or `them`.
//!
//! Everything else (keyword searches, aggregations, `base64`, `windash`, …) is
//! rejected with [`Error::Unsupported`] rather than evaluated approximately.

use std::collections::BTreeMap;

use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("invalid rule: {0}")]
    Invalid(String),
}

/// A parsed rule. `raw` is the YAML document as JSON, kept for conversion.
#[derive(Debug)]
pub struct Rule {
    pub title: String,
    pub raw: Value,
    pub(crate) selections: BTreeMap<String, Vec<Vec<Item>>>,
    pub(crate) condition: Expr,
}

/// One `field|modifiers: values` entry of a selection.
#[derive(Debug)]
pub(crate) struct Item {
    pub field: String,
    pub patterns: Vec<Pattern>,
    /// `|all`: every pattern must match (default: any).
    pub all: bool,
}

#[derive(Debug)]
pub(crate) enum Pattern {
    /// Anchored, case-sensitive wildcard match against the string form.
    Str(Regex),
    Num(f64),
    Bool(bool),
    /// Unanchored regex search.
    Re(Regex),
    Cidr(IpNet),
    Cmp(Cmp, f64),
    Exists(bool),
    Null,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Cmp {
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Debug)]
pub(crate) enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Sel(String),
}

impl Rule {
    pub fn from_yaml(yaml: &str) -> Result<Rule, Error> {
        let raw: Value =
            serde_norway::from_str(yaml).map_err(|e| Error::Invalid(format!("YAML: {e}")))?;
        Rule::from_value(raw)
    }

    pub fn from_value(raw: Value) -> Result<Rule, Error> {
        let title = raw["title"]
            .as_str()
            .ok_or_else(|| Error::Invalid("missing title".into()))?
            .to_owned();
        let detection = raw["detection"]
            .as_object()
            .ok_or_else(|| Error::Invalid("missing detection".into()))?;

        let mut selections = BTreeMap::new();
        let mut conditions = Vec::new();
        for (name, body) in detection {
            match name.as_str() {
                "condition" => conditions = condition_strings(body)?,
                "timeframe" => return Err(Error::Unsupported("timeframe".into())),
                _ => {
                    selections.insert(name.clone(), parse_selection(name, body)?);
                }
            }
        }
        if conditions.is_empty() {
            return Err(Error::Invalid("missing condition".into()));
        }
        let names: Vec<&str> = selections.keys().map(String::as_str).collect();
        let mut exprs = conditions
            .iter()
            .map(|c| Parser::new(c, &names).parse())
            .collect::<Result<Vec<_>, _>>()?;
        let condition = if exprs.len() == 1 {
            exprs.remove(0)
        } else {
            Expr::Or(exprs)
        };
        Ok(Rule {
            title,
            raw,
            selections,
            condition,
        })
    }

    /// Every field the detection references.
    pub fn fields(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .selections
            .values()
            .flatten()
            .flatten()
            .map(|i| i.field.as_str())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

fn condition_strings(v: &Value) -> Result<Vec<String>, Error> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(a) => a
            .iter()
            .map(|c| c.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or_else(|| Error::Invalid("condition list must hold strings".into())),
        _ => Err(Error::Invalid("condition must be a string or list".into())),
    }
}

fn parse_selection(name: &str, body: &Value) -> Result<Vec<Vec<Item>>, Error> {
    match body {
        Value::Object(map) => Ok(vec![parse_map(map)?]),
        Value::Array(list) if list.iter().all(Value::is_object) => list
            .iter()
            .map(|m| parse_map(m.as_object().expect("checked")))
            .collect(),
        _ => Err(Error::Unsupported(format!(
            "selection `{name}` is a keyword search; use field selections"
        ))),
    }
}

fn parse_map(map: &serde_json::Map<String, Value>) -> Result<Vec<Item>, Error> {
    map.iter().map(|(k, v)| parse_item(k, v)).collect()
}

fn parse_item(key: &str, value: &Value) -> Result<Item, Error> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default().to_owned();
    if field.is_empty() {
        return Err(Error::Invalid(format!("empty field name in `{key}`")));
    }
    let mut m = Mods::default();
    for modifier in parts {
        match modifier {
            "contains" => m.contains = true,
            "startswith" => m.startswith = true,
            "endswith" => m.endswith = true,
            "all" => m.all = true,
            "re" => m.re = true,
            "cidr" => m.cidr = true,
            "exists" => m.exists = true,
            "lt" => m.cmp = Some(Cmp::Lt),
            "lte" => m.cmp = Some(Cmp::Lte),
            "gt" => m.cmp = Some(Cmp::Gt),
            "gte" => m.cmp = Some(Cmp::Gte),
            other => return Err(Error::Unsupported(format!("modifier `{other}` in `{key}`"))),
        }
    }
    let values: Vec<&Value> = match value {
        Value::Array(a) => a.iter().collect(),
        v => vec![v],
    };
    if m.all && values.len() < 2 {
        return Err(Error::Invalid(format!(
            "`|all` needs a list of 2+ values in `{key}`"
        )));
    }
    let patterns = values
        .into_iter()
        .map(|v| m.pattern(key, v))
        .collect::<Result<_, _>>()?;
    Ok(Item {
        field,
        patterns,
        all: m.all,
    })
}

#[derive(Default)]
struct Mods {
    contains: bool,
    startswith: bool,
    endswith: bool,
    all: bool,
    re: bool,
    cidr: bool,
    exists: bool,
    cmp: Option<Cmp>,
}

impl Mods {
    fn pattern(&self, key: &str, v: &Value) -> Result<Pattern, Error> {
        let bad = |what: &str| Error::Invalid(format!("`{key}`: {what}"));
        if self.exists {
            return v
                .as_bool()
                .map(Pattern::Exists)
                .ok_or_else(|| bad("exists needs true/false"));
        }
        if let Some(op) = self.cmp {
            return v
                .as_f64()
                .map(|n| Pattern::Cmp(op, n))
                .ok_or_else(|| bad("needs a number"));
        }
        if self.cidr {
            let s = v.as_str().ok_or_else(|| bad("cidr needs a string"))?;
            return s
                .parse()
                .map(Pattern::Cidr)
                .map_err(|e| bad(&format!("cidr {s}: {e}")));
        }
        if self.re {
            let s = v.as_str().ok_or_else(|| bad("re needs a string"))?;
            check_wazuh_regex(s)
                .map_err(|why| Error::Unsupported(format!("`{key}`: regex `{s}`: {why}")))?;
            return RegexBuilder::new(s)
                .dot_matches_new_line(true)
                .build()
                .map(Pattern::Re)
                .map_err(|e| bad(&format!("regex: {e}")));
        }
        let wrapped = self.contains || self.startswith || self.endswith;
        let text = match v {
            Value::String(s) => s.clone(),
            Value::Number(n) if wrapped => n.to_string(),
            Value::Number(n) => return Ok(Pattern::Num(n.as_f64().unwrap_or(f64::NAN))),
            Value::Bool(b) if !wrapped => return Ok(Pattern::Bool(*b)),
            Value::Null if !wrapped => return Ok(Pattern::Null),
            _ => return Err(bad("unsupported value type")),
        };
        let lead = if self.contains || self.endswith {
            ".*"
        } else {
            ""
        };
        let tail = if self.contains || self.startswith {
            ".*"
        } else {
            ""
        };
        let re = format!("^(?s:{lead}{}{tail})$", wildcard_to_regex(&text));
        Ok(Pattern::Str(
            Regex::new(&re).map_err(|e| bad(&format!("pattern: {e}")))?,
        ))
    }
}

/// Accept only the regex subset on which Wazuh 5.0 rc2 and the `regex` crate
/// agree. rc2 compiles `|re` to a Lucene-style regex (probed on the rc2
/// indexer; see README "Wazuh 5.0 regex dialect"):
///
/// * `\` is a literal backslash, so `\+`, `\s`, `\d`, `\|` silently misfire —
///   use character classes (`[+]`, `[ ]`, `[0-9]`, `[|]`) instead;
/// * `/` never matches, in any form (consistent with a `query_string`
///   `/regex/` delimiter);
/// * `^`/`$` anchor only as the first/last character; elsewhere they are literal;
/// * `@ & < > #` are Lucene operators (probed); `"` quotes literals in Lucene;
///   `~` was probed literal in both engines and is allowed;
/// * inline groups such as `(?i)` do not exist.
fn check_wazuh_regex(re: &str) -> Result<(), &'static str> {
    let chars: Vec<char> = re.chars().collect();
    let mut in_class = false;
    for (i, &c) in chars.iter().enumerate() {
        if c == '\\' {
            return Err("backslash is a literal in Wazuh; use a character class like [+] or [ ]");
        }
        if c == '/' {
            return Err(
                "`/` never matches in Wazuh regexes, even as [/] or \\/; use a class like [^ a-z] or a contains/startswith selection",
            );
        }
        if in_class {
            in_class = c != ']';
            continue;
        }
        match c {
            '[' => in_class = true,
            '^' if i != 0 => return Err("`^` only anchors as the first character"),
            '$' if i + 1 != chars.len() => return Err("`$` only anchors as the last character"),
            '(' if chars.get(i + 1) == Some(&'?') => {
                return Err("inline groups like (?i) are not supported");
            }
            '@' | '&' | '<' | '>' | '#' | '"' => {
                return Err(
                    "Lucene operator character; put it in a class like [#] if meant literally",
                );
            }
            _ => {}
        }
    }
    Ok(())
}

/// Sigma string → regex body: `*` and `?` are wildcards, `\` escapes `*`, `?`
/// and `\`; a `\` before anything else is literal.
fn wildcard_to_regex(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '\\' if matches!(chars.peek(), Some('*' | '?' | '\\')) => {
                out.push_str(&regex::escape(&chars.next().unwrap().to_string()));
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out
}

/// Recursive-descent parser for Sigma conditions.
/// Precedence: `not` > `and` > `or`.
struct Parser<'a> {
    tokens: Vec<String>,
    pos: usize,
    names: &'a [&'a str],
}

impl<'a> Parser<'a> {
    fn new(cond: &str, names: &'a [&'a str]) -> Self {
        let tokens = cond
            .replace('(', " ( ")
            .replace(')', " ) ")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        Parser {
            tokens,
            pos: 0,
            names,
        }
    }

    fn parse(mut self) -> Result<Expr, Error> {
        let e = self.or()?;
        match self.peek() {
            None => Ok(e),
            Some(t) => Err(Error::Invalid(format!("unexpected `{t}` in condition"))),
        }
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(String::as_str)
    }

    fn next(&mut self) -> Result<String, Error> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t.ok_or_else(|| Error::Invalid("condition ends early".into()))
    }

    fn or(&mut self) -> Result<Expr, Error> {
        let mut terms = vec![self.and()?];
        while self.peek() == Some("or") {
            self.pos += 1;
            terms.push(self.and()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expr::Or(terms)
        })
    }

    fn and(&mut self) -> Result<Expr, Error> {
        let mut terms = vec![self.not()?];
        while self.peek() == Some("and") {
            self.pos += 1;
            terms.push(self.not()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expr::And(terms)
        })
    }

    fn not(&mut self) -> Result<Expr, Error> {
        if self.peek() == Some("not") {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, Error> {
        let t = self.next()?;
        match t.as_str() {
            "(" => {
                let e = self.or()?;
                match self.next()?.as_str() {
                    ")" => Ok(e),
                    other => Err(Error::Invalid(format!("expected `)`, got `{other}`"))),
                }
            }
            "1" | "all" if self.peek() == Some("of") => {
                self.pos += 1;
                let target = self.next()?;
                let picked = self.expand(&target)?;
                Ok(if t == "1" {
                    Expr::Or(picked)
                } else {
                    Expr::And(picked)
                })
            }
            name if self.names.contains(&name) => Ok(Expr::Sel(name.to_owned())),
            name => Err(Error::Invalid(format!(
                "condition names unknown selection `{name}`"
            ))),
        }
    }

    fn expand(&self, target: &str) -> Result<Vec<Expr>, Error> {
        let re = Regex::new(&format!("^{}$", wildcard_to_regex(target))).expect("valid");
        let picked: Vec<Expr> = self
            .names
            .iter()
            .filter(|n| target == "them" || re.is_match(n))
            .map(|n| Expr::Sel((*n).to_owned()))
            .collect();
        if picked.is_empty() {
            return Err(Error::Invalid(format!(
                "`of {target}` matches no selection"
            )));
        }
        Ok(picked)
    }
}
