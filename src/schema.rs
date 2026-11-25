//! Wazuh Common Schema (WCS) field list, bundled from `schema/wcs-fields.txt`.

use std::collections::HashMap;

use serde_json::Value;

/// Field types whose children are free-form (any key below them is valid).
const FREE_FORM: &[&str] = &["object", "flat_object"];

pub struct Schema {
    types: HashMap<String, String>,
}

impl Schema {
    /// The schema this repository is pinned to.
    pub fn bundled() -> Schema {
        Schema::parse(include_str!("../schema/wcs-fields.txt"))
    }

    /// Parse `name type` lines; `#` lines are comments.
    pub fn parse(text: &str) -> Schema {
        let types = text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(' '))
            .map(|(name, ty)| (name.to_owned(), ty.trim().to_owned()))
            .collect();
        Schema { types }
    }

    /// True if `field` can hold a value: a declared non-object field, or a key
    /// beneath a free-form object.
    pub fn knows(&self, field: &str) -> bool {
        match self.types.get(field) {
            Some(ty) => !FREE_FORM.contains(&ty.as_str()) && ty != "nested",
            None => self.under_free_form(field),
        }
    }

    fn under_free_form(&self, field: &str) -> bool {
        field.match_indices('.').any(|(i, _)| {
            self.types
                .get(&field[..i])
                .is_some_and(|ty| FREE_FORM.contains(&ty.as_str()))
        })
    }

    /// Leaf paths in `event` that WCS does not declare, sorted.
    pub fn unknown_event_fields(&self, event: &Value) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(event, String::new(), &mut out);
        out.sort();
        out.dedup();
        out
    }

    fn walk(&self, v: &Value, path: String, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                let free = self
                    .types
                    .get(&path)
                    .is_some_and(|t| FREE_FORM.contains(&t.as_str()));
                if free {
                    return;
                }
                for (k, child) in map {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    self.walk(child, p, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|i| self.walk(i, path.clone(), out)),
            _ if !self.knows(&path) => out.push(path),
            _ => {}
        }
    }
}
