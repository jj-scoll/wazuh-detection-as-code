//! Standard Sigma rule → Wazuh 5.0 Content Manager rule resource.
//!
//! Rules are authored in plain SigmaHQ format so they stay portable. Wazuh 5.0
//! wants a different envelope (see `docs/ref/modules/ruleset-management/rules.md`
//! in wazuh-indexer-plugins at v5.0.0-rc2):
//!
//! * authorship fields move under `metadata`; the Sigma `id` becomes `sigma_id`
//!   (Wazuh generates its own `id`);
//! * `logsource.product` must name the Wazuh integration — it routes the rule
//!   to that integration's detector — so the Sigma product moves to
//!   `metadata.supports`;
//! * `attack.*` tags become a `mitre` block. Tactics carry names; techniques
//!   carry IDs only (Wazuh accepts names for all entries of a category or none).

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("missing required field `{0}`")]
    Missing(&'static str),
    #[error("unknown ATT&CK tag `{0}`")]
    UnknownTag(String),
}

/// ATT&CK Enterprise tactics: Sigma tag suffix, ID, name.
const TACTICS: &[(&str, &str, &str)] = &[
    ("initial-access", "TA0001", "Initial Access"),
    ("execution", "TA0002", "Execution"),
    ("persistence", "TA0003", "Persistence"),
    ("privilege-escalation", "TA0004", "Privilege Escalation"),
    ("defense-evasion", "TA0005", "Defense Evasion"),
    ("credential-access", "TA0006", "Credential Access"),
    ("discovery", "TA0007", "Discovery"),
    ("lateral-movement", "TA0008", "Lateral Movement"),
    ("collection", "TA0009", "Collection"),
    ("exfiltration", "TA0010", "Exfiltration"),
    ("command-and-control", "TA0011", "Command and Control"),
    ("impact", "TA0040", "Impact"),
    ("resource-development", "TA0042", "Resource Development"),
    ("reconnaissance", "TA0043", "Reconnaissance"),
];

pub fn to_wazuh(sigma: &Value, integration: &str) -> Result<Value, ConvertError> {
    let required = |k: &'static str| sigma.get(k).cloned().ok_or(ConvertError::Missing(k));

    let mut metadata = Map::new();
    metadata.insert("title".into(), required("title")?);
    for key in ["description", "author", "references", "date", "modified"] {
        if let Some(v) = sigma.get(key) {
            metadata.insert(key.into(), v.clone());
        }
    }
    let mut logsource = required("logsource")?;
    if let Some(product) = logsource.get("product").cloned() {
        metadata.insert("supports".into(), json!([product]));
    }
    logsource["product"] = json!(integration);

    let mut out = json!({
        "metadata": metadata,
        "sigma_id": required("id")?,
        "status": required("status")?,
        "level": required("level")?,
        "enabled": true,
        "logsource": logsource,
        "detection": required("detection")?,
    });
    for key in ["tags", "falsepositives"] {
        if let Some(v) = sigma.get(key) {
            out[key] = v.clone();
        }
    }
    let tags: Vec<&str> = sigma["tags"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(mitre) = mitre_block(&tags)? {
        out["mitre"] = mitre;
    }
    Ok(out)
}

fn is_group_or_software(suffix: &str) -> bool {
    let mut chars = suffix.chars();
    matches!(chars.next(), Some('g' | 's'))
        && chars.as_str().len() == 4
        && chars.all(|c| c.is_ascii_digit())
}

fn mitre_block(tags: &[&str]) -> Result<Option<Value>, ConvertError> {
    let mut tactics = Vec::new();
    let mut techniques = BTreeSet::new();
    let mut subtechniques = BTreeSet::new();
    for tag in tags {
        let Some(suffix) = tag.strip_prefix("attack.") else {
            continue;
        };
        if let Some(id) = suffix
            .strip_prefix('t')
            .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        {
            let id = format!("T{}", id.to_ascii_uppercase());
            match id.split_once('.') {
                Some((parent, _)) => {
                    techniques.insert(parent.to_owned());
                    subtechniques.insert(id);
                }
                None => {
                    techniques.insert(id);
                }
            }
        } else if let Some(&(_, id, name)) = TACTICS.iter().find(|(s, ..)| *s == suffix) {
            if !tactics.iter().any(|(i, _)| *i == id) {
                tactics.push((id, name));
            }
        } else if !is_group_or_software(suffix) {
            // attack.gNNNN (groups) and attack.sNNNN (software) are valid tags
            // with no Wazuh mitre category; anything else is a typo.
            return Err(ConvertError::UnknownTag((*tag).to_owned()));
        }
    }
    let mut block = Map::new();
    if !tactics.is_empty() {
        block.insert(
            "tactic".into(),
            json!({
                "id": tactics.iter().map(|t| t.0).collect::<Vec<_>>(),
                "name": tactics.iter().map(|t| t.1).collect::<Vec<_>>(),
            }),
        );
    }
    if !techniques.is_empty() {
        block.insert("technique".into(), json!({ "id": techniques }));
    }
    if !subtechniques.is_empty() {
        block.insert("subtechnique".into(), json!({ "id": subtechniques }));
    }
    Ok((!block.is_empty()).then_some(Value::Object(block)))
}
