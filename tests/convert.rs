use serde_json::{Value, json};
use wazuh_dac::convert::{ConvertError, to_wazuh};

fn sigma() -> Value {
    serde_norway::from_str(
        r#"
title: SSH authorized_keys modified
id: 0b5e7a52-6f0e-4d5c-9a0e-2d1f3c4b5a69
status: experimental
description: A user's authorized_keys file was written.
references:
  - https://attack.mitre.org/techniques/T1098/004/
author: Jeff Scollick
date: 2026-11-24
modified: 2026-11-25
tags:
  - attack.persistence
  - attack.t1098.004
  - attack.t1078
logsource:
  product: linux
  category: file_event
detection:
  sel:
    file.path|endswith: /.ssh/authorized_keys
  condition: sel
falsepositives:
  - Configuration management
level: medium
"#,
    )
    .unwrap()
}

#[test]
fn metadata_block_holds_authorship_fields() {
    let out = to_wazuh(&sigma(), "detection-as-code").unwrap();
    assert_eq!(
        out["metadata"],
        json!({
            "title": "SSH authorized_keys modified",
            "description": "A user's authorized_keys file was written.",
            "author": "Jeff Scollick",
            "references": ["https://attack.mitre.org/techniques/T1098/004/"],
            "date": "2026-11-24",
            "modified": "2026-11-25",
            "supports": ["linux"],
        })
    );
}

#[test]
fn sigma_id_status_level_tags_and_detection_pass_through() {
    let s = sigma();
    let out = to_wazuh(&s, "detection-as-code").unwrap();
    assert_eq!(out["sigma_id"], s["id"]);
    assert_eq!(out["status"], "experimental");
    assert_eq!(out["level"], "medium");
    assert_eq!(out["enabled"], true);
    assert_eq!(out["tags"], s["tags"]);
    assert_eq!(out["falsepositives"], s["falsepositives"]);
    assert_eq!(out["detection"], s["detection"]);
    assert!(out.get("id").is_none(), "id is server-generated in Wazuh");
    assert!(out.get("title").is_none(), "title lives in metadata");
}

#[test]
fn logsource_product_routes_to_integration() {
    let out = to_wazuh(&sigma(), "detection-as-code").unwrap();
    assert_eq!(
        out["logsource"],
        json!({"product": "detection-as-code", "category": "file_event"})
    );
}

#[test]
fn mitre_block_from_attack_tags() {
    let out = to_wazuh(&sigma(), "detection-as-code").unwrap();
    assert_eq!(
        out["mitre"],
        json!({
            "tactic": {"id": ["TA0003"], "name": ["Persistence"]},
            "technique": {"id": ["T1078", "T1098"]},
            "subtechnique": {"id": ["T1098.004"]},
        })
    );
}

#[test]
fn mitre_block_omits_empty_categories() {
    let mut s = sigma();
    s["tags"] = json!(["attack.defense-evasion", "attack.t1070", "cve.2021-44228"]);
    let out = to_wazuh(&s, "x").unwrap();
    assert_eq!(
        out["mitre"],
        json!({
            "tactic": {"id": ["TA0005"], "name": ["Defense Evasion"]},
            "technique": {"id": ["T1070"]},
        })
    );
}

#[test]
fn unknown_attack_tactic_is_an_error() {
    let mut s = sigma();
    s["tags"] = json!(["attack.stealthy-stuff"]);
    let err = to_wazuh(&s, "x").unwrap_err();
    assert!(matches!(err, ConvertError::UnknownTag(ref t) if t == "attack.stealthy-stuff"));
}

#[test]
fn missing_required_field_is_an_error() {
    let mut s = sigma();
    s.as_object_mut().unwrap().remove("level");
    assert!(matches!(
        to_wazuh(&s, "x"),
        Err(ConvertError::Missing("level"))
    ));
}
