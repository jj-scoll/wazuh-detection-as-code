//! Checks over the rule corpus in `rules/`. Each test gathers every problem
//! before failing, so one run lists everything to fix.

use std::collections::HashMap;
use std::path::Path;

use wazuh_dac::catalog::{self, Entry};
use wazuh_dac::convert::to_wazuh;
use wazuh_dac::evaluate::matches;
use wazuh_dac::schema::Schema;

fn corpus() -> Vec<Entry> {
    let entries = catalog::load(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules")
            .as_path(),
    )
    .unwrap_or_else(|e| panic!("loading rules: {e}"));
    assert!(!entries.is_empty(), "no rules found under rules/");
    entries
}

fn report(problems: Vec<String>) {
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[test]
fn every_rule_has_required_metadata() {
    let mut problems = vec![];
    for e in corpus() {
        for key in [
            "id",
            "status",
            "level",
            "description",
            "author",
            "date",
            "falsepositives",
        ] {
            if e.rule.raw.get(key).is_none() {
                problems.push(format!("{}: missing `{key}`", e.path.display()));
            }
        }
        let techniques = e.rule.raw["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str())
            .filter(|t| t.starts_with("attack.t"))
            .count();
        if techniques == 0 {
            problems.push(format!("{}: needs an attack.tNNNN tag", e.path.display()));
        }
    }
    report(problems);
}

#[test]
fn rule_ids_are_unique() {
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut problems = vec![];
    for e in corpus() {
        let id = e.rule.raw["id"].as_str().unwrap_or_default().to_owned();
        if let Some(other) = seen.insert(id.clone(), e.path.display().to_string()) {
            problems.push(format!(
                "{}: id {id} also used by {other}",
                e.path.display()
            ));
        }
    }
    report(problems);
}

#[test]
fn every_rule_converts_to_wazuh() {
    let mut problems = vec![];
    for e in corpus() {
        if let Err(err) = to_wazuh(&e.rule.raw, "detection-as-code") {
            problems.push(format!("{}: {err}", e.path.display()));
        }
    }
    report(problems);
}

#[test]
fn rule_fields_exist_in_wazuh_common_schema() {
    // Wazuh rejects rules that reference fields outside WCS; catch it offline.
    let schema = Schema::bundled();
    let mut problems = vec![];
    for e in corpus() {
        for f in e.rule.fields() {
            if !schema.knows(f) {
                problems.push(format!("{}: field `{f}` is not in WCS", e.path.display()));
            }
        }
    }
    report(problems);
}

#[test]
fn every_rule_has_positive_and_negative_cases() {
    let mut problems = vec![];
    for e in corpus() {
        if e.cases.matches.is_empty() || e.cases.no_match.is_empty() {
            problems.push(format!(
                "{}: needs at least one `match` and one `no_match` case",
                e.path.display()
            ));
        }
    }
    report(problems);
}

#[test]
fn fixture_events_only_use_schema_fields() {
    // Wazuh event data streams reject documents with fields outside WCS, so a
    // fixture that uses one describes an event that can never exist.
    let schema = Schema::bundled();
    let mut problems = vec![];
    for e in corpus() {
        for case in e.cases.matches.iter().chain(&e.cases.no_match) {
            for f in schema.unknown_event_fields(&case.event) {
                problems.push(format!(
                    "{} [{}]: `{f}` not in WCS",
                    e.path.display(),
                    case.description
                ));
            }
        }
    }
    report(problems);
}

#[test]
fn match_cases_fire_and_no_match_cases_do_not() {
    let mut problems = vec![];
    for e in corpus() {
        for (cases, want) in [(&e.cases.matches, true), (&e.cases.no_match, false)] {
            for case in cases {
                if matches(&e.rule, &case.event) != want {
                    problems.push(format!(
                        "{} [{}]: expected {}",
                        e.path.display(),
                        case.description,
                        if want { "match" } else { "no match" }
                    ));
                }
            }
        }
    }
    report(problems);
}
