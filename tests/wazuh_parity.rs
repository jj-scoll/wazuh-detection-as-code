//! Parity suite: every fixture event goes through a real Wazuh 5.0 indexer
//! (Content Manager detection-only logtest, which compiles and percolates rules
//! exactly as a deployed detector does). For each event, the set of rules
//! Wazuh fires must equal the set the local evaluator fires.
//!
//! Needs a running indexer; `scripts/indexer-up.sh` starts one and writes the
//! variables below to `.wazuh/env`. Run with:
//!
//!     set -a; . .wazuh/env; set +a
//!     cargo test --test wazuh_parity -- --ignored

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use wazuh_dac::catalog;
use wazuh_dac::convert::to_wazuh;
use wazuh_dac::evaluate::matches;
use wazuh_dac::wazuh::Client;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; see scripts/indexer-up.sh"))
}

#[test]
#[ignore = "needs a Wazuh 5.0 indexer: scripts/indexer-up.sh"]
fn wazuh_fires_exactly_the_rules_the_local_evaluator_fires() {
    let ca = std::fs::read(env("WAZUH_INDEXER_CA")).expect("read CA");
    let client = Client::new(
        &env("WAZUH_INDEXER_URL"),
        &env("WAZUH_INDEXER_USER"),
        &env("WAZUH_INDEXER_PASSWORD"),
        &ca,
    )
    .expect("client");

    let corpus =
        catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules")).expect("rules");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let name_of = |p: &Path| p.strip_prefix(root).unwrap_or(p).display().to_string();

    // A fresh integration per run, so reruns against one indexer don't collide.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let product = format!("dac-parity-{stamp}");
    let integration = client
        .create_integration(&product, "wazuh-detection-as-code parity run")
        .expect("create integration");

    let mut problems = vec![];
    let mut wazuh_id_to_rule: HashMap<String, String> = HashMap::new();
    for e in &corpus {
        let mut resource = to_wazuh(&e.rule.raw, &product).expect("convert");
        // Rule titles must be unique within a space; suffix them so reruns
        // against the same indexer don't collide with earlier runs.
        let title = resource["metadata"]["title"].as_str().unwrap().to_owned();
        resource["metadata"]["title"] = format!("{title} [{product}]").into();
        match client.create_rule(&integration, &resource) {
            Ok(id) => {
                wazuh_id_to_rule.insert(id, name_of(&e.path));
            }
            Err(err) => problems.push(format!(
                "{}: Wazuh rejected the rule: {err}",
                name_of(&e.path)
            )),
        }
    }
    client
        .promote_draft_to_test()
        .expect("promote draft -> test");

    let mut checked = 0;
    for owner in &corpus {
        for case in owner.cases.matches.iter().chain(&owner.cases.no_match) {
            let local: BTreeSet<String> = corpus
                .iter()
                .filter(|r| matches(&r.rule, &case.event))
                .map(|r| name_of(&r.path))
                .collect();
            let remote: BTreeSet<String> = match client.detect(&integration, &case.event) {
                Ok(ids) => ids
                    .iter()
                    .map(|id| {
                        wazuh_id_to_rule
                            .get(id)
                            .cloned()
                            .unwrap_or_else(|| format!("unknown:{id}"))
                    })
                    .collect(),
                Err(err) => {
                    problems.push(format!(
                        "{} [{}]: logtest failed: {err}",
                        name_of(&owner.path),
                        case.description
                    ));
                    continue;
                }
            };
            checked += 1;
            if local != remote {
                problems.push(format!(
                    "{} [{}]:\n    local only: {:?}\n    wazuh only: {:?}",
                    name_of(&owner.path),
                    case.description,
                    local.difference(&remote).collect::<Vec<_>>(),
                    remote.difference(&local).collect::<Vec<_>>(),
                ));
            }
        }
    }
    eprintln!(
        "parity: {} rules, {checked} events checked against Wazuh",
        corpus.len()
    );
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}
