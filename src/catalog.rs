//! Rule corpus loader: every `rules/**/<name>.yml` with its test cases in the
//! sibling `<name>.tests.yml`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::sigma::Rule;

pub struct Entry {
    pub path: PathBuf,
    pub rule: Rule,
    pub cases: Cases,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cases {
    #[serde(rename = "match", default)]
    pub matches: Vec<Case>,
    #[serde(default)]
    pub no_match: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub description: String,
    pub event: Value,
}

const TESTS_SUFFIX: &str = ".tests.yml";

/// Load all rules under `root`, sorted by path. A missing sidecar yields empty
/// cases (the corpus tests flag it); an unreadable or invalid file is an error.
pub fn load(root: &Path) -> Result<Vec<Entry>, String> {
    let mut paths = Vec::new();
    collect(root, &mut paths)?;
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = read(&path)?;
            let rule = Rule::from_yaml(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            let sidecar = path.with_extension("tests.yml");
            let cases = if sidecar.exists() {
                serde_norway::from_str(&read(&sidecar)?)
                    .map_err(|e| format!("{}: {e}", sidecar.display()))?
            } else {
                Cases::default()
            };
            Ok(Entry { path, rule, cases })
        })
        .collect()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            collect(&path, out)?;
        } else if name.ends_with(".yml") && !name.ends_with(TESTS_SUFFIX) {
            out.push(path);
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}
