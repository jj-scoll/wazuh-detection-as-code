use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wazuh_dac::{catalog, convert};

#[derive(Parser)]
#[command(about = "Sigma detection-as-code for Wazuh 5.0")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert every rule to a Wazuh Content Manager rule resource (JSON).
    Build {
        #[arg(long, default_value = "rules")]
        rules: PathBuf,
        #[arg(long, default_value = "dist")]
        out: PathBuf,
        /// Wazuh integration title; becomes each rule's `logsource.product`.
        #[arg(long, default_value = "detection-as-code")]
        integration: String,
    },
}

fn main() -> ExitCode {
    let Command::Build {
        rules,
        out,
        integration,
    } = Cli::parse().command;
    match build(&rules, &out, &integration) {
        Ok(n) => {
            println!("wrote {n} rules to {}", out.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn build(rules: &Path, out: &Path, integration: &str) -> Result<usize, String> {
    let entries = catalog::load(rules)?;
    for e in &entries {
        let resource = convert::to_wazuh(&e.rule.raw, integration)
            .map_err(|err| format!("{}: {err}", e.path.display()))?;
        let rel = e
            .path
            .strip_prefix(rules)
            .unwrap_or(&e.path)
            .with_extension("json");
        let dest = out.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap_or(out)).map_err(|err| err.to_string())?;
        let json = serde_json::to_string_pretty(&resource).expect("serializable");
        std::fs::write(&dest, json + "\n").map_err(|err| format!("{}: {err}", dest.display()))?;
    }
    Ok(entries.len())
}
