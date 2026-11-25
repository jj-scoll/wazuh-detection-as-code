use std::path::Path;
use std::process::Command;

#[test]
fn build_writes_one_wazuh_resource_per_rule() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::env::temp_dir().join(format!("wazuh-dac-build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);

    let status = Command::new(env!("CARGO_BIN_EXE_wazuh-dac"))
        .args(["build", "--integration", "my-integration", "--out"])
        .arg(&out)
        .current_dir(root)
        .status()
        .expect("run wazuh-dac");
    assert!(status.success());

    let written = out.join("linux/reverse_shell_dev_tcp.json");
    let resource: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&written).expect("output file")).unwrap();
    assert_eq!(resource["logsource"]["product"], "my-integration");
    assert_eq!(resource["sigma_id"], "159ae6cc-72b0-4ed1-83c2-b7ad53a14e29");

    let count = std::fs::read_dir(out.join("linux")).unwrap().count();
    assert_eq!(count, 7);
    std::fs::remove_dir_all(&out).unwrap();
}

#[test]
fn build_fails_on_an_invalid_rule_directory() {
    let status = Command::new(env!("CARGO_BIN_EXE_wazuh-dac"))
        .args(["build", "--rules", "/nonexistent", "--out", "/tmp/unused"])
        .status()
        .expect("run wazuh-dac");
    assert!(!status.success());
}
