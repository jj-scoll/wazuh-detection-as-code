use serde_json::json;
use wazuh_dac::schema::Schema;

#[test]
fn bundled_schema_knows_core_ecs_fields() {
    let s = Schema::bundled();
    for f in [
        "event.action",
        "process.command_line",
        "source.ip",
        "user.name",
    ] {
        assert!(s.knows(f), "{f}");
    }
}

#[test]
fn unknown_and_parent_object_fields_are_rejected() {
    let s = Schema::bundled();
    assert!(!s.knows("aws.cloudtrail.event_name"));
    assert!(!s.knows("event"), "an object is not a matchable field");
}

#[test]
fn free_form_object_children_are_accepted() {
    // `labels` is an `object` field: arbitrary keys beneath it are valid.
    assert!(Schema::bundled().knows("labels.env"));
}

#[test]
fn unknown_event_fields_lists_leaf_paths_outside_the_schema() {
    let s = Schema::bundled();
    let event = json!({
        "event": {"action": "x", "type": ["creation"], "bogus": 1},
        "process": {"args": ["a", "b"]},
        "labels": {"anything": "goes"},
        "related": {"user": ["a"]},
        "nope": {"deep": {"er": true}},
    });
    assert_eq!(
        s.unknown_event_fields(&event),
        vec!["event.bogus", "nope.deep.er"]
    );
}
