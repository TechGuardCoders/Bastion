//! Fleet tests: per-node scoped credentials and allowlists. No network.
//! 1:1 port of tests/test_fleet.py.

use bastion::{fleet_nodes, KeyVault};
use std::collections::BTreeMap;

#[test]
fn test_unscoped_key_works_everywhere() {
    // Default behavior unchanged: no node restriction = all nodes.
    let mut v = KeyVault::new();
    let (raw, _) = v.mint("t1", &["chat:read"], None);
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-a")).is_some());
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-b")).is_some());
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), None).is_some());
}

#[test]
fn test_node_scoped_key_only_authenticates_on_its_node() {
    let mut v = KeyVault::new();
    let nodes = vec!["node-a".to_string()];
    let (raw, _) = v.mint("t1", &["chat:read"], Some(&nodes));
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-a")).is_some());
    // scoped key must not authenticate on a foreign node
    assert!(
        v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-b")).is_none(),
        "scoped key must not authenticate on a foreign node"
    );
    // without a node context (default path), scoped key still verifies
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), None).is_some());
}

#[test]
fn test_scoped_rotate_carries_allowlist() {
    let mut v = KeyVault::new();
    let nodes = vec!["node-b".to_string()];
    let (raw, kid) = v.rotate("t1", &["chat:read"], Some(&nodes));
    let rec = v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-b")).unwrap();
    assert_eq!(rec.key_id, kid);
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-a")).is_none());
}

#[test]
fn test_revoked_scoped_key_dead_everywhere() {
    let mut v = KeyVault::new();
    let nodes = vec!["node-a".to_string()];
    let (raw, kid) = v.mint("t1", &["chat:read"], Some(&nodes));
    v.revoke("t1", &kid);
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), Some("node-a")).is_none());
    assert!(v.authenticate(Some(&format!("Bearer {}", raw)), None).is_none());
}

#[test]
fn test_allowed_on_helper() {
    let mut v = KeyVault::new();
    let nodes = vec!["node-a".to_string(), "node-c".to_string()];
    v.mint("t1", &["chat:read"], Some(&nodes));
    let rec = &v.records["t1"][0];
    assert!(rec.allowed_on("node-a") && rec.allowed_on("node-c"));
    assert!(!rec.allowed_on("node-b"));
    v.mint("t2", &["chat:read"], None);
    assert!(v.records["t2"][0].allowed_on("anything"));
}

#[test]
fn test_fleet_nodes_env_parsing() {
    // SAFETY: tests run in separate processes by default; env is process-global.
    unsafe { std::env::remove_var("BASTION_FLEET_NODES") };
    assert_eq!(fleet_nodes(), BTreeMap::new());
    unsafe { std::env::set_var("BASTION_FLEET_NODES", " n1=http://x:8421 , n2=http://y:8422 ") };
    let nodes = fleet_nodes();
    let mut expected = BTreeMap::new();
    expected.insert("n1".to_string(), "http://x:8421".to_string());
    expected.insert("n2".to_string(), "http://y:8422".to_string());
    assert_eq!(nodes, expected);
    unsafe { std::env::remove_var("BASTION_FLEET_NODES") };
}
