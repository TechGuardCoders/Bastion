//! Offline tests for Bastion security primitives - no network, no servers.
//! 1:1 port of tests/test_bastion.py.

use bastion::{pbkdf2_hex, sandbox_exec, AuditChain, KeyVault, PBKDF2_ITERATIONS};
use sha2::{Digest, Sha256};

#[test]
fn test_key_mint_and_auth() {
    let mut v = KeyVault::new();
    let (raw, kid) = v.mint("t1", &["chat:read"], None);
    assert!(raw.starts_with("bkx-") && kid == "v1");
    let rec = v.authenticate(Some(&format!("Bearer {}", raw)), None).unwrap();
    assert_eq!(rec.tenant_id, "t1");
    assert_eq!(rec.scopes, vec!["chat:read".to_string()]);
    assert!(v.authenticate(Some("Bearer wrong-key"), None).is_none());
    assert!(v.authenticate(None, None).is_none());
}

#[test]
fn test_plaintext_never_stored() {
    let mut v = KeyVault::new();
    let (raw, _) = v.mint("t1", &["chat:read"], None);
    // after minting, no record anywhere holds the plaintext
    let dumped = format!("{:?}", v.records);
    assert!(!dumped.contains(&raw));
}

#[test]
fn test_hash_strength() {
    let mut v = KeyVault::new();
    let (raw, _) = v.mint("t1", &["chat:read"], None);
    let rec = &v.records["t1"][0];
    // PBKDF2 with real iterations: not a bare sha256 of the key
    let bare: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let bare_hex: String = bare.iter().map(|b| format!("{:02x}", b)).collect();
    assert_ne!(rec.hash_hex, bare_hex);
    assert!(PBKDF2_ITERATIONS >= 50_000);
    // sanity: our pbkdf2 helper matches the stored hash derivation
    assert_eq!(pbkdf2_hex(&raw, &rec.salt), rec.hash_hex);
}

#[test]
fn test_revoke_and_rotate() {
    let mut v = KeyVault::new();
    let (raw1, kid1) = v.mint("t1", &["chat:read"], None);
    assert!(v.authenticate(Some(&format!("Bearer {}", raw1)), None).is_some());
    let (raw2, kid2) = v.rotate("t1", &["chat:read"], None);
    assert_eq!(kid2, "v2");
    assert_ne!(raw2, raw1);
    // rotation: both work until revoke
    assert!(v.authenticate(Some(&format!("Bearer {}", raw1)), None).is_some());
    assert!(v.revoke("t1", &kid1));
    assert!(v.authenticate(Some(&format!("Bearer {}", raw1)), None).is_none()); // revoked = dead
    assert!(v.authenticate(Some(&format!("Bearer {}", raw2)), None).is_some()); // new version alive
}

#[test]
fn test_audit_chain_tamper_evidence() {
    let mut ch = AuditChain::new();
    ch.append(&serde_json::json!({"event": "a"}));
    ch.append(&serde_json::json!({"event": "b"}));
    ch.append(&serde_json::json!({"event": "c"}));
    let (ok, _) = ch.verify();
    assert!(ok);

    // edit an entry body -> detect
    let mut ch = ch;
    ch.events[1].body = serde_json::json!({"event": "EVIL"}).to_string();
    let (ok, reason) = ch.verify();
    assert!(!ok);
    assert!(reason.unwrap().contains("entry 1"));

    // delete an entry -> prev mismatch downstream
    let mut ch2 = AuditChain::new();
    for e in ["a", "b", "c"] {
        ch2.append(&serde_json::json!({ "event": e }));
    }
    ch2.events.remove(1);
    let (ok, _) = ch2.verify();
    assert!(!ok);

    // reorder -> detected
    let mut ch3 = AuditChain::new();
    for e in ["a", "b", "c"] {
        ch3.append(&serde_json::json!({ "event": e }));
    }
    ch3.events.swap(0, 2);
    let (ok, _) = ch3.verify();
    assert!(!ok);
}

#[test]
fn test_sandbox_exec_runs_and_jails() {
    let r = sandbox_exec("print('hello from jail')", 10.0);
    assert!(r.ok, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("hello from jail"));
    // cannot read outside its disposable cwd via relative trickery
    let r2 = sandbox_exec("import os; print(sorted(os.listdir('.')))", 10.0);
    assert!(r2.ok, "stderr: {}", r2.stderr);
    let out = r2.stdout.trim();
    assert!(out == "[]" || out == "['task.py']", "got: {}", out);
}

#[test]
fn test_sandbox_timeout() {
    let t0 = std::time::Instant::now();
    let r = sandbox_exec("while True: pass", 2.0);
    assert!(!r.ok);
    assert_eq!(r.stderr, "timeout");
    assert!(t0.elapsed().as_secs_f64() < 8.0);
}
