//! Bastion - secure multi-tenant inference layer (Rust port of bastion.py).
//!
//! Sits in front of Ball Knowledge (:3100) as the security shell:
//!   client -> Bastion :3200 -> Ball Knowledge :3100 -> backends
//!
//! Provides:
//! - Hashed API keys (PBKDF2-HMAC-SHA256, per-key salt, versioned for rotation)
//! - Scopes: chat:read, tools:exec, admin
//! - Tamper-evident audit: hash-chained events, verify() detects any tamper
//! - Sandboxed tool exec path (jailed subprocess: timeout, cwd jail, clean env)
//! - Tenant isolation: audit/exec history is namespaced per tenant
//! - Fleet scoping: per-node key allowlists (X-Fleet-Node)

use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- keys

pub const PBKDF2_ITERATIONS: u32 = 60_000;
pub const SCOPES: [&str; 3] = ["chat:read", "tools:exec", "admin"];

pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A versioned key. The plaintext NEVER lives here after creation.
#[derive(Clone, Debug)]
pub struct KeyRecord {
    pub tenant_id: String,
    pub key_id: String, // version identifier, e.g. "v1"
    pub salt: Vec<u8>,
    pub hash_hex: String, // PBKDF2(..., salt, iters) hex
    pub scopes: Vec<String>,
    /// Node allowlist; None = all fleet nodes.
    pub nodes: Option<Vec<String>>,
    pub revoked: bool,
    pub created: f64,
}

impl KeyRecord {
    /// Fleet scoping: a key may be restricted to specific nodes. A key
    /// with no node restriction works everywhere (default, unchanged).
    pub fn allowed_on(&self, node_id: &str) -> bool {
        match &self.nodes {
            None => true,
            Some(nodes) => nodes.iter().any(|n| n == node_id),
        }
    }
}

/// In-memory key vault. mint() returns the plaintext EXACTLY ONCE;
/// from then on only hashes are held, verification is constant-time.
///
/// `records` is exposed (like Python's `_records`) for tests/introspection
/// only: tenant -> key versions.
pub struct KeyVault {
    pub records: HashMap<String, Vec<KeyRecord>>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Constant-time byte equality (mirrors Python's hmac.compare_digest).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// PBKDF2-HMAC-SHA256 helper (public for tests): hex digest of input+salt.
pub fn pbkdf2_hex(input: &str, salt: &[u8]) -> String {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(input.as_bytes(), salt, PBKDF2_ITERATIONS, &mut out);
    hex(&out)
}

impl Default for KeyVault {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyVault {
    pub fn new() -> Self {
        KeyVault { records: HashMap::new() }
    }

    /// Returns (plaintext_key, key_id). Plaintext is shown once, never stored.
    /// `nodes` optionally scopes the key to a fleet-node allowlist (None = all).
    pub fn mint(
        &mut self,
        tenant_id: &str,
        scopes: &[&str],
        nodes: Option<&[String]>,
    ) -> (String, String) {
        let mut raw_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut raw_bytes);
        let raw = format!("bkx-{}", hex(&raw_bytes));
        let versions = self.records.entry(tenant_id.to_string()).or_default();
        let key_id = format!("v{}", versions.len() + 1);
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let hash_hex = pbkdf2_hex(&raw, &salt);
        let kept_scopes: Vec<String> = scopes
            .iter()
            .filter(|s| SCOPES.contains(&s.as_ref()))
            .map(|s| s.to_string())
            .collect();
        versions.push(KeyRecord {
            tenant_id: tenant_id.to_string(),
            key_id: key_id.clone(),
            salt: salt.to_vec(),
            hash_hex,
            scopes: kept_scopes,
            nodes: nodes.map(|ns| ns.to_vec()),
            revoked: false,
            created: now_unix(),
        });
        (raw, key_id)
    }

    /// Verify a bearer key. When `node_id` is given, keys scoped to other
    /// fleet nodes do not authenticate there (per-node allowlist).
    pub fn authenticate(
        &self,
        authorization: Option<&str>,
        node_id: Option<&str>,
    ) -> Option<KeyRecord> {
        let auth = authorization?;
        if !auth.to_ascii_lowercase().starts_with("bearer ") {
            return None;
        }
        let presented = auth.splitn(2, ' ').nth(1)?.trim();
        for versions in self.records.values() {
            for rec in versions {
                if rec.revoked {
                    continue;
                }
                if let Some(node) = node_id {
                    if !rec.allowed_on(node) {
                        continue;
                    }
                }
                let digest = pbkdf2_hex(presented, &rec.salt);
                // constant-time comparison
                if constant_time_eq(digest.as_bytes(), rec.hash_hex.as_bytes()) {
                    return Some(rec.clone());
                }
            }
        }
        None
    }

    pub fn revoke(&mut self, tenant_id: &str, key_id: &str) -> bool {
        if let Some(versions) = self.records.get_mut(tenant_id) {
            for rec in versions.iter_mut() {
                if rec.key_id == key_id {
                    rec.revoked = true;
                    return true;
                }
            }
        }
        false
    }

    /// Mint a new version; old versions keep working until revoked.
    /// Node scoping carries over only if explicitly passed.
    pub fn rotate(
        &mut self,
        tenant_id: &str,
        scopes: &[&str],
        nodes: Option<&[String]>,
    ) -> (String, String) {
        self.mint(tenant_id, scopes, nodes)
    }
}

// ---------------------------------------------------------------- fleet
//
// Fleet nodes: the compute pool behind Bastion. Each node is a base URL;
// keys may be scoped per node (KeyRecord.nodes). The default gateway
// (BK_BASE_URL) is unchanged when no node is specified.

pub const DEFAULT_NODE: &str = "default";

/// Node id -> base URL, from BASTION_FLEET_NODES (comma-separated
/// id=url pairs). Empty env -> only the default gateway exists.
pub fn fleet_nodes() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let raw = std::env::var("BASTION_FLEET_NODES").unwrap_or_default();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if let Some((nid, url)) = pair.split_once('=') {
            let (nid, url) = (nid.trim(), url.trim());
            if !nid.is_empty() && !url.is_empty() {
                out.insert(nid.to_string(), url.to_string());
            }
        }
    }
    out
}

// ------------------------------------------------- tamper-evident audit

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub seq: usize,
    pub ts: f64,
    pub prev: String,
    pub body: String,
    pub h: String,
}

/// Append-only hash chain. Each entry commits to the previous hash, so
/// editing, deleting, or reordering any event breaks verification.
#[derive(Default)]
pub struct AuditChain {
    /// Exposed (like Python's `events`) so tests can tamper/inspect.
    pub events: Vec<AuditEntry>,
}

/// JSON body with sorted keys, mirroring Python's json.dumps(sort_keys=True).
pub fn sorted_json(event: &serde_json::Value) -> String {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
                let mut out = serde_json::Map::new();
                for (k, val) in sorted {
                    out.insert(k.clone(), sort(val));
                }
                serde_json::Value::Object(out)
            }
            other => other.clone(),
        }
    }
    sort(event).to_string()
}

impl AuditChain {
    pub fn new() -> Self {
        AuditChain { events: Vec::new() }
    }

    pub fn append(&mut self, event: &serde_json::Value) -> AuditEntry {
        let prev = self
            .events
            .last()
            .map(|e| e.h.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let body = sorted_json(event);
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(body.as_bytes());
        let h = hex(&hasher.finalize());
        let entry = AuditEntry {
            seq: self.events.len(),
            ts: now_unix(),
            prev,
            body,
            h,
        };
        self.events.push(entry.clone());
        entry
    }

    /// Recompute the whole chain. Returns (ok, first_bad_reason).
    pub fn verify(&self) -> (bool, Option<String>) {
        let mut prev = GENESIS.to_string();
        for (i, e) in self.events.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(e.prev.as_bytes());
            hasher.update(e.body.as_bytes());
            let expect = hex(&hasher.finalize());
            if e.prev != prev {
                return (
                    false,
                    Some(format!("entry {}: prev-hash mismatch (delete/reorder/edit)", i)),
                );
            }
            if e.h != expect {
                return (
                    false,
                    Some(format!("entry {}: body does not match its hash (edited)", i)),
                );
            }
            prev = e.h.clone();
        }
        (true, None)
    }
}

// ---------------------------------------------------------------- sandbox

pub struct ExecResult {
    pub ok: bool,
    pub rc: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub wall_s: f64,
    pub jail: String,
}

/// Run tenant code in a jailed subprocess: disposable cwd, clean env
/// (no proxy/cluster secrets), output captured, hard timeout.
pub fn sandbox_exec(code: &str, timeout_s: f64) -> ExecResult {
    let jail = std::env::temp_dir().join(format!("bastion-sbx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&jail);
    std::fs::create_dir_all(&jail).expect("create jail dir");
    let jail_name = jail
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let path = jail.join("task.py");
    std::fs::write(&path, code).expect("write task.py");

    let python = if cfg!(windows) { "python" } else { "python3" };
    let t0 = std::time::Instant::now();
    let mut cmd = std::process::Command::new(python);
    cmd.arg(&path)
        .current_dir(&jail)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let result = run_with_timeout(&mut cmd, timeout_s);
    let wall_s = (t0.elapsed().as_secs_f64() * 1000.0).round() / 1000.0;
    let _ = std::fs::remove_dir_all(&jail);

    let (ok, rc, stdout, stderr) = match result {
        Some(Ok((rc, out, err))) => (rc == 0, Some(rc), out, err),
        Some(Err(())) => (false, None, String::new(), "timeout".to_string()),
        None => (false, None, String::new(), "failed to spawn".to_string()),
    };
    ExecResult {
        ok,
        rc,
        stdout: stdout.chars().rev().take(2000).collect::<String>().chars().rev().collect(),
        stderr: stderr.chars().rev().take(2000).collect::<String>().chars().rev().collect(),
        wall_s,
        jail: jail_name,
    }
}

/// Spawn, wait up to `timeout_s`, kill on expiry. Ok((rc, stdout, stderr)) or Err(()) on timeout.
fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout_s: f64,
) -> Option<Result<(i32, String, String), ()>> {
    use std::io::Read;
    let mut child = cmd.spawn().ok()?;
    let mut stdout_pipe = child.stdout.take()?;
    let mut stderr_pipe = child.stderr.take()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(timeout_s);
    // reader threads so an idle child can't block us on a pipe read
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = t_out.join().unwrap_or_default();
                let err = t_err.join().unwrap_or_default();
                return Some(Ok((
                    status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out).to_string(),
                    String::from_utf8_lossy(&err).to_string(),
                )));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(Err(()));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------- proxy

/// Forward to a fleet node. `base_url` targets a specific node; None
/// keeps the default BK_BASE_URL gateway (unchanged behavior).
pub fn forward_to_gateway(payload: &serde_json::Value, path: &str, base_url: Option<&str>) -> (u16, Vec<u8>) {
    let bk = base_url
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("BK_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3100".into()));
    let url = format!("{}{}", bk.trim_end_matches('/'), path);
    let key = std::env::var("bk_key_tenant_a").unwrap_or_else(|_| "bk-tenant-a-dev".into());
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(240))
        .build();
    match agent
        .post(&url)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", key))
        .send_string(&payload.to_string())
    {
        Ok(resp) => {
            let status = resp.status() as u16;
            let body = resp.into_string().unwrap_or_default().into_bytes();
            (status, body)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default().into_bytes();
            (code, body)
        }
        Err(e) => (
            502,
            serde_json::json!({"error": format!("gateway unreachable: {}", e)})
                .to_string()
                .into_bytes(),
        ),
    }
}
