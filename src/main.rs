//! Bastion HTTP server (Rust port of the FastAPI app in bastion.py).
//! Port 3200. 3001 is Cost Peep's, 3100 is Ball Knowledge's, 3000 never touched.

use bastion::{fleet_nodes, forward_to_gateway, sandbox_exec, AuditChain, KeyVault};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};

const SCOPES: [&str; 3] = ["chat:read", "tools:exec", "admin"];

#[derive(Default)]
struct State {
    vault: KeyVault,
    chains: HashMap<String, AuditChain>,
    exec_history: HashMap<String, Vec<serde_json::Value>>,
}

fn json_response(code: u16, body: serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = body.to_string().into_bytes();
    Response::from_data(data)
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn json_body(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

fn main() {
    let server = Server::http("0.0.0.0:3200").expect("bind :3200");
    let state = Arc::new(Mutex::new(State::default()));

    // Seed: mint one key per tenant at boot; log to env for the operator.
    {
        let mut st = state.lock().unwrap();
        for (tenant, scopes) in [
            ("tenant-a", vec!["chat:read", "tools:exec", "admin"]),
            ("tenant-b", vec!["chat:read", "tools:exec"]),
        ] {
            let (raw, kid) = st.vault.mint(tenant, &scopes, None);
            println!("[bastion] minted {} key {}: {}", tenant, kid, raw);
        }
    }

    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let (path, _query) = url.split_once('?').unwrap_or((&url, ""));
        let method = request.method().clone();
        let auth = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_string());
        let admin_token = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Admin-Token"))
            .map(|h| h.value.as_str().to_string());
        let fleet_node = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Fleet-Node"))
            .map(|h| h.value.as_str().to_string());
        let mut body = String::new();
        let _ = request.as_reader().read_to_string(&mut body);

        let state = Arc::clone(&state);
        let response = std::thread::spawn(move || {
            handle(method, path, auth, admin_token, fleet_node, body, state)
        })
        .join()
        .unwrap_or_else(|| json_response(500, serde_json::json!({"error": "handler panic"})));

        let _ = request.respond(response);
    }
}

fn handle(
    method: Method,
    path: &str,
    auth: Option<String>,
    admin_token: Option<String>,
    fleet_node: Option<String>,
    body: String,
    state: Arc<Mutex<State>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut st = state.lock().unwrap();

    match (&method, path) {
        (Method::Get, "/health") => {
            let (ok, bad) = st
                .chains
                .entry("tenant-a".to_string())
                .or_default()
                .verify();
            json_response(
                200,
                serde_json::json!({"ok": true, "audit_ok": ok, "audit_reason": bad}),
            )
        }

        (Method::Post, "/v1/chat/completions") => {
            let rec = st.vault.authenticate(auth.as_deref(), None);
            let rec = match rec {
                Some(r) => r,
                None => {
                    for chain in st.chains.values_mut() {
                        chain.append(&serde_json::json!({"event": "auth_rejected"}));
                    }
                    return json_response(
                        401,
                        serde_json::json!({"error": "invalid or missing key"}),
                    );
                }
            };
            if !rec.scopes.iter().any(|s| s == "chat:read") {
                st.chains
                    .entry(rec.tenant_id.clone())
                    .or_default()
                    .append(&serde_json::json!({"event": "scope_denied", "scope": "chat:read"}));
                return json_response(
                    403,
                    serde_json::json!({"error": "scope chat:read required"}),
                );
            }
            let payload = json_body(&body);
            // Fleet routing: X-Fleet-Node targets a specific node. The key must
            // be allowed on that node; unscoped keys work anywhere.
            let base_url = match &fleet_node {
                Some(node_id) => {
                    let recheck = st
                        .vault
                        .authenticate(auth.as_deref(), Some(node_id));
                    if recheck.is_none() {
                        st.chains
                            .entry(rec.tenant_id.clone())
                            .or_default()
                            .append(&serde_json::json!({"event": "node_denied", "node": node_id}));
                        return json_response(
                            403,
                            serde_json::json!({"error": format!("key not scoped to node {}", node_id)}),
                        );
                    }
                    match fleet_nodes().get(node_id) {
                        Some(u) => Some(u.clone()),
                        None => {
                            return json_response(
                                400,
                                serde_json::json!({"error": format!("unknown node {}", node_id)}),
                            )
                        }
                    }
                }
                None => None,
            };
            let (status, resp) =
                forward_to_gateway(&payload, "/v1/chat/completions", base_url.as_deref());
            let mut event = serde_json::json!({"event": "chat_served", "status": status, "bytes": resp.len()});
            if let Some(node) = &fleet_node {
                event["node"] = serde_json::Value::String(node.clone());
            }
            st.chains
                .entry(rec.tenant_id.clone())
                .or_default()
                .append(&event);
            Response::from_data(resp)
                .with_status_code(status)
                .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        }

        (Method::Post, "/v1/tools/exec") => {
            let rec = match st.vault.authenticate(auth.as_deref(), None) {
                Some(r) => r,
                None => {
                    return json_response(
                        401,
                        serde_json::json!({"error": "invalid or missing key"}),
                    )
                }
            };
            if !rec.scopes.iter().any(|s| s == "tools:exec") {
                st.chains
                    .entry(rec.tenant_id.clone())
                    .or_default()
                    .append(&serde_json::json!({"event": "scope_denied", "scope": "tools:exec"}));
                return json_response(
                    403,
                    serde_json::json!({"error": "scope tools:exec required"}),
                );
            }
            let payload = json_body(&body);
            let code = payload
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .chars()
                .take(20_000)
                .collect::<String>();
            let result = sandbox_exec(&code, 5.0);
            let ok = result.ok;
            let wall_s = result.wall_s;
            let history = st
                .exec_history
                .entry(rec.tenant_id.clone())
                .or_default()
                .len();
            st.exec_history
                .get_mut(&rec.tenant_id)
                .unwrap()
                .push(serde_json::json!({"seq": history, "wall_s": wall_s, "ok": ok}));
            st.chains
                .entry(rec.tenant_id.clone())
                .or_default()
                .append(&serde_json::json!({"event": "tool_exec", "ok": ok, "wall_s": wall_s}));
            json_response(
                if ok { 200 } else { 500 },
                serde_json::json!({
                    "ok": ok, "rc": result.rc, "stdout": result.stdout,
                    "stderr": result.stderr, "wall_s": result.wall_s, "jail": result.jail
                }),
            )
        }

        (Method::Get, "/v1/audit") => {
            let rec = match st.vault.authenticate(auth.as_deref(), None) {
                Some(r) => r,
                None => {
                    return json_response(
                        401,
                        serde_json::json!({"error": "invalid or missing key"}),
                    )
                }
            };
            if !rec.scopes.iter().any(|s| s == "admin") {
                st.chains
                    .entry(rec.tenant_id.clone())
                    .or_default()
                    .append(&serde_json::json!({"event": "scope_denied", "scope": "admin"}));
                return json_response(
                    403,
                    serde_json::json!({"error": "admin scope required"}),
                );
            }
            let chain = st.chains.entry(rec.tenant_id.clone()).or_default();
            let (ok, reason) = chain.verify();
            let events: Vec<serde_json::Value> = chain
                .events
                .iter()
                .rev()
                .take(200)
                .rev()
                .map(|e| {
                    serde_json::json!({"seq": e.seq, "ts": e.ts, "prev": e.prev, "body": e.body, "h": e.h})
                })
                .collect();
            json_response(
                200,
                serde_json::json!({"tenant": rec.tenant_id, "events": events,
                                   "integrity_ok": ok, "integrity_reason": reason}),
            )
        }

        (Method::Post, p) if p.starts_with("/admin/keys/rotate/") => {
            let tenant = p.trim_start_matches("/admin/keys/rotate/");
            if !admin_authorized(admin_token.as_deref()) {
                return json_response(403, serde_json::json!({"error": "admin token required"}));
            }
            // Least privilege: rotations carry ONLY explicitly granted scopes.
            let payload = json_body(&body);
            let scopes: Vec<String> = payload
                .get("scopes")
                .and_then(|s| s.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| SCOPES.contains(s))
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();
            if scopes.is_empty() {
                return json_response(
                    400,
                    serde_json::json!({"error": "pass scopes in body, e.g. {\"scopes\": [\"chat:read\"]}"}),
                );
            }
            let (raw, kid) = st.vault.rotate(tenant, &scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(), None);
            st.chains
                .entry(tenant.to_string())
                .or_default()
                .append(&serde_json::json!({"event": "key_rotated", "key_id": kid, "scopes": scopes}));
            json_response(
                200,
                serde_json::json!({"key": raw, "key_id": kid, "scopes": scopes,
                                   "note": "old version still valid until revoked"}),
            )
        }

        (Method::Post, p) if p.starts_with("/admin/keys/revoke/") => {
            let rest = p.trim_start_matches("/admin/keys/revoke/");
            let (tenant, key_id) = rest.split_once('/').unwrap_or((rest, ""));
            if !admin_authorized(admin_token.as_deref()) {
                return json_response(403, serde_json::json!({"error": "admin token required"}));
            }
            let ok = st.vault.revoke(tenant, key_id);
            st.chains
                .entry(tenant.to_string())
                .or_default()
                .append(&serde_json::json!({
                    "event": if ok { "key_revoked" } else { "revoke_failed" }, "key_id": key_id}));
            json_response(200, serde_json::json!({"revoked": ok, "key_id": key_id}))
        }

        (Method::Get, p) if p.starts_with("/admin/audit/verify/") => {
            let tenant = p.trim_start_matches("/admin/audit/verify/");
            if !admin_authorized(admin_token.as_deref()) {
                return json_response(403, serde_json::json!({"error": "admin token required"}));
            }
            let chain = st.chains.entry(tenant.to_string()).or_default();
            let (ok, reason) = chain.verify();
            let entries = chain.events.len();
            json_response(
                200,
                serde_json::json!({"tenant": tenant, "integrity_ok": ok, "reason": reason, "entries": entries}),
            )
        }

        (Method::Post, p) if p.starts_with("/admin/chaos/tamper-audit/") => {
            let tenant = p.trim_start_matches("/admin/chaos/tamper-audit/");
            if !admin_authorized(admin_token.as_deref()) {
                return json_response(403, serde_json::json!({"error": "admin token required"}));
            }
            let chain = st.chains.entry(tenant.to_string()).or_default();
            if chain.events.is_empty() {
                return json_response(400, serde_json::json!({"error": "no events to tamper"}));
            }
            // Attack simulation: silent in-place edit of an existing entry body.
            let mid = chain.events.len() / 2;
            let victim = &mut chain.events[mid];
            victim.body = format!("{} ", victim.body);
            let (ok, reason) = chain.verify();
            json_response(200, serde_json::json!({"tampered": true, "integrity_ok": ok, "reason": reason}))
        }

        _ => json_response(404, serde_json::json!({"error": "not found"})),
    }
}

/// Admin plane gate: shared token via X-Admin-Token. Dev default; prod
/// would replace with mTLS/SSO. The point is: admin is NEVER anonymous.
fn admin_authorized(presented: Option<&str>) -> bool {
    let expected = std::env::var("BK_ADMIN_TOKEN").unwrap_or_else(|_| "bastion-admin-dev".into());
    let presented = presented.unwrap_or("");
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

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
